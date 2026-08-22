// Package mdns is a hand-written multicast DNS and DNS-SD responder.
//
// It answers three things on the local link, from raw UDP multicast, with no
// Avahi and no Bonjour:
//
//	gate.local                     A     the box's address
//	_gatecrash._tcp.local          PTR   the service instance
//	<instance>._gatecrash._tcp     SRV   port and target
//	<instance>._gatecrash._tcp     TXT   event name, api version, TLS fingerprint
//	_services._dns-sd._udp.local   PTR   service-type enumeration
//
// Why write it rather than wrap something: the box is one static binary that gets
// scp'd onto a Pi, and Avahi is a C daemon with a D-Bus dependency. Shipping it
// would mean shipping a distro, and the entire product promise is "flash the card,
// plug it in".
//
// The parts that turn out to matter in practice are not the record types. They
// are: honouring the unicast-response bit so a hall full of phones does not
// multicast-storm the access point, known-answer suppression so a device that
// already has the record stays quiet, sending unsolicited announcements at boot
// because Android's resolver is unreliable at asking, and sending goodbye packets
// at shutdown so a rebooted box does not inherit a stale cached address.
//
// mDNS is the first rung of the discovery ladder, not the whole thing. Android's
// mDNS support has historically been flaky and the target market is cheap phones,
// so the box also runs a wildcard DNS resolver, a captive portal, a UDP beacon,
// and prints a QR code. This package is expected to work most of the time, not
// all of it.
package mdns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ManasMadan/gatecrash/internal/dnswire"
)

// Protocol constants from RFC 6762.
const (
	// Port is the mDNS port.
	Port = 5353

	// TTLHost is the TTL for address records. RFC 6762 section 10 recommends 120
	// seconds for records that a host defends, which is short enough that a box
	// whose address changed is forgotten within a couple of minutes.
	TTLHost = 120

	// TTLService is the TTL for PTR and TXT records: 75 minutes, again from
	// section 10. These are stable for the life of an event.
	TTLService = 4500

	// TTLGoodbye is the TTL that means "forget this". A goodbye packet is the
	// same records with a zero TTL.
	TTLGoodbye = 0
)

var (
	// groupV4 is the IPv4 mDNS multicast group.
	groupV4 = netip.MustParseAddrPort("224.0.0.251:5353")

	// groupV6 is the IPv6 mDNS multicast group. Answered as well as IPv4 because
	// iOS prefers it and a venue network that is IPv6-only by accident is a real
	// thing on modern consumer routers.
	groupV6 = netip.MustParseAddrPort("[ff02::fb]:5353")
)

// Service describes what the box advertises.
type Service struct {
	// Instance is the human-readable service instance name, shown in a phone's
	// network browser. Typically the event name.
	Instance string

	// Type is the service type, without the domain: "_gatecrash._tcp".
	Type string

	// Host is the box's claimed hostname without the domain: "gate".
	Host string

	// Port is the HTTPS port the box serves on.
	Port uint16

	// IPv4 and IPv6 are the addresses to advertise. Empty slices are fine; a box
	// with no IPv6 simply does not answer AAAA queries.
	IPv4 []netip.Addr
	IPv6 []netip.Addr

	// TXT is the key-value metadata a client reads before connecting. This is
	// where the TLS fingerprint lives, which is what lets a scanner pin the
	// box's private CA without a separate round trip.
	TXT []string
}

// Defaults fills in the conventional values.
func (s *Service) Defaults() {
	if s.Type == "" {
		s.Type = "_gatecrash._tcp"
	}
	if s.Host == "" {
		s.Host = "gate"
	}
	if s.Instance == "" {
		s.Instance = "Gatecrash"
	}
	if s.Port == 0 {
		s.Port = 8443
	}
}

// hostname is the fully qualified host name, "gate.local.".
func (s Service) hostname() string { return dnswire.Fqdn(s.Host + ".local") }

// serviceName is the service type name, "_gatecrash._tcp.local.".
func (s Service) serviceName() string { return dnswire.Fqdn(s.Type + ".local") }

// instanceName is the service instance name.
//
// The instance label may contain spaces and mixed case per RFC 6763 section 4.1 —
// it is a human-readable label, not a hostname — which is why it is not run
// through any normalisation.
func (s Service) instanceName() string {
	return dnswire.Fqdn(s.Instance + "." + s.Type + ".local")
}

// enumerationName is the DNS-SD service-type enumeration name.
const enumerationName = "_services._dns-sd._udp.local."

// Responder answers mDNS queries for one service.
type Responder struct {
	service Service
	log     *slog.Logger

	// conns are the sockets the responder listens and sends on, one per address
	// family that opened successfully.
	conns []*conn

	// random drives the response delay jitter. Seeded rather than crypto/rand
	// because the simulator needs reproducible timing.
	randomMu sync.Mutex
	random   *rand.Rand

	stopped chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

// conn is one multicast socket.
type conn struct {
	pc    net.PacketConn
	group netip.AddrPort
	v6    bool
}

// Config configures a responder.
type Config struct {
	Service Service
	Logger  *slog.Logger

	// Seed makes response jitter reproducible. Zero uses a fixed seed, which is
	// fine: the jitter exists to spread responses across hosts, and this is the
	// only responder in the process.
	Seed int64

	// Interfaces restricts which interfaces to join the group on. Empty means
	// every interface that is up and supports multicast, which is what a box
	// wants: in AP mode it is wlan0, in router mode eth0, and it should not have
	// to be told which.
	Interfaces []net.Interface
}

// New builds a responder. It does not open sockets; call Run.
func New(cfg Config) (*Responder, error) {
	cfg.Service.Defaults()
	if len(cfg.Service.IPv4) == 0 && len(cfg.Service.IPv6) == 0 {
		return nil, errors.New("mdns: service advertises no addresses")
	}
	if strings.ContainsAny(cfg.Service.Host, ". ") {
		return nil, fmt.Errorf("mdns: host %q must be a single label without dots", cfg.Service.Host)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	seed := cfg.Seed
	if seed == 0 {
		seed = 0x6761746563726173
	}
	return &Responder{
		service: cfg.Service,
		log:     logger,
		random:  rand.New(rand.NewSource(seed)),
		stopped: make(chan struct{}),
	}, nil
}

// Run joins the multicast groups, announces, and serves until the context is
// cancelled. It blocks.
func (r *Responder) Run(ctx context.Context) error {
	if err := r.listen(ctx); err != nil {
		return err
	}
	defer r.closeConns()

	for _, c := range r.conns {
		r.wg.Add(1)
		go func(c *conn) {
			defer r.wg.Done()
			r.serve(ctx, c)
		}(c)
	}

	// Unsolicited announcements at startup, because Android's resolver is
	// unreliable at asking and a device that joined the Wi-Fi before the box
	// finished booting would otherwise wait for its own cache to expire. RFC 6762
	// section 8.3 asks for two to eight, a second apart.
	r.announce(ctx)

	<-ctx.Done()

	// Goodbye packets, so a rebooted box does not inherit a stale cached
	// address. This is the difference between a scanner reconnecting in two
	// seconds and one that sits there for two minutes.
	//
	// Sent twice: a lost goodbye costs a scanner the full record TTL pointing at
	// a box that is not there.
	r.broadcast(goodbyeOf(r.allRecords()))
	r.broadcast(goodbyeOf(r.allRecords()))
	r.closeConns()
	r.wg.Wait()
	return nil
}

// listen opens one socket per address family.
func (r *Responder) listen(ctx context.Context) error {
	var listener net.ListenConfig
	var opened []*conn

	if len(r.service.IPv4) > 0 {
		pc, err := listener.ListenPacket(ctx, "udp4", fmt.Sprintf("0.0.0.0:%d", Port))
		if err != nil {
			// A box sharing a host with an existing Avahi cannot bind, which is
			// a normal state on a developer laptop and must not be fatal: the
			// rest of the discovery ladder still works.
			r.log.Warn("mdns: could not bind IPv4", "error", err)
		} else {
			opened = append(opened, &conn{pc: pc, group: groupV4})
		}
	}
	if len(r.service.IPv6) > 0 {
		pc, err := listener.ListenPacket(ctx, "udp6", fmt.Sprintf("[::]:%d", Port))
		if err != nil {
			r.log.Warn("mdns: could not bind IPv6", "error", err)
		} else {
			opened = append(opened, &conn{pc: pc, group: groupV6, v6: true})
		}
	}
	if len(opened) == 0 {
		return errors.New("mdns: could not bind any multicast socket")
	}
	r.conns = opened
	return nil
}

func (r *Responder) closeConns() {
	r.once.Do(func() {
		close(r.stopped)
		for _, c := range r.conns {
			c.pc.Close()
		}
	})
}

// serve reads and answers queries on one socket.
func (r *Responder) serve(ctx context.Context, c *conn) {
	// 9 KB is the largest useful mDNS message; anything larger is malformed and
	// gets truncated into a parse failure, which is the correct outcome.
	buf := make([]byte, dnswire.MaxMessageLen)

	for {
		n, from, err := c.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-r.stopped:
				return
			case <-ctx.Done():
				return
			default:
			}
			// A read error on a multicast socket is usually an interface going
			// away. Log once and keep going; the socket recovers when it comes
			// back.
			r.log.Debug("mdns: read", "error", err)
			continue
		}

		query, err := dnswire.Unpack(buf[:n])
		if err != nil {
			// Anybody on the network can send this. Dropping silently at debug
			// level is deliberate: logging every malformed packet at info would
			// make one hostile device fill the box's disk.
			r.log.Debug("mdns: dropping malformed packet", "from", from, "error", err)
			continue
		}
		// Responses are other hosts talking. The box has no cache to update, so
		// there is nothing to do with them beyond noticing a name conflict, which
		// checkConflict handles.
		if query.Header.Response {
			r.checkConflict(query, from)
			continue
		}
		r.answer(ctx, c, query, from)
	}
}

// answer builds and sends a response to one query.
func (r *Responder) answer(ctx context.Context, c *conn, query dnswire.Message, from net.Addr) {
	packet, unicast, ok := r.Respond(query)
	if !ok {
		return
	}

	// RFC 6762 section 6 asks for a 20 to 120 ms delay on multicast responses to
	// shared records, so that many responders do not answer simultaneously.
	// Unicast responses go immediately: the asker is waiting and there is nobody
	// to collide with.
	if !unicast {
		r.sleepJitter(ctx, 20*time.Millisecond, 120*time.Millisecond)
	}

	target := c.group
	if unicast {
		if addr, ok := addrPortOf(from); ok {
			target = addr
		}
	}
	r.send(c, packet, target)
}

// Respond builds the response to one query without sending it.
//
// Split out from answer so the whole matching, suppression and
// additional-section behaviour is testable without opening a multicast socket.
// Every interesting bug in an mDNS responder lives in this function, and a test
// that has to bind 224.0.0.251 to reach it is a test that does not run in CI.
//
// ok is false when the box has nothing to say, which is the common case: most
// mDNS traffic on a venue network is phones looking for printers.
func (r *Responder) Respond(query dnswire.Message) (packet []byte, unicast, ok bool) {
	if query.Header.Response {
		return nil, false, false
	}

	var answers, additional []dnswire.Record
	for _, q := range query.Questions {
		matched := r.records(q)
		if len(matched) == 0 {
			continue
		}
		// Known-answer suppression, RFC 6762 section 7.1: a querier lists the
		// records it already holds, and a responder holding nothing newer stays
		// quiet. On a network with five thousand phones this is the difference
		// between a working access point and a broadcast storm.
		matched = suppressKnown(matched, query.Answers)
		if len(matched) == 0 {
			continue
		}
		answers = append(answers, matched...)
		additional = append(additional, r.additionalFor(q)...)
		if q.Unicast {
			unicast = true
		}
	}
	if len(answers) == 0 {
		return nil, false, false
	}

	builder := dnswire.NewBuilder(dnswire.Header{
		// A response to a query carries the query's id in unicast mode and zero
		// in multicast mode, per RFC 6762 section 18.1.
		ID:            queryID(query, unicast),
		Response:      true,
		Authoritative: true,
	})
	for _, record := range dedupe(answers, nil) {
		if err := builder.AddAnswer(record); err != nil {
			r.log.Debug("mdns: skipping answer", "error", err)
		}
	}
	for _, record := range dedupe(additional, answers) {
		if err := builder.AddAdditional(record); err != nil {
			r.log.Debug("mdns: skipping additional", "error", err)
		}
	}
	return builder.Bytes(), unicast, true
}

// Announcement returns the unsolicited announcement packet, exposed so the
// discovery ladder's tests and the box's diagnostics page can inspect exactly
// what is being broadcast.
func (r *Responder) Announcement() []byte { return r.packRecords(r.allRecords()) }

// Goodbye returns the shutdown packet: the same records with a zero TTL.
func (r *Responder) Goodbye() []byte {
	records := r.allRecords()
	for i := range records {
		records[i].TTL = TTLGoodbye
	}
	return r.packRecords(records)
}

// queryID returns the id to echo in a response.
func queryID(query dnswire.Message, unicast bool) uint16 {
	if unicast {
		return query.Header.ID
	}
	return 0
}

// records returns the records that answer one question.
func (r *Responder) records(q dnswire.Question) []dnswire.Record {
	if q.Class != dnswire.ClassINET && q.Class != dnswire.ClassANY {
		return nil
	}

	wants := func(t dnswire.Type) bool { return q.Type == t || q.Type == dnswire.TypeANY }

	switch {
	case dnswire.EqualNames(q.Name, r.service.hostname()):
		var out []dnswire.Record
		if wants(dnswire.TypeA) {
			out = append(out, r.addressRecords(false)...)
		}
		if wants(dnswire.TypeAAAA) {
			out = append(out, r.addressRecords(true)...)
		}
		return out

	case dnswire.EqualNames(q.Name, r.service.serviceName()):
		if !wants(dnswire.TypePTR) {
			return nil
		}
		return []dnswire.Record{r.servicePTR()}

	case dnswire.EqualNames(q.Name, r.service.instanceName()):
		var out []dnswire.Record
		if wants(dnswire.TypeSRV) {
			out = append(out, r.srv())
		}
		if wants(dnswire.TypeTXT) {
			out = append(out, r.txt())
		}
		return out

	case dnswire.EqualNames(q.Name, enumerationName):
		if !wants(dnswire.TypePTR) {
			return nil
		}
		// DNS-SD service-type enumeration: "what kinds of service are here".
		// Answering it is what makes the box show up in a generic network
		// browser rather than only to something already looking for Gatecrash.
		return []dnswire.Record{{
			Name: enumerationName, Type: dnswire.TypePTR, Class: dnswire.ClassINET,
			TTL: TTLService, Target: r.service.serviceName(),
		}}
	}
	return nil
}

// additionalFor returns the records a client will need next, so it does not have
// to ask again.
//
// A phone that resolves the PTR immediately wants the SRV, the TXT and the A. On
// a saturated venue network each extra round trip is a real risk of the whole
// resolution timing out, so they all ride along in the additional section.
func (r *Responder) additionalFor(q dnswire.Question) []dnswire.Record {
	switch {
	case dnswire.EqualNames(q.Name, r.service.serviceName()):
		out := []dnswire.Record{r.srv(), r.txt()}
		out = append(out, r.addressRecords(false)...)
		return append(out, r.addressRecords(true)...)
	case dnswire.EqualNames(q.Name, r.service.instanceName()):
		out := r.addressRecords(false)
		return append(out, r.addressRecords(true)...)
	default:
		return nil
	}
}

// addressRecords builds the A or AAAA records for the box.
func (r *Responder) addressRecords(v6 bool) []dnswire.Record {
	addrs, typ := r.service.IPv4, dnswire.TypeA
	if v6 {
		addrs, typ = r.service.IPv6, dnswire.TypeAAAA
	}
	out := make([]dnswire.Record, 0, len(addrs))
	for _, addr := range addrs {
		ip := addr.AsSlice()
		if v6 && len(ip) != 16 {
			continue
		}
		if !v6 && len(ip) != 4 {
			continue
		}
		out = append(out, dnswire.Record{
			Name: r.service.hostname(), Type: typ, Class: dnswire.ClassINET,
			TTL: TTLHost,
			// Cache-flush on address records: the box is the unique owner of its
			// own name, so a receiver should discard whatever it had.
			CacheFlush: true,
			IP:         ip,
		})
	}
	return out
}

func (r *Responder) servicePTR() dnswire.Record {
	return dnswire.Record{
		Name: r.service.serviceName(), Type: dnswire.TypePTR, Class: dnswire.ClassINET,
		TTL: TTLService, Target: r.service.instanceName(),
		// No cache-flush on a service PTR: it is a shared record, and several
		// boxes at one venue legitimately answer it. Setting the bit would make
		// each box erase the others.
	}
}

func (r *Responder) srv() dnswire.Record {
	return dnswire.Record{
		Name: r.service.instanceName(), Type: dnswire.TypeSRV, Class: dnswire.ClassINET,
		TTL: TTLHost, CacheFlush: true,
		Port: r.service.Port, Target: r.service.hostname(),
	}
}

func (r *Responder) txt() dnswire.Record {
	txt := r.service.TXT
	if len(txt) == 0 {
		txt = []string{""}
	}
	return dnswire.Record{
		Name: r.service.instanceName(), Type: dnswire.TypeTXT, Class: dnswire.ClassINET,
		TTL: TTLService, CacheFlush: true, TXT: txt,
	}
}

// allRecords is everything the box advertises, used for announcements and
// goodbyes.
func (r *Responder) allRecords() []dnswire.Record {
	out := []dnswire.Record{
		{
			Name: enumerationName, Type: dnswire.TypePTR, Class: dnswire.ClassINET,
			TTL: TTLService, Target: r.service.serviceName(),
		},
		r.servicePTR(),
		r.srv(),
		r.txt(),
	}
	out = append(out, r.addressRecords(false)...)
	return append(out, r.addressRecords(true)...)
}

// announce sends unsolicited responses at startup.
//
// RFC 6762 section 8.3 asks for two to eight announcements a second apart. Three
// is what this sends: enough that a phone which was mid-DHCP for the first one
// still catches the second, without spending ten seconds of the twenty-second
// boot budget on it.
func (r *Responder) announce(ctx context.Context) {
	const announcements = 3

	for i := 0; i < announcements; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
		r.broadcast(r.allRecords())
	}
}

// goodbyeOf returns the same records with a zero TTL, which is how mDNS says
// "forget this".
func goodbyeOf(records []dnswire.Record) []dnswire.Record {
	out := append([]dnswire.Record(nil), records...)
	for i := range out {
		out[i].TTL = TTLGoodbye
	}
	return out
}

// broadcast multicasts a set of records as an unsolicited response.
func (r *Responder) broadcast(records []dnswire.Record) {
	packed := r.packRecords(records)
	for _, c := range r.conns {
		r.send(c, packed, c.group)
	}
}

// packRecords builds an unsolicited response carrying the given records.
func (r *Responder) packRecords(records []dnswire.Record) []byte {
	builder := dnswire.NewBuilder(dnswire.Header{Response: true, Authoritative: true})
	for _, record := range records {
		if err := builder.AddAnswer(record); err != nil {
			r.log.Debug("mdns: skipping record in announcement", "error", err)
		}
	}
	return builder.Bytes()
}

// send writes a packet, skipping the address families a socket cannot reach.
func (r *Responder) send(c *conn, packet []byte, to netip.AddrPort) {
	if c.v6 != to.Addr().Is6() {
		return
	}
	if _, err := c.pc.WriteTo(packet, net.UDPAddrFromAddrPort(to)); err != nil {
		r.log.Debug("mdns: write", "to", to, "error", err)
	}
}

// checkConflict notices another host claiming the box's name.
//
// RFC 6762 section 9 prescribes a full conflict-resolution dance. The box does
// not do it: two boxes claiming gate.local at one venue is a setup error that
// renaming would hide, and a gate that silently became gate-2.local is a gate
// every scanner has lost. So it logs loudly and lets the operator fix it.
func (r *Responder) checkConflict(msg dnswire.Message, from net.Addr) {
	for _, record := range msg.Answers {
		if record.Type != dnswire.TypeA && record.Type != dnswire.TypeAAAA {
			continue
		}
		if !dnswire.EqualNames(record.Name, r.service.hostname()) {
			continue
		}
		if r.ownAddress(record.IP) {
			continue
		}
		r.log.Warn("mdns: another host is claiming our name",
			"name", r.service.hostname(), "their_address", net.IP(record.IP).String(), "from", from)
	}
}

// ownAddress reports whether an address is one the box advertises.
func (r *Responder) ownAddress(ip []byte) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, own := range r.service.IPv4 {
		if own == addr {
			return true
		}
	}
	for _, own := range r.service.IPv6 {
		if own == addr {
			return true
		}
	}
	return false
}

// suppressKnown drops records the querier says it already has with at least half
// the TTL remaining, per RFC 6762 section 7.1.
func suppressKnown(candidates, known []dnswire.Record) []dnswire.Record {
	if len(known) == 0 {
		return candidates
	}
	out := candidates[:0:0]
	for _, candidate := range candidates {
		suppressed := false
		for _, k := range known {
			if !sameRecord(candidate, k) {
				continue
			}
			// The rule is "at least half the TTL remaining". A querier reporting a
			// nearly-expired record still wants a refresh.
			if k.TTL*2 >= candidate.TTL {
				suppressed = true
				break
			}
		}
		if !suppressed {
			out = append(out, candidate)
		}
	}
	return out
}

// sameRecord reports whether two records carry the same data for the same name.
func sameRecord(a, b dnswire.Record) bool {
	if a.Type != b.Type || !dnswire.EqualNames(a.Name, b.Name) {
		return false
	}
	switch a.Type {
	case dnswire.TypeA, dnswire.TypeAAAA:
		return bytes.Equal(a.IP, b.IP)
	case dnswire.TypePTR, dnswire.TypeCNAME:
		return dnswire.EqualNames(a.Target, b.Target)
	case dnswire.TypeSRV:
		return a.Port == b.Port && dnswire.EqualNames(a.Target, b.Target)
	case dnswire.TypeTXT:
		return strings.Join(a.TXT, "\x00") == strings.Join(b.TXT, "\x00")
	default:
		return bytes.Equal(a.Data, b.Data)
	}
}

// dedupe drops additional records that are already in the answer section.
// Sending the same record twice is legal and makes some resolvers complain.
func dedupe(additional, answers []dnswire.Record) []dnswire.Record {
	out := additional[:0:0]
	for _, candidate := range additional {
		duplicate := false
		for _, existing := range answers {
			if sameRecord(candidate, existing) {
				duplicate = true
				break
			}
		}
		for _, existing := range out {
			if sameRecord(candidate, existing) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, candidate)
		}
	}
	return out
}

// sleepJitter waits a random duration in [low, high].
func (r *Responder) sleepJitter(ctx context.Context, low, high time.Duration) {
	r.randomMu.Lock()
	span := int64(high - low)
	delay := low
	if span > 0 {
		delay += time.Duration(r.random.Int63n(span))
	}
	r.randomMu.Unlock()

	select {
	case <-ctx.Done():
	case <-time.After(delay):
	}
}

// addrPortOf converts a net.Addr to a netip.AddrPort.
func addrPortOf(addr net.Addr) (netip.AddrPort, bool) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	parsed, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(parsed.Unmap(), uint16(udp.Port)), true
}
