// Package dnsd is the box's unicast DNS server: the second rung of the discovery
// ladder.
//
// mDNS is first because it needs no configuration, but Android's mDNS support has
// historically been unreliable and the target market is cheap Android phones. So
// the box also runs a real DNS server, and in AP mode it is the DNS server the
// venue network hands out over DHCP. That buys two things.
//
// First, friendly names that work everywhere: http://go.gate resolves on any
// device with a resolver, which is all of them, with none of mDNS's caveats.
//
// Second, the captive portal. When wildcard mode is on, every name resolves to
// the box, which is what makes an operating system's connectivity probe reach the
// box's portal handler and pop the "sign in to network" sheet. That sheet is the
// single most effective piece of onboarding in the product: it pushes the UI to
// the attendee rather than asking them to type anything.
//
// Lying to a resolver is a real thing to do and it is done deliberately and only
// where it is the box's own network. In router mode, where the venue's own
// infrastructure owns DNS, wildcard is off and anything the box does not own is
// forwarded upstream unchanged.
package dnsd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ManasMadan/gatecrash/internal/dnswire"
)

// Default TTLs.
const (
	// TTLOwned is the TTL for names the box owns. Short, because a box whose
	// address changes should be re-resolved quickly, and because a device that
	// leaves the venue should stop believing in gate.local within a minute.
	TTLOwned = 30

	// TTLWildcard is the TTL for captive-portal answers. Very short: the lie
	// should evaporate the moment the device is on a real network again, and a
	// phone that cached "google.com is 10.11.0.1" for an hour is a phone whose
	// owner will remember this event for the wrong reason.
	TTLWildcard = 5
)

// Config configures the server.
type Config struct {
	// Box is the address every owned and wildcarded name resolves to.
	Box netip.Addr

	// Names are the names the box answers authoritatively, in addition to the
	// conventional ones. Matching includes subdomains, so "gate" also answers
	// "api.gate".
	Names []string

	// Wildcard makes every name the box does not own resolve to the box. This is
	// the captive portal, and it is only correct on a network the box owns.
	Wildcard bool

	// Upstream is where to forward names the box does not own when Wildcard is
	// off. Empty means answer REFUSED, which is the honest thing for a box with
	// no upstream: pretending a name does not exist would make a device give up
	// on DNS entirely rather than try another server.
	Upstream []netip.AddrPort

	// UpstreamTimeout bounds a forwarded query. Zero picks two seconds, which is
	// long enough for a working upstream and short enough that a dead one does
	// not hold a client's resolver open.
	UpstreamTimeout time.Duration

	Logger *slog.Logger
}

// DefaultNames are the names the box always answers.
//
// "gate.local" duplicates mDNS on purpose: a device that failed to resolve it
// over multicast will often retry it as a normal DNS query, and answering both
// ways costs nothing. "go.gate" is the one printed on signage, because it is
// short enough to type on a phone in a queue and has no dot to make a browser
// treat it as a search term.
var DefaultNames = []string{"gate.local", "gate", "go.gate", "gatecrash.local", "tickets.gate"}

// Server answers DNS queries.
type Server struct {
	cfg   Config
	log   *slog.Logger
	names []string
}

// New builds a server.
func New(cfg Config) (*Server, error) {
	if !cfg.Box.IsValid() {
		return nil, errors.New("dnsd: no box address")
	}
	if cfg.UpstreamTimeout == 0 {
		cfg.UpstreamTimeout = 2 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	names := make([]string, 0, len(DefaultNames)+len(cfg.Names))
	seen := make(map[string]bool)
	for _, name := range append(append([]string{}, DefaultNames...), cfg.Names...) {
		normalised := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if normalised == "" || seen[normalised] {
			continue
		}
		seen[normalised] = true
		names = append(names, normalised)
	}
	return &Server{cfg: cfg, log: logger, names: names}, nil
}

// Names returns the names the server answers authoritatively.
func (s *Server) Names() []string { return append([]string(nil), s.names...) }

// Owns reports whether a name is one the box answers for. Matching includes
// subdomains: owning "gate" also owns "api.gate", which is what lets the box
// serve several hostnames without listing them all.
func (s *Server) Owns(name string) bool {
	for _, owned := range s.names {
		if dnswire.HasSuffixName(name, owned) {
			return true
		}
	}
	return false
}

// Resolve answers one query, returning the response packet.
//
// Pure and synchronous apart from upstream forwarding, so the whole decision
// table is testable without binding port 53 — which a test cannot do without
// root, and which would make the test suite unrunnable in CI.
func (s *Server) Resolve(ctx context.Context, query dnswire.Message) []byte {
	// A response arriving on the server port is either a misdirected packet or
	// somebody trying to use the box as a reflector. Neither deserves a reply.
	if query.Header.Response {
		return nil
	}
	// Only standard queries. The box is not a dynamic-update server and saying so
	// is better than ignoring it.
	if query.Header.Opcode != 0 {
		return s.refuse(query, dnswire.RCodeNotImpl)
	}
	if len(query.Questions) == 0 {
		return s.refuse(query, dnswire.RCodeFormat)
	}

	question := query.Questions[0]
	if question.Class != dnswire.ClassINET && question.Class != dnswire.ClassANY {
		return s.refuse(query, dnswire.RCodeNotImpl)
	}

	switch {
	case s.Owns(question.Name):
		return s.answerOwned(query, question)
	case s.cfg.Wildcard:
		return s.answerWildcard(query, question)
	case len(s.cfg.Upstream) > 0:
		return s.forward(ctx, query)
	default:
		// REFUSED rather than NXDOMAIN. NXDOMAIN is an authoritative claim that
		// the name does not exist, which would make a device stop trying other
		// resolvers; REFUSED tells it to ask somebody else, which is the truth.
		return s.refuse(query, dnswire.RCodeRefused)
	}
}

// answerOwned answers for a name the box owns.
func (s *Server) answerOwned(query dnswire.Message, question dnswire.Question) []byte {
	builder := s.reply(query, true)

	switch question.Type {
	case dnswire.TypeA, dnswire.TypeANY:
		if s.cfg.Box.Is4() {
			_ = builder.AddAnswer(dnswire.Record{
				Name: question.Name, Type: dnswire.TypeA, Class: dnswire.ClassINET,
				TTL: TTLOwned, IP: s.cfg.Box.AsSlice(),
			})
		}
	case dnswire.TypeAAAA:
		if s.cfg.Box.Is6() && !s.cfg.Box.Is4In6() {
			_ = builder.AddAnswer(dnswire.Record{
				Name: question.Name, Type: dnswire.TypeAAAA, Class: dnswire.ClassINET,
				TTL: TTLOwned, IP: s.cfg.Box.AsSlice(),
			})
		}
		// An IPv4-only box answers AAAA with an empty NOERROR, not NXDOMAIN.
		// NXDOMAIN here is the classic mistake: it tells the client the name does
		// not exist at all, and a dual-stack client then gives up instead of
		// retrying over IPv4.
	}
	return builder.Bytes()
}

// answerWildcard resolves anything to the box, which is the captive portal.
func (s *Server) answerWildcard(query dnswire.Message, question dnswire.Question) []byte {
	// Not authoritative: the box knows perfectly well it is not the authority for
	// google.com, and claiming to be would be a lie with no upside.
	builder := s.reply(query, false)

	if (question.Type == dnswire.TypeA || question.Type == dnswire.TypeANY) && s.cfg.Box.Is4() {
		_ = builder.AddAnswer(dnswire.Record{
			Name: question.Name, Type: dnswire.TypeA, Class: dnswire.ClassINET,
			TTL: TTLWildcard, IP: s.cfg.Box.AsSlice(),
		})
	}
	// AAAA is deliberately answered empty even in wildcard mode. A device given
	// an IPv6 address for every name will prefer IPv6, fail to reach the box over
	// a link with no IPv6 routing, and report "no internet" without ever showing
	// the portal. Answering only A is what makes the portal actually appear.
	return builder.Bytes()
}

// reply starts a response to a query.
func (s *Server) reply(query dnswire.Message, authoritative bool) *dnswire.Builder {
	builder := dnswire.NewBuilder(dnswire.Header{
		ID:                 query.Header.ID,
		Response:           true,
		Authoritative:      authoritative,
		RecursionDesired:   query.Header.RecursionDesired,
		RecursionAvailable: s.cfg.Wildcard || len(s.cfg.Upstream) > 0,
	})
	for _, question := range query.Questions {
		// Echoing the question back is required by RFC 1035 and is what most
		// resolvers use to match a response to its query.
		_ = builder.AddQuestion(question)
	}
	return builder
}

// refuse builds an error response.
func (s *Server) refuse(query dnswire.Message, code dnswire.RCode) []byte {
	builder := dnswire.NewBuilder(dnswire.Header{
		ID:       query.Header.ID,
		Response: true,
		RCode:    code,
	})
	for _, question := range query.Questions {
		_ = builder.AddQuestion(question)
	}
	return builder.Bytes()
}

// forward relays a query to an upstream resolver.
//
// One socket per query rather than a shared connection with an id map. A venue
// box forwards a handful of queries a second at most, the sockets are ephemeral,
// and the id-rewriting bookkeeping a shared socket needs is exactly where DNS
// proxies grow cache-poisoning bugs.
func (s *Server) forward(ctx context.Context, query dnswire.Message) []byte {
	packed := repack(query)
	if packed == nil {
		return s.refuse(query, dnswire.RCodeFormat)
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.UpstreamTimeout)
	defer cancel()

	for _, upstream := range s.cfg.Upstream {
		response, err := s.exchange(ctx, upstream, packed)
		if err != nil {
			s.log.Debug("dnsd: upstream failed", "upstream", upstream, "error", err)
			continue
		}
		// The upstream's response already carries the right id, because the query
		// was forwarded verbatim.
		return response
	}
	// Every upstream failed. SERVFAIL is the honest answer and tells the client
	// to retry, which is what it should do.
	return s.refuse(query, dnswire.RCodeServer)
}

func (s *Server) exchange(ctx context.Context, upstream netip.AddrPort, packed []byte) ([]byte, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", upstream.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if _, err := conn.Write(packed); err != nil {
		return nil, err
	}

	buf := make([]byte, dnswire.MaxMessageLen)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	// Parse before relaying. Forwarding bytes the box has not validated would
	// make it a laundering service for malformed DNS aimed at whatever phone
	// asked.
	if _, err := dnswire.Unpack(buf[:n]); err != nil {
		return nil, fmt.Errorf("upstream returned an unparseable response: %w", err)
	}
	return buf[:n], nil
}

// repack re-encodes a parsed query for forwarding.
func repack(query dnswire.Message) []byte {
	builder := dnswire.NewBuilder(query.Header)
	for _, question := range query.Questions {
		if err := builder.AddQuestion(question); err != nil {
			return nil
		}
	}
	return builder.Bytes()
}

// ListenAndServe serves DNS on UDP and TCP until the context is cancelled.
//
// TCP as well as UDP because a client that gets a truncated response retries over
// TCP, and a box that only listens on UDP looks broken in exactly that case. The
// box's own answers never truncate, but a forwarded one can.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	// Bound through a ListenConfig rather than the package helpers so that a boot
	// cancelled while the network is still coming up returns instead of blocking.
	var listener net.ListenConfig
	udp, err := listener.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return fmt.Errorf("dnsd: listening on udp %s: %w", addr, err)
	}
	defer udp.Close()

	tcp, err := listener.Listen(ctx, "tcp", addr)
	if err != nil {
		// UDP alone is a working DNS server; TCP is the fallback path. Losing it
		// is worth a warning, not a failure to boot.
		s.log.Warn("dnsd: could not listen on tcp", "addr", addr, "error", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.serveUDP(ctx, udp)
	}()

	if tcp != nil {
		defer func() { _ = tcp.Close() }()
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serveTCP(ctx, tcp)
		}()
	}

	<-ctx.Done()
	udp.Close()
	if tcp != nil {
		_ = tcp.Close()
	}
	wg.Wait()
	return nil
}

func (s *Server) serveUDP(ctx context.Context, pc net.PacketConn) {
	buf := make([]byte, dnswire.MaxMessageLen)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Debug("dnsd: udp read", "error", err)
			continue
		}
		query, err := dnswire.Unpack(buf[:n])
		if err != nil {
			s.log.Debug("dnsd: dropping malformed query", "from", from, "error", err)
			continue
		}
		// One goroutine per query, because forwarding blocks and a single-threaded
		// loop would let one slow upstream stall the whole venue's DNS.
		go func(query dnswire.Message, from net.Addr) {
			if response := s.Resolve(ctx, query); response != nil {
				if _, err := pc.WriteTo(response, from); err != nil {
					s.log.Debug("dnsd: udp write", "to", from, "error", err)
				}
			}
		}(query, from)
	}
}

func (s *Server) serveTCP(ctx context.Context, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Debug("dnsd: tcp accept", "error", err)
			continue
		}
		go s.serveTCPConn(ctx, conn)
	}
}

// serveTCPConn handles one TCP query. DNS over TCP length-prefixes each message
// with a two-byte big-endian length (RFC 1035 section 4.2.2).
func (s *Server) serveTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	var length [2]byte
	if _, err := readFull(conn, length[:]); err != nil {
		return
	}
	size := int(length[0])<<8 | int(length[1])
	if size == 0 || size > dnswire.MaxMessageLen {
		return
	}
	buf := make([]byte, size)
	if _, err := readFull(conn, buf); err != nil {
		return
	}

	query, err := dnswire.Unpack(buf)
	if err != nil {
		return
	}
	response := s.Resolve(ctx, query)
	if response == nil {
		return
	}
	out := make([]byte, 0, len(response)+2)
	out = append(out, byte(len(response)>>8), byte(len(response)))
	if _, err := conn.Write(append(out, response...)); err != nil {
		s.log.Debug("dnsd: tcp write", "error", err)
	}
}

// readFull fills buf or returns an error.
func readFull(conn net.Conn, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := conn.Read(buf[read:])
		if n > 0 {
			read += n
		}
		if err != nil {
			return read, err
		}
	}
	return read, nil
}
