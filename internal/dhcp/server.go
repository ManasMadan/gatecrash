package dhcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Config configures the server.
type Config struct {
	// Box is the box's own address, used as the gateway, the DNS server and the
	// DHCP server identifier. All three are the box: that is what AP mode means.
	Box netip.Addr

	// Subnet is the network being served. The pool is carved out of it.
	Subnet netip.Prefix

	// PoolStart and PoolEnd bound the assignable range. Zero values pick the
	// subnet's usable range excluding the box.
	PoolStart netip.Addr
	PoolEnd   netip.Addr

	// LeaseTime is how long an address is held. Zero picks two hours.
	//
	// Two hours rather than the usual day: an event lasts an evening, and a short
	// lease means the pool recovers from a crowd that has gone home without
	// anybody intervening. Shorter than about an hour and phones wake up to renew
	// often enough to matter for battery.
	LeaseTime time.Duration

	// DomainName is handed out as option 15, so a device can resolve "gate" as
	// "gate.<domain>".
	DomainName string

	// PortalURL is handed out as option 114, RFC 8910. A client that reads it goes
	// straight to the portal and skips all the probe-interception guesswork.
	PortalURL string

	// Now is injected so tests can drive lease expiry.
	Now func() time.Time

	Logger *slog.Logger
}

// Lease is one assigned address.
type Lease struct {
	// Key is the client identity the lease is held against: option 61 when the
	// client sent one, its MAC otherwise.
	Key string

	Addr netip.Addr
	MAC  net.HardwareAddr

	// HostName and Vendor are client-supplied and shown on the dashboard so an
	// operator can tell one connected device from another.
	HostName string
	Vendor   string

	// Expires is when the lease lapses.
	Expires time.Time

	// Offered marks a lease that has been offered but not yet acknowledged. Held
	// briefly so two clients discovering at once are not offered the same
	// address.
	Offered bool
}

// Server hands out addresses.
type Server struct {
	cfg Config
	log *slog.Logger

	poolStart netip.Addr
	poolEnd   netip.Addr

	mu       sync.Mutex
	byKey    map[string]*Lease
	byAddr   map[netip.Addr]*Lease
	declined map[netip.Addr]time.Time
}

// New builds a server.
func New(cfg Config) (*Server, error) {
	if !cfg.Box.Is4() {
		return nil, errors.New("dhcp: the box address must be IPv4")
	}
	if !cfg.Subnet.IsValid() || !cfg.Subnet.Addr().Is4() {
		return nil, errors.New("dhcp: an IPv4 subnet is required")
	}
	if !cfg.Subnet.Contains(cfg.Box) {
		return nil, fmt.Errorf("dhcp: box %s is not inside subnet %s", cfg.Box, cfg.Subnet)
	}
	if cfg.LeaseTime <= 0 {
		cfg.LeaseTime = 2 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	start, end := cfg.PoolStart, cfg.PoolEnd
	if !start.IsValid() || !end.IsValid() {
		var err error
		if start, end, err = defaultPool(cfg.Subnet, cfg.Box); err != nil {
			return nil, err
		}
	}
	if !cfg.Subnet.Contains(start) || !cfg.Subnet.Contains(end) {
		return nil, fmt.Errorf("dhcp: pool %s-%s is not inside %s", start, end, cfg.Subnet)
	}
	if start.Compare(end) > 0 {
		return nil, fmt.Errorf("dhcp: pool start %s is after end %s", start, end)
	}

	return &Server{
		cfg: cfg, log: logger, poolStart: start, poolEnd: end,
		byKey:    make(map[string]*Lease),
		byAddr:   make(map[netip.Addr]*Lease),
		declined: make(map[netip.Addr]time.Time),
	}, nil
}

// defaultPool carves a pool out of a subnet, skipping the network address, the
// broadcast address and the box itself.
func defaultPool(subnet netip.Prefix, box netip.Addr) (netip.Addr, netip.Addr, error) {
	if subnet.Bits() > 30 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("dhcp: subnet %s has no room for a pool", subnet)
	}
	network := subnet.Masked().Addr()
	first := network.Next()
	last := broadcastAddr(subnet).Prev()

	// Start after the box when the box sits at the bottom of the range, which is
	// the conventional layout and what the shipped AP config uses.
	if first == box {
		first = first.Next()
	}
	if last == box {
		last = last.Prev()
	}
	if first.Compare(last) > 0 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("dhcp: subnet %s has no assignable addresses", subnet)
	}
	return first, last, nil
}

// broadcastAddr returns a prefix's broadcast address.
func broadcastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr().As4()
	mask := net.CIDRMask(prefix.Bits(), 32)
	for i := range addr {
		addr[i] |= ^mask[i]
	}
	return netip.AddrFrom4(addr)
}

// Handle processes one packet and returns the reply, or nil to stay silent.
//
// Pure apart from the lease table, so the whole state machine is testable without
// binding port 67 — which needs root and would collide with the machine's own
// DHCP client.
func (s *Server) Handle(p Packet) []byte {
	// Replies are other servers talking. A DHCP server that answers a reply is
	// how a network gets two servers fighting.
	if p.Op != bootRequest {
		return nil
	}
	// Relayed packets are out of scope: the box serves the link it is on, and
	// relaying implies a routed network somebody else is running.
	if p.RelayIP.IsValid() && !p.RelayIP.IsUnspecified() {
		s.log.Debug("dhcp: ignoring relayed packet", "relay", p.RelayIP)
		return nil
	}

	switch p.MessageType() {
	case Discover:
		return s.offer(p)
	case Request:
		return s.request(p)
	case Release:
		s.release(p)
		return nil
	case Decline:
		s.decline(p)
		return nil
	case Inform:
		return s.inform(p)
	default:
		return nil
	}
}

// offer answers a DISCOVER.
func (s *Server) offer(p Packet) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	addr, ok := s.pick(p)
	if !ok {
		// A full pool is a real operational condition at a five-thousand-person
		// event with a /24. Logging it loudly is the only useful response: there
		// is no reply that helps the client.
		s.log.Warn("dhcp: address pool is exhausted", "leases", len(s.byAddr), "client", p.MAC)
		return nil
	}

	now := s.cfg.Now()
	s.put(&Lease{
		Key: p.ClientKey(), Addr: addr, MAC: p.MAC,
		HostName: p.HostName(), Vendor: p.VendorClass(),
		// A short hold, so two clients discovering at once are not offered the
		// same address, but a client that never REQUESTs does not tie it up.
		Expires: now.Add(30 * time.Second), Offered: true,
	})

	s.log.Debug("dhcp: offering", "address", addr, "client", p.MAC, "hostname", p.HostName())
	return s.fill(p.Reply(Offer, addr, s.cfg.Box), p).Bytes()
}

// request answers a REQUEST.
func (s *Server) request(p Packet) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A REQUEST naming another server's identifier is that server's to answer.
	// Replying would produce two ACKs and a client that trusts whichever arrived
	// last.
	if id, ok := p.ServerID(); ok && id != s.cfg.Box {
		return nil
	}

	wanted, hasWanted := p.RequestedIP()
	if !hasWanted && p.ClientIP.Is4() && !p.ClientIP.IsUnspecified() {
		// A renewal carries the address in ciaddr rather than option 50.
		wanted, hasWanted = p.ClientIP, true
	}

	key := p.ClientKey()
	existing := s.byKey[key]

	switch {
	case !hasWanted && existing == nil:
		return s.nak(p, "no address requested and none held")

	case !hasWanted:
		wanted = existing.Addr

	case !s.cfg.Subnet.Contains(wanted):
		// A client that moved networks without releasing. NAK tells it to start
		// over, which is exactly what it should do.
		return s.nak(p, "requested address is on another network")

	case wanted.Compare(s.poolStart) < 0 || wanted.Compare(s.poolEnd) > 0:
		return s.nak(p, "requested address is outside the pool")

	case wanted == s.cfg.Box:
		return s.nak(p, "requested address belongs to the box")
	}

	// The address must be free or already this client's.
	if held, taken := s.byAddr[wanted]; taken && held.Key != key && !s.lapsed(held) {
		return s.nak(p, "requested address is held by another client")
	}

	now := s.cfg.Now()
	s.put(&Lease{
		Key: key, Addr: wanted, MAC: p.MAC,
		HostName: p.HostName(), Vendor: p.VendorClass(),
		Expires: now.Add(s.cfg.LeaseTime),
	})

	s.log.Info("dhcp: leased", "address", wanted, "client", p.MAC,
		"hostname", p.HostName(), "lease", s.cfg.LeaseTime)
	return s.fill(p.Reply(Ack, wanted, s.cfg.Box), p).Bytes()
}

// inform answers an INFORM: the client already has an address and wants only the
// configuration. Notably how macOS asks for the captive-portal URI.
func (s *Server) inform(p Packet) []byte {
	if !p.ClientIP.Is4() || p.ClientIP.IsUnspecified() {
		return nil
	}
	// No lease is recorded: the client configured its own address and the server
	// is not managing it.
	builder := p.Reply(Ack, netip.Addr{}, s.cfg.Box)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fill(builder, p).Bytes()
}

// release frees a lease.
func (s *Server) release(p Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := p.ClientKey()
	lease, ok := s.byKey[key]
	if !ok {
		return
	}
	s.log.Debug("dhcp: released", "address", lease.Addr, "client", p.MAC)
	delete(s.byKey, key)
	delete(s.byAddr, lease.Addr)
}

// decline records an address a client says is already in use.
//
// This happens when somebody has statically configured an address inside the
// pool, which is common at venues where a previous crew set up a printer. Holding
// the address aside rather than immediately re-offering it is what stops the box
// handing out the same conflict to every device in turn.
func (s *Server) decline(p Packet) {
	addr, ok := p.RequestedIP()
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.log.Warn("dhcp: client declined an address, something else is using it",
		"address", addr, "client", p.MAC)
	s.declined[addr] = s.cfg.Now().Add(time.Hour)
	if lease, held := s.byAddr[addr]; held {
		delete(s.byKey, lease.Key)
		delete(s.byAddr, addr)
	}
}

// nak refuses a request.
func (s *Server) nak(p Packet, why string) []byte {
	s.log.Debug("dhcp: refusing request", "client", p.MAC, "reason", why)
	builder := p.Reply(Nak, netip.Addr{}, s.cfg.Box)
	builder.SetString(OptMessage, why)
	return builder.Bytes()
}

// fill adds the network configuration options to a reply. Caller holds the lock.
func (s *Server) fill(b *Builder, p Packet) *Builder {
	b.SetIP(OptSubnetMask, subnetMask(s.cfg.Subnet))
	b.SetIP(OptRouter, s.cfg.Box)
	// The box is the DNS server, which is what makes the wildcard resolver and
	// the friendly names work.
	b.SetIPs(OptDNS, []netip.Addr{s.cfg.Box})
	b.SetIP(OptBroadcastAddress, broadcastAddr(s.cfg.Subnet))
	b.SetString(OptDomainName, s.cfg.DomainName)

	seconds := uint32(s.cfg.LeaseTime / time.Second)
	b.SetUint32(OptLeaseTime, seconds)
	// RFC 2131's recommended timers: renew at half the lease, rebind at seven
	// eighths. Sending them explicitly stops clients inventing their own, which
	// some do aggressively enough to matter for battery.
	b.SetUint32(OptRenewalTime, seconds/2)
	b.SetUint32(OptRebindingTime, seconds*7/8)

	// RFC 8910. Sent unconditionally rather than only when requested: a client
	// that did not ask ignores it, and a client that would have asked next time
	// gets it now.
	b.SetString(OptCaptivePortal, s.cfg.PortalURL)

	_ = p
	return b
}

// subnetMask returns a prefix's mask as an address.
func subnetMask(prefix netip.Prefix) netip.Addr {
	mask := net.CIDRMask(prefix.Bits(), 32)
	return netip.AddrFrom4([4]byte(mask))
}

// pick chooses an address for a client. Caller holds the lock.
//
// The order is deliberate and is about lease stability: the same client gets the
// same address across a reconnect and across a box reboot, so its open
// connections to the box survive. A phone that reconnects onto a different
// address has to re-establish its SSE stream and re-sync its mirror, which at a
// gate is a visible stall.
func (s *Server) pick(p Packet) (netip.Addr, bool) {
	key := p.ClientKey()

	// 1. The address this client already holds.
	if lease, ok := s.byKey[key]; ok && !s.declinedRecently(lease.Addr) {
		return lease.Addr, true
	}
	// 2. The address it asked for, if free.
	if wanted, ok := p.RequestedIP(); ok && s.assignable(wanted) {
		if held, taken := s.byAddr[wanted]; !taken || held.Key == key || s.lapsed(held) {
			return wanted, true
		}
	}
	// 3. The first free address in the pool. A linear walk, which is fine: the
	// pool is a few hundred addresses and this runs once per client per event.
	for addr := s.poolStart; addr.Compare(s.poolEnd) <= 0; addr = addr.Next() {
		if !s.assignable(addr) {
			continue
		}
		if held, taken := s.byAddr[addr]; !taken || s.lapsed(held) {
			return addr, true
		}
	}
	// 4. Reclaim the longest-expired lease. Only reached with a genuinely full
	// pool, and taking the oldest is the least disruptive choice available.
	return s.reclaim()
}

// assignable reports whether an address may be handed out at all.
func (s *Server) assignable(addr netip.Addr) bool {
	if !addr.Is4() || addr == s.cfg.Box {
		return false
	}
	if addr.Compare(s.poolStart) < 0 || addr.Compare(s.poolEnd) > 0 {
		return false
	}
	return !s.declinedRecently(addr)
}

func (s *Server) declinedRecently(addr netip.Addr) bool {
	until, ok := s.declined[addr]
	if !ok {
		return false
	}
	if s.cfg.Now().After(until) {
		delete(s.declined, addr)
		return false
	}
	return true
}

func (s *Server) lapsed(lease *Lease) bool {
	return s.cfg.Now().After(lease.Expires)
}

// reclaim takes the longest-expired lease. Caller holds the lock.
func (s *Server) reclaim() (netip.Addr, bool) {
	var (
		oldest  *Lease
		oldestT time.Time
	)
	for _, lease := range s.byAddr {
		if !s.lapsed(lease) {
			continue
		}
		if oldest == nil || lease.Expires.Before(oldestT) {
			oldest, oldestT = lease, lease.Expires
		}
	}
	if oldest == nil {
		return netip.Addr{}, false
	}
	delete(s.byKey, oldest.Key)
	delete(s.byAddr, oldest.Addr)
	return oldest.Addr, true
}

// put records a lease. Caller holds the lock.
func (s *Server) put(lease *Lease) {
	if previous, ok := s.byKey[lease.Key]; ok && previous.Addr != lease.Addr {
		delete(s.byAddr, previous.Addr)
	}
	s.byKey[lease.Key] = lease
	s.byAddr[lease.Addr] = lease
}

// Leases returns the current lease table, sorted by address, for the dashboard's
// network page.
func (s *Server) Leases() []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Lease, 0, len(s.byAddr))
	for _, lease := range s.byAddr {
		out = append(out, *lease)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Compare(out[j].Addr) < 0 })
	return out
}

// Restore reloads leases after a reboot, so a phone that reconnects gets the same
// address and its open connections survive.
func (s *Server) Restore(leases []Lease) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range leases {
		lease := leases[i]
		if !s.cfg.Subnet.Contains(lease.Addr) || lease.Addr == s.cfg.Box {
			continue
		}
		// An offered-but-unacknowledged lease is not worth restoring: the client
		// will discover again anyway.
		if lease.Offered || s.lapsed(&lease) {
			continue
		}
		s.put(&lease)
	}
}

// Pool returns the assignable range, for the dashboard and for diagnostics.
func (s *Server) Pool() (start, end netip.Addr, size int) {
	size = 0
	for addr := s.poolStart; addr.Compare(s.poolEnd) <= 0; addr = addr.Next() {
		size++
		if size > 65536 {
			break
		}
	}
	return s.poolStart, s.poolEnd, size
}

// ListenAndServe serves DHCP until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, iface string) error {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", ServerPort))
	if err != nil {
		return fmt.Errorf("dhcp: listening on :%d: %w", ServerPort, err)
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	s.log.Info("dhcp: serving", "subnet", s.cfg.Subnet, "box", s.cfg.Box,
		"pool_start", s.poolStart, "pool_end", s.poolEnd, "interface", iface)

	buf := make([]byte, MaxPacketLen)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Debug("dhcp: read", "error", err)
			continue
		}

		packet, err := Unpack(buf[:n])
		if err != nil {
			s.log.Debug("dhcp: dropping malformed packet", "from", from, "error", err)
			continue
		}
		reply := s.Handle(packet)
		if reply == nil {
			continue
		}

		// Broadcast when the client has no address yet, unicast otherwise. A
		// unicast reply to an address-less client is dropped by its own IP stack,
		// which presents as "DHCP just does not work on this phone".
		target := &net.UDPAddr{IP: net.IPv4bcast, Port: ClientPort}
		if !packet.WantsBroadcast() && packet.ClientIP.Is4() {
			target = &net.UDPAddr{IP: packet.ClientIP.AsSlice(), Port: ClientPort}
		}
		if _, err := conn.WriteTo(reply, target); err != nil {
			s.log.Debug("dhcp: write", "to", target, "error", err)
		}
	}
}
