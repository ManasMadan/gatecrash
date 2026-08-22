// Package beacon broadcasts and listens for the box on a UDP port.
//
// This is the fifth rung of the discovery ladder and by far the least clever one,
// which is exactly why it is here. mDNS can be disabled on an access point.
// Client isolation can block peer traffic. Android's resolver can simply decide
// not to answer. A UDP broadcast on a fixed port with a JSON body is immune to
// all of that, needs no resolver, and is about forty lines on each side.
//
// The native scanner and attendee apps listen for it and can find the box before
// any name resolution happens at all. The load rig uses it to find a box on a
// developer's LAN without being told an address.
//
// It carries the CA fingerprint, which is the part that matters for security: a
// device that has the fingerprint from a trusted channel can pin the box's
// certificate without a round trip, and a rogue box on the same network cannot
// forge one. The beacon itself is unauthenticated and says so — it is a hint
// about where to look, and everything that follows is verified over TLS.
package beacon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// Port is the beacon port. Fixed and not configurable: a discoverability
// mechanism that has to be configured is not a discoverability mechanism.
const Port = 47474

// Interval is how often the box broadcasts.
//
// Two seconds is chosen against the moment that matters: a phone joining the
// Wi-Fi wants to find the box inside the couple of seconds before its owner gets
// bored. Twenty-nine bytes every two seconds per box is nothing on any network.
const Interval = 2 * time.Second

// MaxPayload caps what a listener will parse, so a hostile broadcast cannot make
// a phone allocate.
const MaxPayload = 1024

// Announcement is the beacon payload.
type Announcement struct {
	// Magic identifies the payload before anything else is parsed, so a listener
	// on a busy port drops foreign traffic in a string comparison.
	Magic string `json:"magic"`

	// Event is the human-readable event name, shown in the app's "found a box"
	// prompt so an attendee at a multi-stage site picks the right one.
	Event string `json:"event"`

	// EventID scopes the box to an event, so an app holding a ticket knows whether
	// this box is the one it wants.
	EventID string `json:"event_id,omitempty"`

	// Address and Port are where to connect.
	Address string `json:"address"`
	Port    uint16 `json:"port"`

	// CAFingerprint is the SHA-256 fingerprint of the box's private CA
	// certificate, which is what lets a client pin without a round trip.
	CAFingerprint string `json:"ca_fingerprint,omitempty"`

	// OrganizerFingerprint identifies the organizer key the box was provisioned
	// with, so a scanner can refuse a box belonging to somebody else's event.
	OrganizerFingerprint string `json:"organizer_fingerprint,omitempty"`

	// API is the wire contract version. A scanner refuses to enroll against a box
	// whose major differs rather than failing in an interesting way later.
	API string `json:"api"`

	// Mode is the consistency posture, surfaced so a scanner knows before it
	// enrolls whether it will be allowed to admit during a partition.
	Mode string `json:"mode,omitempty"`

	// Seq is the box's current redemption sequence, which lets a reconnecting
	// scanner see how far behind its mirror is before it asks.
	Seq uint64 `json:"seq,omitempty"`
}

// Magic is the payload's magic string.
const Magic = "gatecrash-beacon/1"

// URL returns the base URL to reach the box.
func (a Announcement) URL() string {
	return "https://" + net.JoinHostPort(a.Address, itoa(int(a.Port)))
}

// Valid reports whether an announcement is usable.
func (a Announcement) Valid() bool {
	if a.Magic != Magic || a.Port == 0 || a.API == "" {
		return false
	}
	addr, err := netip.ParseAddr(a.Address)
	return err == nil && addr.IsValid()
}

// Broadcaster sends announcements.
type Broadcaster struct {
	// Announce is called before every broadcast to build the payload.
	//
	// A callback rather than a stored struct because the sequence number and the
	// event change while the box runs, and a beacon carrying a stale sequence
	// would tell a scanner its mirror is fresh when it is not.
	Announce func() Announcement

	Logger *slog.Logger

	// Interval overrides the broadcast interval, for tests.
	Interval time.Duration

	// Targets overrides the broadcast addresses. Empty means every interface's
	// broadcast address plus 255.255.255.255, which is what a box wants: in AP
	// mode it does not know its subnet until hostapd has come up.
	Targets []netip.AddrPort
}

// Run broadcasts until the context is cancelled.
func (b *Broadcaster) Run(ctx context.Context) error {
	if b.Announce == nil {
		return errors.New("beacon: no announcement builder")
	}
	logger := b.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	interval := b.Interval
	if interval <= 0 {
		interval = Interval
	}

	// Port 0 on the send side: the box broadcasts and does not listen, so binding
	// the beacon port here would collide with a second process and buy nothing.
	var listener net.ListenConfig
	conn, err := listener.ListenPacket(ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("beacon: opening socket: %w", err)
	}
	defer conn.Close()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Broadcast immediately rather than waiting out the first interval. Two
	// seconds is a long time to a person holding a phone.
	b.broadcast(conn, logger)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			b.broadcast(conn, logger)
		}
	}
}

func (b *Broadcaster) broadcast(conn net.PacketConn, logger *slog.Logger) {
	announcement := b.Announce()
	announcement.Magic = Magic

	payload, err := json.Marshal(announcement)
	if err != nil {
		logger.Warn("beacon: encoding announcement", "error", err)
		return
	}
	if len(payload) > MaxPayload {
		// A listener will refuse to parse this, so sending it would be a silent
		// discovery failure.
		logger.Warn("beacon: announcement is too large to be parsed by listeners", "bytes", len(payload))
		return
	}

	for _, target := range b.targets(logger) {
		if _, err := conn.WriteTo(payload, net.UDPAddrFromAddrPort(target)); err != nil {
			// A broadcast to an interface that has gone away fails routinely.
			// Debug rather than warn, or the log fills up on a laptop with a
			// sleeping Wi-Fi adapter.
			logger.Debug("beacon: write", "to", target, "error", err)
		}
	}
}

// targets returns where to broadcast.
func (b *Broadcaster) targets(logger *slog.Logger) []netip.AddrPort {
	if len(b.Targets) > 0 {
		return b.Targets
	}

	// The limited broadcast address always works on the local link and needs no
	// knowledge of the subnet, which matters in AP mode where the box is bringing
	// the network up around itself.
	out := []netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), Port)}

	// Per-interface directed broadcasts as well, because some access points drop
	// 255.255.255.255 while forwarding a subnet broadcast.
	interfaces, err := net.Interfaces()
	if err != nil {
		logger.Debug("beacon: listing interfaces", "error", err)
		return out
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			if broadcast, ok := broadcastOf(ipnet); ok {
				out = append(out, netip.AddrPortFrom(broadcast, Port))
			}
		}
	}
	return out
}

// broadcastOf computes a subnet's broadcast address.
func broadcastOf(ipnet *net.IPNet) (netip.Addr, bool) {
	ip := ipnet.IP.To4()
	mask := net.IP(ipnet.Mask).To4()
	if ip == nil || mask == nil {
		return netip.Addr{}, false
	}
	var out [4]byte
	for i := 0; i < 4; i++ {
		out[i] = ip[i] | ^mask[i]
	}
	return netip.AddrFrom4(out), true
}

// Listen watches for announcements until the context is cancelled, calling fn for
// each valid one.
//
// Used by the load rig, by the demo, and mirrored in the native apps. Invalid
// payloads are dropped silently: the beacon port is a public broadcast port and
// anything may arrive on it.
func Listen(ctx context.Context, fn func(Announcement, netip.AddrPort)) error {
	var listener net.ListenConfig
	conn, err := listener.ListenPacket(ctx, "udp4", fmt.Sprintf("0.0.0.0:%d", Port))
	if err != nil {
		return fmt.Errorf("beacon: listening: %w", err)
	}
	defer conn.Close()

	// Close the socket when the context ends, which is what unblocks the read.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, MaxPayload)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("beacon: read: %w", err)
		}
		announcement, ok := Parse(buf[:n])
		if !ok {
			continue
		}
		addr, ok := addrPortOf(from)
		if !ok {
			continue
		}
		fn(announcement, addr)
	}
}

// Parse decodes a beacon payload, reporting whether it is a valid announcement.
func Parse(payload []byte) (Announcement, bool) {
	if len(payload) == 0 || len(payload) > MaxPayload {
		return Announcement{}, false
	}
	var announcement Announcement
	if err := json.Unmarshal(payload, &announcement); err != nil {
		return Announcement{}, false
	}
	if !announcement.Valid() {
		return Announcement{}, false
	}
	return announcement, true
}

// Discover waits for the first valid announcement, or until the context ends.
//
// This is the whole client-side story for a native app on a network where nothing
// else works: open a socket, wait two seconds, get an address and a fingerprint.
func Discover(ctx context.Context, timeout time.Duration) (Announcement, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	found := make(chan Announcement, 1)
	errs := make(chan error, 1)

	go func() {
		err := Listen(ctx, func(a Announcement, _ netip.AddrPort) {
			select {
			case found <- a:
			default:
			}
		})
		if err != nil {
			errs <- err
		}
	}()

	select {
	case a := <-found:
		return a, nil
	case err := <-errs:
		return Announcement{}, err
	case <-ctx.Done():
		return Announcement{}, fmt.Errorf("beacon: no box found within %s", timeout)
	}
}

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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
