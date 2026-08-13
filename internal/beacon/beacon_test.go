package beacon

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func validAnnouncement() Announcement {
	return Announcement{
		Magic:                Magic,
		Event:                "Sundown Sessions",
		EventID:              "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
		Address:              "10.11.0.1",
		Port:                 8443,
		CAFingerprint:        "sha256:aabbccdd",
		OrganizerFingerprint: "gc-AbCdEfGh",
		API:                  "1",
		Mode:                 "strict",
		Seq:                  4127,
	}
}

func TestAnnouncementRoundTripsAndStaysSmall(t *testing.T) {
	payload, err := json.Marshal(validAnnouncement())
	if err != nil {
		t.Fatal(err)
	}
	// A payload a listener refuses to parse is a silent discovery failure, so the
	// full announcement has to stay well inside the cap.
	if len(payload) > MaxPayload {
		t.Fatalf("a full announcement is %d bytes, over the %d byte cap", len(payload), MaxPayload)
	}
	t.Logf("full announcement: %d bytes", len(payload))

	got, ok := Parse(payload)
	if !ok {
		t.Fatal("a valid announcement did not parse")
	}
	if got != validAnnouncement() {
		t.Fatalf("round trip changed the announcement:\n got %+v\nwant %+v", got, validAnnouncement())
	}
}

func TestURL(t *testing.T) {
	if got := validAnnouncement().URL(); got != "https://10.11.0.1:8443" {
		t.Fatalf("URL is %q", got)
	}
	// IPv6 has to be bracketed, or every client's URL parser rejects it.
	v6 := validAnnouncement()
	v6.Address = "fd00::1"
	if got := v6.URL(); got != "https://[fd00::1]:8443" {
		t.Fatalf("IPv6 URL is %q", got)
	}
}

// TestParseRejectsAnythingSuspicious matters because the beacon port is a public
// broadcast port: anything at all may arrive on it, including from a device
// trying to point scanners at a box it controls. The beacon is a hint, and
// everything after it is verified over TLS, but a hint that crashes the app is
// still a denial of service.
func TestParseRejectsAnythingSuspicious(t *testing.T) {
	valid := validAnnouncement()

	mutate := func(fn func(*Announcement)) []byte {
		a := valid
		fn(&a)
		payload, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}

	for name, payload := range map[string][]byte{
		"empty":          {},
		"not json":       []byte("hello"),
		"json array":     []byte("[1,2,3]"),
		"truncated json": []byte(`{"magic":"gatecrash-beacon/1"`),
		"wrong magic":    mutate(func(a *Announcement) { a.Magic = "something-else" }),
		"no magic":       mutate(func(a *Announcement) { a.Magic = "" }),
		"no address":     mutate(func(a *Announcement) { a.Address = "" }),
		"hostname":       mutate(func(a *Announcement) { a.Address = "evil.example.com" }),
		"bad address":    mutate(func(a *Announcement) { a.Address = "999.999.999.999" }),
		"zero port":      mutate(func(a *Announcement) { a.Port = 0 }),
		"no api version": mutate(func(a *Announcement) { a.API = "" }),
		"oversized":      []byte(`{"magic":"gatecrash-beacon/1","event":"` + strings.Repeat("x", MaxPayload) + `"}`),
	} {
		if _, ok := Parse(payload); ok {
			t.Errorf("%s: Parse accepted it", name)
		}
	}
}

// TestAddressMustBeALiteral is worth its own test: accepting a hostname would let
// a broadcast steer a scanner into a DNS lookup the attacker also controls.
func TestAddressMustBeALiteral(t *testing.T) {
	a := validAnnouncement()
	for _, address := range []string{"gate.local", "evil.example.com", "localhost", ""} {
		a.Address = address
		if a.Valid() {
			t.Errorf("Valid() accepted the non-literal address %q", address)
		}
	}
	for _, address := range []string{"10.11.0.1", "192.168.1.1", "fd00::1"} {
		a.Address = address
		if !a.Valid() {
			t.Errorf("Valid() rejected the literal address %q", address)
		}
	}
}

// TestBroadcastAndDiscoverOverLoopback exercises the real sockets on an explicit
// loopback target, so it neither needs a real network nor sprays a developer's
// LAN with test packets.
func TestBroadcastAndDiscoverOverLoopback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var built atomic.Int64
	b := &Broadcaster{
		Interval: 20 * time.Millisecond,
		Targets:  []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), Port)},
		Announce: func() Announcement {
			a := validAnnouncement()
			// Sequence changes while the box runs, which is why the payload is
			// built per broadcast rather than stored: a beacon carrying a stale
			// sequence tells a scanner its mirror is fresh when it is not.
			a.Seq = uint64(built.Add(1))
			return a
		},
	}

	// The listener has to be up before the first broadcast, which happens
	// immediately rather than after one interval.
	found := make(chan Announcement, 8)
	listenReady := make(chan struct{})
	go func() {
		close(listenReady)
		_ = Listen(ctx, func(a Announcement, _ netip.AddrPort) {
			select {
			case found <- a:
			default:
			}
		})
	}()
	<-listenReady
	// Give the socket a moment to bind; the port is fixed so this cannot be
	// discovered from the listener.
	time.Sleep(50 * time.Millisecond)

	go func() {
		if err := b.Run(ctx); err != nil {
			t.Error(err)
		}
	}()

	select {
	case a := <-found:
		if a.Event != "Sundown Sessions" || a.Port != 8443 {
			t.Fatalf("received %+v", a)
		}
		if a.Seq == 0 {
			t.Error("the announcement carries no sequence")
		}
		if a.CAFingerprint == "" {
			t.Error("the announcement carries no CA fingerprint, so a client cannot pin")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no beacon received over loopback")
	}

	if built.Load() < 1 {
		t.Fatal("the announcement builder was never called")
	}
}

func TestRunRequiresAnAnnouncementBuilder(t *testing.T) {
	if err := (&Broadcaster{}).Run(context.Background()); err == nil {
		t.Fatal("Run accepted a broadcaster with no announcement builder")
	}
}

func TestDiscoverTimesOutCleanly(t *testing.T) {
	// Nothing is broadcasting, so this has to return an error rather than block
	// forever: an app that hangs on discovery is worse than one that says "not
	// found, scan the QR at the gate".
	start := time.Now()
	if _, err := Discover(context.Background(), 150*time.Millisecond); err == nil {
		t.Fatal("Discover found a box that does not exist")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Discover took %s to time out", elapsed)
	}
}

func TestBroadcastAddressComputation(t *testing.T) {
	// Some access points drop 255.255.255.255 while forwarding a subnet
	// broadcast, so the directed address has to be right.
	for _, tc := range []struct {
		cidr string
		want string
	}{
		{"10.11.0.1/24", "10.11.0.255"},
		{"192.168.1.50/24", "192.168.1.255"},
		{"172.16.4.9/16", "172.16.255.255"},
		{"10.0.0.1/8", "10.255.255.255"},
		{"10.11.0.1/30", "10.11.0.3"},
	} {
		prefix, err := netip.ParsePrefix(tc.cidr)
		if err != nil {
			t.Fatal(err)
		}
		ipnet := netipPrefixToIPNet(prefix)
		got, ok := broadcastOf(ipnet)
		if !ok {
			t.Errorf("%s: broadcastOf failed", tc.cidr)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("%s: broadcast is %s, want %s", tc.cidr, got, tc.want)
		}
	}
}

func TestParseNeverPanics(t *testing.T) {
	for _, payload := range [][]byte{
		nil, {}, {0}, []byte("{"), []byte("}"), []byte(`{"port":99999999999999999999}`),
		[]byte(`{"magic":"gatecrash-beacon/1","address":null,"port":null}`),
		make([]byte, MaxPayload+1),
	} {
		_, _ = Parse(payload)
	}
}

func BenchmarkParse(b *testing.B) {
	payload, err := json.Marshal(validAnnouncement())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, ok := Parse(payload); !ok {
			b.Fatal("parse failed")
		}
	}
}

// netipPrefixToIPNet converts a netip.Prefix to the older net.IPNet that
// broadcastOf takes, which is the shape net.Interface.Addrs returns and therefore
// the shape the production path deals with.
func netipPrefixToIPNet(prefix netip.Prefix) *net.IPNet {
	addr := prefix.Addr()
	return &net.IPNet{
		IP:   addr.AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), addr.BitLen()),
	}
}
