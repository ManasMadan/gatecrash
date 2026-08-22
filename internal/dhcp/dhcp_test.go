package dhcp

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func newServer(t *testing.T) (*Server, *clock) {
	t.Helper()
	c := &clock{at: time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)}
	s, err := New(Config{
		Box:        netip.MustParseAddr("10.11.0.1"),
		Subnet:     netip.MustParsePrefix("10.11.0.0/24"),
		LeaseTime:  2 * time.Hour,
		DomainName: "gate",
		PortalURL:  "http://10.11.0.1/portal",
		Now:        c.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

// client builds a request packet from a made-up device.
func client(mac string, kind MessageType, options map[byte][]byte) Packet {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	all := map[byte][]byte{OptMessageType: {byte(kind)}}
	for code, value := range options {
		all[code] = value
	}
	return Packet{
		Op: bootRequest, HType: ethernetHardware, HLen: byte(len(hw)),
		XID: 0xDEADBEEF, Flags: flagBroadcast, MAC: hw, Options: all,
	}
}

// reply decodes a server response.
func reply(t *testing.T, raw []byte) Packet {
	t.Helper()
	if raw == nil {
		t.Fatal("the server stayed silent")
	}
	p, err := Unpack(raw)
	if err != nil {
		t.Fatalf("the server produced a packet it cannot parse: %v", err)
	}
	return p
}

func ip4(value []byte) netip.Addr {
	if len(value) != 4 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(value))
}

// TestFullHandshake is the whole point: a phone joins the Wi-Fi and gets an
// address, a gateway, a DNS server and the captive-portal URI.
func TestFullHandshake(t *testing.T) {
	s, _ := newServer(t)

	offer := reply(t, s.Handle(client("aa:bb:cc:dd:ee:01", Discover, nil)))
	if offer.MessageType() != Offer {
		t.Fatalf("got %s, want OFFER", offer.MessageType())
	}
	if !s.cfg.Subnet.Contains(offer.YourIP) {
		t.Fatalf("offered %s, which is not in the subnet", offer.YourIP)
	}
	if offer.YourIP == s.cfg.Box {
		t.Fatal("the server offered its own address")
	}
	if offer.XID != 0xDEADBEEF {
		t.Errorf("the transaction id was not echoed: %#x", offer.XID)
	}
	if id := ip4(offer.Options[OptServerID]); id != s.cfg.Box {
		t.Errorf("server identifier is %s", id)
	}

	ack := reply(t, s.Handle(client("aa:bb:cc:dd:ee:01", Request, map[byte][]byte{
		OptRequestedIP: offer.YourIP.AsSlice(),
		OptServerID:    s.cfg.Box.AsSlice(),
	})))
	if ack.MessageType() != Ack {
		t.Fatalf("got %s, want ACK", ack.MessageType())
	}
	if ack.YourIP != offer.YourIP {
		t.Fatalf("acknowledged %s but offered %s", ack.YourIP, offer.YourIP)
	}

	// The box is the gateway and the DNS server. Both being the box is what makes
	// the wildcard resolver and the friendly names work.
	if got := ip4(ack.Options[OptRouter]); got != s.cfg.Box {
		t.Errorf("router option is %s, want the box", got)
	}
	if got := ip4(ack.Options[OptDNS]); got != s.cfg.Box {
		t.Errorf("dns option is %s, want the box", got)
	}
	if got := ip4(ack.Options[OptSubnetMask]); got != netip.MustParseAddr("255.255.255.0") {
		t.Errorf("subnet mask is %s", got)
	}
	if got := ip4(ack.Options[OptBroadcastAddress]); got != netip.MustParseAddr("10.11.0.255") {
		t.Errorf("broadcast address is %s", got)
	}
	if got := string(ack.Options[OptDomainName]); got != "gate" {
		t.Errorf("domain name is %q", got)
	}

	// RFC 8910. The single most useful option in the file: a client that reads it
	// goes straight to the portal.
	if got := string(ack.Options[OptCaptivePortal]); got != "http://10.11.0.1/portal" {
		t.Errorf("captive portal option is %q", got)
	}

	// Lease timers, sent explicitly so clients do not invent their own.
	if got := binary.BigEndian.Uint32(ack.Options[OptLeaseTime]); got != 7200 {
		t.Errorf("lease time is %d seconds, want 7200", got)
	}
	if got := binary.BigEndian.Uint32(ack.Options[OptRenewalTime]); got != 3600 {
		t.Errorf("renewal time is %d, want half the lease", got)
	}
	if got := binary.BigEndian.Uint32(ack.Options[OptRebindingTime]); got != 6300 {
		t.Errorf("rebinding time is %d, want seven eighths of the lease", got)
	}

	leases := s.Leases()
	if len(leases) != 1 || leases[0].Addr != ack.YourIP {
		t.Fatalf("lease table is %+v", leases)
	}
	if leases[0].Offered {
		t.Error("the lease is still marked as merely offered after an ACK")
	}
}

// TestSameClientKeepsItsAddress is about lease stability. A phone that reconnects
// onto a different address has to re-establish its SSE stream and re-sync its
// mirror, which at a gate is a visible stall.
func TestSameClientKeepsItsAddress(t *testing.T) {
	s, c := newServer(t)

	first := reply(t, s.Handle(client("aa:bb:cc:dd:ee:02", Discover, nil))).YourIP
	ack := reply(t, s.Handle(client("aa:bb:cc:dd:ee:02", Request, map[byte][]byte{
		OptRequestedIP: first.AsSlice(),
	})))
	if ack.YourIP != first {
		t.Fatal("the acknowledged address differs from the offered one")
	}

	// Reconnect an hour later, mid-lease.
	c.advance(time.Hour)
	again := reply(t, s.Handle(client("aa:bb:cc:dd:ee:02", Discover, nil)))
	if again.YourIP != first {
		t.Fatalf("a reconnecting client was offered %s, want its existing %s", again.YourIP, first)
	}

	// And after the lease lapses, since the lease row is still there.
	c.advance(3 * time.Hour)
	lapsed := reply(t, s.Handle(client("aa:bb:cc:dd:ee:02", Discover, nil)))
	if lapsed.YourIP != first {
		t.Fatalf("after expiry the client was offered %s, want its previous %s", lapsed.YourIP, first)
	}
}

// TestClientIdentifierBeatsMAC matters on phones with MAC randomisation: a device
// that rotates its MAC but keeps its client id keeps its address.
func TestClientIdentifierBeatsMAC(t *testing.T) {
	s, _ := newServer(t)
	identifier := []byte{0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03}

	first := client("aa:bb:cc:dd:ee:03", Discover, map[byte][]byte{OptClientID: identifier})
	offered := reply(t, s.Handle(first)).YourIP
	if _, err := Unpack(s.Handle(client("aa:bb:cc:dd:ee:03", Request, map[byte][]byte{
		OptClientID: identifier, OptRequestedIP: offered.AsSlice(),
	}))); err != nil {
		t.Fatal(err)
	}

	// Same identifier, brand new randomised MAC.
	rotated := client("de:ad:be:ef:00:99", Discover, map[byte][]byte{OptClientID: identifier})
	again := reply(t, s.Handle(rotated))
	if again.YourIP != offered {
		t.Fatalf("a client that rotated its MAC was offered %s, want its existing %s", again.YourIP, offered)
	}

	// And the identifier is echoed, because some clients reject a reply without
	// it and the failure looks like the server being absent.
	if string(again.Options[OptClientID]) != string(identifier) {
		t.Error("the client identifier was not echoed back")
	}
}

func TestTwoClientsGetDifferentAddresses(t *testing.T) {
	s, _ := newServer(t)

	// Two DISCOVERs before either REQUESTs. Without the short offer hold both
	// would be offered the same address.
	firstOffer := reply(t, s.Handle(client("aa:bb:cc:dd:ee:04", Discover, nil))).YourIP
	secondOffer := reply(t, s.Handle(client("aa:bb:cc:dd:ee:05", Discover, nil))).YourIP
	if firstOffer == secondOffer {
		t.Fatalf("both clients were offered %s", firstOffer)
	}
}

func TestOfferedButNeverRequestedAddressesComeBack(t *testing.T) {
	// A client that DISCOVERs and walks away must not tie up an address for the
	// whole lease.
	s, c := newServer(t)
	offered := reply(t, s.Handle(client("aa:bb:cc:dd:ee:06", Discover, nil))).YourIP

	c.advance(31 * time.Second)
	other := reply(t, s.Handle(client("aa:bb:cc:dd:ee:07", Discover, nil))).YourIP
	if other != offered {
		t.Fatalf("the abandoned offer of %s was not reused (got %s)", offered, other)
	}
}

func TestRequestForAnotherServerIsIgnored(t *testing.T) {
	// Replying would produce two ACKs and a client that trusts whichever arrived
	// last.
	s, _ := newServer(t)
	response := s.Handle(client("aa:bb:cc:dd:ee:08", Request, map[byte][]byte{
		OptRequestedIP: {10, 11, 0, 50},
		OptServerID:    {10, 11, 0, 254},
	}))
	if response != nil {
		t.Fatal("the server answered a request addressed to another server")
	}
}

func TestNakForImpossibleRequests(t *testing.T) {
	s, _ := newServer(t)

	for name, options := range map[string]map[byte][]byte{
		"another network":  {OptRequestedIP: []byte{192, 168, 5, 20}},
		"outside the pool": {OptRequestedIP: []byte{10, 11, 0, 1}},
		"nothing at all":   {},
	} {
		response := s.Handle(client("aa:bb:cc:dd:ee:09", Request, options))
		decoded := reply(t, response)
		if decoded.MessageType() != Nak {
			t.Errorf("%s: got %s, want NAK", name, decoded.MessageType())
		}
		// A NAK carries a reason, which is the difference between a debuggable
		// network and an afternoon with a packet capture.
		if len(decoded.Options[OptMessage]) == 0 {
			t.Errorf("%s: the NAK carries no reason", name)
		}
	}
}

func TestRequestForAnAddressHeldByAnotherClientIsRefused(t *testing.T) {
	s, _ := newServer(t)

	held := reply(t, s.Handle(client("aa:bb:cc:dd:ee:0a", Discover, nil))).YourIP
	if _, err := Unpack(s.Handle(client("aa:bb:cc:dd:ee:0a", Request, map[byte][]byte{
		OptRequestedIP: held.AsSlice(),
	}))); err != nil {
		t.Fatal(err)
	}

	thief := reply(t, s.Handle(client("aa:bb:cc:dd:ee:0b", Request, map[byte][]byte{
		OptRequestedIP: held.AsSlice(),
	})))
	if thief.MessageType() != Nak {
		t.Fatalf("got %s, want NAK for an address another client holds", thief.MessageType())
	}
}

func TestReleaseFreesTheAddress(t *testing.T) {
	s, _ := newServer(t)

	addr := reply(t, s.Handle(client("aa:bb:cc:dd:ee:0c", Discover, nil))).YourIP
	if _, err := Unpack(s.Handle(client("aa:bb:cc:dd:ee:0c", Request, map[byte][]byte{
		OptRequestedIP: addr.AsSlice(),
	}))); err != nil {
		t.Fatal(err)
	}
	if len(s.Leases()) != 1 {
		t.Fatal("no lease recorded")
	}

	if response := s.Handle(client("aa:bb:cc:dd:ee:0c", Release, nil)); response != nil {
		t.Error("RELEASE produced a reply, which nothing expects")
	}
	if len(s.Leases()) != 0 {
		t.Fatalf("lease table is %+v after a release", s.Leases())
	}
}

// TestDeclineHoldsTheAddressAside covers the venue reality: somebody has
// statically configured a printer inside the pool. Re-offering the same conflict
// to every device in turn is the failure this avoids.
func TestDeclineHoldsTheAddressAside(t *testing.T) {
	s, c := newServer(t)

	conflicted := reply(t, s.Handle(client("aa:bb:cc:dd:ee:0d", Discover, nil))).YourIP
	if response := s.Handle(client("aa:bb:cc:dd:ee:0d", Decline, map[byte][]byte{
		OptRequestedIP: conflicted.AsSlice(),
	})); response != nil {
		t.Error("DECLINE produced a reply")
	}

	next := reply(t, s.Handle(client("aa:bb:cc:dd:ee:0e", Discover, nil))).YourIP
	if next == conflicted {
		t.Fatalf("the declined address %s was immediately re-offered", conflicted)
	}

	// It comes back after the hold-aside window. Asking for it directly, because
	// a DISCOVER would hand it to whichever client asked first and the point here
	// is only that the address is no longer being held aside.
	c.advance(2 * time.Hour)
	back := reply(t, s.Handle(client("aa:bb:cc:dd:ee:0f", Request, map[byte][]byte{
		OptRequestedIP: conflicted.AsSlice(),
	})))
	if back.MessageType() != Ack {
		t.Errorf("the declined address never became available again: %s", back.MessageType())
	}
}

func TestInformAnswersConfigurationWithoutALease(t *testing.T) {
	// How macOS asks for the captive-portal URI when it already has an address.
	s, _ := newServer(t)
	packet := client("aa:bb:cc:dd:ee:10", Inform, nil)
	packet.ClientIP = netip.MustParseAddr("10.11.0.77")
	packet.Flags = 0

	response := reply(t, s.Handle(packet))
	if response.MessageType() != Ack {
		t.Fatalf("got %s, want ACK", response.MessageType())
	}
	if string(response.Options[OptCaptivePortal]) == "" {
		t.Error("INFORM was answered without the captive-portal option")
	}
	// No lease is recorded: the client configured its own address and the server
	// is not managing it.
	if len(s.Leases()) != 0 {
		t.Errorf("INFORM created %d leases", len(s.Leases()))
	}
}

func TestPoolExhaustionIsSilentRatherThanWrong(t *testing.T) {
	c := &clock{at: time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)}
	// A /29 gives six usable addresses, one of which is the box.
	s, err := New(Config{
		Box:    netip.MustParseAddr("10.11.0.1"),
		Subnet: netip.MustParsePrefix("10.11.0.0/29"),
		Now:    c.now,
	})
	if err != nil {
		t.Fatal(err)
	}

	start, end, size := s.Pool()
	t.Logf("pool %s-%s (%d addresses)", start, end, size)

	handed := make(map[netip.Addr]bool)
	for i := 0; i < size; i++ {
		mac := net.HardwareAddr{0xAA, 0, 0, 0, 0, byte(i)}
		packet := Packet{
			Op: bootRequest, HType: ethernetHardware, HLen: 6, XID: uint32(i),
			MAC: mac, Options: map[byte][]byte{OptMessageType: {byte(Discover)}},
		}
		response := s.Handle(packet)
		if response == nil {
			t.Fatalf("the pool ran dry after %d of %d addresses", i, size)
		}
		offered := reply(t, response).YourIP
		if handed[offered] {
			t.Fatalf("%s was handed out twice", offered)
		}
		handed[offered] = true

		packet.Options[OptMessageType] = []byte{byte(Request)}
		packet.Options[OptRequestedIP] = offered.AsSlice()
		if _, err := Unpack(s.Handle(packet)); err != nil {
			t.Fatal(err)
		}
	}

	// One more client than the pool holds. Staying silent is the only useful
	// response: there is no reply that helps the client.
	overflow := Packet{
		Op: bootRequest, HType: ethernetHardware, HLen: 6, XID: 999,
		MAC:     net.HardwareAddr{0xAA, 0, 0, 0, 0, 0xFF},
		Options: map[byte][]byte{OptMessageType: {byte(Discover)}},
	}
	if s.Handle(overflow) != nil {
		t.Fatal("the server offered an address from an exhausted pool")
	}

	// Once a lease lapses, the address is reclaimed.
	c.advance(3 * time.Hour)
	if s.Handle(overflow) == nil {
		t.Fatal("an expired lease was not reclaimed")
	}
}

func TestRestoreKeepsAddressesAcrossAReboot(t *testing.T) {
	s, c := newServer(t)

	addr := reply(t, s.Handle(client("aa:bb:cc:dd:ee:11", Discover, nil))).YourIP
	if _, err := Unpack(s.Handle(client("aa:bb:cc:dd:ee:11", Request, map[byte][]byte{
		OptRequestedIP: addr.AsSlice(),
	}))); err != nil {
		t.Fatal(err)
	}
	saved := s.Leases()

	// The box reboots.
	rebooted, err := New(Config{
		Box: netip.MustParseAddr("10.11.0.1"), Subnet: netip.MustParsePrefix("10.11.0.0/24"), Now: c.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	rebooted.Restore(saved)

	again := reply(t, rebooted.Handle(client("aa:bb:cc:dd:ee:11", Discover, nil)))
	if again.YourIP != addr {
		t.Fatalf("after a reboot the client was offered %s, want its previous %s", again.YourIP, addr)
	}
	// And a different client must not be handed the restored address.
	other := reply(t, rebooted.Handle(client("aa:bb:cc:dd:ee:12", Discover, nil)))
	if other.YourIP == addr {
		t.Fatal("a restored lease was handed to a different client")
	}
}

func TestRestoreIgnoresJunk(t *testing.T) {
	s, c := newServer(t)
	s.Restore([]Lease{
		// Wrong network.
		{Key: "mac:a", Addr: netip.MustParseAddr("192.168.1.5"), Expires: c.at.Add(time.Hour)},
		// The box's own address.
		{Key: "mac:b", Addr: netip.MustParseAddr("10.11.0.1"), Expires: c.at.Add(time.Hour)},
		// Already expired.
		{Key: "mac:c", Addr: netip.MustParseAddr("10.11.0.20"), Expires: c.at.Add(-time.Hour)},
		// Merely offered, never acknowledged.
		{Key: "mac:d", Addr: netip.MustParseAddr("10.11.0.21"), Expires: c.at.Add(time.Hour), Offered: true},
		// Good.
		{Key: "mac:e", Addr: netip.MustParseAddr("10.11.0.22"), Expires: c.at.Add(time.Hour)},
	})
	leases := s.Leases()
	if len(leases) != 1 || leases[0].Addr != netip.MustParseAddr("10.11.0.22") {
		t.Fatalf("restored %+v", leases)
	}
}

func TestRepliesAndRelaysAreIgnored(t *testing.T) {
	s, _ := newServer(t)

	// A server that answers a reply is how a network gets two servers fighting.
	response := client("aa:bb:cc:dd:ee:13", Discover, nil)
	response.Op = bootReply
	if s.Handle(response) != nil {
		t.Error("the server answered a BOOTREPLY")
	}

	// Relaying implies a routed network somebody else is running.
	relayed := client("aa:bb:cc:dd:ee:14", Discover, nil)
	relayed.RelayIP = netip.MustParseAddr("10.99.0.1")
	if s.Handle(relayed) != nil {
		t.Error("the server answered a relayed packet")
	}
}

func TestUnknownMessageTypesAreIgnored(t *testing.T) {
	s, _ := newServer(t)
	for _, kind := range []MessageType{0, 9, 12, 200} {
		if s.Handle(client("aa:bb:cc:dd:ee:15", kind, nil)) != nil {
			t.Errorf("the server answered message type %d", kind)
		}
	}
}

func TestUnpackRejectsHostilePackets(t *testing.T) {
	// Anybody on the venue Wi-Fi can send these bytes.
	valid := func() []byte {
		return client("aa:bb:cc:dd:ee:16", Discover, nil).Reply(Offer,
			netip.MustParseAddr("10.11.0.50"), netip.MustParseAddr("10.11.0.1")).Bytes()
	}

	t.Run("too short", func(t *testing.T) {
		for _, length := range []int{0, 1, 100, minPacketLen - 1} {
			if _, err := Unpack(make([]byte, length)); !errors.Is(err, ErrShort) {
				t.Errorf("%d bytes: got %v, want ErrShort", length, err)
			}
		}
	})

	t.Run("too long", func(t *testing.T) {
		if _, err := Unpack(make([]byte, MaxPacketLen+1)); err == nil {
			t.Error("an oversized packet was accepted")
		}
	})

	t.Run("no magic cookie", func(t *testing.T) {
		packet := make([]byte, minPacketLen)
		if _, err := Unpack(packet); !errors.Is(err, ErrNotDHCP) {
			t.Errorf("got %v, want ErrNotDHCP", err)
		}
	})

	t.Run("option running past the buffer", func(t *testing.T) {
		packet := valid()
		// Overwrite the first option's length with something huge.
		packet[241] = 250
		if _, err := Unpack(packet); !errors.Is(err, ErrShort) {
			t.Errorf("got %v, want ErrShort", err)
		}
	})

	t.Run("option with no length byte", func(t *testing.T) {
		packet := make([]byte, minPacketLen+1)
		binary.BigEndian.PutUint32(packet[236:240], magicCookie)
		packet[240] = 53 // a code with nothing after it
		if _, err := Unpack(packet); !errors.Is(err, ErrShort) {
			t.Errorf("got %v, want ErrShort", err)
		}
	})

	t.Run("absurd hardware length", func(t *testing.T) {
		// HLen is client-supplied. Clamping rather than trusting it is the
		// difference between a MAC address and a 255-byte read.
		packet := valid()
		packet[2] = 255
		decoded, err := Unpack(packet)
		if err != nil {
			t.Fatal(err)
		}
		if len(decoded.MAC) > 16 {
			t.Fatalf("a 255-byte hardware length produced a %d byte MAC", len(decoded.MAC))
		}
	})

	t.Run("garbage never panics", func(t *testing.T) {
		for length := 0; length < 400; length += 7 {
			for _, fill := range []byte{0x00, 0xFF, 0x63, 0x35} {
				buf := make([]byte, length)
				for i := range buf {
					buf[i] = fill
				}
				_, _ = Unpack(buf)
			}
		}
	})
}

func TestClientSuppliedTextIsSanitized(t *testing.T) {
	// Hostnames land on the dashboard. A device called "\r\nADMIN" must not be
	// able to forge a log line or scramble a terminal.
	s, _ := newServer(t)
	packet := client("aa:bb:cc:dd:ee:17", Discover, map[byte][]byte{
		OptHostName: []byte("evil\r\n\x1b[2Jname"),
	})
	if _, err := Unpack(s.Handle(packet)); err != nil {
		t.Fatal(err)
	}

	leases := s.Leases()
	if len(leases) != 1 {
		t.Fatal("no lease")
	}
	for _, r := range leases[0].HostName {
		if r < 0x20 || r == 0x7F {
			t.Fatalf("hostname %q still contains a control character", leases[0].HostName)
		}
	}

	// Null termination is respected rather than rendered as padding.
	nulled := client("aa:bb:cc:dd:ee:18", Discover, map[byte][]byte{
		OptHostName: append([]byte("phone"), 0, 0, 0),
	})
	if _, err := Unpack(s.Handle(nulled)); err != nil {
		t.Fatal(err)
	}
	for _, lease := range s.Leases() {
		if lease.HostName == "phone" {
			return
		}
	}
	t.Errorf("a null-terminated hostname was not trimmed: %+v", s.Leases())
}

func TestRepliesAreAtLeast300Bytes(t *testing.T) {
	// Some clients ignore anything shorter, which is a memorable afternoon to
	// debug.
	s, _ := newServer(t)
	raw := s.Handle(client("aa:bb:cc:dd:ee:19", Discover, nil))
	if len(raw) < 300 {
		t.Fatalf("the reply is %d bytes, which some clients ignore", len(raw))
	}
}

func TestBroadcastDecision(t *testing.T) {
	// A unicast reply to an address-less client is dropped by its own IP stack,
	// which presents as "DHCP just does not work on this phone".
	addressless := client("aa:bb:cc:dd:ee:1a", Discover, nil)
	addressless.Flags = 0
	if !addressless.WantsBroadcast() {
		t.Error("a client with no address is not being answered by broadcast")
	}

	flagged := client("aa:bb:cc:dd:ee:1b", Request, nil)
	flagged.ClientIP = netip.MustParseAddr("10.11.0.40")
	flagged.Flags = flagBroadcast
	if !flagged.WantsBroadcast() {
		t.Error("the broadcast flag was ignored")
	}

	renewing := client("aa:bb:cc:dd:ee:1c", Request, nil)
	renewing.ClientIP = netip.MustParseAddr("10.11.0.40")
	renewing.Flags = 0
	if renewing.WantsBroadcast() {
		t.Error("a renewing client with an address is being answered by broadcast")
	}
}

func TestRepeatedOptionsAreConcatenated(t *testing.T) {
	// RFC 3396. A client that splits its parameter list across two option 55s
	// would otherwise have half of it silently dropped.
	buf := make([]byte, minPacketLen)
	binary.BigEndian.PutUint32(buf[236:240], magicCookie)
	buf = append(buf,
		OptMessageType, 1, byte(Discover),
		OptParameterList, 2, 1, 3,
		OptParameterList, 2, 6, 114,
		OptEnd)

	packet, err := Unpack(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := packet.Options[OptParameterList]; len(got) != 4 {
		t.Fatalf("parameter list is %v, want the two halves concatenated", got)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	valid := Config{
		Box:    netip.MustParseAddr("10.11.0.1"),
		Subnet: netip.MustParsePrefix("10.11.0.0/24"),
	}

	for name, mutate := range map[string]func(Config) Config{
		"no box":           func(c Config) Config { c.Box = netip.Addr{}; return c },
		"ipv6 box":         func(c Config) Config { c.Box = netip.MustParseAddr("fd00::1"); return c },
		"no subnet":        func(c Config) Config { c.Subnet = netip.Prefix{}; return c },
		"box outside":      func(c Config) Config { c.Box = netip.MustParseAddr("192.168.1.1"); return c },
		"subnet too small": func(c Config) Config { c.Subnet = netip.MustParsePrefix("10.11.0.0/31"); return c },
		"pool outside": func(c Config) Config {
			c.PoolStart = netip.MustParseAddr("192.168.1.10")
			c.PoolEnd = netip.MustParseAddr("192.168.1.20")
			return c
		},
		"pool inverted": func(c Config) Config {
			c.PoolStart = netip.MustParseAddr("10.11.0.200")
			c.PoolEnd = netip.MustParseAddr("10.11.0.100")
			return c
		},
	} {
		if _, err := New(mutate(valid)); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
	if _, err := New(valid); err != nil {
		t.Errorf("New rejected a valid config: %v", err)
	}
}

func TestDefaultPoolSkipsTheBoxAndTheEdges(t *testing.T) {
	s, _ := newServer(t)
	start, end, size := s.Pool()

	if start != netip.MustParseAddr("10.11.0.2") {
		t.Errorf("pool starts at %s, want 10.11.0.2 (after the network address and the box)", start)
	}
	if end != netip.MustParseAddr("10.11.0.254") {
		t.Errorf("pool ends at %s, want 10.11.0.254 (before the broadcast address)", end)
	}
	if size != 253 {
		t.Errorf("pool holds %d addresses, want 253", size)
	}
}

func BenchmarkHandleDiscover(b *testing.B) {
	c := &clock{at: time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)}
	s, err := New(Config{
		Box: netip.MustParseAddr("10.11.0.1"), Subnet: netip.MustParsePrefix("10.11.0.0/16"), Now: c.now,
	})
	if err != nil {
		b.Fatal(err)
	}
	packet := Packet{
		Op: bootRequest, HType: ethernetHardware, HLen: 6, XID: 1,
		MAC:     net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		Options: map[byte][]byte{OptMessageType: {byte(Discover)}},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if s.Handle(packet) == nil {
			b.Fatal("no reply")
		}
	}
}
