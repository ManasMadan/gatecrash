package mdns

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/ManasMadan/gatecrash/internal/dnswire"
)

func testResponder(t *testing.T) *Responder {
	t.Helper()
	r, err := New(Config{Service: Service{
		Instance: "Sundown Sessions",
		Type:     "_gatecrash._tcp",
		Host:     "gate",
		Port:     8443,
		IPv4:     []netip.Addr{netip.MustParseAddr("10.11.0.1")},
		IPv6:     []netip.Addr{netip.MustParseAddr("fe80::1")},
		TXT:      []string{"api=1", "event=Sundown Sessions", "fp=gc-AbCdEfGh", "mode=strict"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ask builds a query and returns the decoded response, or nil when the responder
// stays quiet.
func ask(t *testing.T, r *Responder, questions ...dnswire.Question) *dnswire.Message {
	t.Helper()
	builder := dnswire.NewBuilder(dnswire.Header{ID: 0x4242})
	for _, q := range questions {
		if q.Class == 0 {
			q.Class = dnswire.ClassINET
		}
		if err := builder.AddQuestion(q); err != nil {
			t.Fatal(err)
		}
	}
	query, err := dnswire.Unpack(builder.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	packet, _, ok := r.Respond(query)
	if !ok {
		return nil
	}
	msg, err := dnswire.Unpack(packet)
	if err != nil {
		t.Fatalf("the responder produced a message it cannot parse: %v", err)
	}
	return &msg
}

// find returns the first record of a type in a slice.
func find(records []dnswire.Record, name string, typ dnswire.Type) *dnswire.Record {
	for i := range records {
		if records[i].Type == typ && dnswire.EqualNames(records[i].Name, name) {
			return &records[i]
		}
	}
	return nil
}

func TestAnswersTheHostAddress(t *testing.T) {
	r := testResponder(t)

	msg := ask(t, r, dnswire.Question{Name: "gate.local.", Type: dnswire.TypeA})
	if msg == nil {
		t.Fatal("no response to an A query for the box's own name")
	}
	if !msg.Header.Response || !msg.Header.Authoritative {
		t.Errorf("response header is %+v", msg.Header)
	}
	// A multicast response carries a zero id, per RFC 6762 section 18.1.
	if msg.Header.ID != 0 {
		t.Errorf("multicast response carries id %d, want 0", msg.Header.ID)
	}

	record := find(msg.Answers, "gate.local.", dnswire.TypeA)
	if record == nil {
		t.Fatal("no A record in the answer")
	}
	if netip.AddrFrom4([4]byte(record.IP)) != netip.MustParseAddr("10.11.0.1") {
		t.Errorf("A record is %v", record.IP)
	}
	// The box is the unique owner of its own name, so a receiver should discard
	// whatever it had cached.
	if !record.CacheFlush {
		t.Error("the address record does not set the cache-flush bit")
	}
	if record.TTL != TTLHost {
		t.Errorf("address TTL is %d, want %d", record.TTL, TTLHost)
	}
}

func TestAnswersCaseInsensitively(t *testing.T) {
	// Every device on the network disagrees about case. A responder that compares
	// byte-for-byte answers some phones and not others.
	r := testResponder(t)
	for _, name := range []string{"gate.local.", "GATE.LOCAL.", "Gate.Local", "gate.local"} {
		if msg := ask(t, r, dnswire.Question{Name: name, Type: dnswire.TypeA}); msg == nil {
			t.Errorf("no response to %q", name)
		}
	}
}

func TestAnswersAAAASeparatelyFromA(t *testing.T) {
	r := testResponder(t)

	v6 := ask(t, r, dnswire.Question{Name: "gate.local.", Type: dnswire.TypeAAAA})
	if v6 == nil {
		t.Fatal("no response to an AAAA query")
	}
	if find(v6.Answers, "gate.local.", dnswire.TypeAAAA) == nil {
		t.Fatal("no AAAA record")
	}
	// An A query must not be answered with an AAAA record.
	if find(v6.Answers, "gate.local.", dnswire.TypeA) != nil {
		t.Error("an AAAA query was answered with an A record too")
	}
}

func TestAnyQueryReturnsEverythingForTheName(t *testing.T) {
	r := testResponder(t)
	msg := ask(t, r, dnswire.Question{Name: "gate.local.", Type: dnswire.TypeANY})
	if msg == nil {
		t.Fatal("no response to an ANY query")
	}
	if find(msg.Answers, "gate.local.", dnswire.TypeA) == nil {
		t.Error("ANY did not include the A record")
	}
	if find(msg.Answers, "gate.local.", dnswire.TypeAAAA) == nil {
		t.Error("ANY did not include the AAAA record")
	}
}

// TestServiceBrowseGetsEverythingItNeedsInOneRoundTrip is the behaviour that
// actually decides whether a phone finds the box. On a saturated venue network
// every extra round trip is a real chance of the whole resolution timing out, so
// a PTR query comes back with the SRV, the TXT and the addresses attached.
func TestServiceBrowseGetsEverythingItNeedsInOneRoundTrip(t *testing.T) {
	r := testResponder(t)

	msg := ask(t, r, dnswire.Question{Name: "_gatecrash._tcp.local.", Type: dnswire.TypePTR})
	if msg == nil {
		t.Fatal("no response to a service browse")
	}

	instance := "Sundown Sessions._gatecrash._tcp.local."
	ptr := find(msg.Answers, "_gatecrash._tcp.local.", dnswire.TypePTR)
	if ptr == nil || !dnswire.EqualNames(ptr.Target, instance) {
		t.Fatalf("service PTR is %+v", ptr)
	}
	// A shared record must not carry the cache-flush bit, or several boxes at one
	// venue would each erase the others.
	if ptr.CacheFlush {
		t.Error("the service PTR sets the cache-flush bit on a shared record")
	}

	everything := append(append([]dnswire.Record{}, msg.Answers...), msg.Additionals...)
	srv := find(everything, instance, dnswire.TypeSRV)
	if srv == nil {
		t.Fatal("no SRV record in the response")
	}
	if srv.Port != 8443 || !dnswire.EqualNames(srv.Target, "gate.local.") {
		t.Errorf("SRV is port %d target %q", srv.Port, srv.Target)
	}
	txt := find(everything, instance, dnswire.TypeTXT)
	if txt == nil {
		t.Fatal("no TXT record in the response")
	}
	// The TLS fingerprint in the TXT record is what lets a scanner pin the box's
	// private CA without a separate round trip.
	var sawFingerprint bool
	for _, entry := range txt.TXT {
		if strings.HasPrefix(entry, "fp=") {
			sawFingerprint = true
		}
	}
	if !sawFingerprint {
		t.Errorf("TXT record carries no TLS fingerprint: %q", txt.TXT)
	}
	if find(everything, "gate.local.", dnswire.TypeA) == nil {
		t.Error("no address record, so the phone has to ask again")
	}
}

func TestInstanceQueryReturnsSRVAndTXTWithAddresses(t *testing.T) {
	r := testResponder(t)
	instance := "Sundown Sessions._gatecrash._tcp.local."

	msg := ask(t, r, dnswire.Question{Name: instance, Type: dnswire.TypeSRV})
	if msg == nil {
		t.Fatal("no response to an SRV query")
	}
	if find(msg.Answers, instance, dnswire.TypeSRV) == nil {
		t.Fatal("no SRV in the answer section")
	}
	// The target's address rides along, because resolving SRV then A is two round
	// trips and the second one is the one that gets lost.
	if find(msg.Additionals, "gate.local.", dnswire.TypeA) == nil {
		t.Error("the SRV target's address is not in the additional section")
	}
}

func TestServiceTypeEnumeration(t *testing.T) {
	// Answering this is what makes the box show up in a generic network browser
	// rather than only to something already looking for Gatecrash.
	r := testResponder(t)
	msg := ask(t, r, dnswire.Question{Name: enumerationName, Type: dnswire.TypePTR})
	if msg == nil {
		t.Fatal("no response to service-type enumeration")
	}
	ptr := find(msg.Answers, enumerationName, dnswire.TypePTR)
	if ptr == nil || !dnswire.EqualNames(ptr.Target, "_gatecrash._tcp.local.") {
		t.Fatalf("enumeration PTR is %+v", ptr)
	}
}

func TestStaysQuietForEverythingElse(t *testing.T) {
	// Most mDNS traffic on a venue network is phones looking for printers and
	// Chromecasts. Answering any of it would be both wrong and loud.
	r := testResponder(t)
	for _, q := range []dnswire.Question{
		{Name: "_ipp._tcp.local.", Type: dnswire.TypePTR},
		{Name: "printer.local.", Type: dnswire.TypeA},
		{Name: "_googlecast._tcp.local.", Type: dnswire.TypePTR},
		{Name: "notgate.local.", Type: dnswire.TypeA},
		{Name: "gate.lan.", Type: dnswire.TypeA},
		// A name that merely ends in ours must not match.
		{Name: "evil.gate.local.", Type: dnswire.TypeA},
		// The wrong class.
		{Name: "gate.local.", Type: dnswire.TypeA, Class: 3},
		// A type we do not serve for a name we own.
		{Name: "gate.local.", Type: dnswire.TypeSOA},
		{Name: "_gatecrash._tcp.local.", Type: dnswire.TypeA},
	} {
		if msg := ask(t, r, q); msg != nil {
			t.Errorf("answered %s %s with %d records", q.Name, q.Type, len(msg.Answers))
		}
	}
}

func TestIgnoresResponsesFromOtherHosts(t *testing.T) {
	r := testResponder(t)
	builder := dnswire.NewBuilder(dnswire.Header{Response: true, Authoritative: true})
	if err := builder.AddAnswer(dnswire.Record{
		Name: "gate.local.", Type: dnswire.TypeA, Class: dnswire.ClassINET,
		TTL: 120, IP: []byte{192, 168, 1, 5},
	}); err != nil {
		t.Fatal(err)
	}
	msg, err := dnswire.Unpack(builder.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// Responding to a response is how an mDNS storm starts.
	if _, _, ok := r.Respond(msg); ok {
		t.Fatal("the responder replied to another host's response")
	}
}

// TestKnownAnswerSuppression is the difference between a working access point and
// a broadcast storm on a network with several thousand phones.
func TestKnownAnswerSuppression(t *testing.T) {
	r := testResponder(t)

	build := func(known dnswire.Record) dnswire.Message {
		builder := dnswire.NewBuilder(dnswire.Header{})
		if err := builder.AddQuestion(dnswire.Question{
			Name: "gate.local.", Type: dnswire.TypeA, Class: dnswire.ClassINET,
		}); err != nil {
			t.Fatal(err)
		}
		if err := builder.AddAnswer(known); err != nil {
			t.Fatal(err)
		}
		msg, err := dnswire.Unpack(builder.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return msg
	}

	t.Run("a fresh known answer is suppressed", func(t *testing.T) {
		query := build(dnswire.Record{
			Name: "gate.local.", Type: dnswire.TypeA, Class: dnswire.ClassINET,
			TTL: TTLHost, IP: []byte{10, 11, 0, 1},
		})
		if _, _, ok := r.Respond(query); ok {
			t.Fatal("answered a querier that already holds the record")
		}
	})

	t.Run("a nearly-expired known answer still gets a refresh", func(t *testing.T) {
		// The rule is "at least half the TTL remaining". A querier reporting a
		// record about to expire wants it refreshed.
		query := build(dnswire.Record{
			Name: "gate.local.", Type: dnswire.TypeA, Class: dnswire.ClassINET,
			TTL: TTLHost/2 - 1, IP: []byte{10, 11, 0, 1},
		})
		if _, _, ok := r.Respond(query); !ok {
			t.Fatal("did not refresh a nearly-expired known answer")
		}
	})

	t.Run("a known answer with a different address is not suppressed", func(t *testing.T) {
		query := build(dnswire.Record{
			Name: "gate.local.", Type: dnswire.TypeA, Class: dnswire.ClassINET,
			TTL: TTLHost, IP: []byte{192, 168, 1, 5},
		})
		if _, _, ok := r.Respond(query); !ok {
			t.Fatal("suppressed an answer because a querier held a different address")
		}
	})
}

func TestUnicastResponseIsHonoured(t *testing.T) {
	// Honouring the QU bit is most of what keeps mDNS traffic off a saturated
	// venue network, and iOS sets it routinely.
	r := testResponder(t)

	builder := dnswire.NewBuilder(dnswire.Header{ID: 0x1234})
	if err := builder.AddQuestion(dnswire.Question{
		Name: "gate.local.", Type: dnswire.TypeA, Class: dnswire.ClassINET, Unicast: true,
	}); err != nil {
		t.Fatal(err)
	}
	query, err := dnswire.Unpack(builder.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	packet, unicast, ok := r.Respond(query)
	if !ok {
		t.Fatal("no response")
	}
	if !unicast {
		t.Fatal("the unicast-response request was ignored")
	}
	msg, err := dnswire.Unpack(packet)
	if err != nil {
		t.Fatal(err)
	}
	// A unicast response echoes the query id so the asker can match it up.
	if msg.Header.ID != 0x1234 {
		t.Errorf("unicast response carries id %d, want the query's 0x1234", msg.Header.ID)
	}
}

func TestNoDuplicateRecordsAcrossSections(t *testing.T) {
	// Sending the same record in both the answer and additional sections is legal
	// and makes some resolvers complain.
	r := testResponder(t)
	msg := ask(t,
		r,
		dnswire.Question{Name: "_gatecrash._tcp.local.", Type: dnswire.TypePTR},
		dnswire.Question{Name: "Sundown Sessions._gatecrash._tcp.local.", Type: dnswire.TypeANY},
		dnswire.Question{Name: "gate.local.", Type: dnswire.TypeANY},
	)
	if msg == nil {
		t.Fatal("no response")
	}

	seen := make(map[string]int)
	for _, record := range append(append([]dnswire.Record{}, msg.Answers...), msg.Additionals...) {
		key := strings.ToLower(record.Name) + "|" + record.Type.String() + "|" + string(record.IP) + record.Target
		seen[key]++
		if seen[key] > 1 {
			t.Errorf("record %s appears %d times", key, seen[key])
		}
	}
}

func TestAnnouncementCarriesEverything(t *testing.T) {
	// Android's resolver is unreliable at asking, so a device that joined the
	// Wi-Fi before the box finished booting depends entirely on this packet.
	r := testResponder(t)
	msg, err := dnswire.Unpack(r.Announcement())
	if err != nil {
		t.Fatal(err)
	}
	if !msg.Header.Response || !msg.Header.Authoritative {
		t.Errorf("announcement header is %+v", msg.Header)
	}
	instance := "Sundown Sessions._gatecrash._tcp.local."
	for _, want := range []struct {
		name string
		typ  dnswire.Type
	}{
		{enumerationName, dnswire.TypePTR},
		{"_gatecrash._tcp.local.", dnswire.TypePTR},
		{instance, dnswire.TypeSRV},
		{instance, dnswire.TypeTXT},
		{"gate.local.", dnswire.TypeA},
		{"gate.local.", dnswire.TypeAAAA},
	} {
		if find(msg.Answers, want.name, want.typ) == nil {
			t.Errorf("the announcement is missing %s %s", want.name, want.typ)
		}
	}
	// It also has to fit in one frame, or it fragments and cheap access points
	// drop it.
	if len(r.Announcement()) > 500 {
		t.Errorf("the announcement is %d bytes", len(r.Announcement()))
	}
	t.Logf("announcement: %d bytes, %d records", len(r.Announcement()), len(msg.Answers))
}

func TestGoodbyeZeroesEveryTTL(t *testing.T) {
	// A rebooted box that did not say goodbye inherits a stale cached address,
	// and a scanner sits there for the full record TTL pointing at nothing.
	r := testResponder(t)
	msg, err := dnswire.Unpack(r.Goodbye())
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers) == 0 {
		t.Fatal("the goodbye packet carries no records")
	}
	for _, record := range msg.Answers {
		if record.TTL != 0 {
			t.Errorf("%s %s has TTL %d in a goodbye packet", record.Name, record.Type, record.TTL)
		}
	}
	// And a goodbye must not be mistaken for a fresh announcement.
	if len(msg.Answers) != len(mustUnpackAnswers(t, r.Announcement())) {
		t.Error("the goodbye packet does not cover the same records as the announcement")
	}
}

func mustUnpackAnswers(t *testing.T, packet []byte) []dnswire.Record {
	t.Helper()
	msg, err := dnswire.Unpack(packet)
	if err != nil {
		t.Fatal(err)
	}
	return msg.Answers
}

func TestNewValidatesTheService(t *testing.T) {
	base := Service{Host: "gate", IPv4: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}

	if _, err := New(Config{Service: Service{Host: "gate"}}); err == nil {
		t.Error("accepted a service with no addresses")
	}
	// A host with a dot would produce "gate.local.local.", which resolves to
	// nothing and is very hard to notice.
	bad := base
	bad.Host = "gate.local"
	if _, err := New(Config{Service: bad}); err == nil {
		t.Error("accepted a multi-label host")
	}
	bad = base
	bad.Host = "my gate"
	if _, err := New(Config{Service: bad}); err == nil {
		t.Error("accepted a host with a space")
	}
	if _, err := New(Config{Service: base}); err != nil {
		t.Errorf("rejected a valid service: %v", err)
	}
}

func TestDefaultsAreTheConventionalValues(t *testing.T) {
	var s Service
	s.Defaults()
	if s.Type != "_gatecrash._tcp" || s.Host != "gate" || s.Port != 8443 || s.Instance == "" {
		t.Fatalf("defaults are %+v", s)
	}
}

func TestIPv4OnlyBoxDoesNotAnswerAAAA(t *testing.T) {
	r, err := New(Config{Service: Service{
		Host: "gate", Port: 8443, IPv4: []netip.Addr{netip.MustParseAddr("10.11.0.1")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if msg := ask(t, r, dnswire.Question{Name: "gate.local.", Type: dnswire.TypeAAAA}); msg != nil {
		t.Fatal("an IPv4-only box answered an AAAA query")
	}
	if msg := ask(t, r, dnswire.Question{Name: "gate.local.", Type: dnswire.TypeA}); msg == nil {
		t.Fatal("an IPv4-only box did not answer an A query")
	}
}

func TestRespondNeverPanicsOnGarbage(t *testing.T) {
	// Any device on the venue Wi-Fi can send these bytes.
	r := testResponder(t)
	for length := 12; length < 80; length++ {
		for _, fill := range []byte{0x00, 0xC0, 0xFF, 0x2A} {
			buf := make([]byte, length)
			for i := range buf {
				buf[i] = fill
			}
			msg, err := dnswire.Unpack(buf)
			if err != nil {
				continue
			}
			_, _, _ = r.Respond(msg)
		}
	}
}

func BenchmarkRespondToBrowse(b *testing.B) {
	r, err := New(Config{Service: Service{
		Instance: "Sundown", Host: "gate", Port: 8443,
		IPv4: []netip.Addr{netip.MustParseAddr("10.11.0.1")},
		TXT:  []string{"api=1", "mode=strict"},
	}})
	if err != nil {
		b.Fatal(err)
	}
	builder := dnswire.NewBuilder(dnswire.Header{})
	if err := builder.AddQuestion(dnswire.Question{
		Name: "_gatecrash._tcp.local.", Type: dnswire.TypePTR, Class: dnswire.ClassINET,
	}); err != nil {
		b.Fatal(err)
	}
	query, err := dnswire.Unpack(builder.Bytes())
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, ok := r.Respond(query); !ok {
			b.Fatal("no response")
		}
	}
}
