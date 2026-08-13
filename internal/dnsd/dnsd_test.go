package dnsd

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/dnswire"
)

var boxIP = netip.MustParseAddr("10.11.0.1")

func newServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	if !cfg.Box.IsValid() {
		cfg.Box = boxIP
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ask sends one question and returns the decoded response.
func ask(t *testing.T, s *Server, name string, typ dnswire.Type) *dnswire.Message {
	t.Helper()
	builder := dnswire.NewBuilder(dnswire.Header{ID: 0xBEEF, RecursionDesired: true})
	if err := builder.AddQuestion(dnswire.Question{
		Name: name, Type: typ, Class: dnswire.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	query, err := dnswire.Unpack(builder.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	response := s.Resolve(context.Background(), query)
	if response == nil {
		return nil
	}
	msg, err := dnswire.Unpack(response)
	if err != nil {
		t.Fatalf("the server produced a message it cannot parse: %v", err)
	}
	return &msg
}

func TestAnswersItsOwnNames(t *testing.T) {
	s := newServer(t, Config{})

	for _, name := range append(DefaultNames, "gate.local.", "GO.GATE") {
		msg := ask(t, s, name, dnswire.TypeA)
		if msg == nil {
			t.Fatalf("no response for %q", name)
		}
		if msg.Header.ID != 0xBEEF {
			t.Errorf("%q: response id is %d, want the query's", name, msg.Header.ID)
		}
		if !msg.Header.Authoritative {
			t.Errorf("%q: the box is the authority for its own names and should say so", name)
		}
		if msg.Header.RCode != dnswire.RCodeSuccess {
			t.Errorf("%q: rcode is %d", name, msg.Header.RCode)
		}
		if len(msg.Answers) != 1 {
			t.Fatalf("%q: %d answers", name, len(msg.Answers))
		}
		if got, _ := netip.AddrFromSlice(msg.Answers[0].IP); got != boxIP {
			t.Errorf("%q resolved to %v, want %v", name, got, boxIP)
		}
		if msg.Answers[0].TTL != TTLOwned {
			t.Errorf("%q: TTL is %d, want %d", name, msg.Answers[0].TTL, TTLOwned)
		}
		// Echoing the question back is required by RFC 1035 and is what most
		// resolvers use to match a response to its query.
		if len(msg.Questions) != 1 {
			t.Errorf("%q: the question was not echoed back", name)
		}
	}
}

func TestOwnershipCoversSubdomains(t *testing.T) {
	// Owning "gate" also owns "api.gate", which is what lets the box serve
	// several hostnames without listing them all.
	s := newServer(t, Config{})
	for _, name := range []string{"api.gate", "portal.go.gate", "anything.gate.local"} {
		if !s.Owns(name) {
			t.Errorf("Owns(%q) = false", name)
		}
		if msg := ask(t, s, name, dnswire.TypeA); msg == nil {
			t.Errorf("no response for %q", name)
		}
	}
	// But it must be on a label boundary, or "notgate" matches "gate".
	if s.Owns("notgate") {
		t.Error(`Owns("notgate") matched across a label boundary`)
	}
}

func TestExtraNamesAreAdded(t *testing.T) {
	s := newServer(t, Config{Names: []string{"Sundown.Fest", " tickets.local "}})
	for _, name := range []string{"sundown.fest", "tickets.local"} {
		if !s.Owns(name) {
			t.Errorf("configured name %q is not owned", name)
		}
	}
	// Names are normalised and deduplicated, so a config listing gate.local twice
	// does not produce two answers.
	s2 := newServer(t, Config{Names: []string{"gate.local", "GATE.LOCAL."}})
	count := 0
	for _, name := range s2.Names() {
		if name == "gate.local" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("gate.local appears %d times in the name list", count)
	}
}

// TestAAAAForAnIPv4BoxIsEmptyNotNXDomain is the mistake that breaks captive
// portals. NXDOMAIN tells a dual-stack client the name does not exist at all, and
// it gives up instead of retrying over IPv4.
func TestAAAAForAnIPv4BoxIsEmptyNotNXDomain(t *testing.T) {
	s := newServer(t, Config{})

	msg := ask(t, s, "go.gate", dnswire.TypeAAAA)
	if msg == nil {
		t.Fatal("no response to an AAAA query")
	}
	if msg.Header.RCode != dnswire.RCodeSuccess {
		t.Fatalf("AAAA for an IPv4-only box gave rcode %d, want NOERROR with no answers", msg.Header.RCode)
	}
	if len(msg.Answers) != 0 {
		t.Fatalf("%d answers to an AAAA query on an IPv4-only box", len(msg.Answers))
	}
	// And the A query still works, which is the whole point.
	if v4 := ask(t, s, "go.gate", dnswire.TypeA); v4 == nil || len(v4.Answers) != 1 {
		t.Fatal("the A query broke")
	}
}

func TestAnIPv6BoxAnswersAAAA(t *testing.T) {
	s := newServer(t, Config{Box: netip.MustParseAddr("fd00::1")})
	msg := ask(t, s, "go.gate", dnswire.TypeAAAA)
	if msg == nil || len(msg.Answers) != 1 {
		t.Fatal("an IPv6 box did not answer AAAA")
	}
	if got, _ := netip.AddrFromSlice(msg.Answers[0].IP); got != netip.MustParseAddr("fd00::1") {
		t.Errorf("AAAA is %v", got)
	}
	// And it does not invent an A record it cannot serve.
	if v4 := ask(t, s, "go.gate", dnswire.TypeA); v4 != nil && len(v4.Answers) != 0 {
		t.Error("an IPv6-only box answered an A query")
	}
}

// TestWildcardIsTheCaptivePortal covers the behaviour that makes the "sign in to
// network" sheet appear, which is the single most effective piece of onboarding
// in the product.
func TestWildcardIsTheCaptivePortal(t *testing.T) {
	s := newServer(t, Config{Wildcard: true})

	for _, name := range []string{
		"connectivitycheck.gstatic.com",
		"captive.apple.com",
		"www.msftconnecttest.com",
		"detectportal.firefox.com",
		"google.com",
		"literally-anything.example",
	} {
		msg := ask(t, s, name, dnswire.TypeA)
		if msg == nil {
			t.Fatalf("wildcard mode did not answer %q", name)
		}
		if len(msg.Answers) != 1 {
			t.Fatalf("%q: %d answers", name, len(msg.Answers))
		}
		if got, _ := netip.AddrFromSlice(msg.Answers[0].IP); got != boxIP {
			t.Errorf("%q resolved to %v", name, got)
		}
		// A very short TTL, so the lie evaporates the moment the device is on a
		// real network again.
		if msg.Answers[0].TTL != TTLWildcard {
			t.Errorf("%q: wildcard TTL is %d, want %d", name, msg.Answers[0].TTL, TTLWildcard)
		}
		// The box knows it is not the authority for google.com, and claiming to
		// be would be a lie with no upside.
		if msg.Header.Authoritative {
			t.Errorf("%q: the box claimed authority for a name it does not own", name)
		}
	}
}

// TestWildcardAnswersNoAAAA is subtle and important. A device handed an IPv6
// address for every name prefers IPv6, fails to reach the box over a link with no
// IPv6 routing, and reports "no internet" without ever showing the portal.
func TestWildcardAnswersNoAAAA(t *testing.T) {
	s := newServer(t, Config{Wildcard: true, Box: netip.MustParseAddr("fd00::1")})
	msg := ask(t, s, "connectivitycheck.gstatic.com", dnswire.TypeAAAA)
	if msg == nil {
		t.Fatal("no response")
	}
	if len(msg.Answers) != 0 {
		t.Fatalf("wildcard mode answered AAAA with %d records, which stops the portal appearing", len(msg.Answers))
	}
}

// TestRefusedRatherThanNXDomainWithNoUpstream matters because NXDOMAIN is an
// authoritative claim that a name does not exist, which makes a device stop
// asking. REFUSED tells it to ask somebody else, which is the truth.
func TestRefusedRatherThanNXDomainWithNoUpstream(t *testing.T) {
	s := newServer(t, Config{})
	msg := ask(t, s, "google.com", dnswire.TypeA)
	if msg == nil {
		t.Fatal("no response")
	}
	if msg.Header.RCode != dnswire.RCodeRefused {
		t.Fatalf("rcode is %d, want REFUSED", msg.Header.RCode)
	}
	if len(msg.Answers) != 0 {
		t.Error("a refusal carried answers")
	}
}

func TestForwardsToUpstreamInRouterMode(t *testing.T) {
	// A stub upstream that answers everything with 1.2.3.4.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			query, err := dnswire.Unpack(buf[:n])
			if err != nil {
				continue
			}
			builder := dnswire.NewBuilder(dnswire.Header{
				ID: query.Header.ID, Response: true, RecursionAvailable: true,
			})
			for _, q := range query.Questions {
				_ = builder.AddQuestion(q)
				_ = builder.AddAnswer(dnswire.Record{
					Name: q.Name, Type: dnswire.TypeA, Class: dnswire.ClassINET,
					TTL: 300, IP: []byte{1, 2, 3, 4},
				})
			}
			_, _ = pc.WriteTo(builder.Bytes(), from)
		}
	}()

	upstream := netip.MustParseAddrPort(pc.LocalAddr().String())
	s := newServer(t, Config{Upstream: []netip.AddrPort{upstream}})

	msg := ask(t, s, "example.com", dnswire.TypeA)
	if msg == nil {
		t.Fatal("no response from a forwarded query")
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("%d answers from the upstream", len(msg.Answers))
	}
	if got, _ := netip.AddrFromSlice(msg.Answers[0].IP); got != netip.MustParseAddr("1.2.3.4") {
		t.Errorf("forwarded answer is %v, want the upstream's", got)
	}
	// The response has to carry the client's id, or the client discards it.
	if msg.Header.ID != 0xBEEF {
		t.Errorf("forwarded response carries id %d, want the client's", msg.Header.ID)
	}

	// Names the box owns are still answered locally rather than forwarded.
	own := ask(t, s, "go.gate", dnswire.TypeA)
	if own == nil || len(own.Answers) != 1 {
		t.Fatal("an owned name was not answered locally")
	}
	if got, _ := netip.AddrFromSlice(own.Answers[0].IP); got != boxIP {
		t.Errorf("an owned name resolved to %v, want the box", got)
	}
}

func TestDeadUpstreamGivesServfailNotSilence(t *testing.T) {
	// SERVFAIL tells the client to retry. Silence makes it wait for its own
	// timeout, which on some Android builds is five seconds per query.
	s := newServer(t, Config{
		// Port 1 on loopback: nothing is listening and the connection is refused
		// immediately, so this does not sit on a timeout.
		Upstream:        []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")},
		UpstreamTimeout: 200 * time.Millisecond,
	})
	msg := ask(t, s, "example.com", dnswire.TypeA)
	if msg == nil {
		t.Fatal("a dead upstream produced no response at all")
	}
	if msg.Header.RCode != dnswire.RCodeServer {
		t.Fatalf("rcode is %d, want SERVFAIL", msg.Header.RCode)
	}
}

func TestIgnoresResponsesAndRefusesOddQueries(t *testing.T) {
	s := newServer(t, Config{Wildcard: true})

	t.Run("a response is not answered", func(t *testing.T) {
		// Answering a response is how a box becomes a reflector.
		builder := dnswire.NewBuilder(dnswire.Header{ID: 1, Response: true})
		_ = builder.AddQuestion(dnswire.Question{Name: "go.gate.", Type: dnswire.TypeA, Class: dnswire.ClassINET})
		msg, err := dnswire.Unpack(builder.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if s.Resolve(context.Background(), msg) != nil {
			t.Fatal("the server replied to a response")
		}
	})

	t.Run("a non-standard opcode is not implemented", func(t *testing.T) {
		// The box is not a dynamic-update server, and saying so is better than
		// ignoring it.
		builder := dnswire.NewBuilder(dnswire.Header{ID: 1, Opcode: 5})
		_ = builder.AddQuestion(dnswire.Question{Name: "go.gate.", Type: dnswire.TypeA, Class: dnswire.ClassINET})
		msg, err := dnswire.Unpack(builder.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		response, err := dnswire.Unpack(s.Resolve(context.Background(), msg))
		if err != nil {
			t.Fatal(err)
		}
		if response.Header.RCode != dnswire.RCodeNotImpl {
			t.Fatalf("rcode is %d, want NOTIMP", response.Header.RCode)
		}
	})

	t.Run("no question is a format error", func(t *testing.T) {
		msg, err := dnswire.Unpack(dnswire.NewBuilder(dnswire.Header{ID: 1}).Bytes())
		if err != nil {
			t.Fatal(err)
		}
		response, err := dnswire.Unpack(s.Resolve(context.Background(), msg))
		if err != nil {
			t.Fatal(err)
		}
		if response.Header.RCode != dnswire.RCodeFormat {
			t.Fatalf("rcode is %d, want FORMERR", response.Header.RCode)
		}
	})

	t.Run("a chaos-class query is not implemented", func(t *testing.T) {
		builder := dnswire.NewBuilder(dnswire.Header{ID: 1})
		_ = builder.AddQuestion(dnswire.Question{Name: "version.bind.", Type: dnswire.TypeTXT, Class: 3})
		msg, err := dnswire.Unpack(builder.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		response, err := dnswire.Unpack(s.Resolve(context.Background(), msg))
		if err != nil {
			t.Fatal(err)
		}
		if response.Header.RCode != dnswire.RCodeNotImpl {
			t.Fatalf("rcode is %d, want NOTIMP", response.Header.RCode)
		}
	})
}

func TestListenAndServeAnswersOverUDPAndTCP(t *testing.T) {
	// Port 0 so the test does not need root and does not collide with a real
	// resolver on the machine.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := newServer(t, Config{Wildcard: true})

	// Bind explicitly so the test knows the port.
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := udp.LocalAddr().String()
	udp.Close()

	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe(ctx, addr) }()

	// Give the listeners a moment to bind. Polling rather than sleeping a fixed
	// duration so this is not slow and not flaky.
	var query []byte
	builder := dnswire.NewBuilder(dnswire.Header{ID: 0x0101, RecursionDesired: true})
	if err := builder.AddQuestion(dnswire.Question{Name: "go.gate.", Type: dnswire.TypeA, Class: dnswire.ClassINET}); err != nil {
		t.Fatal(err)
	}
	query = builder.Bytes()

	var lastErr error
	for attempt := 0; attempt < 50; attempt++ {
		conn, err := net.Dial("udp", addr)
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write(query); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		msg, err := dnswire.Unpack(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		if len(msg.Answers) != 1 {
			t.Fatalf("%d answers over UDP", len(msg.Answers))
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		t.Fatalf("no UDP answer: %v", lastErr)
	}

	// TCP, which is what a client falls back to after a truncated response. A box
	// that only listens on UDP looks broken in exactly that case.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("no TCP listener: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	framed := append([]byte{byte(len(query) >> 8), byte(len(query))}, query...)
	if _, err := conn.Write(framed); err != nil {
		t.Fatal(err)
	}
	var length [2]byte
	if _, err := readFull(conn, length[:]); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(length[0])<<8|int(length[1]))
	if _, err := readFull(conn, body); err != nil {
		t.Fatal(err)
	}
	msg, err := dnswire.Unpack(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("%d answers over TCP", len(msg.Answers))
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("ListenAndServe returned %v", err)
	}
}

func TestNewRequiresABoxAddress(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New accepted a config with no box address")
	}
}

func TestResolveNeverPanicsOnGarbage(t *testing.T) {
	s := newServer(t, Config{Wildcard: true})
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
			_ = s.Resolve(context.Background(), msg)
		}
	}
}

func BenchmarkResolveOwned(b *testing.B) {
	s, err := New(Config{Box: boxIP})
	if err != nil {
		b.Fatal(err)
	}
	builder := dnswire.NewBuilder(dnswire.Header{ID: 1})
	_ = builder.AddQuestion(dnswire.Question{Name: "go.gate.", Type: dnswire.TypeA, Class: dnswire.ClassINET})
	query, err := dnswire.Unpack(builder.Bytes())
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if s.Resolve(ctx, query) == nil {
			b.Fatal("no response")
		}
	}
}
