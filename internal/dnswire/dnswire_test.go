package dnswire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestRoundTripEveryRecordTypeTheBoxServes(t *testing.T) {
	b := NewBuilder(Header{ID: 0x1234, Response: true, Authoritative: true})

	if err := b.AddQuestion(Question{Name: "gate.local.", Type: TypeA, Class: ClassINET}); err != nil {
		t.Fatal(err)
	}
	records := []Record{
		{Name: "gate.local.", Type: TypeA, Class: ClassINET, TTL: 120, CacheFlush: true, IP: net.IPv4(10, 11, 0, 1).To4()},
		{Name: "gate.local.", Type: TypeAAAA, Class: ClassINET, TTL: 120, IP: net.ParseIP("fe80::1").To16()},
		{Name: "_gatecrash._tcp.local.", Type: TypePTR, Class: ClassINET, TTL: 4500, Target: "Sundown._gatecrash._tcp.local."},
		{
			Name: "Sundown._gatecrash._tcp.local.", Type: TypeSRV, Class: ClassINET, TTL: 120,
			Priority: 0, Weight: 0, Port: 8443, Target: "gate.local.",
		},
		{
			Name: "Sundown._gatecrash._tcp.local.", Type: TypeTXT, Class: ClassINET, TTL: 4500,
			TXT: []string{"api=1", "event=Sundown Sessions", "fp=gc-AbCdEf"},
		},
	}
	for _, r := range records {
		if err := b.AddAnswer(r); err != nil {
			t.Fatal(err)
		}
	}

	msg, err := Unpack(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.ID != 0x1234 || !msg.Header.Response || !msg.Header.Authoritative {
		t.Fatalf("header round trip: %+v", msg.Header)
	}
	if len(msg.Questions) != 1 || msg.Questions[0].Name != "gate.local." {
		t.Fatalf("questions: %+v", msg.Questions)
	}
	if len(msg.Answers) != len(records) {
		t.Fatalf("%d answers, want %d", len(msg.Answers), len(records))
	}

	got := msg.Answers
	if !got[0].CacheFlush {
		t.Error("the cache-flush bit did not survive")
	}
	if !bytes.Equal(got[0].IP, net.IPv4(10, 11, 0, 1).To4()) {
		t.Errorf("A record address is %v", got[0].IP)
	}
	if !bytes.Equal(got[1].IP, net.ParseIP("fe80::1").To16()) {
		t.Errorf("AAAA record address is %v", got[1].IP)
	}
	if got[2].Target != "Sundown._gatecrash._tcp.local." {
		t.Errorf("PTR target is %q", got[2].Target)
	}
	if got[3].Port != 8443 || got[3].Target != "gate.local." {
		t.Errorf("SRV is port %d target %q", got[3].Port, got[3].Target)
	}
	if len(got[4].TXT) != 3 || got[4].TXT[1] != "event=Sundown Sessions" {
		t.Errorf("TXT strings are %q", got[4].TXT)
	}
}

// TestCompressionKeepsAServiceAnnouncementInsideOneEthernetFrame is the reason
// compression is implemented at all. A full DNS-SD announcement repeats the same
// long names four times; without compression it exceeds the MTU and gets
// fragmented, and fragmented mDNS is unreliable on exactly the cheap access
// points this product targets.
func TestCompressionKeepsAServiceAnnouncementInsideOneEthernetFrame(t *testing.T) {
	const instance = "Sundown Sessions at the Kingdom of Dreams._gatecrash._tcp.local."
	b := NewBuilder(Header{Response: true, Authoritative: true})

	for _, r := range []Record{
		{Name: "_services._dns-sd._udp.local.", Type: TypePTR, Class: ClassINET, TTL: 4500, Target: "_gatecrash._tcp.local."},
		{Name: "_gatecrash._tcp.local.", Type: TypePTR, Class: ClassINET, TTL: 4500, Target: instance},
		{Name: instance, Type: TypeSRV, Class: ClassINET, TTL: 120, Port: 8443, Target: "gate.local."},
		{Name: instance, Type: TypeTXT, Class: ClassINET, TTL: 4500, TXT: []string{
			"api=1", "event=Sundown Sessions", "fp=gc-AbCdEfGhIj", "mode=strict", "seq=41287",
		}},
		{Name: "gate.local.", Type: TypeA, Class: ClassINET, TTL: 120, IP: net.IPv4(10, 11, 0, 1).To4()},
	} {
		if err := b.AddAnswer(r); err != nil {
			t.Fatal(err)
		}
	}

	packed := b.Bytes()
	// Comfortably inside a 1,500-byte frame with room for IP and UDP headers.
	if len(packed) > 400 {
		t.Errorf("a full announcement is %d bytes, which suggests compression is not working", len(packed))
	}
	// And it must still decode, because a compressed message nobody can read is
	// worse than a fragmented one.
	msg, err := Unpack(packed)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers) != 5 {
		t.Fatalf("%d answers survived", len(msg.Answers))
	}
	for i, r := range msg.Answers {
		if r.Name == "" {
			t.Errorf("answer %d lost its name", i)
		}
	}
	t.Logf("full DNS-SD announcement: %d bytes", len(packed))
}

func TestSRVTargetsAreNotCompressed(t *testing.T) {
	// RFC 2782 says an SRV target must not be compressed. Some stacks cope and
	// some do not, and the ones that do not are exactly the cheap Android builds
	// this has to work on.
	b := NewBuilder(Header{Response: true})
	if err := b.AddAnswer(Record{Name: "gate.local.", Type: TypeA, Class: ClassINET, IP: net.IPv4(10, 0, 0, 1).To4()}); err != nil {
		t.Fatal(err)
	}
	if err := b.AddAnswer(Record{
		Name: "x._gatecrash._tcp.local.", Type: TypeSRV, Class: ClassINET, Port: 443, Target: "gate.local.",
	}); err != nil {
		t.Fatal(err)
	}
	packed := b.Bytes()

	// The SRV target has to appear as literal labels, not as a pointer to the
	// earlier "gate.local." at the top of the message.
	if !bytes.Contains(packed[len(packed)-20:], []byte("gate")) {
		t.Fatal("the SRV target does not appear literally, so it was compressed")
	}
	msg, err := Unpack(packed)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Answers[1].Target != "gate.local." {
		t.Fatalf("SRV target is %q", msg.Answers[1].Target)
	}
}

func TestUnicastResponseBitRoundTrips(t *testing.T) {
	// The mDNS QU bit is common on iOS, and honouring it is most of what keeps
	// mDNS traffic off a saturated venue network.
	b := NewBuilder(Header{})
	if err := b.AddQuestion(Question{Name: "gate.local.", Type: TypeA, Class: ClassINET, Unicast: true}); err != nil {
		t.Fatal(err)
	}
	msg, err := Unpack(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !msg.Questions[0].Unicast {
		t.Fatal("the unicast-response bit did not survive")
	}
	// And the class must not have the bit smeared into it.
	if msg.Questions[0].Class != ClassINET {
		t.Fatalf("class is %d, want ClassINET with the QU bit stripped", msg.Questions[0].Class)
	}
}

// TestUnpackRejectsHostileMessages is the security half of this package. Any
// device on the venue Wi-Fi can send these bytes, so each of these has to be a
// clean rejection rather than a panic, a hang, or a large allocation.
func TestUnpackRejectsHostileMessages(t *testing.T) {
	valid := func() []byte {
		b := NewBuilder(Header{ID: 1, Response: true})
		if err := b.AddAnswer(Record{Name: "gate.local.", Type: TypeA, Class: ClassINET, IP: net.IPv4(10, 0, 0, 1).To4()}); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}

	t.Run("empty and truncated", func(t *testing.T) {
		for _, input := range [][]byte{{}, {0}, make([]byte, headerLen-1)} {
			if _, err := Unpack(input); !errors.Is(err, ErrShort) {
				t.Errorf("Unpack(%d bytes) gave %v, want ErrShort", len(input), err)
			}
		}
	})

	t.Run("oversized message", func(t *testing.T) {
		if _, err := Unpack(make([]byte, MaxMessageLen+1)); !errors.Is(err, ErrTooLarge) {
			t.Error("an oversized message was accepted")
		}
	})

	t.Run("counts that would force a huge allocation", func(t *testing.T) {
		// A header claiming 65,535 questions in a 12-byte packet is the cheapest
		// way to make a naive parser allocate per packet.
		hostile := make([]byte, headerLen)
		binary.BigEndian.PutUint16(hostile[4:6], 0xFFFF)
		if _, err := Unpack(hostile); !errors.Is(err, ErrShort) {
			t.Errorf("got %v, want ErrShort", err)
		}

		hostile = make([]byte, headerLen)
		binary.BigEndian.PutUint16(hostile[6:8], 0xFFFF)
		if _, err := Unpack(hostile); !errors.Is(err, ErrShort) {
			t.Errorf("got %v, want ErrShort", err)
		}
	})

	// These packets are padded past the header so the count guard passes and the
	// name parser is genuinely reached: a packet too small to hold its declared
	// question is rejected earlier, by a different check.
	t.Run("forward compression pointer", func(t *testing.T) {
		// The classic parser loop. Pointers may only point backwards here, which
		// makes a loop impossible rather than merely bounded.
		hostile := make([]byte, headerLen+16)
		binary.BigEndian.PutUint16(hostile[4:6], 1)
		hostile[headerLen] = 0xC0
		hostile[headerLen+1] = byte(headerLen + 4) // points forward
		if _, err := Unpack(hostile); !errors.Is(err, ErrBadName) {
			t.Errorf("got %v, want ErrBadName", err)
		}
	})

	t.Run("self-referential pointer", func(t *testing.T) {
		hostile := make([]byte, headerLen+16)
		binary.BigEndian.PutUint16(hostile[4:6], 1)
		hostile[headerLen] = 0xC0
		hostile[headerLen+1] = byte(headerLen) // points at itself
		if _, err := Unpack(hostile); !errors.Is(err, ErrBadName) {
			t.Errorf("got %v, want ErrBadName", err)
		}
	})

	t.Run("reserved label type", func(t *testing.T) {
		hostile := make([]byte, headerLen+16)
		binary.BigEndian.PutUint16(hostile[4:6], 1)
		hostile[headerLen] = 0x80
		if _, err := Unpack(hostile); !errors.Is(err, ErrBadName) {
			t.Errorf("got %v, want ErrBadName", err)
		}
	})

	t.Run("label running past the buffer", func(t *testing.T) {
		hostile := make([]byte, headerLen+2)
		binary.BigEndian.PutUint16(hostile[4:6], 1)
		hostile[headerLen] = 60 // claims 60 bytes with 1 available
		if _, err := Unpack(hostile); !errors.Is(err, ErrShort) {
			t.Errorf("got %v, want ErrShort", err)
		}
	})

	t.Run("record data running past the buffer", func(t *testing.T) {
		packed := valid()
		// Inflate the RDLENGTH of the answer.
		binary.BigEndian.PutUint16(packed[len(packed)-6:len(packed)-4], 0xFFFF)
		if _, err := Unpack(packed); !errors.Is(err, ErrShort) {
			t.Errorf("got %v, want ErrShort", err)
		}
	})

	t.Run("A record with the wrong length", func(t *testing.T) {
		b := NewBuilder(Header{Response: true})
		if err := b.AddAnswer(Record{Name: "x.local.", Type: 999, Class: ClassINET, Data: []byte{1, 2}}); err != nil {
			t.Fatal(err)
		}
		packed := b.Bytes()
		// Relabel the unknown type as an A record so its 2-byte body is wrong.
		// Counting back from the end: rdata(2) rdlength(2) ttl(4) class(2) type(2).
		binary.BigEndian.PutUint16(packed[len(packed)-12:len(packed)-10], uint16(TypeA))
		if _, err := Unpack(packed); !errors.Is(err, ErrShort) {
			t.Errorf("got %v, want ErrShort", err)
		}
	})

	t.Run("TXT string claiming more than it has", func(t *testing.T) {
		// Built through the unknown-type path so the RDATA is written verbatim,
		// then relabelled as TXT: the TXT encoder would never produce this.
		hostile := NewBuilder(Header{Response: true})
		if err := hostile.AddAnswer(Record{Name: "x.local.", Type: 999, Class: ClassINET, Data: []byte{200, 'a'}}); err != nil {
			t.Fatal(err)
		}
		packed := hostile.Bytes()
		binary.BigEndian.PutUint16(packed[len(packed)-12:len(packed)-10], uint16(TypeTXT))
		if _, err := Unpack(packed); err == nil {
			t.Error("a TXT string claiming more bytes than it has was accepted")
		}
	})

	t.Run("fuzz-shaped garbage never panics", func(t *testing.T) {
		// Not a real fuzzer, just the shapes that historically break DNS
		// parsers, asserted not to take the box down.
		for length := 0; length < 64; length++ {
			for _, fill := range []byte{0x00, 0xC0, 0xFF, 0x3F, 0x80} {
				buf := make([]byte, length)
				for i := range buf {
					buf[i] = fill
				}
				_, _ = Unpack(buf)
			}
		}
	})
}

func TestUnpackNameReturnsTheOffsetPastTheNameNotPastThePointer(t *testing.T) {
	// Getting this wrong is how a parser ends up reading records out of the
	// middle of a name.
	b := NewBuilder(Header{Response: true})
	if err := b.AddAnswer(Record{Name: "gate.local.", Type: TypeA, Class: ClassINET, IP: net.IPv4(10, 0, 0, 1).To4()}); err != nil {
		t.Fatal(err)
	}
	if err := b.AddAnswer(Record{Name: "gate.local.", Type: TypeA, Class: ClassINET, IP: net.IPv4(10, 0, 0, 2).To4()}); err != nil {
		t.Fatal(err)
	}
	packed := b.Bytes()

	// The second record's name is a two-byte pointer, so the record header must
	// start two bytes later, not at the end of the first record's name.
	msg, err := Unpack(packed)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers) != 2 {
		t.Fatalf("%d answers", len(msg.Answers))
	}
	if !bytes.Equal(msg.Answers[1].IP, net.IPv4(10, 0, 0, 2).To4()) {
		t.Fatalf("second answer address is %v, so the offset after a pointer is wrong", msg.Answers[1].IP)
	}
}

func TestNameLengthLimits(t *testing.T) {
	b := NewBuilder(Header{})

	if err := b.AddQuestion(Question{Name: strings.Repeat("a", 64) + ".local.", Type: TypeA, Class: ClassINET}); err == nil {
		t.Error("a 64-byte label was accepted")
	}
	long := strings.TrimSuffix(strings.Repeat(strings.Repeat("a", 60)+".", 5), ".") + "." + strings.Repeat("b.", 30) + "local."
	if err := b.AddQuestion(Question{Name: long, Type: TypeA, Class: ClassINET}); err == nil {
		t.Errorf("a %d-byte name was accepted", len(long))
	}
	if err := b.AddQuestion(Question{Name: "gate..local.", Type: TypeA, Class: ClassINET}); err == nil {
		t.Error("a name with an empty label was accepted")
	}
}

func TestBuilderRefusesOutOfOrderSections(t *testing.T) {
	// DNS sections are positional: an answer written after an additional would be
	// parsed as the wrong kind of record by everybody.
	b := NewBuilder(Header{Response: true})
	if err := b.AddAdditional(Record{Name: "gate.local.", Type: TypeA, Class: ClassINET, IP: net.IPv4(10, 0, 0, 1).To4()}); err != nil {
		t.Fatal(err)
	}
	if err := b.AddAnswer(Record{Name: "gate.local.", Type: TypeA, Class: ClassINET, IP: net.IPv4(10, 0, 0, 1).To4()}); err == nil {
		t.Error("an answer was accepted after an additional")
	}
	if err := b.AddQuestion(Question{Name: "gate.local.", Type: TypeA, Class: ClassINET}); err == nil {
		t.Error("a question was accepted after a record")
	}
}

func TestBuilderRejectsMalformedRecords(t *testing.T) {
	b := NewBuilder(Header{Response: true})
	if err := b.AddAnswer(Record{Name: "x.local.", Type: TypeA, Class: ClassINET, IP: []byte{1, 2}}); err == nil {
		t.Error("an A record with a 2-byte address was accepted")
	}
	if err := b.AddAnswer(Record{Name: "x.local.", Type: TypeAAAA, Class: ClassINET, IP: []byte{1, 2, 3, 4}}); err == nil {
		t.Error("an AAAA record with a 4-byte address was accepted")
	}
	if err := b.AddAnswer(Record{Name: "x.local.", Type: TypeTXT, Class: ClassINET, TXT: []string{strings.Repeat("a", 256)}}); err == nil {
		t.Error("a 256-byte TXT string was accepted")
	}
}

func TestEmptyTXTIsAZeroLengthString(t *testing.T) {
	// Some resolvers reject a genuinely empty TXT RDATA, so an empty record is
	// encoded as one zero-length string.
	b := NewBuilder(Header{Response: true})
	if err := b.AddAnswer(Record{Name: "x.local.", Type: TypeTXT, Class: ClassINET}); err != nil {
		t.Fatal(err)
	}
	msg, err := Unpack(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers[0].TXT) != 1 || msg.Answers[0].TXT[0] != "" {
		t.Fatalf("empty TXT decoded as %q", msg.Answers[0].TXT)
	}
}

func TestNameComparisonIsCaseInsensitiveAndDotAgnostic(t *testing.T) {
	// Every device on the network disagrees about whether to send "Gate.local",
	// "gate.local." or "GATE.LOCAL". A responder that compares byte-for-byte
	// answers some phones and not others.
	for _, pair := range [][2]string{
		{"gate.local", "gate.local."},
		{"GATE.LOCAL.", "gate.local"},
		{"Gate.Local", "gATE.lOCAL."},
	} {
		if !EqualNames(pair[0], pair[1]) {
			t.Errorf("EqualNames(%q, %q) = false", pair[0], pair[1])
		}
	}
	if EqualNames("gate.local", "gate.lan") {
		t.Error("EqualNames matched different names")
	}

	if !HasSuffixName("Sundown._gatecrash._TCP.local.", "_gatecrash._tcp.local") {
		t.Error("HasSuffixName failed on a mixed-case service name")
	}
	if !HasSuffixName("_gatecrash._tcp.local", "_gatecrash._tcp.local.") {
		t.Error("HasSuffixName failed on an exact match")
	}
	// A suffix match must be on a label boundary, or "notgate.local" matches
	// "gate.local".
	if HasSuffixName("notgate.local.", "gate.local") {
		t.Error("HasSuffixName matched across a label boundary")
	}
}

func TestFqdn(t *testing.T) {
	if Fqdn("gate.local") != "gate.local." || Fqdn("gate.local.") != "gate.local." {
		t.Fatal("Fqdn is not idempotent")
	}
}

func TestTypeStrings(t *testing.T) {
	for typ, want := range map[Type]string{
		TypeA: "A", TypePTR: "PTR", TypeTXT: "TXT", TypeSRV: "SRV",
		TypeAAAA: "AAAA", TypeANY: "ANY", 999: "TYPE999",
	} {
		if got := typ.String(); got != want {
			t.Errorf("Type(%d).String() = %q, want %q", typ, got, want)
		}
	}
}

func FuzzUnpack(f *testing.F) {
	// Seeds are real messages, so the fuzzer starts from something structurally
	// valid and mutates towards the interesting failures rather than spending its
	// budget rediscovering the header layout.
	b := NewBuilder(Header{ID: 1, Response: true, Authoritative: true})
	_ = b.AddQuestion(Question{Name: "gate.local.", Type: TypeA, Class: ClassINET})
	_ = b.AddAnswer(Record{Name: "gate.local.", Type: TypeA, Class: ClassINET, TTL: 120, IP: net.IPv4(10, 11, 0, 1).To4()})
	_ = b.AddAdditional(Record{Name: "x._gatecrash._tcp.local.", Type: TypeSRV, Class: ClassINET, Port: 8443, Target: "gate.local."})
	f.Add(b.Bytes())
	f.Add(make([]byte, headerLen))

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := Unpack(data)
		if err != nil {
			return
		}
		// Anything that parsed must re-pack and re-parse. A message that decodes
		// but cannot be reproduced means the decoder is inventing structure.
		out := NewBuilder(msg.Header)
		for _, q := range msg.Questions {
			if err := out.AddQuestion(q); err != nil {
				return
			}
		}
		for _, r := range msg.Answers {
			if err := out.AddAnswer(r); err != nil {
				return
			}
		}
		if _, err := Unpack(out.Bytes()); err != nil {
			t.Fatalf("a re-packed message does not parse: %v", err)
		}
	})
}

func BenchmarkUnpack(b *testing.B) {
	builder := NewBuilder(Header{ID: 1, Response: true, Authoritative: true})
	_ = builder.AddAnswer(Record{Name: "_gatecrash._tcp.local.", Type: TypePTR, Class: ClassINET, TTL: 4500, Target: "Sundown._gatecrash._tcp.local."})
	_ = builder.AddAnswer(Record{Name: "Sundown._gatecrash._tcp.local.", Type: TypeSRV, Class: ClassINET, TTL: 120, Port: 8443, Target: "gate.local."})
	_ = builder.AddAnswer(Record{Name: "Sundown._gatecrash._tcp.local.", Type: TypeTXT, Class: ClassINET, TTL: 4500, TXT: []string{"api=1", "mode=strict"}})
	_ = builder.AddAnswer(Record{Name: "gate.local.", Type: TypeA, Class: ClassINET, TTL: 120, IP: net.IPv4(10, 11, 0, 1).To4()})
	packed := builder.Bytes()

	b.ReportAllocs()
	b.SetBytes(int64(len(packed)))
	for i := 0; i < b.N; i++ {
		if _, err := Unpack(packed); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPackAnnouncement(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		builder := NewBuilder(Header{Response: true, Authoritative: true})
		_ = builder.AddAnswer(Record{Name: "_gatecrash._tcp.local.", Type: TypePTR, Class: ClassINET, TTL: 4500, Target: "Sundown._gatecrash._tcp.local."})
		_ = builder.AddAnswer(Record{Name: "Sundown._gatecrash._tcp.local.", Type: TypeSRV, Class: ClassINET, TTL: 120, Port: 8443, Target: "gate.local."})
		_ = builder.AddAnswer(Record{Name: "gate.local.", Type: TypeA, Class: ClassINET, TTL: 120, IP: net.IPv4(10, 11, 0, 1).To4()})
		_ = builder.Bytes()
	}
}
