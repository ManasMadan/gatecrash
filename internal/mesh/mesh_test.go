package mesh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/cuckoo"
	"github.com/ManasMadan/gatecrash/internal/meshcrypto"
)

func msgID(n uint64) cuckoo.MessageID {
	var id cuckoo.MessageID
	binary.BigEndian.PutUint64(id[:], n)
	return id
}

// clock is a hand-driven clock, so the tests never sleep and the simulator can run
// a festival in a millisecond.
type clock struct{ at time.Time }

func newClock() *clock {
	return &clock{at: time.Date(2026, 8, 21, 21, 0, 0, 0, time.UTC)}
}

func (c *clock) now() time.Time          { return c.at }
func (c *clock) advance(d time.Duration) { c.at = c.at.Add(d) }

// fixedRandom returns a sequence of values, so a relay decision is a fact rather
// than a coin flip.
func fixedRandom(values ...float64) func() float64 {
	i := 0
	return func() float64 {
		if len(values) == 0 {
			return 0
		}
		out := values[i%len(values)]
		i++
		return out
	}
}

func TestFrameRoundTrip(t *testing.T) {
	original := Frame{
		Version:       Version,
		Kind:          KindChannel,
		Flags:         FlagPriority,
		TTL:           4,
		ID:            msgID(0x0102030405060708),
		Channel:       meshcrypto.ChannelID{9, 10, 11, 12},
		FragmentIndex: 0,
		FragmentTotal: 0,
		Body:          []byte("ciphertext"),
	}

	raw, err := original.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != HeaderSize+len("ciphertext") {
		t.Errorf("encoded to %d bytes", len(raw))
	}

	decoded, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != original.Kind || decoded.TTL != original.TTL ||
		decoded.ID != original.ID || decoded.Channel != original.Channel ||
		decoded.Flags != original.Flags || !bytes.Equal(decoded.Body, original.Body) {
		t.Errorf("round trip changed the frame:\n got %+v\nwant %+v", decoded, original)
	}
}

// TestFramesFitInOneAdvertisement. Anything over the limit gets fragmented, and
// every fragment is another chance for a message to arrive incomplete.
func TestFramesFitInOneAdvertisement(t *testing.T) {
	frame := Frame{Version: Version, Kind: KindChannel, TTL: MaxTTL, Body: make([]byte, MaxBodySize)}
	raw, err := frame.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != MaxFrame {
		t.Errorf("a full frame is %d bytes, want exactly %d", len(raw), MaxFrame)
	}

	frame.Body = make([]byte, MaxBodySize+1)
	if _, err := frame.Encode(); !errors.Is(err, ErrTooLong) {
		t.Errorf("an oversized frame encoded: %v", err)
	}
}

// TestTheTTLIsNotAuthenticated is the most important property in the codec. Every
// relay decrements the TTL, so a TTL inside the AAD would mean a message travelled
// exactly one hop and the mesh would not work at all.
func TestTheTTLIsNotAuthenticated(t *testing.T) {
	frame := Frame{Version: Version, Kind: KindChannel, TTL: 6, ID: msgID(1), Body: []byte("x")}

	hopped, ok := frame.Hop()
	if !ok {
		t.Fatal("a frame with a positive ttl would not hop")
	}
	if hopped.TTL != 5 {
		t.Errorf("ttl is %d after one hop", hopped.TTL)
	}
	if !bytes.Equal(frame.AAD(), hopped.AAD()) {
		t.Fatal("the authenticated data changed when the ttl was decremented")
	}
}

// TestEverythingElseIsAuthenticated: a frame cannot be re-labelled into another
// channel, promoted to priority, or re-stitched into a different message.
func TestEverythingElseIsAuthenticated(t *testing.T) {
	base := Frame{Version: Version, Kind: KindChannel, TTL: 6, ID: msgID(1),
		Channel: meshcrypto.ChannelID{1, 2, 3, 4}, Body: []byte("x")}

	for name, mutate := range map[string]func(Frame) Frame{
		"kind":     func(f Frame) Frame { f.Kind = KindDirect; return f },
		"flags":    func(f Frame) Frame { f.Flags |= FlagPriority; return f },
		"id":       func(f Frame) Frame { f.ID = msgID(2); return f },
		"channel":  func(f Frame) Frame { f.Channel = meshcrypto.ChannelID{9}; return f },
		"fragment": func(f Frame) Frame { f.FragmentIndex = 1; return f },
	} {
		if bytes.Equal(base.AAD(), mutate(base).AAD()) {
			t.Errorf("changing the %s did not change the authenticated data", name)
		}
	}
}

func TestDecodeRejectsWhatItShould(t *testing.T) {
	valid := Frame{Version: Version, Kind: KindChannel, TTL: 2, ID: msgID(1), Body: []byte("x")}
	raw, err := valid.Encode()
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		mutate func([]byte) []byte
		want   error
	}{
		"short":                {func(b []byte) []byte { return b[:3] }, ErrTooShort},
		"wrong version":        {func(b []byte) []byte { c := clone(b); c[0] = 99; return c }, ErrVersion},
		"ttl past the limit":   {func(b []byte) []byte { c := clone(b); c[3] = MaxTTL + 1; return c }, ErrBadTTL},
		"unknown kind":         {func(b []byte) []byte { c := clone(b); c[1] = 42; return c }, ErrBadKind},
		"fragment of one":      {func(b []byte) []byte { c := clone(b); c[2] |= byte(FlagFragment); c[17] = 1; return c }, ErrBadFragile},
		"index past total":     {func(b []byte) []byte { c := clone(b); c[2] |= byte(FlagFragment); c[16] = 5; c[17] = 3; return c }, ErrBadFragile},
		"position without bit": {func(b []byte) []byte { c := clone(b); c[17] = 3; return c }, ErrBadFragile},
	} {
		if _, err := Decode(tc.mutate(raw)); !errors.Is(err, tc.want) {
			t.Errorf("%s: error is %v, want %v", name, err, tc.want)
		}
	}

	long := make([]byte, MaxFrame+1)
	long[0] = Version
	if _, err := Decode(long); !errors.Is(err, ErrTooLong) {
		t.Errorf("an oversized frame decoded: %v", err)
	}
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

// TestADuplicateIsDroppedNotRelayed is what stops a message ping-ponging between
// two phones forever.
func TestADuplicateIsDroppedNotRelayed(t *testing.T) {
	c := newClock()
	r := New(Config{Now: c.now, Random: fixedRandom(0)})

	frame := Frame{Version: Version, Kind: KindChannel, TTL: 4, ID: msgID(1), Body: []byte("x")}

	first := r.Handle(frame, "peer-a")
	if !first.Deliver || !first.Relay {
		t.Fatalf("the first sighting was not delivered and relayed: %+v", first)
	}

	second := r.Handle(frame, "peer-b")
	if second.Deliver || second.Relay {
		t.Errorf("a duplicate was acted on: %+v", second)
	}
	if r.Stats().Duplicate != 1 {
		t.Errorf("duplicate count is %d", r.Stats().Duplicate)
	}
}

// TestOwnMessagesComeBackAsDuplicates. A phone that hears its own message relayed
// by a neighbour must not show it to its owner twice.
func TestOwnMessagesComeBackAsDuplicates(t *testing.T) {
	c := newClock()
	r := New(Config{Now: c.now, Random: fixedRandom(0)})

	mine := r.Originate(Frame{Kind: KindChannel, ID: msgID(7), Body: []byte("hello")})
	if mine.TTL != MaxTTL {
		t.Errorf("an originated frame has ttl %d", mine.TTL)
	}

	echo, _ := mine.Hop()
	if decision := r.Handle(echo, "peer-a"); decision.Deliver {
		t.Error("a phone delivered its own message back to itself")
	}
}

// TestAFrameAtTheHopLimitIsDeliveredButNotRelayed.
func TestAFrameAtTheHopLimitIsDeliveredButNotRelayed(t *testing.T) {
	c := newClock()
	r := New(Config{Now: c.now, Random: fixedRandom(0)})

	decision := r.Handle(Frame{Version: Version, Kind: KindChannel, TTL: 0, ID: msgID(1)}, "peer")
	if !decision.Deliver {
		t.Error("a frame at the hop limit was not delivered locally")
	}
	if decision.Relay {
		t.Error("a frame at the hop limit was relayed")
	}
	if r.Stats().Expired != 1 {
		t.Errorf("expired count is %d", r.Stats().Expired)
	}
}

// TestRelayProbabilityFallsWithDensity is the storm control. In a packed pit almost
// nobody relays, and the message still crosses because there are hundreds of phones
// each rolling that die.
func TestRelayProbabilityFallsWithDensity(t *testing.T) {
	c := newClock()
	r := New(Config{K: 3, Now: c.now, Random: fixedRandom(0.5)})

	if got := r.RelayProbability(); got != 1 {
		t.Errorf("a node that has heard nobody relays at %v, want 1", got)
	}

	for i := 0; i < 3; i++ {
		r.Observe(PeerID(string(rune('a' + i))))
	}
	if got := r.RelayProbability(); got != 1 {
		t.Errorf("with three neighbours and k=3 the probability is %v, want 1", got)
	}

	for i := 0; i < 297; i++ {
		r.Observe(PeerID(string(rune('A'+i%26)) + string(rune('a'+i/26))))
	}
	got := r.RelayProbability()
	if got >= 0.05 || got <= 0 {
		t.Errorf("in a crowd of %d the probability is %v, want a small positive number", r.Neighbors(), got)
	}
	t.Logf("%d neighbours -> relay probability %.4f", r.Neighbors(), got)
}

// TestDensityForgetsPhonesThatWalkedAway, or the estimate only ever rises and the
// mesh goes quiet for the rest of the night.
func TestDensityForgetsPhonesThatWalkedAway(t *testing.T) {
	c := newClock()
	r := New(Config{K: 3, NeighborWindow: 30 * time.Second, Now: c.now, Random: fixedRandom(0)})

	for i := 0; i < 100; i++ {
		r.Observe(PeerID(string(rune('a'+i%26)) + string(rune('0'+i/26))))
	}
	if r.Neighbors() < 90 {
		t.Fatalf("only counted %d neighbours", r.Neighbors())
	}

	c.advance(time.Minute)
	if got := r.Neighbors(); got != 0 {
		t.Errorf("%d neighbours are still counted a minute later", got)
	}
	if got := r.RelayProbability(); got != 1 {
		t.Errorf("an emptied field relays at %v, want 1", got)
	}
}

// TestAnAnnouncementRelaysEvenInASaturatedCrowd. "Lost child at the mixer desk"
// has to cross the field.
func TestAnAnnouncementRelaysEvenInASaturatedCrowd(t *testing.T) {
	c := newClock()
	// A random value of 0.99 means an ordinary frame would never relay at this
	// density, so the only thing that can carry this is the priority flag.
	r := New(Config{K: 3, Now: c.now, Random: fixedRandom(0.99)})
	for i := 0; i < 500; i++ {
		r.Observe(PeerID(string(rune('a'+i%26)) + string(rune('0'+i/26))))
	}

	ordinary := r.Handle(Frame{Version: Version, Kind: KindChannel, TTL: 4, ID: msgID(1)}, "peer")
	if ordinary.Relay {
		t.Error("an ordinary frame relayed in a saturated crowd")
	}

	priority := r.Handle(Frame{
		Version: Version, Kind: KindAnnouncement, Flags: FlagPriority, TTL: 4, ID: msgID(2),
	}, "peer")
	if !priority.Relay {
		t.Error("a priority announcement did not relay in a saturated crowd")
	}
}

// TestABeaconIsNeverRelayed. The feature works by hearing a token directly; a
// relayed token means walking towards somebody three hops away.
func TestABeaconIsNeverRelayed(t *testing.T) {
	c := newClock()
	r := New(Config{Now: c.now, Random: fixedRandom(0)})

	frame := EncodeBeacon(msgID(1), [4]byte{1, 2, 3, 4})
	frame.Version = Version

	decision := r.Handle(frame, "peer")
	if !decision.Deliver {
		t.Error("a beacon was not delivered")
	}
	if decision.Relay {
		t.Error("a beacon was relayed")
	}

	token, ok := frame.BeaconToken()
	if !ok || token != [4]byte{1, 2, 3, 4} {
		t.Errorf("beacon token is %v, %v", token, ok)
	}
}

// TestARelayIsJittered. Without it, every node that decided to relay transmits at
// the same instant and they collide instead of delivering.
func TestARelayIsJittered(t *testing.T) {
	c := newClock()
	r := New(Config{Now: c.now, Random: fixedRandom(0.0, 0.5), MaxJitter: 200 * time.Millisecond})

	// First value picks the relay, second picks the jitter.
	decision := r.Handle(Frame{Version: Version, Kind: KindChannel, TTL: 4, ID: msgID(1)}, "peer")
	if !decision.Relay {
		t.Fatal("did not relay")
	}
	if decision.After != 100*time.Millisecond {
		t.Errorf("jitter is %v, want 100ms from a 0.5 draw over a 200ms window", decision.After)
	}
}

// TestSuppressedFramesAreStillCarried is what crosses the gap between two clusters
// of people who never hear each other directly — BLE mesh's worst real failure.
func TestSuppressedFramesAreStillCarried(t *testing.T) {
	c := newClock()
	r := New(Config{K: 1, Now: c.now, Random: fixedRandom(0.99)})
	for i := 0; i < 100; i++ {
		r.Observe(PeerID(string(rune('a'+i%26)) + string(rune('0'+i/26))))
	}

	decision := r.Handle(Frame{Version: Version, Kind: KindChannel, TTL: 4, ID: msgID(1)}, "peer")
	if decision.Relay {
		t.Fatal("expected the relay to be suppressed at this density")
	}
	if r.Stats().Suppressed != 1 {
		t.Errorf("suppressed count is %d", r.Stats().Suppressed)
	}

	carried := r.Carried()
	if len(carried) != 1 || carried[0].ID != msgID(1) {
		t.Errorf("the suppressed frame was not carried: %+v", carried)
	}
}

func TestCarriedFramesExpireAndAreBounded(t *testing.T) {
	c := newClock()
	r := New(Config{Now: c.now, Random: fixedRandom(0), CarryFor: time.Minute, CarryLimit: 4})

	for i := 0; i < 10; i++ {
		r.Handle(Frame{Version: Version, Kind: KindChannel, TTL: 4, ID: msgID(uint64(i))}, "peer")
	}
	if got := len(r.Carried()); got != 4 {
		t.Errorf("carrying %d frames, want the limit of 4", got)
	}

	// Freshest first, because a phone that has just walked up may only be in range
	// for a few seconds.
	if first := r.Carried()[0]; first.ID != msgID(9) {
		t.Errorf("the freshest carried frame is %v", first.ID)
	}

	c.advance(2 * time.Minute)
	if got := len(r.Carried()); got != 0 {
		t.Errorf("%d frames survived the carry window", got)
	}
}

func TestWipeClearsEverything(t *testing.T) {
	c := newClock()
	r := New(Config{Now: c.now, Random: fixedRandom(0)})

	for i := 0; i < 20; i++ {
		r.Observe(PeerID(string(rune('a' + i))))
		r.Handle(Frame{Version: Version, Kind: KindChannel, TTL: 4, ID: msgID(uint64(i))}, "peer")
	}

	r.Wipe()

	if got := len(r.Carried()); got != 0 {
		t.Errorf("%d carried frames survived", got)
	}
	if got := r.Neighbors(); got != 0 {
		t.Errorf("%d neighbours survived", got)
	}
	// And a message it had already seen is new again, which is the point: nothing
	// about what it heard is left.
	if decision := r.Handle(Frame{Version: Version, Kind: KindChannel, TTL: 4, ID: msgID(0)}, "peer"); !decision.Deliver {
		t.Error("a previously seen message was still remembered after a wipe")
	}
}

func TestAFrameFromAnUnknownVersionIsDroppedSilently(t *testing.T) {
	c := newClock()
	r := New(Config{Now: c.now, Random: fixedRandom(0)})

	decision := r.Handle(Frame{Version: 99, Kind: KindChannel, TTL: 4, ID: msgID(1)}, "peer")
	if decision.Deliver || decision.Relay {
		t.Error("a frame from an unknown protocol version was acted on")
	}
	if r.Stats().Malformed != 1 {
		t.Errorf("malformed count is %d", r.Stats().Malformed)
	}
}

// TestFragmentAndReassemble.
func TestFragmentAndReassemble(t *testing.T) {
	body := bytes.Repeat([]byte("abcdefghij"), 60) // 600 bytes, four fragments
	frames, err := Fragment(Frame{Kind: KindChannel, TTL: MaxTTL, ID: msgID(1)}, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 4 {
		t.Fatalf("split into %d fragments", len(frames))
	}

	c := newClock()
	r := NewReassembler(ReassemblerConfig{Now: c.now})

	// Out of order, because fragments take different paths across a crowd.
	for _, index := range []int{2, 0, 3, 1} {
		frame, done, err := r.Accept(frames[index])
		if err != nil {
			t.Fatal(err)
		}
		if done && index != 1 {
			t.Fatalf("reported complete at fragment %d", index)
		}
		if done && !bytes.Equal(frame.Body, body) {
			t.Error("reassembled body does not match")
		}
		if done && frame.Fragmented() {
			t.Error("the reassembled frame still claims to be a fragment")
		}
	}
}

func TestAnUnfragmentedFrameCompletesImmediately(t *testing.T) {
	c := newClock()
	r := NewReassembler(ReassemblerConfig{Now: c.now})

	frame, done, err := r.Accept(Frame{Version: Version, Kind: KindChannel, ID: msgID(1), Body: []byte("short")})
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if string(frame.Body) != "short" {
		t.Errorf("body is %q", frame.Body)
	}
}

// TestFragmentsGetTheirOwnDedupKey. Keyed on the message id alone, fragment two
// would look like a duplicate of fragment one and the message would never arrive.
func TestFragmentsGetTheirOwnDedupKey(t *testing.T) {
	frames, err := Fragment(Frame{Kind: KindChannel, ID: msgID(1)}, bytes.Repeat([]byte("x"), 400))
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatal("expected a fragmented message")
	}
	if bytes.Equal(FragmentKey(frames[0]), FragmentKey(frames[1])) {
		t.Error("two fragments share a dedup key, so the second looks like a duplicate")
	}

	// An unfragmented frame keys on the id alone, unchanged.
	single := Frame{Kind: KindChannel, ID: msgID(2)}
	if !bytes.Equal(FragmentKey(single), single.ID[:]) {
		t.Error("an unfragmented frame's key is not its id")
	}
}

// TestReassemblyIsBounded. Everything here arrives from strangers, and an unbounded
// reassembly buffer on a phone in a crowd is a way for one person to exhaust
// everybody else's memory.
func TestReassemblyIsBounded(t *testing.T) {
	if _, err := Fragment(Frame{Kind: KindChannel, ID: msgID(1)},
		bytes.Repeat([]byte("x"), MaxFragments*MaxBodySize+1)); !errors.Is(err, ErrTooBig) {
		t.Errorf("an oversized message was fragmented: %v", err)
	}

	c := newClock()
	r := NewReassembler(ReassemblerConfig{Limit: 2, Now: c.now})
	for i := 0; i < 10; i++ {
		frames, err := Fragment(Frame{Kind: KindChannel, ID: msgID(uint64(i))}, bytes.Repeat([]byte("x"), 400))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.Accept(frames[0]); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.Pending(); got > 2 {
		t.Errorf("holding %d partial messages, want at most 2", got)
	}
}

func TestPartialMessagesExpire(t *testing.T) {
	c := newClock()
	r := NewReassembler(ReassemblerConfig{Timeout: 30 * time.Second, Now: c.now})

	frames, err := Fragment(Frame{Kind: KindChannel, ID: msgID(1)}, bytes.Repeat([]byte("x"), 400))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Accept(frames[0]); err != nil {
		t.Fatal(err)
	}
	if r.Pending() != 1 {
		t.Fatal("the first fragment was not held")
	}

	c.advance(time.Minute)
	if r.Pending() != 0 {
		t.Error("a partial message survived the timeout")
	}
}

func TestReassemblyRejectsInconsistentFragments(t *testing.T) {
	c := newClock()
	r := NewReassembler(ReassemblerConfig{Now: c.now})

	frames, err := Fragment(Frame{Kind: KindChannel, ID: msgID(1)}, bytes.Repeat([]byte("x"), 400))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Accept(frames[0]); err != nil {
		t.Fatal(err)
	}

	// The same piece twice.
	if _, _, err := r.Accept(frames[0]); !errors.Is(err, ErrDuplicate) {
		t.Errorf("a repeated fragment: %v", err)
	}

	// A piece claiming a different total for the same message, which is either a bug
	// or an attempt to corrupt a reassembly in progress.
	confused := frames[1]
	confused.FragmentTotal = 9
	if _, _, err := r.Accept(confused); !errors.Is(err, ErrMismatch) {
		t.Errorf("a fragment with the wrong total: %v", err)
	}
}

// TestAChannelMessageIsSealedAgainstItsOwnHeader, so it cannot be re-labelled into
// another channel or promoted to priority.
func TestAChannelMessageIsSealedAgainstItsOwnHeader(t *testing.T) {
	key := meshcrypto.DeriveChannelKey("EVENT", "lost-and-found", "orange lanyard")

	frames, err := ChannelMessage(msgID(1), key, []byte("blue shirt kid at the mixer desk"))
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("a short message needed %d frames", len(frames))
	}

	got, err := OpenChannelMessage(frames[0], key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "blue shirt kid at the mixer desk" {
		t.Errorf("got %q", got)
	}

	// Promoted to priority by somebody in the middle.
	tampered := frames[0]
	tampered.Flags |= FlagPriority
	if _, err := OpenChannelMessage(tampered, key); err == nil {
		t.Error("a frame promoted to priority still authenticated")
	}

	// And a phone in a different channel does not pay for a decryption to find out.
	other := meshcrypto.DeriveChannelKey("EVENT", "vip", "different")
	if _, err := OpenChannelMessage(frames[0], other); !errors.Is(err, meshcrypto.ErrNotForUs) {
		t.Errorf("error for another channel is %v", err)
	}
}

func TestALongChannelMessageSurvivesFragmentation(t *testing.T) {
	key := meshcrypto.DeriveChannelKey("EVENT", "general", "pass")
	long := bytes.Repeat([]byte("the queue at gate four is enormous. "), 20)

	frames, err := ChannelMessage(msgID(1), key, long)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatalf("expected fragmentation, got %d frame", len(frames))
	}

	c := newClock()
	r := NewReassembler(ReassemblerConfig{Now: c.now})
	var complete Frame
	for _, frame := range frames {
		assembled, done, err := r.Accept(frame)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			complete = assembled
		}
	}

	got, err := OpenChannelMessage(complete, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, long) {
		t.Error("the reassembled message did not decrypt to the original")
	}
}

// TestAnAnnouncementCarriesItsSignature and cannot be forged.
func TestAnAnnouncementCarriesItsSignature(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const eventID = "SUNDOWN"
	body := []byte("Gate 4 is now open")
	signature := meshcrypto.SignAnnouncement(private, eventID, body)

	frames, err := Announcement(msgID(1), eventID, body, signature)
	if err != nil {
		t.Fatal(err)
	}
	if !frames[0].Priority() {
		t.Error("an announcement is not flagged priority")
	}

	c := newClock()
	r := NewReassembler(ReassemblerConfig{Now: c.now})
	var complete Frame
	for _, frame := range frames {
		assembled, done, err := r.Accept(frame)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			complete = assembled
		}
	}

	gotSignature, gotBody, ok := SplitAnnouncement(complete)
	if !ok {
		t.Fatal("could not split the announcement")
	}
	if !bytes.Equal(gotBody, body) {
		t.Errorf("body is %q", gotBody)
	}
	if !meshcrypto.VerifyAnnouncement(public, eventID, gotBody, gotSignature) {
		t.Error("a genuine announcement did not verify")
	}
	if meshcrypto.VerifyAnnouncement(public, eventID, []byte("Gate 4 is closed"), gotSignature) {
		t.Error("a forged announcement verified")
	}
}

// TestAMessageCrossesAChainOfPhones is the end-to-end property: a message
// originated at one end of a line of nodes reaches the other, and stops.
func TestAMessageCrossesAChainOfPhones(t *testing.T) {
	c := newClock()

	// Sparse: each node has a couple of neighbours, so everybody relays.
	nodes := make([]*Router, 8)
	for i := range nodes {
		nodes[i] = New(Config{K: 3, Now: c.now, Random: fixedRandom(0)})
	}

	frame := nodes[0].Originate(Frame{Kind: KindChannel, ID: msgID(1), Body: []byte("hello")})

	delivered := 0
	current := frame
	for i := 1; i < len(nodes); i++ {
		decision := nodes[i].Handle(current, PeerID("previous"))
		if decision.Deliver {
			delivered++
		}
		if !decision.Relay {
			break
		}
		current = decision.Hopped
	}

	// The arithmetic: the first node downstream receives the frame with a full TTL
	// of 6 and relays it at 5, and so on down to a node that receives it at 0 and
	// stops. That is six relays and seven receivers — one more than the TTL, because
	// the TTL counts relays rather than receptions.
	if delivered != MaxTTL+1 {
		t.Errorf("%d nodes received the message, want %d", delivered, MaxTTL+1)
	}
}

func BenchmarkHandle(b *testing.B) {
	c := newClock()
	r := New(Config{Now: c.now, Random: fixedRandom(0.5)})
	frames := make([]Frame, 1024)
	for i := range frames {
		frames[i] = Frame{Version: Version, Kind: KindChannel, TTL: 4, ID: msgID(uint64(i)), Body: []byte("body")}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Handle(frames[i%len(frames)], "peer")
	}
}
