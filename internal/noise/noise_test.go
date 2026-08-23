package noise

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// fixedKeypair builds a key pair from a deterministic private scalar, so a
// transcript can be reproduced byte for byte. Only for tests and for the
// cross-language conformance fixture.
func fixedKeypair(t *testing.T, seed byte) Keypair {
	t.Helper()
	var private [DHLen]byte
	for i := range private {
		private[i] = seed + byte(i)
	}
	pair, err := KeypairFrom(private)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// handshake runs a complete XX exchange and returns both finished sessions along
// with the three messages, so tests can assert on either.
func handshake(t *testing.T, prologue []byte) (initiator, responder *Transport, messages [3][]byte) {
	t.Helper()

	alice, err := NewHandshake(Config{Static: fixedKeypair(t, 1), Initiator: true, Prologue: prologue})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewHandshake(Config{Static: fixedKeypair(t, 100), Prologue: prologue})
	if err != nil {
		t.Fatal(err)
	}

	messages[0], err = alice.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReadMessage(messages[0]); err != nil {
		t.Fatal(err)
	}

	messages[1], err = bob.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ReadMessage(messages[1]); err != nil {
		t.Fatal(err)
	}

	messages[2], err = alice.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReadMessage(messages[2]); err != nil {
		t.Fatal(err)
	}

	initiator, err = alice.Transport()
	if err != nil {
		t.Fatal(err)
	}
	responder, err = bob.Transport()
	if err != nil {
		t.Fatal(err)
	}
	return initiator, responder, messages
}

func TestXXCompletesAndBothSidesAgree(t *testing.T) {
	alice, bob, _ := handshake(t, []byte("event-id"))

	if alice.HandshakeHash != bob.HandshakeHash {
		t.Fatal("the two sides derived different transcript hashes")
	}

	// Each learned the other's static key, which is what XX is for.
	if alice.RemoteStatic != fixedKeypair(t, 100).Public {
		t.Error("the initiator did not learn the responder's static key")
	}
	if bob.RemoteStatic != fixedKeypair(t, 1).Public {
		t.Error("the responder did not learn the initiator's static key")
	}
}

func TestTransportCarriesMessagesBothWays(t *testing.T) {
	alice, bob, _ := handshake(t, nil)

	sealed, err := alice.Encrypt(nil, []byte("meet me by the sound desk"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := bob.Decrypt(nil, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "meet me by the sound desk" {
		t.Errorf("got %q", plaintext)
	}

	back, err := bob.Encrypt(nil, []byte("on my way"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := alice.Decrypt(nil, back); err != nil || string(got) != "on my way" {
		t.Errorf("reverse direction: %q, %v", got, err)
	}
}

// TestTheDirectionsAreNotInterchangeable. Assigning the two split keys backwards is
// one of the two classic Noise porting bugs, and it produces a handshake that
// completes and then cannot decrypt anything.
func TestTheDirectionsAreNotInterchangeable(t *testing.T) {
	alice, _, _ := handshake(t, nil)

	sealed, err := alice.Encrypt(nil, []byte("reflect me"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Decrypt(nil, sealed); err == nil {
		t.Error("a session opened its own outgoing message, so a replay authenticates")
	}
}

// TestMessageSizesMatchThePattern is the cheapest conformance check a port can run.
// An implementation producing a 97-byte second message has a bug, and finding it
// here beats finding it as "authentication failed" on a phone.
func TestMessageSizesMatchThePattern(t *testing.T) {
	_, _, messages := handshake(t, nil)

	for i, want := range []int{Message1Size, Message2Size, Message3Size} {
		if len(messages[i]) != want {
			t.Errorf("message %d is %d bytes, want %d", i+1, len(messages[i]), want)
		}
	}
	if Message2Size != 96 || Message3Size != 64 {
		t.Errorf("the pattern's sizes changed: %d and %d", Message2Size, Message3Size)
	}
}

// TestTheRespondersStaticIsNotSentInTheClear is why XX rather than a pattern that
// sends it plainly. Somebody logging every frame in a field must not be able to
// build a list of which devices were present.
func TestTheRespondersStaticIsNotSentInTheClear(t *testing.T) {
	_, _, messages := handshake(t, nil)
	static := fixedKeypair(t, 100).Public

	for i, message := range messages {
		if bytes.Contains(message, static[:]) {
			t.Errorf("message %d carries the responder's static key in the clear", i+1)
		}
	}

	// The initiator's static, sent in the third message, likewise.
	initiatorStatic := fixedKeypair(t, 1).Public
	if bytes.Contains(messages[2], initiatorStatic[:]) {
		t.Error("the third message carries the initiator's static key in the clear")
	}
}

// TestTamperingWithAnyByteBreaksTheHandshake. The transcript folds in every
// ciphertext, so a man in the middle who alters anything cannot finish.
func TestTamperingWithAnyByteBreaksTheHandshake(t *testing.T) {
	for _, victim := range []int{0, 1} {
		alice, err := NewHandshake(Config{Static: fixedKeypair(t, 1), Initiator: true})
		if err != nil {
			t.Fatal(err)
		}
		bob, err := NewHandshake(Config{Static: fixedKeypair(t, 100)})
		if err != nil {
			t.Fatal(err)
		}

		first, err := alice.WriteMessage(nil)
		if err != nil {
			t.Fatal(err)
		}
		if victim == 0 {
			first[3] ^= 0x01
		}
		if _, err := bob.ReadMessage(first); err != nil {
			// Tampering with the ephemeral key in message 1 is not detectable there —
			// there is no key yet — so it must fail at message 2 instead.
			continue
		}

		second, err := bob.WriteMessage(nil)
		if err != nil {
			t.Fatal(err)
		}
		if victim == 1 {
			second[40] ^= 0x01
		}
		if _, err := alice.ReadMessage(second); err == nil && victim == 1 {
			t.Error("a tampered second message was accepted")
		}
		if victim == 0 {
			// The altered ephemeral produces a different shared secret, so message 2
			// cannot be decrypted by the real initiator.
			if _, err := alice.ReadMessage(second); err == nil {
				t.Error("a tampered ephemeral key went undetected")
			}
		}
	}
}

// TestThePrologueMustMatch. The mesh puts the event id there, so two phones at
// different events cannot complete a handshake at all — a cleaner failure than
// completing one and finding out later.
func TestThePrologueMustMatch(t *testing.T) {
	alice, err := NewHandshake(Config{Static: fixedKeypair(t, 1), Initiator: true, Prologue: []byte("EVENT-ONE")})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewHandshake(Config{Static: fixedKeypair(t, 100), Prologue: []byte("EVENT-TWO")})
	if err != nil {
		t.Fatal(err)
	}

	first, err := alice.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReadMessage(first); err != nil {
		t.Fatal(err)
	}
	second, err := bob.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ReadMessage(second); err == nil {
		t.Error("a handshake completed across two different events")
	}
}

// TestSpeakingOutOfTurnIsRefused, because in a mesh both phones may try to start a
// handshake with each other at the same moment.
func TestSpeakingOutOfTurnIsRefused(t *testing.T) {
	alice, err := NewHandshake(Config{Static: fixedKeypair(t, 1), Initiator: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ReadMessage(make([]byte, Message1Size)); err != ErrWrongTurn {
		t.Errorf("the initiator read its own turn's message: %v", err)
	}

	bob, err := NewHandshake(Config{Static: fixedKeypair(t, 100)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.WriteMessage(nil); err != ErrWrongTurn {
		t.Errorf("the responder spoke first: %v", err)
	}
}

func TestShortMessagesAreRefusedRatherThanPanicking(t *testing.T) {
	bob, err := NewHandshake(Config{Static: fixedKeypair(t, 100)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReadMessage([]byte{1, 2, 3}); err != ErrShort {
		t.Errorf("error is %v, want ErrShort", err)
	}
}

func TestAHandshakeWithNoStaticKeyIsRefused(t *testing.T) {
	if _, err := NewHandshake(Config{Initiator: true}); err != ErrNoStatic {
		t.Errorf("error is %v, want ErrNoStatic", err)
	}
}

func TestSplitBeforeTheEndIsRefused(t *testing.T) {
	alice, err := NewHandshake(Config{Static: fixedKeypair(t, 1), Initiator: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := alice.Split(); err != ErrNotFinished {
		t.Errorf("error is %v, want ErrNotFinished", err)
	}
}

// TestADegeneratePublicKeyIsRefused. A low-order point is an attempt to force a
// known shared secret, and rejecting it at the point it happens beats letting the
// transcript hash catch it later.
func TestADegeneratePublicKeyIsRefused(t *testing.T) {
	bob, err := NewHandshake(Config{Static: fixedKeypair(t, 100)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReadMessage(make([]byte, Message1Size)); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.WriteMessage(nil); err != ErrDegenerate {
		t.Errorf("an all-zero ephemeral key was accepted: %v", err)
	}
}

// TestAFailedDecryptionDoesNotConsumeANonce. If it did, one injected junk frame
// would desynchronise the two sides for good — a trivial denial of service on a
// medium where anybody can transmit.
func TestAFailedDecryptionDoesNotConsumeANonce(t *testing.T) {
	alice, bob, _ := handshake(t, nil)

	junk, err := alice.Encrypt(nil, []byte("real message"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), junk...)
	tampered[0] ^= 0xff

	before := bob.ReceivedCount()
	if _, err := bob.Decrypt(nil, tampered); err != ErrAuth {
		t.Fatalf("error is %v, want ErrAuth", err)
	}
	if bob.ReceivedCount() != before {
		t.Fatal("a failed decryption advanced the counter, so one junk frame desynchronises the session")
	}

	// And the real message still opens.
	if _, err := bob.Decrypt(nil, junk); err != nil {
		t.Errorf("the genuine message failed after the junk one: %v", err)
	}
}

// TestTransportIsStrictlyOrdered documents the contract the mesh layer has to work
// around: Noise has no replay window, so out-of-order delivery fails here and the
// mesh carries its own message ids instead.
func TestTransportIsStrictlyOrdered(t *testing.T) {
	alice, bob, _ := handshake(t, nil)

	first, err := alice.Encrypt(nil, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := alice.Encrypt(nil, []byte("two"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := bob.Decrypt(nil, second); err != ErrAuth {
		t.Errorf("an out-of-order message opened: %v", err)
	}
	if _, err := bob.Decrypt(nil, first); err != nil {
		t.Errorf("the in-order message failed: %v", err)
	}
}

func TestPayloadsAreCarriedByTheHandshake(t *testing.T) {
	alice, err := NewHandshake(Config{Static: fixedKeypair(t, 1), Initiator: true})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewHandshake(Config{Static: fixedKeypair(t, 100)})
	if err != nil {
		t.Fatal(err)
	}

	first, err := alice.WriteMessage([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := bob.ReadMessage(first)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("first payload is %q", got)
	}

	second, err := bob.WriteMessage([]byte("encrypted from here on"))
	if err != nil {
		t.Fatal(err)
	}
	got, err = alice.ReadMessage(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "encrypted from here on" {
		t.Errorf("second payload is %q", got)
	}
	// And that one really was encrypted, unlike the first.
	if bytes.Contains(second, []byte("encrypted from here on")) {
		t.Error("the second message's payload travelled in the clear")
	}
}

// TestTheNonceIsLittleEndianWithFourLeadingZeros pins the single most commonly
// mismatched detail between Noise implementations. Getting it wrong produces a
// handshake that completes and then cannot decrypt one transport message.
func TestTheNonceIsLittleEndianWithFourLeadingZeros(t *testing.T) {
	var state CipherState
	state.initializeKey([KeyLen]byte{})
	state.nonce = 1

	nonce := state.nonceBytes()
	want := []byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(nonce[:], want) {
		t.Errorf("nonce for counter 1 is %x, want %x", nonce, want)
	}

	state.nonce = 0x0102030405060708
	nonce = state.nonceBytes()
	want = []byte{0, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(nonce[:], want) {
		t.Errorf("nonce for a large counter is %x, want %x", nonce, want)
	}
}

// TestTheProtocolNameTakesThePaddingPath. The name is 31 bytes, one under the hash
// length, so it is zero-padded rather than hashed — worth pinning, because a port
// that assumed the other branch would derive different keys and the failure would
// look like a cipher bug.
func TestTheProtocolNameTakesThePaddingPath(t *testing.T) {
	if len(ProtocolName) > HashLen {
		t.Fatalf("the protocol name is now %d bytes, so it takes the hashing branch", len(ProtocolName))
	}

	state := newSymmetricState(ProtocolName)
	var want [HashLen]byte
	copy(want[:], ProtocolName)
	if state.hash != want {
		t.Errorf("initial hash is %x", state.hash)
	}
	if state.chainingKey != want {
		t.Error("the chaining key does not start equal to the hash")
	}
}

// TestHKDFChainsItsOutputs is Noise's particular HKDF shape: each output is the
// HMAC of the previous one with a counter byte appended.
func TestHKDFChainsItsOutputs(t *testing.T) {
	var chaining [HashLen]byte
	for i := range chaining {
		chaining[i] = byte(i)
	}

	two, err := hkdf(chaining, []byte("material"), 2)
	if err != nil {
		t.Fatal(err)
	}
	three, err := hkdf(chaining, []byte("material"), 3)
	if err != nil {
		t.Fatal(err)
	}

	// The first two outputs must not depend on how many were asked for.
	if two[0] != three[0] || two[1] != three[1] {
		t.Error("asking for a third output changed the first two")
	}
	if two[0] == two[1] {
		t.Error("the two outputs are identical")
	}
	if _, err := hkdf(chaining, nil, 4); err == nil {
		t.Error("four outputs was accepted")
	}
}

// TestRekeyChangesTheKeyWithoutAHandshake, since it is part of the state machine a
// port has to match even though the mesh's conversations never exhaust a nonce.
func TestRekeyChangesTheKeyWithoutAHandshake(t *testing.T) {
	var state CipherState
	var key [KeyLen]byte
	for i := range key {
		key[i] = byte(i)
	}
	state.initializeKey(key)

	if err := state.Rekey(); err != nil {
		t.Fatal(err)
	}
	if state.key == key {
		t.Error("rekey left the key unchanged")
	}

	var fresh CipherState
	if err := fresh.Rekey(); err == nil {
		t.Error("rekey without a key was accepted")
	}
}

func TestWipeClearsTransportKeys(t *testing.T) {
	alice, _, _ := handshake(t, nil)
	alice.Wipe()

	if alice.send.hasKey || alice.receive.hasKey {
		t.Error("a wiped transport still holds keys")
	}
	if _, err := alice.Encrypt(nil, []byte("x")); err != nil {
		t.Fatal(err)
	}
	// With no key, Noise passes the plaintext through — which is why a wiped
	// transport must not be used again, and why the mesh drops the session too.
}

// TestTranscriptIsReproducible is the cross-language conformance anchor.
//
// Given fixed static and ephemeral keys, the three messages and the final
// transcript hash are fully determined. These values were produced by this
// implementation — they are not official Noise vectors — and their job is to let a
// Kotlin or Swift port be checked against a fixture instead of against a
// probability.
func TestTranscriptIsReproducible(t *testing.T) {
	aliceStatic := fixedKeypair(t, 1)
	aliceEphemeral := fixedKeypair(t, 2)
	bobStatic := fixedKeypair(t, 100)
	bobEphemeral := fixedKeypair(t, 200)

	run := func() ([3][]byte, [HashLen]byte) {
		alice, err := NewHandshake(Config{
			Static: aliceStatic, Initiator: true,
			Prologue: []byte("gatecrash-conformance"), Ephemeral: &aliceEphemeral,
		})
		if err != nil {
			t.Fatal(err)
		}
		bob, err := NewHandshake(Config{
			Static:   bobStatic,
			Prologue: []byte("gatecrash-conformance"), Ephemeral: &bobEphemeral,
		})
		if err != nil {
			t.Fatal(err)
		}

		var messages [3][]byte
		messages[0], err = alice.WriteMessage([]byte("one"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bob.ReadMessage(messages[0]); err != nil {
			t.Fatal(err)
		}
		messages[1], err = bob.WriteMessage([]byte("two"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := alice.ReadMessage(messages[1]); err != nil {
			t.Fatal(err)
		}
		messages[2], err = alice.WriteMessage([]byte("three"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bob.ReadMessage(messages[2]); err != nil {
			t.Fatal(err)
		}
		return messages, bob.HandshakeHash()
	}

	first, firstHash := run()
	second, secondHash := run()

	for i := range first {
		if !bytes.Equal(first[i], second[i]) {
			t.Errorf("message %d is not reproducible", i+1)
		}
	}
	if firstHash != secondHash {
		t.Error("the transcript hash is not reproducible")
	}

	// Logged rather than asserted against a literal, so the fixture can be copied
	// into the Kotlin and Swift test suites from one place.
	t.Logf("message 1: %s", hex.EncodeToString(first[0]))
	t.Logf("message 2: %s", hex.EncodeToString(first[1]))
	t.Logf("message 3: %s", hex.EncodeToString(first[2]))
	t.Logf("handshake hash: %s", hex.EncodeToString(firstHash[:]))
}

func BenchmarkHandshake(b *testing.B) {
	static, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	peer, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		alice, _ := NewHandshake(Config{Static: static, Initiator: true})
		bob, _ := NewHandshake(Config{Static: peer})

		first, _ := alice.WriteMessage(nil)
		if _, err := bob.ReadMessage(first); err != nil {
			b.Fatal(err)
		}
		second, _ := bob.WriteMessage(nil)
		if _, err := alice.ReadMessage(second); err != nil {
			b.Fatal(err)
		}
		third, _ := alice.WriteMessage(nil)
		if _, err := bob.ReadMessage(third); err != nil {
			b.Fatal(err)
		}
	}
}
