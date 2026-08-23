package meshcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

const eventID = "SRYIIALUSUJ6AX6DLMN2LUWAZM"

func TestChannelRoundTrip(t *testing.T) {
	key := DeriveChannelKey(eventID, "#lost-and-found", "orange lanyard")

	sealed, err := key.Seal([]byte("blue shirt kid at the mixer desk"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := key.Open(sealed, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "blue shirt kid at the mixer desk" {
		t.Errorf("got %q", plaintext)
	}
}

// TestTwoPhonesDeriveTheSameChannelKey is the whole point of deriving the salt
// rather than randomising it: two phones with no way to talk to each other still
// end up in the same room.
func TestTwoPhonesDeriveTheSameChannelKey(t *testing.T) {
	a := DeriveChannelKey(eventID, "gate-3", "shared secret")
	b := DeriveChannelKey(eventID, "gate-3", "shared secret")

	if a.ID != b.ID {
		t.Errorf("channel ids differ: %s vs %s", a.ID, b.ID)
	}
	if !bytes.Equal(a.key[:], b.key[:]) {
		t.Error("keys differ, so the two phones are in different rooms")
	}
}

// TestChannelNamesAreForgiving. Two people typing "#Gate-3" and "gate-3" and
// silently ending up in different rooms is the most predictable failure here.
func TestChannelNamesAreForgiving(t *testing.T) {
	canonical := DeriveChannelKey(eventID, "gate-3", "pass")
	for _, written := range []string{"#gate-3", "  #Gate-3 ", "GATE-3", " gate-3"} {
		if DeriveChannelKey(eventID, written, "pass").ID != canonical.ID {
			t.Errorf("%q derived a different channel", written)
		}
	}
}

// TestAWrongPassphraseIsNotAnError, because in a crowd a phone hears far more
// frames than it can read and most of them are for channels it is not in.
func TestAWrongPassphraseIsNotAnError(t *testing.T) {
	right := DeriveChannelKey(eventID, "vip", "correct horse")
	wrong := DeriveChannelKey(eventID, "vip", "incorrect horse")

	sealed, err := right.Seal([]byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Open(sealed, nil); err != ErrNotForUs {
		t.Errorf("error is %v, want ErrNotForUs", err)
	}
}

// TestAChannelIsScopedToItsEvent. A frame captured at one festival must not open a
// channel at the next one, even with the same channel name and passphrase.
func TestAChannelIsScopedToItsEvent(t *testing.T) {
	first := DeriveChannelKey("EVENT-ONE", "afterparty", "same passphrase")
	second := DeriveChannelKey("EVENT-TWO", "afterparty", "same passphrase")

	if first.ID == second.ID {
		t.Fatal("the same channel id at two different events")
	}
	sealed, err := first.Seal([]byte("see you at the gate"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Open(sealed, nil); err == nil {
		t.Error("a frame from one event opened at another")
	}
}

// TestTheChannelIDDoesNotLeakTheName. If the id were a hash of the name, anybody
// listening could enumerate which channels exist at an event from a wordlist.
func TestTheChannelIDDoesNotLeakTheName(t *testing.T) {
	sameName := DeriveChannelKey(eventID, "staff", "passphrase one")
	alsoSameName := DeriveChannelKey(eventID, "staff", "passphrase two")

	if sameName.ID == alsoSameName.ID {
		t.Error("the channel id is determined by the name alone, so it can be guessed")
	}
}

// TestAdditionalDataIsAuthenticated. The mesh puts the frame header in the AAD, so
// somebody cannot take a valid ciphertext and re-broadcast it with a different
// channel id or a reset TTL.
func TestAdditionalDataIsAuthenticated(t *testing.T) {
	key := DeriveChannelKey(eventID, "general", "pass")
	sealed, err := key.Seal([]byte("body"), []byte("header-as-sent"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.Open(sealed, []byte("header-tampered")); err != ErrNotForUs {
		t.Errorf("a tampered header opened anyway: %v", err)
	}
}

func TestTruncatedCiphertextIsMalformedRatherThanAPanic(t *testing.T) {
	key := DeriveChannelKey(eventID, "general", "pass")
	if _, err := key.Open([]byte{1, 2, 3}, nil); err != ErrMalformed {
		t.Errorf("error is %v, want ErrMalformed", err)
	}
}

// TestDirectMessageRoundTrip: two phones that have never met a server.
func TestDirectMessageRoundTrip(t *testing.T) {
	alice, alicePub, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bob, bobPub, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	fromAlice, err := alice.Session(bobPub)
	if err != nil {
		t.Fatal(err)
	}
	fromBob, err := bob.Session(alicePub)
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := fromAlice.Seal([]byte("by the sound desk"), nil)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := fromBob.Open(sealed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "by the sound desk" {
		t.Errorf("got %q", plaintext)
	}

	// And the other direction, which uses the other key of the pair.
	back, err := fromBob.Seal([]byte("on my way"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := fromAlice.Open(back, nil); err != nil || string(got) != "on my way" {
		t.Errorf("reverse direction: %q, %v", got, err)
	}
}

// TestDirectionsAreSeparateKeys. With one shared key, an attacker can replay
// somebody's own message back at them and it authenticates.
func TestDirectionsAreSeparateKeys(t *testing.T) {
	alice, alicePub, _ := NewIdentity()
	bob, bobPub, _ := NewIdentity()

	fromAlice, err := alice.Session(bobPub)
	if err != nil {
		t.Fatal(err)
	}
	fromBob, err := bob.Session(alicePub)
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := fromAlice.Seal([]byte("reflect me"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Alice must not be able to open her own outgoing message as if it had arrived.
	if _, err := fromAlice.Open(sealed, nil); err == nil {
		t.Error("a message opened in the direction it was sent, so a replay authenticates")
	}
	if _, err := fromBob.Open(sealed, nil); err != nil {
		t.Fatal("and yet the peer could not open it either")
	}
}

// TestAThirdPartyCannotOpenADirectMessage, which is the one thing a DM has to do.
func TestAThirdPartyCannotOpenADirectMessage(t *testing.T) {
	alice, _, _ := NewIdentity()
	_, bobPub, _ := NewIdentity()
	eve, _, _ := NewIdentity()

	session, err := alice.Session(bobPub)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := session.Seal([]byte("private"), nil)
	if err != nil {
		t.Fatal(err)
	}

	eavesdrop, err := eve.Session(bobPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eavesdrop.Open(sealed, nil); err == nil {
		t.Fatal("a third party read a direct message")
	}
}

// TestADegeneratePublicKeyIsRefused. A peer sending a low-order point is trying to
// force a known shared secret, not making a transmission error.
func TestADegeneratePublicKeyIsRefused(t *testing.T) {
	alice, _, _ := NewIdentity()
	if _, err := alice.Session(PublicIdentity{}); err == nil {
		t.Error("an all-zero public key was accepted")
	}
}

// TestFingerprintsAreShortEnoughToReadOut. A fingerprint nobody will read aloud
// protects nobody.
func TestFingerprintsAreShortEnoughToReadOut(t *testing.T) {
	_, pub, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := pub.Fingerprint()
	if len(fingerprint) != 6 {
		t.Errorf("fingerprint %q is %d characters", fingerprint, len(fingerprint))
	}
	if strings.ToLower(fingerprint) != fingerprint {
		t.Errorf("fingerprint %q is not lower case, so it is harder to read out", fingerprint)
	}

	_, other, _ := NewIdentity()
	if other.Fingerprint() == fingerprint {
		t.Error("two identities share a fingerprint")
	}
}

// TestIdentitiesAreEphemeralAndUnlinkable. There is no account, so two identities
// minted moments apart must share nothing.
func TestIdentitiesAreEphemeralAndUnlinkable(t *testing.T) {
	_, first, _ := NewIdentity()
	_, second, _ := NewIdentity()

	if bytes.Equal(first.Verify, second.Verify) || first.Agree == second.Agree {
		t.Error("two ephemeral identities share key material")
	}
}

func TestWipeClearsKeyMaterial(t *testing.T) {
	identity, pub, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	session, err := identity.Session(pub)
	// Talking to yourself is a degenerate case but a valid X25519 operation.
	if err != nil {
		t.Fatal(err)
	}

	identity.Wipe()
	session.Wipe()

	if !allZero(identity.Agree[:]) || !allZero(identity.Sign) {
		t.Error("identity key material survived a wipe")
	}
	if !allZero(session.send[:]) || !allZero(session.receive[:]) {
		t.Error("session key material survived a wipe")
	}

	key := DeriveChannelKey(eventID, "x", "y")
	key.Wipe()
	if !allZero(key.key[:]) {
		t.Error("channel key material survived a wipe")
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// TestAnnouncementsAreSignedNotSecret. The property that matters is that nobody can
// invent "everybody leave the building".
func TestAnnouncementsAreSigned(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte("Gate 4 is now open")
	signature := SignAnnouncement(private, eventID, body)

	if !VerifyAnnouncement(public, eventID, body, signature) {
		t.Fatal("a valid announcement did not verify")
	}
	if VerifyAnnouncement(public, eventID, []byte("Gate 4 is now closed"), signature) {
		t.Error("a modified announcement verified")
	}

	// And it cannot be replayed at another event, which matters most for exactly the
	// messages somebody would want to replay.
	if VerifyAnnouncement(public, "ANOTHER-EVENT", body, signature) {
		t.Error("an announcement from one event verified at another")
	}

	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if VerifyAnnouncement(other, eventID, body, signature) {
		t.Error("an announcement verified against the wrong organizer key")
	}
}

func TestVerifyAnnouncementRejectsNonsenseInputs(t *testing.T) {
	if VerifyAnnouncement(nil, eventID, []byte("x"), nil) {
		t.Error("a nil key and signature verified")
	}
	if VerifyAnnouncement(make(ed25519.PublicKey, 3), eventID, []byte("x"), make([]byte, 64)) {
		t.Error("a short key verified")
	}
}

// TestFriendBeaconTokensRotate is the anti-stalking property. A constant
// identifier broadcast in a field is how early Bluetooth trackers became a
// stalking tool.
func TestFriendBeaconTokensRotate(t *testing.T) {
	key, err := NewBeaconKey()
	if err != nil {
		t.Fatal(err)
	}

	window := uint64(time.Date(2026, 8, 21, 20, 0, 0, 0, time.UTC).Unix() / 300)
	first := key.BeaconToken(window)
	second := key.BeaconToken(window + 1)

	if first == second {
		t.Error("the token did not change between windows, so somebody can be followed")
	}

	// The friend still recognises it, with a window either side of tolerance because
	// two phones disagree about the time by a second or two.
	if !key.MatchesBeacon(first, window) {
		t.Error("a friend did not recognise the current token")
	}
	if !key.MatchesBeacon(first, window+1) {
		t.Error("a friend did not recognise the previous window's token")
	}
	if key.MatchesBeacon(first, window+5) {
		t.Error("a token from five windows ago still matched")
	}

	other, _ := NewBeaconKey()
	if other.MatchesBeacon(first, window) {
		t.Error("a stranger's key matched somebody else's beacon")
	}
}

func TestChecksumCatchesAMisstitchedMessage(t *testing.T) {
	if Checksum([]byte("hello world")) == Checksum([]byte("hello worlds")) {
		t.Error("the checksum did not distinguish two different bodies")
	}
	if Checksum(nil) != Checksum([]byte{}) {
		t.Error("nil and empty disagree")
	}
}

// BenchmarkDeriveChannelKey is the number that decides whether the Argon2id
// parameters are usable. This runs on a phone while somebody stands in a queue, so
// the budget is a couple of hundred milliseconds on hardware several times slower
// than a laptop.
func BenchmarkDeriveChannelKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DeriveChannelKey(eventID, "gate-3", "orange lanyard")
	}
}

func BenchmarkChannelSeal(b *testing.B) {
	key := DeriveChannelKey(eventID, "gate-3", "orange lanyard")
	body := bytes.Repeat([]byte("x"), 160)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := key.Seal(body, nil); err != nil {
			b.Fatal(err)
		}
	}
}
