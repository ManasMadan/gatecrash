// Package meshcrypto is the encryption behind Backstage, the mesh chat.
//
// Three kinds of traffic, three different answers, because they have genuinely
// different threat models:
//
//   - Channels (#lost-and-found, #gate-3) are group chats where the group is
//     "whoever knows the passphrase". A symmetric key derived from that passphrase
//     with Argon2id, so a passphrase somebody can say out loud at a campsite is
//     still expensive to brute force from a captured frame.
//
//   - Direct messages are between two phones that have never met a server. X25519
//     to agree a key, ChaCha20-Poly1305 to use it. Identities are ephemeral per
//     event: there is no account, nothing to subpoena, and nothing that links this
//     festival to the next one.
//
//   - Announcements come from the organizer and must be unforgeable but not secret.
//     Ed25519 signatures over plaintext, verified against the key in the manifest
//     every phone already has. Encrypting them would be theatre — the point is that
//     nobody can invent "Gate 4 is now open".
//
// What this deliberately does not do is hide who is talking to whom. A BLE mesh
// broadcasts to everybody in range by construction, and a design that claimed
// otherwise would be lying. Contents are protected; the fact of a transmission is
// not, and §11 of the spec says so.
package meshcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Argon2id parameters for channel passphrases.
//
// These are the interactive-login numbers, not the disk-encryption ones, and the
// reason is the device: a five-year-old Android phone has to derive this while
// somebody stands in a queue, and a parameter set that takes four seconds there
// means the feature does not get used. 64 MiB and one pass lands around 100ms on a
// mid-range phone, which is fast enough to feel instant and still forces an
// attacker with a captured frame to spend 64 MiB per guess.
//
// The memory cost is the one that matters. Time cost can be bought with more cores;
// memory cost cannot be bought at all on a GPU, which is what turns a guessable
// passphrase like "backstage" from seconds of cracking into weeks.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = chacha20poly1305.KeySize
)

// A channel's salt is derived from the event and the channel name rather than being
// random.
//
// This is a real trade and it goes the other way from a password database. A random
// salt would have to travel with every frame, which at ~200 bytes a frame is
// expensive, and worse, two phones that both know the passphrase could not derive
// the same key without first exchanging the salt — which is exactly the
// coordination a mesh with no infrastructure cannot do. Deriving it means anybody
// who knows the event and the channel name can start guessing passphrases offline,
// so the Argon2id cost is what carries the security rather than the salt.
const saltPrefix = "gatecrash-mesh-channel-v1"

// ChannelKey is the symmetric key for one channel of one event.
type ChannelKey struct {
	key [chacha20poly1305.KeySize]byte

	// ID is a public, non-secret identifier for the channel, carried in the clear
	// in every frame so a phone knows which key to try without trying all of them.
	//
	// Derived from the key, so it cannot be used to guess the passphrase, and short
	// because it is on the wire.
	ID ChannelID
}

// ChannelID identifies a channel on the wire.
//
// Four bytes. Long enough that channels at one event do not collide by accident,
// short enough to sit in a frame that has 200 bytes total. A deliberate collision
// costs an attacker nothing and gains them nothing: they still cannot decrypt.
type ChannelID [4]byte

// String renders a channel id for logs and for the UI's "you are in #x" line.
func (id ChannelID) String() string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id[:]))
}

// DeriveChannelKey turns a passphrase into a channel key.
//
// Slow on purpose. Callers should do this once when somebody joins a channel and
// keep the result; doing it per message would make the app unusable and is the
// mistake this comment exists to prevent.
func DeriveChannelKey(eventID, channel, passphrase string) ChannelKey {
	salt := sha256.Sum256([]byte(saltPrefix + "\x00" + eventID + "\x00" + normalizeChannel(channel)))

	raw := argon2.IDKey(
		[]byte(passphrase),
		salt[:],
		argonTime,
		argonMemory,
		argonThreads,
		argonKeyLen,
	)

	var out ChannelKey
	copy(out.key[:], raw)

	// The id is a hash of the key rather than of the passphrase or the name. Of the
	// name would leak which channels exist at an event to anybody listening; of the
	// passphrase would hand an attacker an oracle to test guesses against without
	// paying the Argon2id cost.
	sum := sha256.Sum256(append([]byte("gatecrash-mesh-channel-id-v1\x00"), out.key[:]...))
	copy(out.ID[:], sum[:])
	return out
}

// normalizeChannel makes "#Gate-3", "gate-3" and " GATE-3 " the same channel.
//
// Two people typing the same channel name slightly differently and silently ending
// up in different rooms is the most predictable failure this feature has.
func normalizeChannel(name string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), "#")))
}

// Seal encrypts a message for a channel.
//
// The nonce is random and travels with the ciphertext. Random rather than a
// counter, because a counter needs state that survives an app restart and two
// phones in the same channel have no way to coordinate counters — a repeated nonce
// with the same key is the one mistake that breaks ChaCha20-Poly1305 completely.
// At 96 bits, random is safe well past any number of messages a festival produces.
func (k ChannelKey) Seal(plaintext, additional []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(k.key[:])
	if err != nil {
		return nil, fmt.Errorf("meshcrypto: channel cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("meshcrypto: nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, additional), nil
}

// Open decrypts a channel message.
//
// A failure here is the normal case rather than an error worth surfacing: every
// phone in range hears every frame, and most of them are for channels it is not in.
func (k ChannelKey) Open(sealed, additional []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(k.key[:])
	if err != nil {
		return nil, fmt.Errorf("meshcrypto: channel cipher: %w", err)
	}
	if len(sealed) < aead.NonceSize() {
		return nil, ErrMalformed
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, additional)
	if err != nil {
		return nil, ErrNotForUs
	}
	return plaintext, nil
}

// Wipe overwrites the key material.
//
// Part of the panic wipe. Go's garbage collector may already have copied this
// somewhere unreachable, so it is a best effort rather than a guarantee, and
// pretending otherwise would be the kind of security claim this project does not
// make.
func (k *ChannelKey) Wipe() {
	for i := range k.key {
		k.key[i] = 0
	}
	k.ID = ChannelID{}
}

// ErrNotForUs means the frame did not decrypt.
//
// Expected, constantly. In a crowd a phone hears far more frames than it can read,
// and treating this as an error to report would fill a log with the normal
// operation of the protocol.
var ErrNotForUs = errors.New("meshcrypto: not for us")

// ErrMalformed means the frame was too short to be a frame.
var ErrMalformed = errors.New("meshcrypto: malformed ciphertext")

// Identity is one phone's ephemeral identity for one event.
//
// Ephemeral is the whole point. There is no account, no phone number, no handle
// that survives the night. Two people who talked at one festival cannot be linked
// at the next one, and a phone that is lost or seized carries nothing that
// identifies its owner or anybody they spoke to.
//
// The signing key and the agreement key are separate. Using one key for both
// signing and Diffie-Hellman is a well-known way to weaken both, and the second key
// costs 32 bytes.
type Identity struct {
	// Sign proves that a message came from this identity within one event.
	Sign ed25519.PrivateKey

	// Agree is the X25519 private key for direct messages.
	Agree [32]byte
}

// PublicIdentity is what an identity looks like to everybody else.
type PublicIdentity struct {
	Verify ed25519.PublicKey `json:"verify"`
	Agree  [32]byte          `json:"agree"`
}

// NewIdentity mints an ephemeral identity.
func NewIdentity() (Identity, PublicIdentity, error) {
	verify, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, PublicIdentity{}, fmt.Errorf("meshcrypto: signing key: %w", err)
	}

	var agree [32]byte
	if _, err := io.ReadFull(rand.Reader, agree[:]); err != nil {
		return Identity{}, PublicIdentity{}, fmt.Errorf("meshcrypto: agreement key: %w", err)
	}
	// Clamping is done inside curve25519.X25519, so the raw bytes are kept as
	// generated. Doing it here as well would be harmless and misleading.

	public, err := curve25519.X25519(agree[:], curve25519.Basepoint)
	if err != nil {
		return Identity{}, PublicIdentity{}, fmt.Errorf("meshcrypto: agreement public key: %w", err)
	}

	out := PublicIdentity{Verify: verify}
	copy(out.Agree[:], public)
	return Identity{Sign: sign, Agree: agree}, out, nil
}

// Wipe overwrites an identity's key material. Best effort, same caveat as
// ChannelKey.Wipe.
func (i *Identity) Wipe() {
	for j := range i.Sign {
		i.Sign[j] = 0
	}
	for j := range i.Agree {
		i.Agree[j] = 0
	}
}

// Fingerprint is the short, human-comparable form of a public identity.
//
// This is what two people read out to each other to confirm they are talking to
// the person in front of them rather than to somebody relaying. Six characters,
// because a fingerprint nobody will read out loud protects nobody, and the mesh's
// threat model here is a casual impersonator in the same field rather than a
// state-level attacker grinding collisions.
func (p PublicIdentity) Fingerprint() string {
	sum := sha256.Sum256(append(append([]byte("gatecrash-mesh-identity-v1\x00"), p.Verify...), p.Agree[:]...))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:4]))[:6]
}

// SessionKey is a shared key between two identities, for direct messages.
type SessionKey struct {
	send    [chacha20poly1305.KeySize]byte
	receive [chacha20poly1305.KeySize]byte
}

// Session derives the pair of keys for talking to a peer.
//
// Two keys rather than one, split by direction. With a single shared key, a frame
// this phone sent is indistinguishable from one it received, so an attacker can
// replay somebody's own message back at them and it authenticates. Splitting the
// directions makes that impossible for free.
//
// The direction each phone calls "send" is decided by comparing the two public
// keys, which is the only ordering both sides can agree on without talking.
func (i Identity) Session(peer PublicIdentity) (SessionKey, error) {
	shared, err := curve25519.X25519(i.Agree[:], peer.Agree[:])
	if err != nil {
		return SessionKey{}, fmt.Errorf("meshcrypto: agreement failed: %w", err)
	}

	// A shared secret of all zeroes means the peer sent a low-order point, which is
	// an attempt to force a known key rather than a transmission error.
	var zero [32]byte
	if subtle.ConstantTimeCompare(shared, zero[:]) == 1 {
		return SessionKey{}, errors.New("meshcrypto: peer sent a degenerate public key")
	}

	mine, err := curve25519.X25519(i.Agree[:], curve25519.Basepoint)
	if err != nil {
		return SessionKey{}, fmt.Errorf("meshcrypto: own public key: %w", err)
	}

	// The transcript binds both public keys into the derivation, so a shared secret
	// alone is not enough to derive the session — this is what stops an unknown
	// key-share attack, where somebody convinces two people they are talking to
	// them rather than to each other.
	weAreLow := compare(mine, peer.Agree[:]) < 0
	low, high := mine, peer.Agree[:]
	if !weAreLow {
		low, high = peer.Agree[:], mine
	}

	transcript := make([]byte, 0, 64)
	transcript = append(transcript, low...)
	transcript = append(transcript, high...)

	var out SessionKey
	if err := expand(shared, transcript, "gatecrash-mesh-dm-v1 low-to-high", keyOf(&out, weAreLow)); err != nil {
		return SessionKey{}, err
	}
	if err := expand(shared, transcript, "gatecrash-mesh-dm-v1 high-to-low", keyOf(&out, !weAreLow)); err != nil {
		return SessionKey{}, err
	}
	return out, nil
}

// keyOf picks which of the two directional keys a label fills, so the caller reads
// as two symmetric lines instead of an if/else that is easy to get backwards.
func keyOf(session *SessionKey, sending bool) []byte {
	if sending {
		return session.send[:]
	}
	return session.receive[:]
}

func expand(shared, transcript []byte, label string, out []byte) error {
	reader := hkdf.New(sha256.New, shared, transcript, []byte(label))
	if _, err := io.ReadFull(reader, out); err != nil {
		return fmt.Errorf("meshcrypto: deriving %s: %w", label, err)
	}
	return nil
}

// compare is a plain lexicographic comparison of two public keys.
//
// Not constant time, and it does not need to be: both inputs are public keys that
// were broadcast to a field full of people.
func compare(a, b []byte) int {
	for i := range a {
		if i >= len(b) {
			return 1
		}
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	return 0
}

// Seal encrypts a direct message to the peer this session was derived with.
func (s SessionKey) Seal(plaintext, additional []byte) ([]byte, error) {
	return sealWith(s.send[:], plaintext, additional)
}

// Open decrypts a direct message from that peer.
func (s SessionKey) Open(sealed, additional []byte) ([]byte, error) {
	return openWith(s.receive[:], sealed, additional)
}

// Wipe overwrites a session's keys.
func (s *SessionKey) Wipe() {
	for i := range s.send {
		s.send[i] = 0
	}
	for i := range s.receive {
		s.receive[i] = 0
	}
}

func sealWith(key, plaintext, additional []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("meshcrypto: cipher: %w", err)
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("meshcrypto: nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, additional), nil
}

func openWith(key, sealed, additional []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("meshcrypto: cipher: %w", err)
	}
	if len(sealed) < aead.NonceSize() {
		return nil, ErrMalformed
	}
	plaintext, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], additional)
	if err != nil {
		return nil, ErrNotForUs
	}
	return plaintext, nil
}

// SignAnnouncement signs an organizer announcement.
//
// Signed and not encrypted, deliberately. "Gate 4 is now open" is not a secret; the
// property that matters is that nobody else can say it. Encrypting it would mean
// distributing a key to twenty thousand phones, which is the same as not having a
// key.
func SignAnnouncement(key ed25519.PrivateKey, eventID string, body []byte) []byte {
	return ed25519.Sign(key, announcementTranscript(eventID, body))
}

// VerifyAnnouncement checks an announcement against the organizer key every phone
// already has from the manifest.
func VerifyAnnouncement(key ed25519.PublicKey, eventID string, body, signature []byte) bool {
	if len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(key, announcementTranscript(eventID, body), signature)
}

// announcementTranscript binds a signature to one event.
//
// Without the event id, an announcement signed at one event could be replayed at
// another by anybody who kept the frame — and "everybody leave the building" is
// exactly the message somebody would want to replay.
func announcementTranscript(eventID string, body []byte) []byte {
	out := make([]byte, 0, len(eventID)+len(body)+40)
	out = append(out, "gatecrash-mesh-announcement-v1\x00"...)
	out = append(out, eventID...)
	out = append(out, 0)
	return append(out, body...)
}

// BeaconKey is the shared secret behind the friend finder.
//
// Two people who want to find each other in a crowd exchange this once, in person
// or over an already-established direct message. After that each phone broadcasts a
// rotating token derived from it, and the other recognises the token without
// anybody else being able to tell who is looking for whom.
type BeaconKey [32]byte

// NewBeaconKey mints a beacon key.
func NewBeaconKey() (BeaconKey, error) {
	var out BeaconKey
	if _, err := io.ReadFull(rand.Reader, out[:]); err != nil {
		return out, fmt.Errorf("meshcrypto: beacon key: %w", err)
	}
	return out, nil
}

// BeaconToken is the rotating value a phone advertises for one friend.
//
// It rotates every window so that somebody who is not the friend cannot follow a
// person around a festival by tracking a constant identifier — which is the exact
// privacy failure that made early Bluetooth trackers a stalking tool.
//
// Four bytes, because it rides in a BLE advertisement where there are barely a
// couple of dozen bytes to spend.
func (k BeaconKey) BeaconToken(window uint64) [4]byte {
	var counter [8]byte
	for i := 7; i >= 0; i-- {
		counter[i] = byte(window)
		window >>= 8
	}
	sum := sha256.Sum256(append(append([]byte("gatecrash-mesh-beacon-v1\x00"), k[:]...), counter[:]...))

	var out [4]byte
	copy(out[:], sum[:])
	return out
}

// MatchesBeacon reports whether a token belongs to this friend, allowing one window
// either side.
//
// The tolerance is for the same reason the rotating ticket code has one: two phones
// disagree about the time by a second or two, and a friend finder that stops
// working on the boundary of every window is a friend finder nobody trusts.
func (k BeaconKey) MatchesBeacon(token [4]byte, window uint64) bool {
	for _, candidate := range []uint64{window, window - 1, window + 1} {
		expected := k.BeaconToken(candidate)
		if subtle.ConstantTimeCompare(token[:], expected[:]) == 1 {
			return true
		}
	}
	return false
}

// Checksum is the CRC32 of a frame body, used by the fragment reassembler to notice
// a message that was stitched together wrongly.
//
// A CRC and not a MAC: the authenticity of the contents is already covered by
// Poly1305, and this is only there to catch a reassembly bug or a corrupted radio
// frame before the AEAD wastes time on it.
func Checksum(body []byte) uint32 {
	return crc32.ChecksumIEEE(body)
}
