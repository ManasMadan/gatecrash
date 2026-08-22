// Package noise implements the Noise XX handshake, by hand.
//
// Noise_XX_25519_ChaChaPoly_SHA256, following the Noise Protocol Framework
// revision 34. Written out rather than taken from a library for a reason that is
// specific to this project: the same handshake has to exist three times — here in
// Go for the box, in Kotlin for the Android app and in Swift for the iOS one — and
// three ports of one 400-line state machine that agrees byte for byte is a far more
// tractable problem than three different libraries that each almost agree.
//
// # Why XX
//
// XX is the pattern where neither side knows the other's static key in advance.
// That is exactly the mesh's situation: two phones in a crowd have never met, there
// is no directory, no server, and no certificate authority they both trust. XX also
// gives the property that matters most in a field full of strangers — the
// responder's static key is sent encrypted, so somebody sitting in the crowd
// logging every frame cannot build a list of who was present.
//
//	-> e
//	<- e, ee, s, es
//	-> s, se
//
// Three messages, and the initiator's static key is only revealed in the third,
// after the responder has proven it can decrypt. What XX does not give is identity
// binding to anything outside the handshake: it proves the peer holds the private
// key for the static it presented, and nothing about who that is. That is what the
// out-of-band fingerprint comparison in meshcrypto is for.
//
// # What this is for
//
// Direct messages between two phones. Channels use a passphrase-derived symmetric
// key (see meshcrypto) because a group chat of strangers has no pairwise handshake
// to do, and announcements are signed rather than encrypted. This is the pairwise
// case, and it is the one where forward secrecy is worth three round trips: a phone
// seized after the event cannot decrypt what it said during it, because the
// ephemeral keys are gone.
package noise

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// ProtocolName identifies the exact cryptographic choices.
//
// It is mixed into the handshake hash as the very first act, which is what makes
// two implementations that disagree about any of it fail immediately and loudly
// rather than producing keys that almost match.
const ProtocolName = "Noise_XX_25519_ChaChaPoly_SHA256"

// DHLen, HashLen and KeyLen are the sizes the pattern above is written against.
const (
	DHLen   = 32
	HashLen = 32
	KeyLen  = chacha20poly1305.KeySize

	// TagLen is the Poly1305 authentication tag appended to every encrypted field.
	TagLen = 16
)

// Message sizes, which are fixed for XX with an empty payload.
//
// Stated as constants because they are the cheapest possible conformance check for
// a port: an implementation that produces a 97-byte second message has a bug, and
// finding that here beats finding it as "decryption failed" on a phone.
const (
	// Message1Size is the initiator's ephemeral public key, in the clear.
	Message1Size = DHLen

	// Message2Size is the responder's ephemeral key, then its static key and the
	// payload, both encrypted and tagged.
	Message2Size = DHLen + (DHLen + TagLen) + TagLen

	// Message3Size is the initiator's static key and the payload, both encrypted.
	Message3Size = (DHLen + TagLen) + TagLen
)

// Errors the handshake can return.
//
// These are all normal in a mesh: a frame arrives from a phone that is mid-way
// through a handshake with somebody else, or an attacker replays a message, or two
// phones start a handshake with each other simultaneously.
var (
	ErrWrongTurn   = errors.New("noise: not this side's turn to speak")
	ErrDone        = errors.New("noise: handshake is already finished")
	ErrShort       = errors.New("noise: message is too short for the pattern")
	ErrAuth        = errors.New("noise: authentication failed")
	ErrNonceLimit  = errors.New("noise: nonce exhausted, rekey required")
	ErrNoStatic    = errors.New("noise: a static key is required for this pattern")
	ErrDegenerate  = errors.New("noise: peer sent a degenerate public key")
	ErrNotFinished = errors.New("noise: handshake is not finished")
)

// Keypair is a Curve25519 key pair.
type Keypair struct {
	Private [DHLen]byte
	Public  [DHLen]byte
}

// GenerateKeypair mints a Curve25519 key pair.
func GenerateKeypair() (Keypair, error) {
	var pair Keypair
	if _, err := io.ReadFull(rand.Reader, pair.Private[:]); err != nil {
		return Keypair{}, fmt.Errorf("noise: generating a key: %w", err)
	}
	public, err := curve25519.X25519(pair.Private[:], curve25519.Basepoint)
	if err != nil {
		return Keypair{}, fmt.Errorf("noise: deriving a public key: %w", err)
	}
	copy(pair.Public[:], public)
	return pair, nil
}

// KeypairFrom rebuilds a key pair from stored private bytes, for a phone that keeps
// one static identity for the length of an event.
func KeypairFrom(private [DHLen]byte) (Keypair, error) {
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return Keypair{}, fmt.Errorf("noise: deriving a public key: %w", err)
	}
	pair := Keypair{Private: private}
	copy(pair.Public[:], public)
	return pair, nil
}

// dh is the Diffie-Hellman function, with the one check the Noise spec leaves as
// optional and this uses anyway.
//
// X25519 returns an all-zero shared secret when the peer supplies a low-order
// point. Noise permits ignoring that, on the grounds that the transcript hash
// catches the resulting mismatch. Rejecting it outright is cheap and turns a
// deliberate attempt to force a known key into an error at the point it happens,
// which is a better thing to see in a log than "authentication failed".
func dh(private, public [DHLen]byte) ([DHLen]byte, error) {
	shared, err := curve25519.X25519(private[:], public[:])
	if err != nil {
		return [DHLen]byte{}, ErrDegenerate
	}

	var zero [DHLen]byte
	if subtle.ConstantTimeCompare(shared, zero[:]) == 1 {
		return [DHLen]byte{}, ErrDegenerate
	}

	var out [DHLen]byte
	copy(out[:], shared)
	return out, nil
}

// hkdf is Noise's HKDF: one extract and two or three expands.
//
// Written out rather than using x/crypto/hkdf because Noise's variant is a
// particular shape — the chaining key is the salt, the input material is the
// message, and the outputs are chained through each other — and the explicit form
// is what a port can be checked against line by line.
func hkdf(chainingKey [HashLen]byte, material []byte, outputs int) ([3][HashLen]byte, error) {
	if outputs < 2 || outputs > 3 {
		return [3][HashLen]byte{}, fmt.Errorf("noise: hkdf wants 2 or 3 outputs, got %d", outputs)
	}

	temp := hmacSHA256(chainingKey[:], material)

	var out [3][HashLen]byte
	out[0] = hmacSHA256(temp[:], []byte{0x01})
	out[1] = hmacSHA256(temp[:], append(out[0][:], 0x02))
	if outputs == 3 {
		out[2] = hmacSHA256(temp[:], append(out[1][:], 0x03))
	}
	return out, nil
}

func hmacSHA256(key, data []byte) [HashLen]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	var out [HashLen]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// CipherState is one direction of an encrypted channel: a key and a counter.
type CipherState struct {
	key    [KeyLen]byte
	nonce  uint64
	hasKey bool
}

// maxNonce is the point at which a key must not be used again.
//
// ChaCha20-Poly1305 with a 64-bit counter is safe to 2^64-1 messages. The spec
// reserves the maximum value, so the ceiling is one below it. No mesh conversation
// will ever come close; the check exists so that if something ever loops, it fails
// closed instead of reusing a nonce, which is the one mistake that breaks this
// cipher completely.
const maxNonce = ^uint64(0) - 1

func (c *CipherState) initializeKey(key [KeyLen]byte) {
	c.key = key
	c.nonce = 0
	c.hasKey = true
}

// HasKey reports whether this state can encrypt yet. During the first handshake
// message there is no key, and the payload travels in the clear — which is the
// pattern, not an oversight.
func (c *CipherState) HasKey() bool { return c.hasKey }

// Nonce is the message counter, exposed for the replay window in the transport.
func (c *CipherState) Nonce() uint64 { return c.nonce }

// nonceBytes lays the counter out the way ChaChaPoly wants it in Noise: four zero
// bytes, then the counter little-endian.
//
// This is the single most commonly mismatched detail between Noise
// implementations. Big-endian here, or the zeros at the wrong end, produces a
// handshake that completes and then cannot decrypt a single transport message.
func (c *CipherState) nonceBytes() [chacha20poly1305.NonceSize]byte {
	var out [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(out[4:], c.nonce)
	return out
}

// EncryptWithAd encrypts and advances the counter.
//
// With no key set this returns the plaintext unchanged, which is what Noise
// specifies and what makes the first handshake message work.
func (c *CipherState) EncryptWithAd(additional, plaintext []byte) ([]byte, error) {
	if !c.hasKey {
		return append([]byte(nil), plaintext...), nil
	}
	if c.nonce > maxNonce {
		return nil, ErrNonceLimit
	}

	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return nil, fmt.Errorf("noise: cipher: %w", err)
	}
	nonce := c.nonceBytes()
	out := aead.Seal(nil, nonce[:], plaintext, additional)
	c.nonce++
	return out, nil
}

// DecryptWithAd decrypts and advances the counter.
//
// The counter only advances on success. A failed decryption must not consume a
// nonce, or one injected junk frame would desynchronise the two sides for good —
// which is a trivial denial of service on a medium where anybody can transmit.
func (c *CipherState) DecryptWithAd(additional, ciphertext []byte) ([]byte, error) {
	if !c.hasKey {
		return append([]byte(nil), ciphertext...), nil
	}
	if c.nonce > maxNonce {
		return nil, ErrNonceLimit
	}

	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return nil, fmt.Errorf("noise: cipher: %w", err)
	}
	nonce := c.nonceBytes()
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, additional)
	if err != nil {
		return nil, ErrAuth
	}
	c.nonce++
	return plaintext, nil
}

// Rekey replaces the key with one derived from itself, without another handshake.
//
// Noise's rekey. Not used on the mesh's hot path — conversations there are far too
// short to exhaust a nonce — but it is part of the state machine and leaving it out
// would mean a port of this had nothing to check against.
func (c *CipherState) Rekey() error {
	if !c.hasKey {
		return errors.New("noise: cannot rekey without a key")
	}
	var zeros [KeyLen]byte
	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return fmt.Errorf("noise: cipher: %w", err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	for i := range nonce {
		nonce[i] = 0xff
	}
	out := aead.Seal(nil, nonce[:], zeros[:], nil)
	copy(c.key[:], out[:KeyLen])
	return nil
}

// Wipe overwrites the key. Best effort — Go may have copied it — and stated as such
// rather than promised.
func (c *CipherState) Wipe() {
	for i := range c.key {
		c.key[i] = 0
	}
	c.hasKey = false
}

// symmetricState is the handshake's running hash and chaining key.
type symmetricState struct {
	cipher      CipherState
	chainingKey [HashLen]byte
	hash        [HashLen]byte
}

func newSymmetricState(protocolName string) symmetricState {
	var state symmetricState

	// The protocol name seeds the hash. Shorter than the hash gets zero-padded;
	// longer gets hashed. Both branches exist in the spec and the name used here
	// happens to be exactly 31 bytes, so it takes the padding path — which is worth
	// knowing when checking a port that assumed the other branch.
	if len(protocolName) <= HashLen {
		copy(state.hash[:], protocolName)
	} else {
		state.hash = sha256.Sum256([]byte(protocolName))
	}
	state.chainingKey = state.hash
	return state
}

func (s *symmetricState) mixHash(data []byte) {
	h := sha256.New()
	h.Write(s.hash[:])
	h.Write(data)
	copy(s.hash[:], h.Sum(nil))
}

func (s *symmetricState) mixKey(material []byte) error {
	out, err := hkdf(s.chainingKey, material, 2)
	if err != nil {
		return err
	}
	s.chainingKey = out[0]

	var key [KeyLen]byte
	copy(key[:], out[1][:])
	s.cipher.initializeKey(key)
	return nil
}

// encryptAndHash encrypts a field and folds the ciphertext into the transcript.
//
// Folding in the ciphertext rather than the plaintext is what binds every byte
// either side actually sent, so a man in the middle who alters anything at all
// ends up with a different hash and cannot complete the handshake.
func (s *symmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	ciphertext, err := s.cipher.EncryptWithAd(s.hash[:], plaintext)
	if err != nil {
		return nil, err
	}
	s.mixHash(ciphertext)
	return ciphertext, nil
}

func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := s.cipher.DecryptWithAd(s.hash[:], ciphertext)
	if err != nil {
		return nil, err
	}
	s.mixHash(ciphertext)
	return plaintext, nil
}

// split produces the two transport keys, one per direction.
func (s *symmetricState) split() (CipherState, CipherState, error) {
	out, err := hkdf(s.chainingKey, nil, 2)
	if err != nil {
		return CipherState{}, CipherState{}, err
	}

	var first, second CipherState
	var k1, k2 [KeyLen]byte
	copy(k1[:], out[0][:])
	copy(k2[:], out[1][:])
	first.initializeKey(k1)
	second.initializeKey(k2)
	return first, second, nil
}

// Handshake is one side of an XX handshake in progress.
type Handshake struct {
	symmetric symmetricState

	static    Keypair
	ephemeral Keypair

	remoteStatic    [DHLen]byte
	remoteEphemeral [DHLen]byte
	hasRemoteStatic bool

	initiator bool
	step      int
	done      bool
}

// Config configures a handshake.
type Config struct {
	// Static is this side's long-term key for the event. Required: XX authenticates
	// both sides.
	Static Keypair

	// Initiator is true for the side that speaks first.
	Initiator bool

	// Prologue is data both sides must agree on, mixed into the transcript before
	// anything else.
	//
	// The mesh puts the event id here. Two phones at different events then cannot
	// complete a handshake at all, which is a cleaner failure than completing one
	// and finding out later, and it costs nothing on the wire because the prologue
	// is never transmitted.
	Prologue []byte

	// Ephemeral overrides ephemeral key generation. Only for tests and for the
	// cross-language conformance fixture, where the whole point is a transcript that
	// reproduces byte for byte.
	Ephemeral *Keypair
}

// NewHandshake starts a handshake.
func NewHandshake(cfg Config) (*Handshake, error) {
	var empty [DHLen]byte
	if cfg.Static.Public == empty {
		return nil, ErrNoStatic
	}

	h := &Handshake{
		symmetric: newSymmetricState(ProtocolName),
		static:    cfg.Static,
		initiator: cfg.Initiator,
	}
	h.symmetric.mixHash(cfg.Prologue)

	if cfg.Ephemeral != nil {
		h.ephemeral = *cfg.Ephemeral
	} else {
		pair, err := GenerateKeypair()
		if err != nil {
			return nil, err
		}
		h.ephemeral = pair
	}
	return h, nil
}

// WriteMessage produces the next handshake message.
//
// The payload is encrypted where the pattern allows it. In the first message there
// is no key yet, so a payload there is in the clear — the mesh sends nothing in it
// for that reason.
func (h *Handshake) WriteMessage(payload []byte) ([]byte, error) {
	if h.done {
		return nil, ErrDone
	}
	if h.turn() != h.initiator {
		return nil, ErrWrongTurn
	}

	switch h.step {
	case 0:
		return h.writeMessage1(payload)
	case 1:
		return h.writeMessage2(payload)
	case 2:
		return h.writeMessage3(payload)
	default:
		return nil, ErrDone
	}
}

// ReadMessage consumes a handshake message and returns its payload.
func (h *Handshake) ReadMessage(message []byte) ([]byte, error) {
	if h.done {
		return nil, ErrDone
	}
	if h.turn() == h.initiator {
		return nil, ErrWrongTurn
	}

	switch h.step {
	case 0:
		return h.readMessage1(message)
	case 1:
		return h.readMessage2(message)
	case 2:
		return h.readMessage3(message)
	default:
		return nil, ErrDone
	}
}

// turn reports whether it is the initiator's turn. Messages 1 and 3 are the
// initiator's, message 2 is the responder's.
func (h *Handshake) turn() bool { return h.step%2 == 0 }

// -> e
func (h *Handshake) writeMessage1(payload []byte) ([]byte, error) {
	h.symmetric.mixHash(h.ephemeral.Public[:])

	body, err := h.symmetric.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}

	h.step = 1
	return append(append([]byte(nil), h.ephemeral.Public[:]...), body...), nil
}

func (h *Handshake) readMessage1(message []byte) ([]byte, error) {
	if len(message) < DHLen {
		return nil, ErrShort
	}
	copy(h.remoteEphemeral[:], message[:DHLen])
	h.symmetric.mixHash(h.remoteEphemeral[:])

	payload, err := h.symmetric.decryptAndHash(message[DHLen:])
	if err != nil {
		return nil, err
	}

	h.step = 1
	return payload, nil
}

// <- e, ee, s, es
func (h *Handshake) writeMessage2(payload []byte) ([]byte, error) {
	h.symmetric.mixHash(h.ephemeral.Public[:])

	shared, err := dh(h.ephemeral.Private, h.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	if err := h.symmetric.mixKey(shared[:]); err != nil {
		return nil, err
	}

	// The responder's static key goes out encrypted. This is the property that
	// makes XX the right pattern for a crowd: somebody logging every frame in the
	// field cannot build a list of which devices were present.
	staticField, err := h.symmetric.encryptAndHash(h.static.Public[:])
	if err != nil {
		return nil, err
	}

	shared, err = dh(h.static.Private, h.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	if err := h.symmetric.mixKey(shared[:]); err != nil {
		return nil, err
	}

	body, err := h.symmetric.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}

	h.step = 2
	out := make([]byte, 0, DHLen+len(staticField)+len(body))
	out = append(out, h.ephemeral.Public[:]...)
	out = append(out, staticField...)
	out = append(out, body...)
	return out, nil
}

func (h *Handshake) readMessage2(message []byte) ([]byte, error) {
	if len(message) < DHLen+DHLen+TagLen {
		return nil, ErrShort
	}

	copy(h.remoteEphemeral[:], message[:DHLen])
	h.symmetric.mixHash(h.remoteEphemeral[:])

	shared, err := dh(h.ephemeral.Private, h.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	if err := h.symmetric.mixKey(shared[:]); err != nil {
		return nil, err
	}

	staticField := message[DHLen : DHLen+DHLen+TagLen]
	remoteStatic, err := h.symmetric.decryptAndHash(staticField)
	if err != nil {
		return nil, err
	}
	if len(remoteStatic) != DHLen {
		return nil, ErrShort
	}
	copy(h.remoteStatic[:], remoteStatic)
	h.hasRemoteStatic = true

	shared, err = dh(h.ephemeral.Private, h.remoteStatic)
	if err != nil {
		return nil, err
	}
	if err := h.symmetric.mixKey(shared[:]); err != nil {
		return nil, err
	}

	payload, err := h.symmetric.decryptAndHash(message[DHLen+DHLen+TagLen:])
	if err != nil {
		return nil, err
	}

	h.step = 2
	return payload, nil
}

// -> s, se
func (h *Handshake) writeMessage3(payload []byte) ([]byte, error) {
	staticField, err := h.symmetric.encryptAndHash(h.static.Public[:])
	if err != nil {
		return nil, err
	}

	shared, err := dh(h.static.Private, h.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	if err := h.symmetric.mixKey(shared[:]); err != nil {
		return nil, err
	}

	body, err := h.symmetric.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}

	h.step = 3
	h.done = true
	return append(staticField, body...), nil
}

func (h *Handshake) readMessage3(message []byte) ([]byte, error) {
	if len(message) < DHLen+TagLen {
		return nil, ErrShort
	}

	remoteStatic, err := h.symmetric.decryptAndHash(message[:DHLen+TagLen])
	if err != nil {
		return nil, err
	}
	if len(remoteStatic) != DHLen {
		return nil, ErrShort
	}
	copy(h.remoteStatic[:], remoteStatic)
	h.hasRemoteStatic = true

	shared, err := dh(h.ephemeral.Private, h.remoteStatic)
	if err != nil {
		return nil, err
	}
	if err := h.symmetric.mixKey(shared[:]); err != nil {
		return nil, err
	}

	payload, err := h.symmetric.decryptAndHash(message[DHLen+TagLen:])
	if err != nil {
		return nil, err
	}

	h.step = 3
	h.done = true
	return payload, nil
}

// Finished reports whether the handshake is complete.
func (h *Handshake) Finished() bool { return h.done }

// RemoteStatic is the peer's static public key, known once the handshake reaches
// the message that carries it.
//
// This is what gets compared against a fingerprint read out loud. XX proves the
// peer holds the private key for this static and says nothing about whose it is,
// so the comparison is the only thing standing between a conversation and a man in
// the middle.
func (h *Handshake) RemoteStatic() ([DHLen]byte, bool) {
	return h.remoteStatic, h.hasRemoteStatic
}

// HandshakeHash is the final transcript hash.
//
// Both sides derive the same value only if every byte of the handshake matched, so
// it doubles as a channel binding: a short prefix of it is what a UI shows when it
// asks two people to confirm they are talking to each other.
func (h *Handshake) HandshakeHash() [HashLen]byte { return h.symmetric.hash }

// Split returns the two transport ciphers.
//
// The initiator sends with the first and receives with the second; the responder
// does the reverse. Getting this backwards is the other classic Noise porting bug,
// so Transport does the assignment rather than leaving it to a caller.
func (h *Handshake) Split() (send, receive CipherState, err error) {
	if !h.done {
		return CipherState{}, CipherState{}, ErrNotFinished
	}
	first, second, err := h.symmetric.split()
	if err != nil {
		return CipherState{}, CipherState{}, err
	}
	if h.initiator {
		return first, second, nil
	}
	return second, first, nil
}

// Transport is a finished session: two ciphers and the peer's identity.
type Transport struct {
	send    CipherState
	receive CipherState

	RemoteStatic  [DHLen]byte
	HandshakeHash [HashLen]byte
}

// Transport finishes the handshake into a session.
func (h *Handshake) Transport() (*Transport, error) {
	send, receive, err := h.Split()
	if err != nil {
		return nil, err
	}
	if !h.hasRemoteStatic {
		return nil, ErrNoStatic
	}
	return &Transport{
		send:          send,
		receive:       receive,
		RemoteStatic:  h.remoteStatic,
		HandshakeHash: h.symmetric.hash,
	}, nil
}

// Encrypt seals a transport message.
func (t *Transport) Encrypt(additional, plaintext []byte) ([]byte, error) {
	return t.send.EncryptWithAd(additional, plaintext)
}

// Decrypt opens a transport message.
//
// Strictly in order. Noise transport messages are counter-based with no replay
// window, so a message that arrives out of order fails — which on a BLE mesh that
// reorders and duplicates freely is the transport layer's problem to solve, and
// mesh solves it by carrying its own message ids rather than by weakening this.
func (t *Transport) Decrypt(additional, ciphertext []byte) ([]byte, error) {
	return t.receive.DecryptWithAd(additional, ciphertext)
}

// Wipe overwrites both directions' keys. The forward-secrecy claim depends on the
// ephemeral keys already being gone; this is the rest of it.
func (t *Transport) Wipe() {
	t.send.Wipe()
	t.receive.Wipe()
}

// SentCount reports how many messages this side has sent, for the mesh's own
// bookkeeping.
func (t *Transport) SentCount() uint64 { return t.send.Nonce() }

// ReceivedCount reports how many it has accepted.
func (t *Transport) ReceivedCount() uint64 { return t.receive.Nonce() }
