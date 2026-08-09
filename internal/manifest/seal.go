package manifest

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Sealing exists because of one field: the event master key.
//
// A manifest carrying a master key is a file that can mint a rotating code for
// every ticket in the event, and it travels by USB stick, email attachment and
// scp — the three least trustworthy transports in existence. So a manifest can be
// sealed under a passphrase the organizer types into the box once at setup.
//
// The passphrase is stretched with Argon2id rather than a plain hash because the
// passphrases people actually choose for this are four words long, and a memory-
// hard KDF is the only thing standing between "venue2026" and an offline attack
// on a stick somebody left in a van.

// SealFormat is the sealed envelope's format string.
const SealFormat = "gatecrash-manifest-sealed/v1"

// Argon2id parameters.
//
// 64 MB and three passes is roughly a second on a Raspberry Pi 4, which is the
// slowest machine that has to open one of these. Unsealing happens once, at
// setup, while somebody is standing there typing — so a second is free, and it
// buys about four orders of magnitude against an offline guesser compared with a
// single SHA-256.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = chacha20poly1305.KeySize

	saltLen = 16
)

// Sealed is a passphrase-encrypted manifest.
type Sealed struct {
	Format string `json:"format"`

	// Salt for the KDF. Fresh per seal, so sealing the same manifest twice with
	// the same passphrase produces different ciphertext.
	Salt []byte `json:"salt"`

	// Params are recorded in the file so a future box can open an old manifest
	// even after the defaults are raised. A sealed file that can only be opened
	// by the exact version that wrote it is a file that gets lost.
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`

	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`

	// Fingerprint of the signing key, left in the clear so an operator can tell
	// which event a sealed file belongs to without the passphrase. It leaks only
	// which key signed it, which is public anyway.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// ErrBadPassphrase is returned when a sealed manifest will not open. It is
// indistinguishable from a corrupted file on purpose: the AEAD cannot tell them
// apart, and pretending otherwise would be guessing.
var ErrBadPassphrase = errors.New("manifest: wrong passphrase or corrupted file")

// Seal encrypts a signed envelope under a passphrase.
//
// The signature is sealed along with the body, so unsealing yields exactly the
// envelope that went in and the signature check still happens afterwards.
// Encryption is confidentiality; the signature is authenticity; conflating the
// two is how systems end up trusting whatever the person with the passphrase
// decided to put in the file.
func Seal(env Envelope, passphrase string) (Sealed, error) {
	if passphrase == "" {
		return Sealed{}, errors.New("manifest: sealing needs a passphrase")
	}
	raw, err := env.Marshal()
	if err != nil {
		return Sealed{}, err
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return Sealed{}, fmt.Errorf("manifest: generating salt: %w", err)
	}
	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Sealed{}, fmt.Errorf("manifest: constructing cipher: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, fmt.Errorf("manifest: generating nonce: %w", err)
	}

	out := Sealed{
		Format:      SealFormat,
		Salt:        salt,
		Time:        argonTime,
		Memory:      argonMemory,
		Threads:     argonThreads,
		Nonce:       nonce,
		Fingerprint: env.Fingerprint,
	}
	// The KDF parameters are authenticated as additional data, so an attacker
	// cannot downgrade a sealed file to one-pass Argon2 and then brute-force it.
	out.Ciphertext = aead.Seal(nil, nonce, raw, out.additionalData())
	return out, nil
}

// Open decrypts a sealed manifest back into an envelope. The caller still has to
// Verify the result.
func Open(sealed Sealed, passphrase string) (Envelope, error) {
	if sealed.Format != SealFormat {
		return Envelope{}, fmt.Errorf("%w: %q, want %q", ErrBadFormat, sealed.Format, SealFormat)
	}
	if len(sealed.Salt) != saltLen {
		return Envelope{}, fmt.Errorf("%w: salt is %d bytes, want %d", ErrBadFormat, len(sealed.Salt), saltLen)
	}
	if sealed.Threads == 0 || sealed.Time == 0 || sealed.Memory == 0 {
		return Envelope{}, fmt.Errorf("%w: kdf parameters are missing", ErrBadFormat)
	}
	// Guard the memory parameter before handing it to the KDF: a hostile file
	// declaring 64 GB would otherwise take the box out with an allocation.
	if sealed.Memory > 1024*1024 {
		return Envelope{}, fmt.Errorf("%w: kdf asks for %d KiB of memory", ErrBadFormat, sealed.Memory)
	}

	key := argon2.IDKey([]byte(passphrase), sealed.Salt, sealed.Time, sealed.Memory, sealed.Threads, argonKeyLen)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Envelope{}, fmt.Errorf("manifest: constructing cipher: %w", err)
	}
	if len(sealed.Nonce) != aead.NonceSize() {
		return Envelope{}, fmt.Errorf("%w: nonce is %d bytes, want %d", ErrBadFormat, len(sealed.Nonce), aead.NonceSize())
	}

	raw, err := aead.Open(nil, sealed.Nonce, sealed.Ciphertext, sealed.additionalData())
	if err != nil {
		return Envelope{}, ErrBadPassphrase
	}
	return Unmarshal(raw)
}

// additionalData binds the KDF parameters into the AEAD so they cannot be
// tampered with.
func (s Sealed) additionalData() []byte {
	out := make([]byte, 0, len(SealFormat)+len(s.Salt)+9)
	out = append(out, SealFormat...)
	out = append(out, s.Salt...)
	out = binary.BigEndian.AppendUint32(out, s.Time)
	out = binary.BigEndian.AppendUint32(out, s.Memory)
	return append(out, s.Threads)
}
