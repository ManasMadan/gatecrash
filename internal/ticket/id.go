// Package ticket implements Gatecrash's two QR ticket formats and the key
// schedule behind them.
//
// There are exactly two formats and they exist for different threat models:
//
//	GC1  static, printed or emailed. Ed25519-signed, verifiable offline by
//	     anyone holding the event public key. A screenshot of a GC1 ticket is
//	     valid until first use, exactly like every printed ticket ever issued;
//	     single use is enforced by the redemption engine, not by the QR.
//
//	GC2  rotating, generated inside the attendee app. TOTP-style 30 second
//	     windows over an HMAC of a per-ticket secret, so a screenshot dies in
//	     at most 60 seconds. Generated fully offline by the phone and validated
//	     fully offline by the box.
//
// Per-ticket secrets are derived, never stored: ticket_secret =
// HKDF(event_master, ticket_id). The box can validate any ticket in the event
// while holding exactly one 32-byte key, and dumping the box's database yields
// no secret capable of minting a GC2 code.
package ticket

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
)

// IDLen is the length of a ticket or event identifier in bytes. 128 bits of
// random is enough that guessing an identifier is hopeless, and it encodes to
// 26 base32 characters, which keeps a GC1 payload inside QR version 7.
const IDLen = 16

// ID identifies a ticket or an event. It is an opaque random value with no
// structure: the box stores nothing else about an attendee, so a leaked
// database is a list of meaningless numbers.
type ID [IDLen]byte

// encoding is RFC 4648 base32 without padding. Base32's alphabet (A-Z, 2-7) is
// a subset of the QR alphanumeric character set, which lets the encoder use
// alphanumeric mode instead of byte mode: the same payload fits in a smaller,
// lower-density symbol that cheap phone cameras decode more reliably in bad
// light. That is the entire reason this is not base64.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodedIDLen is the length of an ID in its base32 wire form.
const EncodedIDLen = 26

// NewID returns a cryptographically random identifier.
func NewID() (ID, error) {
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		return ID{}, fmt.Errorf("ticket: generating id: %w", err)
	}
	return id, nil
}

// MustNewID is NewID for callers that cannot proceed without an identifier,
// such as CLI ticket issuance. A failing system CSPRNG is not a recoverable
// condition.
func MustNewID() ID {
	id, err := NewID()
	if err != nil {
		panic(err)
	}
	return id
}

// String returns the base32 wire form used inside QR payloads and on the HTTP
// API. It is uppercase and unpadded.
func (id ID) String() string { return encoding.EncodeToString(id[:]) }

// Hex returns the lowercase hex form. SQLite stores identifiers as hex text so
// that a human debugging the database with the sqlite3 shell can read and
// paste them; the 10 extra bytes per row are not worth optimising.
func (id ID) Hex() string { return hex.EncodeToString(id[:]) }

// IsZero reports whether the identifier is the zero value, which is never a
// valid identifier.
func (id ID) IsZero() bool { return id == ID{} }

// MarshalText implements encoding.TextMarshaler, giving base32 in JSON.
func (id ID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler and accepts either the
// base32 or the hex form, because the CLI, the database and the wire disagree
// and being liberal here removes a whole class of paper cut.
func (id *ID) UnmarshalText(b []byte) error {
	parsed, err := ParseID(string(b))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// ErrBadID is returned for identifiers that are not a valid 128-bit value in
// either the base32 or the hex form.
var ErrBadID = errors.New("ticket: bad id")

// ParseID reads an identifier in base32 (26 chars) or hex (32 chars) form.
func ParseID(s string) (ID, error) {
	var id ID
	switch len(s) {
	case EncodedIDLen:
		decoded, err := encoding.DecodeString(s)
		if err != nil {
			return ID{}, fmt.Errorf("%w: %q: %w", ErrBadID, s, err)
		}
		copy(id[:], decoded)
		return id, nil
	case hex.EncodedLen(IDLen):
		decoded, err := hex.DecodeString(s)
		if err != nil {
			return ID{}, fmt.Errorf("%w: %q: %w", ErrBadID, s, err)
		}
		copy(id[:], decoded)
		return id, nil
	default:
		return ID{}, fmt.Errorf("%w: %q: want %d base32 or %d hex characters, got %d",
			ErrBadID, s, EncodedIDLen, hex.EncodedLen(IDLen), len(s))
	}
}

// ParseIDBase32 reads an identifier in base32 form only. QR decoders use this
// rather than ParseID: accepting hex inside a QR payload would let one payload
// have two spellings, and two spellings of one ticket is a bug waiting to
// become a double admission.
func ParseIDBase32(s string) (ID, error) {
	if len(s) != EncodedIDLen {
		return ID{}, fmt.Errorf("%w: %q: want %d base32 characters, got %d", ErrBadID, s, EncodedIDLen, len(s))
	}
	return ParseID(s)
}
