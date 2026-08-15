package ticket

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// GC1 payload layout:
//
//	GC1.<base32(ticket_id:16B)>.<base32(ed25519_sig:64B)>
//
// which is 4 + 26 + 1 + 103 = 134 characters. In QR alphanumeric mode at error
// correction level L that is a version 7 symbol (45x45 modules): large enough
// to print at 25mm and still decode from a scratched phone screen, small enough
// that a 2015-era camera locks onto it in one frame.
const (
	// Prefix identifies the format. It is checked before anything else so a
	// scanner can reject a supermarket barcode without doing any crypto.
	gc1Prefix = "GC1"

	// GC1Len is the exact character length of a GC1 payload.
	GC1Len = len(gc1Prefix) + 1 + EncodedIDLen + 1 + encodedSigLen

	encodedSigLen = 103 // base32, unpadded, of 64 bytes
)

// Claims are the fields an Ed25519 signature commits to. They are not carried
// inside the QR payload: the scanner and the box both hold the event manifest,
// so they can look the claims up by ticket id and rebuild the signed message.
//
// This is a deliberate trade. Putting tier and issue time in the payload would
// push a GC1 code past 200 characters and up two QR versions, which measurably
// hurts decode time on the cheap Android phones that are the whole point of the
// product. Keeping them out means a GC1 code is only verifiable by a party that
// also has the manifest, which is every party that matters: gates, the box, and
// the organizer's auditor.
type Claims struct {
	EventID  ID     `json:"event_id"`
	TicketID ID     `json:"ticket_id"`
	Tier     string `json:"tier"`
	IssuedAt int64  `json:"issued_at"` // unix milliseconds, organizer's clock
}

// ErrBadPayload is returned for anything that is not a well-formed payload of
// the claimed format.
var ErrBadPayload = errors.New("ticket: bad payload")

// signedMessage is the canonical byte string an organizer signature covers.
// Field order and framing are frozen: changing either invalidates every ticket
// ever issued, which is why the domain string carries a version.
func (c Claims) signedMessage() []byte {
	out := make([]byte, 0, IDLen+IDLen+1+len(c.Tier)+8)
	out = append(out, c.EventID[:]...)
	out = append(out, c.TicketID[:]...)
	// A single length byte caps tier names at 255 bytes, which is 250 more than
	// any real tier name ("GA", "VIP", "Artist", "Crew").
	out = append(out, byte(len(c.Tier)))
	out = append(out, c.Tier...)
	return binary.BigEndian.AppendUint64(out, uint64(c.IssuedAt))
}

// IssuedTime renders IssuedAt as a time.Time for display.
func (c Claims) IssuedTime() time.Time { return time.UnixMilli(c.IssuedAt).UTC() }

// Validate checks that the claims are structurally usable before they are
// signed. Signing garbage produces a valid signature over garbage, which fails
// much later and much more confusingly.
func (c Claims) Validate() error {
	switch {
	case c.EventID.IsZero():
		return errors.New("ticket: claims have no event id")
	case c.TicketID.IsZero():
		return errors.New("ticket: claims have no ticket id")
	case c.Tier == "":
		return errors.New("ticket: claims have no tier")
	case len(c.Tier) > 255:
		return fmt.Errorf("ticket: tier name is %d bytes, limit is 255", len(c.Tier))
	case c.IssuedAt <= 0:
		return errors.New("ticket: claims have no issue time")
	}
	return nil
}

// SignGC1 issues a static ticket payload for the given claims.
func SignGC1(key SigningKey, claims Claims) (string, error) {
	if key.IsZero() {
		return "", errors.New("ticket: no signing key")
	}
	if err := claims.Validate(); err != nil {
		return "", err
	}
	signature := key.Sign(domainGC1, claims.signedMessage())
	return gc1Prefix + "." + claims.TicketID.String() + "." + encoding.EncodeToString(signature), nil
}

// EncodeGC1 renders a payload from an id and a signature the caller already
// holds.
//
// Used by the attendee API, which has the signature in the manifest and does not
// have the organizer's private key — the whole point of storing the signature is
// that the box can reproduce a ticket without being able to mint one.
func EncodeGC1(ticketID ID, signature []byte) string {
	if len(signature) != ed25519.SignatureSize {
		return ""
	}
	return gc1Prefix + "." + ticketID.String() + "." + encoding.EncodeToString(signature)
}

// GC1 is a parsed static payload. Parsing is separate from verification
// because a scanner does them at different times: it parses and looks the id up
// in its Bloom filter with zero crypto, and only verifies the signature for ids
// the filter admits.
type GC1 struct {
	TicketID  ID
	Signature []byte
}

// IsGC1 reports whether a scanned string claims to be a GC1 payload. Cheap
// enough to run on every camera frame.
func IsGC1(payload string) bool { return strings.HasPrefix(payload, gc1Prefix+".") }

// ParseGC1 reads a static payload without verifying it.
func ParseGC1(payload string) (GC1, error) {
	if len(payload) != GC1Len {
		return GC1{}, fmt.Errorf("%w: GC1 is %d characters, got %d", ErrBadPayload, GC1Len, len(payload))
	}
	parts := strings.Split(payload, ".")
	if len(parts) != 3 || parts[0] != gc1Prefix {
		return GC1{}, fmt.Errorf("%w: not a GC1 payload", ErrBadPayload)
	}
	ticketID, err := ParseIDBase32(parts[1])
	if err != nil {
		return GC1{}, fmt.Errorf("%w: ticket id: %v", ErrBadPayload, err)
	}
	signature, err := encoding.DecodeString(parts[2])
	if err != nil {
		return GC1{}, fmt.Errorf("%w: signature: %v", ErrBadPayload, err)
	}
	if len(signature) != ed25519.SignatureSize {
		return GC1{}, fmt.Errorf("%w: signature is %d bytes, want %d", ErrBadPayload, len(signature), ed25519.SignatureSize)
	}
	return GC1{TicketID: ticketID, Signature: signature}, nil
}

// Verify checks the payload's signature against the claims the verifier looked
// up for this ticket id.
//
// The claims must come from a trusted manifest, not from the payload, and their
// TicketID must match the payload's; a mismatch means the caller looked up the
// wrong row and is about to admit the wrong ticket, so it is an error rather
// than a false.
func (p GC1) Verify(key VerifyingKey, claims Claims) (bool, error) {
	if key.IsZero() {
		return false, errors.New("ticket: no verifying key")
	}
	if claims.TicketID != p.TicketID {
		return false, fmt.Errorf("ticket: claims are for %s but payload is for %s", claims.TicketID, p.TicketID)
	}
	return key.Verify(domainGC1, claims.signedMessage(), p.Signature), nil
}
