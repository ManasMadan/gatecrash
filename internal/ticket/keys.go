package ticket

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// MasterKeyLen is the length of an event master key in bytes.
const MasterKeyLen = 32

// Domain separation strings. Every key derivation and every signature in
// Gatecrash is prefixed with one of these. Without domain separation a GC2 code
// for window N could be replayed as some other protocol's authenticator, and
// the organizer signing key would sign two different message families with no
// way to tell them apart. The version suffix is what lets a future GC3 coexist
// with GC1 and GC2 on the same key material.
const (
	domainEventMaster  = "gatecrash/event-master/v1"
	domainTicketSecret = "gatecrash/ticket-secret/v1"
	domainGC1          = "gatecrash/gc1/v1"
	domainGC2          = "gatecrash/gc2/v1"
)

// MasterKey is the per-event symmetric root from which every GC2 ticket secret
// is derived.
//
// The organizer holds an organization-wide root key which never leaves their
// machine; each event's master key is derived from it. Only the event master
// key is shipped to the box, so a box seized or stolen after an event cannot
// mint codes for any other event. This is the single most valuable secret on
// the box and the reason the box stores it in a 0600 file outside the database.
type MasterKey [MasterKeyLen]byte

// NewMasterKey returns a random master key.
func NewMasterKey() (MasterKey, error) {
	var key MasterKey
	if _, err := rand.Read(key[:]); err != nil {
		return MasterKey{}, fmt.Errorf("ticket: generating master key: %w", err)
	}
	return key, nil
}

// DeriveEventMaster derives an event-scoped master key from an organization
// root key. Compromise of one event's key tells an attacker nothing about the
// root or about any sibling event.
func DeriveEventMaster(root MasterKey, eventID ID) (MasterKey, error) {
	derived, err := hkdf.Key(sha256.New, root[:], eventID[:], domainEventMaster, MasterKeyLen)
	if err != nil {
		return MasterKey{}, fmt.Errorf("ticket: deriving event master: %w", err)
	}
	var key MasterKey
	copy(key[:], derived)
	return key, nil
}

// String renders the key as base64 for config files and the presale API. It is
// deliberately not the Stringer used in logs; see Redacted.
func (k MasterKey) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Redacted returns a fingerprint safe to print in logs and on the dashboard, so
// an operator can confirm the box loaded the key they expected without the log
// file becoming a ticket-minting oracle.
func (k MasterKey) Redacted() string {
	sum := sha256.Sum256(append([]byte(domainEventMaster), k[:]...))
	return "master:" + base64.RawURLEncoding.EncodeToString(sum[:6])
}

// IsZero reports whether the key is unset. A zero master key means GC2 is
// unavailable for the event, which is a supported configuration: GC1-only
// events exist and are honest about their screenshot exposure.
func (k MasterKey) IsZero() bool { return k == MasterKey{} }

// ParseMasterKey reads a base64 master key.
func ParseMasterKey(s string) (MasterKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return MasterKey{}, fmt.Errorf("ticket: bad master key encoding: %w", err)
	}
	if len(raw) != MasterKeyLen {
		return MasterKey{}, fmt.Errorf("ticket: master key is %d bytes, want %d", len(raw), MasterKeyLen)
	}
	var key MasterKey
	copy(key[:], raw)
	return key, nil
}

// SecretLen is the length of a per-ticket secret in bytes.
const SecretLen = 32

// Secret is a per-ticket symmetric secret. It is never stored anywhere: the box
// derives it on demand for the ticket being scanned, and the attendee app holds
// only its own.
type Secret [SecretLen]byte

// DeriveSecret computes ticket_secret = HKDF(event_master, ticket_id).
//
// This is the mechanism that makes the box stateless with respect to ticket
// secrets. Fifty thousand tickets need fifty thousand secrets; the box stores
// one key and does one HKDF per scan, which costs about two microseconds and
// removes an entire table from the threat model.
func DeriveSecret(master MasterKey, ticketID ID) (Secret, error) {
	if master.IsZero() {
		return Secret{}, errors.New("ticket: event master key is not set, GC2 unavailable")
	}
	derived, err := hkdf.Key(sha256.New, master[:], ticketID[:], domainTicketSecret, SecretLen)
	if err != nil {
		return Secret{}, fmt.Errorf("ticket: deriving ticket secret: %w", err)
	}
	var secret Secret
	copy(secret[:], derived)
	return secret, nil
}

// String renders the secret as base64. This is what the attendee app receives
// once, over TLS, when it claims its ticket.
func (s Secret) String() string { return base64.StdEncoding.EncodeToString(s[:]) }

// ParseSecret reads a base64 ticket secret.
func ParseSecret(text string) (Secret, error) {
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return Secret{}, fmt.Errorf("ticket: bad secret encoding: %w", err)
	}
	if len(raw) != SecretLen {
		return Secret{}, fmt.Errorf("ticket: secret is %d bytes, want %d", len(raw), SecretLen)
	}
	var secret Secret
	copy(secret[:], raw)
	return secret, nil
}

// SigningKey is the organizer's Ed25519 private key. It signs GC1 tickets,
// presale manifests and organizer-priority mesh announcements.
type SigningKey struct {
	priv ed25519.PrivateKey
}

// VerifyingKey is the corresponding public key. Scanners, attendee apps and
// anyone auditing an event hold this and nothing else.
type VerifyingKey struct {
	pub ed25519.PublicKey
}

// GenerateSigningKey returns a fresh organizer key pair.
func GenerateSigningKey() (SigningKey, VerifyingKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SigningKey{}, VerifyingKey{}, fmt.Errorf("ticket: generating signing key: %w", err)
	}
	return SigningKey{priv: priv}, VerifyingKey{pub: pub}, nil
}

// Public returns the verifying half of the key pair.
func (k SigningKey) Public() VerifyingKey {
	return VerifyingKey{pub: k.priv.Public().(ed25519.PublicKey)}
}

// IsZero reports whether the key is unset.
func (k SigningKey) IsZero() bool { return len(k.priv) == 0 }

// Sign signs a domain-separated message.
func (k SigningKey) Sign(domain string, message []byte) []byte {
	return ed25519.Sign(k.priv, domainSeparated(domain, message))
}

// String renders the private key as base64. Only ever written to a 0600 file.
func (k SigningKey) String() string { return base64.StdEncoding.EncodeToString(k.priv) }

// Redacted returns a log-safe fingerprint of the key pair, which is just the
// public key's fingerprint: printing that is harmless and identifies the key.
func (k SigningKey) Redacted() string { return k.Public().Fingerprint() }

// ParseSigningKey reads a base64 Ed25519 private key.
func ParseSigningKey(text string) (SigningKey, error) {
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return SigningKey{}, fmt.Errorf("ticket: bad signing key encoding: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return SigningKey{}, fmt.Errorf("ticket: signing key is %d bytes, want %d", len(raw), ed25519.PrivateKeySize)
	}
	return SigningKey{priv: ed25519.PrivateKey(raw)}, nil
}

// IsZero reports whether the verifying key is unset.
func (k VerifyingKey) IsZero() bool { return len(k.pub) == 0 }

// Verify checks a domain-separated signature. It returns false rather than an
// error: at a gate there is exactly one thing to do with a bad signature and
// distinguishing why it was bad only helps a forger.
func (k VerifyingKey) Verify(domain string, message, signature []byte) bool {
	if len(k.pub) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(k.pub, domainSeparated(domain, message), signature)
}

// Bytes returns the raw 32-byte public key.
func (k VerifyingKey) Bytes() []byte { return append([]byte(nil), k.pub...) }

// String renders the public key as base64, which is the form that appears in
// event config, the enrollment QR and the mesh announcement header.
func (k VerifyingKey) String() string { return base64.StdEncoding.EncodeToString(k.pub) }

// Fingerprint returns a short, human-comparable identifier for the key. Gate
// staff read this off a printed sheet to confirm the box in front of them
// belongs to the event they were briefed on.
func (k VerifyingKey) Fingerprint() string {
	sum := sha256.Sum256(k.pub)
	return "gc-" + base64.RawURLEncoding.EncodeToString(sum[:8])
}

// Equal reports whether two verifying keys are the same key.
func (k VerifyingKey) Equal(other VerifyingKey) bool {
	return subtle.ConstantTimeCompare(k.pub, other.pub) == 1
}

// MarshalText implements encoding.TextMarshaler.
func (k VerifyingKey) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *VerifyingKey) UnmarshalText(b []byte) error {
	parsed, err := ParseVerifyingKey(string(b))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// ParseVerifyingKey reads a base64 Ed25519 public key.
func ParseVerifyingKey(text string) (VerifyingKey, error) {
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return VerifyingKey{}, fmt.Errorf("ticket: bad verifying key encoding: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return VerifyingKey{}, fmt.Errorf("ticket: verifying key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return VerifyingKey{pub: ed25519.PublicKey(raw)}, nil
}

// domainSeparated prefixes a message with its domain string and a length byte,
// so that no message in one domain can ever be a valid message in another. The
// length prefix matters: without it, domain "a" with message "bc" and domain
// "ab" with message "c" would produce identical signed bytes.
func domainSeparated(domain string, message []byte) []byte {
	out := make([]byte, 0, 1+len(domain)+len(message))
	out = append(out, byte(len(domain)))
	out = append(out, domain...)
	return append(out, message...)
}
