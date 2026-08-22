// Package manifest is the signed bundle that turns a blank box into an event.
//
// A manifest is produced before doors — by the organizer's CLI or by the cloud
// presale service — and carries everything the box needs: the event metadata, the
// compiled venue, every issued ticket, the enrolled scanner roster, and the keys
// to verify tickets against. The box ingests one file and is ready.
//
// It is signed, and the signature is checked on ingest, because the manifest is
// the root of trust for the entire gate. Anyone who can substitute a manifest can
// mint tickets, so the box refuses one it cannot verify and refuses one signed by
// a key it was not told to expect.
//
// The wire format is an envelope: the body is opaque bytes and the signature
// covers those exact bytes. This is the same shape as a JWS and for the same
// reason — canonical JSON is a swamp, and any scheme that re-serialises before
// verifying has a signature that covers something other than what was checked.
package manifest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ManasMadan/gatecrash/internal/bloom"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// Format is the envelope's format string, checked before anything is parsed.
const Format = "gatecrash-manifest/v1"

// domainManifest separates manifest signatures from ticket signatures. Without
// it, an organizer key that signs both could have a ticket payload presented as
// a manifest body or the reverse.
const domainManifest = "gatecrash/manifest/v1"

// Event is the metadata the gates and the apps display.
type Event struct {
	ID   ticket.ID `json:"id"`
	Name string    `json:"name"`

	// Venue is the human name of the place, shown on the attendee's ticket. The
	// structural venue graph is in Body.Venue.
	Venue string `json:"venue,omitempty"`

	// Timezone is an IANA name, used only for display. Nothing in the box makes
	// a decision on local time.
	Timezone string `json:"timezone,omitempty"`

	Doors  time.Time `json:"doors,omitzero"`
	Curfew time.Time `json:"curfew,omitzero"`

	// Mode is the consistency posture the organizer chose, and it is inside the
	// signed body on purpose: whether gates may admit during a partition is the
	// organizer's decision to make, not a box-local setting somebody can flip
	// at 1am.
	Mode engine.Mode `json:"mode"`

	// Support is what an attendee sees when something goes wrong: a phone
	// number, a tent, a WhatsApp. Optional and frequently the most useful field
	// in the file.
	Support string `json:"support,omitempty"`

	// Backstage is where the optional mesh chat app can be downloaded.
	//
	// In the signed manifest rather than in box-local config, because it is a link
	// the box invites attendees to install software from. A field an operator could
	// edit on the night is a field somebody with shell access could point at their
	// own APK, and the people following it are standing in a queue trusting the
	// event. Signed by the organizer, it cannot be changed without the organizer
	// key.
	//
	// Empty means the app is simply not offered, which is the correct default: it is
	// not required for a ticket to work.
	Backstage BackstageLinks `json:"backstage,omitzero"`
}

// BackstageLinks points at the optional mesh chat apps.
//
// Nothing about a ticket depends on these. Backstage is for talking to people when the
// phone signal has gone, and an attendee who never installs it still gets in.
type BackstageLinks struct {
	// Android is where the APK or Play listing lives.
	Android string `json:"android,omitempty"`

	// IOS is a TestFlight or App Store link.
	IOS string `json:"ios,omitempty"`

	// Note is one line shown next to the links, for an organizer who wants to say
	// what the app is for in their own words.
	Note string `json:"note,omitempty"`
}

// Body is the signed content of a manifest.
type Body struct {
	Event Event      `json:"event"`
	Venue venue.Plan `json:"venue"`

	// Tickets is every ticket issued for the event.
	Tickets []engine.Ticket `json:"tickets"`

	// Devices is the scanner roster with its checkpoint allowlists. Shipping it
	// in the manifest means a venue can be set up entirely offline: flash the
	// box, ingest the manifest, and the scanners enroll against a roster that was
	// decided in advance rather than by whoever walks up first.
	Devices []engine.Device `json:"devices,omitempty"`

	// Verifying is the organizer's public key, which the box uses to check GC1
	// ticket signatures.
	//
	// It is inside the signed body, which is only meaningful because the box
	// pins the expected key fingerprint out of band: a manifest that carries its
	// own verification key and is trusted on that basis is not signed, it is
	// merely decorated.
	Verifying ticket.VerifyingKey `json:"verifying_key"`

	// Master is the event master key, from which every GC2 ticket secret is
	// derived. Empty for print-only events.
	//
	// This is the most sensitive field in the file. Anyone holding it can mint
	// rotating codes for every ticket in the event, so a manifest carrying one
	// must be transported and stored as a secret; Seal exists for exactly that.
	Master string `json:"master_key,omitempty"`

	IssuedAt time.Time `json:"issued_at"`

	// Sequence lets a box reject a manifest older than the one it already holds,
	// which is what stops a stale file on a USB stick from rolling back a
	// revocation.
	Sequence uint64 `json:"sequence"`
}

// Envelope is the on-disk and on-the-wire form.
type Envelope struct {
	Format string `json:"format"`

	// Body is the exact JSON bytes the signature covers, base64-encoded. Opaque
	// on purpose: verify these bytes, then parse them, never the other way round.
	Body []byte `json:"body"`

	Signature []byte `json:"signature"`

	// Fingerprint is the signing key's fingerprint, present so a human can see
	// which key signed a file without parsing it. It is a convenience, never a
	// trust decision.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Errors returned by parsing and verification.
var (
	// ErrBadFormat means the file is not a Gatecrash manifest.
	ErrBadFormat = errors.New("manifest: unrecognised format")

	// ErrBadSignature means the signature does not verify under the expected
	// key. The box refuses to ingest and says which fingerprint it wanted.
	ErrBadSignature = errors.New("manifest: signature does not verify")

	// ErrWrongKey means the manifest was signed by a key other than the one this
	// box was told to expect.
	ErrWrongKey = errors.New("manifest: signed by an unexpected key")

	// ErrStale means the manifest is older than one already ingested.
	ErrStale = errors.New("manifest: older than the manifest already loaded")
)

// Sign serialises and signs a body.
func Sign(key ticket.SigningKey, body Body) (Envelope, error) {
	if key.IsZero() {
		return Envelope{}, errors.New("manifest: no signing key")
	}
	if err := body.Validate(); err != nil {
		return Envelope{}, err
	}
	// Indented on purpose. A manifest is a file a human will open in an editor
	// when something has gone wrong at 8pm, and the extra bytes cost nothing
	// next to the ticket list. The signature covers these exact bytes, so
	// formatting is part of the signed artifact and stays stable.
	raw, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return Envelope{}, fmt.Errorf("manifest: encoding body: %w", err)
	}
	return Envelope{
		Format:      Format,
		Body:        raw,
		Signature:   key.Sign(domainManifest, raw),
		Fingerprint: key.Public().Fingerprint(),
	}, nil
}

// Verify checks an envelope and returns its body.
//
// expect is the key fingerprint this box was provisioned with. An empty expect
// accepts any key that signed the body correctly, which is only appropriate for
// tooling; the box always passes a fingerprint, because a signature checked
// against a key taken from the same file proves nothing.
func Verify(env Envelope, expect ticket.VerifyingKey, expectFingerprint string) (Body, error) {
	if env.Format != Format {
		return Body{}, fmt.Errorf("%w: %q, want %q", ErrBadFormat, env.Format, Format)
	}
	if len(env.Body) == 0 {
		return Body{}, fmt.Errorf("%w: empty body", ErrBadFormat)
	}

	// Parse only after the signature is checked, and check it against the key
	// the caller supplied rather than one read out of the body.
	if !expect.IsZero() {
		if expectFingerprint != "" && expect.Fingerprint() != expectFingerprint {
			return Body{}, fmt.Errorf("%w: box expects %s", ErrWrongKey, expectFingerprint)
		}
		if !expect.Verify(domainManifest, env.Body, env.Signature) {
			return Body{}, ErrBadSignature
		}
	}

	var body Body
	if err := json.Unmarshal(env.Body, &body); err != nil {
		return Body{}, fmt.Errorf("manifest: decoding body: %w", err)
	}

	// With no key supplied, fall back to the body's own key so tooling can read
	// a manifest it has no prior relationship with. This is self-signature and
	// proves only internal consistency, which the error message says.
	if expect.IsZero() {
		if body.Verifying.IsZero() || !body.Verifying.Verify(domainManifest, env.Body, env.Signature) {
			return Body{}, fmt.Errorf("%w: self-signature check failed", ErrBadSignature)
		}
		if expectFingerprint != "" && body.Verifying.Fingerprint() != expectFingerprint {
			return Body{}, fmt.Errorf("%w: box expects %s, file carries %s",
				ErrWrongKey, expectFingerprint, body.Verifying.Fingerprint())
		}
	}

	if err := body.Validate(); err != nil {
		return Body{}, err
	}
	return body, nil
}

// Validate checks a body for internal consistency.
//
// This runs both when signing and after verifying, because a manifest can be
// correctly signed and still be wrong — a ticket referencing a tier the venue
// does not define, a device allowlisted for a checkpoint that was renamed — and
// those failures are far cheaper to find here than at a gate.
func (b Body) Validate() error {
	if b.Event.ID.IsZero() {
		return errors.New("manifest: event has no id")
	}
	if b.Event.Name == "" {
		return errors.New("manifest: event has no name")
	}
	switch b.Event.Mode {
	case engine.ModeStrict, engine.ModeDegraded:
	case "":
		return errors.New("manifest: event has no consistency mode")
	default:
		return fmt.Errorf("manifest: unknown consistency mode %q", b.Event.Mode)
	}
	if b.Verifying.IsZero() {
		return errors.New("manifest: no verifying key")
	}
	if !b.Event.Doors.IsZero() && !b.Event.Curfew.IsZero() && !b.Event.Curfew.After(b.Event.Doors) {
		return errors.New("manifest: curfew is at or before doors")
	}

	compiled, err := venue.Compile(b.Venue)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}

	if b.Master != "" {
		if _, err := ticket.ParseMasterKey(b.Master); err != nil {
			return fmt.Errorf("manifest: %w", err)
		}
	}

	seen := make(map[ticket.ID]bool, len(b.Tickets))
	for i, t := range b.Tickets {
		switch {
		case t.ID.IsZero():
			return fmt.Errorf("manifest: ticket %d has no id", i)
		case seen[t.ID]:
			return fmt.Errorf("manifest: ticket %s appears twice", t.ID)
		case t.EventID != b.Event.ID:
			return fmt.Errorf("manifest: ticket %s belongs to event %s", t.ID, t.EventID)
		}
		seen[t.ID] = true

		if _, ok := compiled.Tier(t.Tier); !ok {
			return fmt.Errorf("manifest: ticket %s has tier %q, which the venue does not define", t.ID, t.Tier)
		}
		if err := compiled.ValidateSeat(t.Tier, t.Seat); err != nil {
			return fmt.Errorf("manifest: ticket %s: %w", t.ID, err)
		}
		switch t.Format {
		case engine.FormatStatic, engine.FormatRotating, engine.FormatEither:
		case "":
			return fmt.Errorf("manifest: ticket %s has no format", t.ID)
		default:
			return fmt.Errorf("manifest: ticket %s has unknown format %q", t.ID, t.Format)
		}
		if t.Format != engine.FormatStatic && b.Master == "" {
			return fmt.Errorf("manifest: ticket %s wants rotating codes but the manifest carries no master key", t.ID)
		}
	}

	devices := make(map[string]bool, len(b.Devices))
	for i, d := range b.Devices {
		if d.ID == "" {
			return fmt.Errorf("manifest: device %d has no id", i)
		}
		if devices[d.ID] {
			return fmt.Errorf("manifest: device %s appears twice", d.ID)
		}
		devices[d.ID] = true
		for _, code := range d.Checkpoints {
			if _, ok := compiled.Checkpoint(code); !ok {
				return fmt.Errorf("manifest: device %s is allowlisted for checkpoint %q, which does not exist", d.ID, code)
			}
		}
	}
	return nil
}

// Summary is the human-readable shape of a manifest, printed by the CLI and shown
// on the dashboard's setup page.
type Summary struct {
	Event       string    `json:"event"`
	EventID     ticket.ID `json:"event_id"`
	Fingerprint string    `json:"fingerprint"`
	Sequence    uint64    `json:"sequence"`
	IssuedAt    time.Time `json:"issued_at"`

	Tickets     int `json:"tickets"`
	Zones       int `json:"zones"`
	Checkpoints int `json:"checkpoints"`
	Tiers       int `json:"tiers"`
	Sections    int `json:"sections"`
	Seats       int `json:"seats"`
	Devices     int `json:"devices"`

	Rotating int `json:"rotating_tickets"`

	Mode engine.Mode `json:"mode"`

	// Digest identifies this exact manifest, so an operator can confirm the box
	// and the office are holding the same file without diffing megabytes.
	Digest string `json:"digest"`
}

// Summarise describes a verified body.
func (b Body) Summarise() Summary {
	out := Summary{
		Event:       b.Event.Name,
		EventID:     b.Event.ID,
		Fingerprint: b.Verifying.Fingerprint(),
		Sequence:    b.Sequence,
		IssuedAt:    b.IssuedAt,
		Tickets:     len(b.Tickets),
		Zones:       len(b.Venue.Zones),
		Checkpoints: len(b.Venue.Checkpoints),
		Tiers:       len(b.Venue.Tiers),
		Sections:    len(b.Venue.Sections),
		Devices:     len(b.Devices),
		Mode:        b.Event.Mode,
	}
	for _, section := range b.Venue.Sections {
		for _, row := range section.Rows {
			out.Seats += len(row.Seats)
		}
	}
	for _, t := range b.Tickets {
		if t.Format != engine.FormatStatic {
			out.Rotating++
		}
	}
	return out
}

// Digest returns a short identifier for an envelope's exact bytes.
func (env Envelope) Digest() string {
	sum := sha256.Sum256(env.Body)
	return hex.EncodeToString(sum[:8])
}

// Bloom builds the ticket-id Bloom filter a scanner syncs, sized for the
// manifest's ticket count.
//
// falsePositiveRate is the target. One in a million is the shipped default: at
// fifty thousand tickets that is about 175 KB, and a false positive costs one
// round trip to a box that knows the truth.
func (b Body) Bloom(falsePositiveRate float64) (*bloom.Filter, error) {
	// An empty manifest still needs a filter, and a filter sized for zero
	// elements is undefined, so size for one.
	expected := max(len(b.Tickets), 1)

	filter, err := bloom.New(expected, falsePositiveRate)
	if err != nil {
		return nil, fmt.Errorf("manifest: sizing bloom filter: %w", err)
	}
	for _, t := range b.Tickets {
		filter.Add(t.ID[:])
	}
	return filter, nil
}

// IssuedByTier counts tickets per tier, which the dashboard shows as turnout
// against tickets sold.
func (b Body) IssuedByTier() map[venue.TierCode]int {
	out := make(map[venue.TierCode]int)
	for _, t := range b.Tickets {
		out[t.Tier]++
	}
	return out
}

// MasterKey parses the event master key, returning the zero key for a print-only
// manifest.
func (b Body) MasterKey() (ticket.MasterKey, error) {
	if b.Master == "" {
		return ticket.MasterKey{}, nil
	}
	return ticket.ParseMasterKey(b.Master)
}

// Marshal renders an envelope as the bytes written to a file.
func (env Envelope) Marshal() ([]byte, error) {
	out, err := json.MarshalIndent(struct {
		Format      string `json:"format"`
		Body        string `json:"body"`
		Signature   string `json:"signature"`
		Fingerprint string `json:"fingerprint,omitempty"`
	}{
		Format:      env.Format,
		Body:        base64.StdEncoding.EncodeToString(env.Body),
		Signature:   base64.StdEncoding.EncodeToString(env.Signature),
		Fingerprint: env.Fingerprint,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("manifest: encoding envelope: %w", err)
	}
	return append(out, '\n'), nil
}

// Unmarshal parses an envelope from file bytes.
func Unmarshal(raw []byte) (Envelope, error) {
	var wire struct {
		Format      string `json:"format"`
		Body        string `json:"body"`
		Signature   string `json:"signature"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrBadFormat, err)
	}
	body, err := base64.StdEncoding.DecodeString(wire.Body)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: body is not base64: %w", ErrBadFormat, err)
	}
	signature, err := base64.StdEncoding.DecodeString(wire.Signature)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: signature is not base64: %w", ErrBadFormat, err)
	}
	return Envelope{Format: wire.Format, Body: body, Signature: signature, Fingerprint: wire.Fingerprint}, nil
}
