package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/incident"
	"github.com/ManasMadan/gatecrash/internal/stats"
	"github.com/ManasMadan/gatecrash/internal/ticket"
)

// AttendanceFormat is the format string of the post-event report.
const AttendanceFormat = "gatecrash-attendance/v1"

// domainAttendance separates attendance signatures from manifest and ticket
// signatures.
const domainAttendance = "gatecrash/attendance/v1"

// Attendance is what the box produces at session close: what happened, who
// admitted it, and a cryptographic commitment to the whole log.
//
// This is the artifact that settles a door split. It is signed by the box's own
// key so that a promoter cannot edit the numbers on the way to the artist's
// manager, and it carries the Merkle root so that any individual admission in it
// can be proved later with about twenty hashes.
type Attendance struct {
	EventID ticket.ID `json:"event_id"`
	Event   string    `json:"event"`

	// ManifestDigest ties this report to the exact manifest the event ran on, so
	// a report cannot be quietly re-attributed to a different ticket list.
	ManifestDigest string `json:"manifest_digest"`

	OpenedAt time.Time `json:"opened_at"`
	ClosedAt time.Time `json:"closed_at"`

	// Checkpoint is the final sealed audit checkpoint: the row count, the chain
	// head and the Merkle root. Three numbers that commit to everything.
	Checkpoint audit.Checkpoint `json:"checkpoint"`

	// Totals is the final live picture, which is where the headline numbers come
	// from.
	Totals stats.Live `json:"totals"`

	// Incidents is the staff-signal record, including how long the control room
	// took to respond. It is in here because an event's safety record is part of
	// what happened, and because an operator who knows the response times are
	// published behaves differently.
	Incidents        []incident.Incident `json:"incidents,omitempty"`
	IncidentResponse incident.Response   `json:"incident_response,omitzero"`

	// Flags is every double use the reconciliation detected. Publishing them is
	// the honest half of DEGRADED mode: the report says how many people got in
	// on a ticket that was already used, rather than quietly rounding it away.
	Flags []Flag `json:"flags,omitempty"`

	// BoxKey is the box's public key, so a recipient can check the signature
	// against a fingerprint the organizer published in advance.
	BoxKey ticket.VerifyingKey `json:"box_key"`
}

// Flag is one detected double use, in the shape the report publishes.
type Flag struct {
	TicketID     ticket.ID `json:"ticket_id"`
	Winner       string    `json:"winner"`
	WinnerAt     time.Time `json:"winner_at"`
	Loser        string    `json:"loser"`
	LoserAt      time.Time `json:"loser_at"`
	LoserOffline bool      `json:"loser_offline"`
}

// SignedAttendance is the envelope form.
type SignedAttendance struct {
	Format    string `json:"format"`
	Body      []byte `json:"body"`
	Signature []byte `json:"signature"`

	// Fingerprint of the box key, for humans.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// SignAttendance serialises and signs a report with the box's own key.
func SignAttendance(key ticket.SigningKey, report Attendance) (SignedAttendance, error) {
	if key.IsZero() {
		return SignedAttendance{}, errors.New("manifest: no box signing key")
	}
	if report.EventID.IsZero() {
		return SignedAttendance{}, errors.New("manifest: attendance has no event id")
	}
	report.BoxKey = key.Public()

	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return SignedAttendance{}, fmt.Errorf("manifest: encoding attendance: %w", err)
	}
	return SignedAttendance{
		Format:      AttendanceFormat,
		Body:        raw,
		Signature:   key.Sign(domainAttendance, raw),
		Fingerprint: key.Public().Fingerprint(),
	}, nil
}

// VerifyAttendance checks a signed report.
//
// expect is the box's public key, which the organizer publishes before the event
// so that the report can be checked by somebody who was not there. Passing the
// zero key falls back to the key inside the body, which proves only internal
// consistency and is flagged as such in the error.
func VerifyAttendance(signed SignedAttendance, expect ticket.VerifyingKey) (Attendance, error) {
	if signed.Format != AttendanceFormat {
		return Attendance{}, fmt.Errorf("%w: %q, want %q", ErrBadFormat, signed.Format, AttendanceFormat)
	}
	if !expect.IsZero() && !expect.Verify(domainAttendance, signed.Body, signed.Signature) {
		return Attendance{}, ErrBadSignature
	}

	var report Attendance
	if err := json.Unmarshal(signed.Body, &report); err != nil {
		return Attendance{}, fmt.Errorf("manifest: decoding attendance: %w", err)
	}
	if expect.IsZero() {
		if report.BoxKey.IsZero() || !report.BoxKey.Verify(domainAttendance, signed.Body, signed.Signature) {
			return Attendance{}, fmt.Errorf("%w: self-signature check failed", ErrBadSignature)
		}
	}
	return report, nil
}
