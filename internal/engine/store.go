package engine

import (
	"context"
	"errors"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/merkle"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// Ticket is what the box knows about one ticket. This is the whole of it, and it
// is deliberately small: no name, no email, no phone number, no order id. The
// box holds pseudonymous ids and nothing that would make it worth stealing, and
// personal data stays in the optional presale layer where it can be deleted.
type Ticket struct {
	ID       ticket.ID      `json:"id"`
	EventID  ticket.ID      `json:"event_id"`
	Tier     venue.TierCode `json:"tier"`
	Seat     venue.SeatRef  `json:"seat,omitzero"`
	IssuedAt int64          `json:"issued_at"`
	Revoked  bool           `json:"revoked,omitempty"`

	// Signature is the organizer's Ed25519 signature over the GC1 claims. It is
	// stored rather than recomputed so that a GC1 payload can be verified without
	// the organizer's private key ever touching the box.
	Signature []byte `json:"signature,omitempty"`

	// Format restricts which payload formats this ticket may present. A ticket
	// sold as an in-app rotating code should not also be admissible as a static
	// printed one, or the anti-screenshot property evaporates.
	Format Format `json:"format"`
}

// Format is which QR formats a ticket may be presented as.
type Format string

// The formats.
const (
	// FormatStatic is GC1 only: printed and emailed tickets.
	FormatStatic Format = "gc1"

	// FormatRotating is GC2 only: in-app tickets. A ticket issued as rotating
	// cannot be admitted from a static payload, which is what makes the
	// screenshot resistance real rather than advisory.
	FormatRotating Format = "gc2"

	// FormatEither accepts both, for events that sell online and at the door and
	// accept the weaker property on the printed half.
	FormatEither Format = "both"
)

// Allows reports whether a format permits a payload kind.
func (f Format) Allows(other Format) bool {
	return f == FormatEither || f == other || f == ""
}

// Device is an enrolled scanner.
type Device struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`

	// Checkpoints is the allowlist: the checkpoints this device may scan at.
	// Empty means the device is enrolled but unassigned, which is not the same
	// as universal — an unassigned device scans nothing, because a scanner that
	// works everywhere is a scanner that admits to the pit when somebody picks
	// up the wrong phone.
	Checkpoints []venue.CheckpointCode `json:"checkpoints"`

	Revoked bool `json:"revoked,omitempty"`

	// LastSeen is used by the dashboard to show which gates have gone quiet, and
	// by the staffing view to notice a device whose battery died.
	LastSeen time.Time `json:"last_seen,omitzero"`
}

// Allows reports whether this device may scan at a checkpoint.
func (d Device) Allows(code venue.CheckpointCode) bool {
	for _, allowed := range d.Checkpoints {
		if allowed == code {
			return true
		}
	}
	return false
}

// Redemption is one recorded pass through a checkpoint. The (TicketID,
// Checkpoint, Occurrence) triple is unique, and that uniqueness constraint is
// the linearization point of the whole system.
type Redemption struct {
	TicketID   ticket.ID            `json:"ticket_id"`
	Checkpoint venue.CheckpointCode `json:"checkpoint"`
	Occurrence uint32               `json:"occurrence"`

	ScanID    ticket.ID       `json:"scan_id"`
	Device    string          `json:"device"`
	Direction venue.Direction `json:"direction"`
	Zone      venue.ZoneCode  `json:"zone"`

	HLC hlc.Timestamp `json:"hlc"`
	At  time.Time     `json:"at,omitzero"`
	Seq uint64        `json:"seq"`

	Offline bool `json:"offline,omitempty"`
}

// DoubleUse is a flagged conflict: two admissions for one ticket where only one
// should exist, discovered when an offline scanner reconciled.
//
// Under a partition this cannot be prevented — that is CAP, not a bug — so the
// design goal is that it is always detected, always within seconds of the
// network healing, and always with both records attached so a supervisor can
// decide what actually happened.
type DoubleUse struct {
	TicketID ticket.ID `json:"ticket_id"`

	// Winner is the admission that holds the unique row; Loser is the one that
	// arrived later and was rejected by the CAS. "Loser" is about the insert,
	// not about who was physically let in: a loser with Offline set means a real
	// person really did walk through a real door.
	Winner Admission `json:"winner"`
	Loser  Admission `json:"loser"`

	HLC hlc.Timestamp `json:"hlc"`
	At  time.Time     `json:"at,omitzero"`
	Seq uint64        `json:"seq"`
}

// Tx is the set of primitives a scan decision needs, all inside one serialized
// write transaction.
//
// The interface exists so the engine can be run against three storage
// implementations with identical semantics: SQLite on the box, an in-memory
// store in the deterministic simulator, and a fault-injecting store that loses
// un-fsynced writes on demand. Everything above it — the decision logic, the
// verdicts, the audit chain — is written once and tested against all three by
// the conformance suite in this package.
//
// Every method is called at most a handful of times per scan, from a single
// goroutine, inside a transaction that the store serialises. No method may
// block on the network.
type Tx interface {
	// StoredResult returns the result of a previous scan with this id. This is
	// the idempotency lookup, and it runs first so that a retry after a Wi-Fi
	// blip replays the original verdict instead of inventing a new one.
	StoredResult(scanID ticket.ID) (Result, bool, error)

	// StoreResult records a scan's outcome against its idempotency key.
	StoreResult(scanID ticket.ID, result Result) error

	// Ticket looks a ticket up in the manifest.
	Ticket(id ticket.ID) (Ticket, bool, error)

	// Device looks up an enrolled scanner.
	Device(id string) (Device, bool, error)

	// TouchDevice records that a device is alive. Best effort: a failure here
	// must not fail a scan.
	TouchDevice(id string, at time.Time) error

	// Redemptions returns every recorded pass for a ticket, in sequence order.
	// Used for prerequisite checks, re-entry direction and pass counting.
	Redemptions(id ticket.ID) ([]Redemption, error)

	// InsertRedemption is the linearization point.
	//
	// It must behave exactly like:
	//
	//	INSERT INTO redemptions (...) VALUES (...)
	//	ON CONFLICT (ticket_id, checkpoint, occurrence) DO NOTHING
	//
	// Returning inserted=false together with the row that won. Ten scanners
	// racing on one QR code all call this; exactly one gets inserted=true, and
	// the rest get the winner to show as evidence. An implementation that
	// returns true twice breaks the only guarantee this system makes.
	InsertRedemption(r Redemption) (inserted bool, winner Redemption, err error)

	// AppendRecord writes an audit row. The engine has already linked it into
	// the hash chain, so the store must persist it exactly as given.
	AppendRecord(r audit.Record) error

	// FlagDoubleUse records a detected conflict for the security feed.
	FlagDoubleUse(f DoubleUse) error

	// NextSeq allocates the next monotonic sequence number for the redemption
	// stream. Scanners resume the SSE delta stream from a sequence, so it has to
	// be gapless and it has to survive a reboot.
	NextSeq() (uint64, error)

	// AuditHead returns the current hash-chain head and row count.
	AuditHead() (merkle.Hash, uint64, error)

	// SetAuditHead advances the persisted chain head. Called in the same
	// transaction as AppendRecord so the two can never disagree.
	SetAuditHead(head merkle.Hash, rows uint64) error
}

// Store owns transactions.
type Store interface {
	// Write runs fn inside a serialized write transaction. Exactly one Write
	// runs at a time — SQLite's single-writer model is a feature here, not a
	// limitation, because it is what makes the decision logic linearizable
	// without any locking of its own.
	//
	// If fn returns an error the transaction must roll back completely.
	Write(ctx context.Context, fn func(Tx) error) error

	// Read runs fn inside a read transaction, concurrently with a writer.
	Read(ctx context.Context, fn func(Tx) error) error
}

// ErrStoreClosed is returned by a store that has been shut down.
var ErrStoreClosed = errors.New("engine: store is closed")
