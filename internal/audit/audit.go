// Package audit implements the tamper-evident redemption log.
//
// Every admission the box records is a link in a hash chain: each row commits to
// the row before it, so inserting, deleting, editing or reordering any admission
// after the fact invalidates every row that follows. Nobody can quietly rewrite
// the door count — and "nobody" deliberately includes the organizer, who is the
// party with the strongest motive.
//
// That is the property that makes a post-event settlement dispute tractable. An
// artist's manager who thinks the door was undercounted does not have to trust
// the promoter's spreadsheet: the box publishes a Merkle root at close, and any
// specific admission can be proved against it with about twenty hashes.
//
// The chain is append-only by construction, not by permission. There is no code
// path in Gatecrash that updates or deletes a redemption row, and the verifier
// in this package is what proves that claim on a database somebody hands you.
package audit

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/merkle"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// domainRow separates audit row hashing from every other hash in the system.
const domainRow = "gatecrash/audit-row/v1"

// CheckpointEvery is how many rows the box seals into a Merkle checkpoint.
//
// A thousand rows is roughly one gate-minute at peak. Small enough that a power
// cut loses at most a minute of checkpoint coverage — the chain itself covers
// every row regardless — and large enough that sealing costs about a hundred
// microseconds of hashing per thousand admissions, which is invisible next to
// the camera pipeline.
const CheckpointEvery = 1000

// Record is one admission decision, in the exact shape the chain commits to.
//
// Every field here is part of the hash. That is a deliberate constraint on the
// design: anything worth arguing about after the event has to be in this struct,
// because anything outside it is not covered by the proof. The gate, the device,
// the seat and the verdict are all in scope, so "your staff admitted this
// wristband at the wrong door" is a provable claim rather than an assertion.
type Record struct {
	// Seq is the row's position in the chain, starting at 1.
	Seq uint64 `json:"seq"`

	TicketID   ticket.ID            `json:"ticket_id"`
	Checkpoint venue.CheckpointCode `json:"checkpoint"`

	// Occurrence distinguishes repeat passes at a re-entry or counted
	// checkpoint. Zero for the first pass, which is the only value a
	// once-only checkpoint ever has.
	Occurrence uint32 `json:"occurrence"`

	// ScanID is the client-generated idempotency key for the scan that produced
	// this row.
	ScanID ticket.ID `json:"scan_id"`

	// Device is the enrolled scanner that made the decision. Every admission is
	// attributed; an unattributed admission is not a thing the box can record.
	Device string `json:"device"`

	// Verdict is the decision. Denials are chained too: a log that only records
	// successes cannot prove that a gate was working, and "we never saw that
	// ticket" is exactly the claim a dispute turns on.
	Verdict string `json:"verdict"`

	Direction venue.Direction `json:"direction"`
	Seat      venue.SeatRef   `json:"seat,omitzero"`

	// HLC is the hybrid logical clock reading at the linearization point. This
	// is the ordering authority for the log, not wall time, because the box has
	// no reliable wall clock.
	HLC hlc.Timestamp `json:"hlc"`

	// Offline marks a row that was admitted locally by a scanner during a
	// partition and reconciled afterwards. It is in the hash because it changes
	// what the row means: an offline admission is a claim by a device, not a
	// decision by the box.
	Offline bool `json:"offline,omitempty"`

	// PrevHash and RowHash are the chain links. Both are set by Chain.Append;
	// callers leave them zero.
	PrevHash merkle.Hash `json:"prev_hash"`
	RowHash  merkle.Hash `json:"row_hash"`
}

// Canonical returns the exact bytes the row hash covers.
//
// The encoding is length-prefixed on every variable field. Without that,
// (device "a", verdict "bc") and (device "ab", verdict "c") produce identical
// bytes, which would let two different admissions share a row hash — and a
// collision in the chain is a hole in the whole guarantee. Fixed-width fields
// are big-endian so a hexdump reads in the same order as the number.
func (r Record) Canonical() []byte {
	out := make([]byte, 0, 160)
	out = appendString(out, domainRow)
	out = binary.BigEndian.AppendUint64(out, r.Seq)
	out = append(out, r.TicketID[:]...)
	out = appendString(out, string(r.Checkpoint))
	out = binary.BigEndian.AppendUint32(out, r.Occurrence)
	out = append(out, r.ScanID[:]...)
	out = appendString(out, r.Device)
	out = appendString(out, r.Verdict)
	out = appendString(out, string(r.Direction))
	out = appendString(out, string(r.Seat.Section))
	out = appendString(out, r.Seat.Row)
	out = appendString(out, r.Seat.Seat)
	out = binary.BigEndian.AppendUint64(out, uint64(r.HLC))
	if r.Offline {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	return out
}

// appendString writes a length-prefixed string. The length is a uint32 rather
// than a byte because a verdict string is short but a device name is
// operator-supplied, and a silent truncation at 255 bytes would be a collision
// generator.
func appendString(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

// Leaf returns the Merkle leaf hash for this row, which is the hash of its
// canonical form. Checkpoints are built over these.
func (r Record) Leaf() merkle.Hash { return merkle.HashLeaf(r.Canonical()) }

// hashRow computes row_hash = H(prev_hash ‖ canonical_row).
func hashRow(prev merkle.Hash, r Record) merkle.Hash {
	body := make([]byte, 0, merkle.Size+160)
	body = append(body, prev[:]...)
	body = append(body, r.Canonical()...)
	return merkle.HashLeaf(body)
}

// GenesisHash is the chain's prev_hash for the very first row. It is the hash of
// the domain string rather than zero, so that an empty chain and a chain whose
// first row was deleted are distinguishable: a zero genesis would let somebody
// drop row 1 and renumber, and the chain would still verify.
func GenesisHash() merkle.Hash { return merkle.HashLeaf([]byte(domainRow + "/genesis")) }

// Chain appends rows and maintains the running hash.
//
// It is safe for concurrent use, but in practice exactly one goroutine calls
// Append: the redemption engine's single writer. The mutex is here because the
// dashboard reads Head and Len from its own goroutine, and a torn read of a
// 32-byte hash would show an operator a chain head that never existed.
type Chain struct {
	mu   sync.RWMutex
	head merkle.Hash
	seq  uint64

	// leaves accumulates row leaf hashes for the current checkpoint window.
	// Only the window is held in memory; sealed checkpoints keep their root and
	// the rows themselves live in SQLite, so a long event does not grow this
	// without bound.
	leaves []merkle.Hash

	// window is the checkpoint size, kept as a field so tests can seal small
	// checkpoints without generating a thousand rows.
	window int
}

// NewChain starts a chain at the genesis hash.
func NewChain() *Chain {
	return &Chain{head: GenesisHash(), window: CheckpointEvery}
}

// Resume restores a chain's position from persisted state, which is what happens
// on every boot after the first and after every power cut.
//
// The caller passes the head hash and sequence it read from the database plus
// the leaf hashes of the rows since the last sealed checkpoint. Getting the
// leaves wrong would produce a checkpoint root that does not match the log, so
// the store recomputes them from the rows rather than caching them.
func Resume(head merkle.Hash, seq uint64, pending []merkle.Hash) *Chain {
	if head.IsZero() {
		head = GenesisHash()
	}
	return &Chain{
		head:   head,
		seq:    seq,
		leaves: append([]merkle.Hash(nil), pending...),
		window: CheckpointEvery,
	}
}

// SetCheckpointWindow overrides how many rows seal a checkpoint. Intended for
// tests and for the simulator, which needs to exercise sealing without
// generating a thousand admissions per scenario.
func (c *Chain) SetCheckpointWindow(rows int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rows > 0 {
		c.window = rows
	}
}

// ErrSequence is returned when a row's sequence does not follow the chain, which
// means the caller and the chain disagree about how many rows exist.
var ErrSequence = errors.New("audit: sequence does not follow the chain")

// Append links a row into the chain, filling in its sequence and hashes.
//
// The returned record is the one to persist. Nothing is written to storage here:
// the chain is an in-memory accumulator, and the engine writes the row and
// advances the chain inside one SQLite transaction so that a crash between the
// two is impossible.
func (c *Chain) Append(r Record) (Record, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// A caller-supplied sequence must match; zero means "you assign it". The
	// engine supplies one so that the value it writes to SQLite and the value in
	// the hash cannot drift.
	next := c.seq + 1
	if r.Seq != 0 && r.Seq != next {
		return Record{}, fmt.Errorf("%w: row claims seq %d, chain is at %d", ErrSequence, r.Seq, c.seq)
	}
	r.Seq = next
	r.PrevHash = c.head
	r.RowHash = hashRow(c.head, r)

	c.head = r.RowHash
	c.seq = next
	c.leaves = append(c.leaves, r.Leaf())
	return r, nil
}

// Head returns the current chain head.
func (c *Chain) Head() merkle.Hash {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.head
}

// Len returns how many rows have been appended.
func (c *Chain) Len() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.seq
}

// Pending returns the leaf hashes accumulated since the last seal. The store
// persists these so a reboot can Resume without replaying the whole log.
func (c *Chain) Pending() []merkle.Hash {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]merkle.Hash(nil), c.leaves...)
}

// DueForCheckpoint reports whether enough rows have accumulated to seal.
func (c *Chain) DueForCheckpoint() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.leaves) >= c.window
}

// Checkpoint is a sealed, publishable statement about the log.
type Checkpoint struct {
	// Seq is the last row covered.
	Seq uint64 `json:"seq"`

	// Rows is how many rows this checkpoint's tree covers, which is the same as
	// Seq for a cumulative tree but is stated explicitly because a verifier
	// needs the tree size to check an inclusion proof.
	Rows uint64 `json:"rows"`

	// Root is the Merkle root over every row leaf from 1 to Seq.
	Root merkle.Hash `json:"root"`

	// Head is the hash-chain head at the same point. Publishing both means a
	// verifier can check either property: the chain proves append-only, the root
	// proves membership cheaply.
	Head merkle.Hash `json:"head"`

	HLC hlc.Timestamp `json:"hlc"`
}

// Seal builds a checkpoint over every row leaf from the start of the log.
//
// The tree is cumulative rather than per-window because that is what makes a
// proof useful: an inclusion proof against the latest published root covers any
// row in the event, so the organizer publishes one 32-byte number at close and
// every admission that ever happened is provable against it. Per-window trees
// would need the manager to be handed a list of roots and told which one their
// row lives under, which is not a settlement process anybody would accept.
//
// The caller supplies every leaf, which the store reads back from the rows. At
// fifty thousand admissions that is a 1.6 MB read and about five milliseconds of
// hashing, done between scans rather than on the scan path.
func Seal(allLeaves []merkle.Hash, head merkle.Hash, at hlc.Timestamp) Checkpoint {
	return Checkpoint{
		Seq:  uint64(len(allLeaves)),
		Rows: uint64(len(allLeaves)),
		Root: merkle.Root(allLeaves),
		Head: head,
		HLC:  at,
	}
}

// MarkSealed clears the pending window after a checkpoint has been persisted.
func (c *Chain) MarkSealed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leaves = c.leaves[:0]
}

// Errors returned by Verify. They are distinct because they mean different
// things to an operator: a broken link is evidence of tampering, whereas a
// sequence gap is usually evidence of a bad export.
var (
	// ErrBrokenLink means a row's prev_hash does not match the previous row's
	// row_hash. Something between the two rows was inserted, deleted or edited.
	ErrBrokenLink = errors.New("audit: chain link is broken")

	// ErrBadRowHash means a row's own hash does not match its contents. That row
	// was edited in place.
	ErrBadRowHash = errors.New("audit: row hash does not match its contents")

	// ErrGap means the sequence numbers are not consecutive.
	ErrGap = errors.New("audit: sequence gap")
)

// Verify replays a chain and reports the first inconsistency.
//
// This is the function an auditor runs against a database handed to them by
// somebody they do not trust. It takes rows in sequence order and needs nothing
// else — no keys, no network, no cooperation from the box.
func Verify(rows []Record) error {
	previous := GenesisHash()
	var expectedSeq uint64 = 1

	for i, row := range rows {
		if row.Seq != expectedSeq {
			return fmt.Errorf("%w: row %d claims seq %d, expected %d", ErrGap, i, row.Seq, expectedSeq)
		}
		if row.PrevHash != previous {
			return fmt.Errorf("%w: row %d (seq %d) points at %s, previous row hashed to %s",
				ErrBrokenLink, i, row.Seq, row.PrevHash, previous)
		}
		// Recompute from the row's own contents. This is what catches an in-place
		// edit: the stored row_hash and prev_hash can be made consistent with
		// each other by anyone who can write the table, but not with the data.
		stored := row.RowHash
		row.RowHash = merkle.Hash{}
		if recomputed := hashRow(row.PrevHash, row); recomputed != stored {
			return fmt.Errorf("%w: row %d (seq %d) stores %s but hashes to %s",
				ErrBadRowHash, i, row.Seq, stored, recomputed)
		}
		previous = stored
		expectedSeq++
	}
	return nil
}

// VerifyCheckpoint reports whether a sealed checkpoint agrees with a set of
// rows: the chain has to verify, the head has to match, and the Merkle root has
// to be reproducible from the rows.
func VerifyCheckpoint(cp Checkpoint, rows []Record) error {
	if err := Verify(rows); err != nil {
		return err
	}
	if uint64(len(rows)) != cp.Rows {
		return fmt.Errorf("audit: checkpoint covers %d rows but %d were supplied", cp.Rows, len(rows))
	}
	if len(rows) > 0 {
		if head := rows[len(rows)-1].RowHash; head != cp.Head {
			return fmt.Errorf("%w: checkpoint head %s, log head %s", ErrBrokenLink, cp.Head, head)
		}
	}
	leaves := make([]merkle.Hash, 0, len(rows))
	for _, row := range rows {
		row.PrevHash, row.RowHash = merkle.Hash{}, merkle.Hash{}
		leaves = append(leaves, row.Leaf())
	}
	if root := merkle.Root(leaves); root != cp.Root {
		return fmt.Errorf("audit: checkpoint root %s, recomputed %s", cp.Root, root)
	}
	return nil
}

// Attendance is a provable statement that one ticket was admitted, which is what
// a settlement dispute actually needs.
type Attendance struct {
	Record     Record       `json:"record"`
	Proof      merkle.Proof `json:"proof"`
	Checkpoint Checkpoint   `json:"checkpoint"`
	Signature  string       `json:"signature,omitempty"`
}

// VerifyAttendance checks an attendance proof against nothing but the published
// checkpoint root. No log, no database, no box.
func VerifyAttendance(a Attendance) error {
	row := a.Record
	row.PrevHash, row.RowHash = merkle.Hash{}, merkle.Hash{}
	if !merkle.Verify(a.Checkpoint.Root, row.Leaf(), a.Proof) {
		return errors.New("audit: attendance proof does not verify against the checkpoint root")
	}
	return nil
}
