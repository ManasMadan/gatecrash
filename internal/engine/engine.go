package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/merkle"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// Mode is the event's consistency posture, and it is the one place where the box
// asks the organizer to make a CAP tradeoff out loud.
type Mode string

// The two modes.
const (
	// ModeStrict is CP and the default. During a scanner-to-box partition the
	// gate shows amber and stops admitting. The guarantee is absolute: at most
	// one ADMIT per ticket per once-only checkpoint, ever, linearizable.
	ModeStrict Mode = "strict"

	// ModeDegraded is AP and opt-in per event. During a partition a scanner
	// keeps admitting from its local mirror and queues the scans. Double use
	// becomes possible and is instead detected and flagged within seconds of the
	// network healing, with both records as evidence.
	//
	// Prevention under partition is impossible. That is CAP, not an
	// implementation shortcoming, and the honest thing is to offer the choice
	// with the consequence written down rather than to pick one silently.
	ModeDegraded Mode = "degraded"
)

// Config is everything the engine needs that does not come from the store.
type Config struct {
	// EventID scopes every ticket. A valid ticket for another show is a
	// WrongEvent, not an UnknownTicket, and telling them apart is what stops a
	// multi-room venue's staff from thinking their manifest is broken.
	EventID ticket.ID

	// Venue is the compiled venue graph.
	Venue *venue.Venue

	// Verifying is the organizer's public key, used to check GC1 signatures.
	Verifying ticket.VerifyingKey

	// Master is the event master key, used to derive per-ticket secrets for GC2
	// validation. Zero disables GC2, which is a supported configuration for
	// print-only events.
	Master ticket.MasterKey

	Mode Mode

	// Now is the box's clock. Injected so the deterministic simulator can drive
	// it; nothing in the engine calls time.Now directly.
	Now func() time.Time

	// Clock is the hybrid logical clock. Optional: one is built over Now when
	// this is nil.
	Clock *hlc.Clock
}

// Engine decides scans.
//
// One Engine serves every gate. It is safe for concurrent use: reads take no
// locks at all, and writes are serialised by the store's single writer plus one
// mutex protecting the in-memory chain head. There is no per-gate state, which
// is what lets a scanner reconnect to a rebooted box and carry on.
type Engine struct {
	cfg   Config
	clock *hlc.Clock

	// mu guards the chain head and row count. Held only across the write
	// transaction, which is microseconds.
	mu    sync.Mutex
	head  merkle.Hash
	rows  uint64
	ready bool

	// listeners receive every committed redemption for the SSE delta stream.
	listenersMu sync.RWMutex
	listeners   map[int]func(Redemption)
	nextID      int
}

// New builds an engine. It does not touch the store; call Recover before the
// first scan so the audit chain resumes from where the last boot left it.
func New(cfg Config) (*Engine, error) {
	switch {
	case cfg.EventID.IsZero():
		return nil, errors.New("engine: config has no event id")
	case cfg.Venue == nil:
		return nil, errors.New("engine: config has no venue")
	case cfg.Verifying.IsZero():
		return nil, errors.New("engine: config has no verifying key")
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeStrict
	}
	if cfg.Mode != ModeStrict && cfg.Mode != ModeDegraded {
		return nil, fmt.Errorf("engine: unknown mode %q", cfg.Mode)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	clock := cfg.Clock
	if clock == nil {
		clock = hlc.NewClock(cfg.Now)
	}
	return &Engine{cfg: cfg, clock: clock, listeners: make(map[int]func(Redemption))}, nil
}

// Recover reads the persisted audit head so the chain continues across a reboot.
// Calling Scan before Recover is a programming error and is refused rather than
// silently starting a second chain from genesis.
func (e *Engine) Recover(ctx context.Context, store Store) error {
	var head merkle.Hash
	var rows uint64
	if err := store.Read(ctx, func(tx Tx) error {
		var err error
		head, rows, err = tx.AuditHead()
		return err
	}); err != nil {
		return fmt.Errorf("engine: recovering audit head: %w", err)
	}
	if head.IsZero() {
		head = audit.GenesisHash()
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.head, e.rows, e.ready = head, rows, true
	return nil
}

// Mode returns the configured consistency mode.
func (e *Engine) Mode() Mode { return e.cfg.Mode }

// Clock exposes the engine's hybrid logical clock, so the SSE stream and the
// replication layer stamp messages from the same clock the gates do.
func (e *Engine) Clock() *hlc.Clock { return e.clock }

// AuditHead returns the in-memory chain head and row count.
func (e *Engine) AuditHead() (merkle.Hash, uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.head, e.rows
}

// Subscribe registers a callback invoked for every committed redemption, and
// returns a function that unregisters it.
//
// Callbacks run on the writer's goroutine immediately after commit, so they must
// not block: the SSE hub hands off to a buffered channel and returns. A listener
// that blocks here stalls every gate in the venue, which is why this is the only
// comment in the file written in capitals in spirit.
func (e *Engine) Subscribe(fn func(Redemption)) func() {
	e.listenersMu.Lock()
	id := e.nextID
	e.nextID++
	e.listeners[id] = fn
	e.listenersMu.Unlock()

	return func() {
		e.listenersMu.Lock()
		delete(e.listeners, id)
		e.listenersMu.Unlock()
	}
}

func (e *Engine) publish(r Redemption) {
	e.listenersMu.RLock()
	defer e.listenersMu.RUnlock()
	for _, fn := range e.listeners {
		fn(r)
	}
}

// Scan is one presentation of a QR code at a gate.
type Scan struct {
	// ScanID is the client-generated idempotency key. A scanner that retries
	// after a network blip resends the same id and gets the original verdict
	// back rather than a spurious "already used".
	ScanID ticket.ID

	// Payload is the raw decoded string from the camera or the barcode gun.
	Payload string

	Checkpoint venue.CheckpointCode
	Device     string

	// Direction is which way the holder is moving, for bidirectional
	// checkpoints. Empty takes the checkpoint's own direction.
	Direction venue.Direction

	// DeviceHLC is the scanner's clock reading, merged into the box's so that
	// causality across devices is preserved even though nobody's wall clock is
	// right.
	DeviceHLC hlc.Timestamp

	// OfflineAdmitted means the scanner already let this person through from its
	// local mirror during a partition. The box records the admission as offline
	// and, if it loses the CAS, flags a double use.
	OfflineAdmitted bool

	// ObservedAt is the scanner's belief about when it scanned. Advisory: shown
	// in the audit trail, never used to decide anything.
	ObservedAt time.Time
}

// ErrNotRecovered is returned when Scan is called before Recover.
var ErrNotRecovered = errors.New("engine: Recover must run before the first scan")

// Scan decides one scan and, when it admits, records it.
//
// The whole decision happens inside one write transaction. That is what makes it
// linearizable: the idempotency lookup, the prerequisite reads, the compare-and-
// set insert, the audit row and the stored result either all happen or none of
// them do, and the store runs exactly one of these at a time.
//
// The order of the checks is not arbitrary. Cheap and definitive first, so that
// a gate being sprayed with garbage QR codes spends no cryptography on them;
// attribution before authority, so an unenrolled device cannot learn whether a
// ticket exists; and the compare-and-set last, so nothing can be recorded for a
// scan that was going to be refused anyway.
func (e *Engine) Scan(ctx context.Context, store Store, scan Scan) (Result, error) {
	e.mu.Lock()
	ready := e.ready
	e.mu.Unlock()
	if !ready {
		return Result{}, ErrNotRecovered
	}
	if scan.ScanID.IsZero() {
		return Result{}, errors.New("engine: scan has no idempotency key")
	}

	var (
		result    Result
		committed *Redemption
	)

	err := store.Write(ctx, func(tx Tx) error {
		// The clock advances inside the transaction so that the timestamp on the
		// row and the timestamp in the hash are the same value, and so that two
		// concurrent scans cannot be stamped with the same reading.
		stamp := e.clock.Update(scan.DeviceHLC)
		now := e.cfg.Now()

		decision, err := e.decide(tx, scan, stamp, now)
		if err != nil {
			return err
		}
		result = decision.result
		committed = decision.committed
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	if committed != nil {
		e.publish(*committed)
	}
	return result, nil
}

// decision is the internal outcome of one pass through the decision path.
type decision struct {
	result    Result
	committed *Redemption
}

func (e *Engine) decide(tx Tx, scan Scan, stamp hlc.Timestamp, now time.Time) (decision, error) {
	// 1. Idempotency. A duplicated request is not a duplicated ticket, and this
	// is the check that keeps the two from being confused.
	if stored, found, err := tx.StoredResult(scan.ScanID); err != nil {
		return decision{}, fmt.Errorf("engine: idempotency lookup: %w", err)
	} else if found {
		stored.Idempotent = true
		return decision{result: stored}, nil
	}

	base := Result{
		ScanID:     scan.ScanID,
		Checkpoint: scan.Checkpoint,
		Device:     scan.Device,
		HLC:        stamp,
		At:         now,
	}

	// 2. Is this scanner allowed to be asking? Attribution comes before
	// everything about the ticket: an unenrolled or revoked device must not be
	// able to use the gate as an oracle for which ticket ids exist.
	device, found, err := tx.Device(scan.Device)
	if err != nil {
		return decision{}, fmt.Errorf("engine: device lookup: %w", err)
	}
	if !found || device.Revoked || !device.Allows(scan.Checkpoint) {
		return e.refuse(tx, base, ScannerNotAuthorized, scan, stamp, now)
	}
	// Best effort: a failure to record liveness must never fail a scan.
	_ = tx.TouchDevice(scan.Device, now)

	checkpoint, ok := e.cfg.Venue.Checkpoint(scan.Checkpoint)
	if !ok {
		// The device is enrolled for a checkpoint the venue does not have, which
		// means the box was reconfigured under it. Same verdict: this scanner is
		// not signed in here.
		return e.refuse(tx, base, ScannerNotAuthorized, scan, stamp, now)
	}
	base.CheckpointName = checkpoint.Name
	base.Zone = checkpoint.Zone
	if zone, ok := e.cfg.Venue.Zone(checkpoint.Zone); ok {
		base.ZoneName = zone.Name
	}

	// 3. Parse the payload. No cryptography yet: a supermarket barcode should
	// cost a string prefix comparison, not a signature verification.
	parsed, err := parsePayload(scan.Payload)
	if err != nil {
		return e.refuse(tx, base, Malformed, scan, stamp, now)
	}
	base.Ticket = parsed.ticketID

	// 4. Look the ticket up.
	record, found, err := tx.Ticket(parsed.ticketID)
	if err != nil {
		return decision{}, fmt.Errorf("engine: ticket lookup: %w", err)
	}
	if !found {
		return e.refuse(tx, base, UnknownTicket, scan, stamp, now)
	}
	if record.EventID != e.cfg.EventID {
		return e.refuse(tx, base, WrongEvent, scan, stamp, now)
	}
	if record.Revoked {
		return e.refuse(tx, base, Revoked, scan, stamp, now)
	}

	base.Tier = record.Tier
	base.Seat = record.Seat
	base.SeatLabel = e.cfg.Venue.SeatLabel(record.Seat)
	if tier, ok := e.cfg.Venue.Tier(record.Tier); ok {
		base.TierName = tier.Name
		base.TierColour = tier.Colour
	}
	if section, ok := e.cfg.Venue.Section(record.Seat.Section); ok {
		base.SectionName = section.Name
	}

	// 5. Cryptography. A ticket sold as a rotating in-app code must not be
	// admissible from a static payload, or the screenshot resistance is a
	// suggestion rather than a property.
	if !record.Format.Allows(parsed.format) {
		return e.refuse(tx, base, InvalidSig, scan, stamp, now)
	}
	if verdict := e.verify(parsed, record, now); verdict != Admit {
		return e.refuse(tx, base, verdict, scan, stamp, now)
	}

	// 6. Is the holder entitled to be behind this checkpoint at all?
	if !e.cfg.Venue.TierAdmits(record.Tier, checkpoint.Zone) {
		return e.refuse(tx, base, WrongZone, scan, stamp, now)
	}

	// 7. Is this their door? Entitled but misrouted is an amber verdict with
	// directions, not a red one.
	if !e.cfg.Venue.CheckpointServes(scan.Checkpoint, record.Tier, record.Seat) {
		base.Redirect = e.redirectsFor(record, checkpoint.Zone)
		return e.refuse(tx, base, WrongDoor, scan, stamp, now)
	}

	// 8. Opening hours.
	if !e.cfg.Venue.CheckpointOpen(scan.Checkpoint, now) {
		return e.refuse(tx, base, DoorsClosed, scan, stamp, now)
	}

	// 9. Read this ticket's history. One read serves the prerequisite check, the
	// re-entry direction and the pass count.
	history, err := tx.Redemptions(parsed.ticketID)
	if err != nil {
		return decision{}, fmt.Errorf("engine: redemption history: %w", err)
	}

	// 10. Prerequisites: has this person been where they need to have been?
	if missing := e.unmetPrerequisites(checkpoint, history); len(missing) > 0 {
		base.Missing = missing
		base.Redirect = e.redirectsForZones(record, missing)
		return e.refuse(tx, base, PrerequisiteMissing, scan, stamp, now)
	}

	// 11. Policy: how many times may this ticket pass this door, and which way?
	pass, verdict := e.nextPass(checkpoint, scan, history)
	if verdict != Admit {
		base.Direction = pass.direction
		base.Occurrence = pass.occurrence
		if pass.passesLeft != nil {
			base.PassesLeft = pass.passesLeft
		}
		if pass.previous != nil {
			base.Previous = pass.previous
			base.Ago = pass.previous.Ago(now)
		}
		return e.refuse(tx, base, verdict, scan, stamp, now)
	}
	base.Direction = pass.direction
	base.Occurrence = pass.occurrence
	base.PassesLeft = pass.passesLeft

	// 12. The linearization point.
	seq, err := tx.NextSeq()
	if err != nil {
		return decision{}, fmt.Errorf("engine: allocating sequence: %w", err)
	}
	candidate := Redemption{
		TicketID:   parsed.ticketID,
		Checkpoint: scan.Checkpoint,
		Occurrence: pass.occurrence,
		ScanID:     scan.ScanID,
		Device:     scan.Device,
		Direction:  pass.direction,
		Zone:       checkpoint.Zone,
		HLC:        stamp,
		At:         now,
		Seq:        seq,
		Offline:    scan.OfflineAdmitted,
	}

	inserted, winner, err := tx.InsertRedemption(candidate)
	if err != nil {
		return decision{}, fmt.Errorf("engine: compare-and-set: %w", err)
	}
	if !inserted {
		// Somebody else got there first. This is the interesting branch and the
		// whole reason the insert is a CAS rather than a read-then-write.
		previous := admissionOf(winner, e.cfg.Venue)
		base.Previous = &previous
		base.Ago = previous.Ago(now)
		base.Occurrence = winner.Occurrence

		if scan.OfflineAdmitted {
			// A real person really did walk through a real door on this
			// scanner's local decision, and another gate had already admitted
			// the same ticket. Prevention was impossible under the partition;
			// detection is not, and this is it.
			base.Flagged = true
			loser := admissionOf(candidate, e.cfg.Venue)
			if err := tx.FlagDoubleUse(DoubleUse{
				TicketID: parsed.ticketID,
				Winner:   previous,
				Loser:    loser,
				HLC:      stamp,
				At:       now,
				Seq:      seq,
			}); err != nil {
				return decision{}, fmt.Errorf("engine: flagging double use: %w", err)
			}
		}
		return e.refuse(tx, base, AlreadyUsed, scan, stamp, now)
	}

	base.Verdict = Admit
	base.Severity = SeverityAdmit
	base.Reason = Admit.Reason()
	base.Seq = seq

	if err := e.record(tx, base, scan, stamp); err != nil {
		return decision{}, err
	}
	if err := tx.StoreResult(scan.ScanID, base); err != nil {
		return decision{}, fmt.Errorf("engine: storing result: %w", err)
	}
	return decision{result: base, committed: &candidate}, nil
}

// refuse finalises a denial: it fills in the presentation fields, writes the
// audit row and stores the result under the idempotency key.
//
// Denials are chained too. A log that records only successes cannot prove a gate
// was working, and "we never saw that ticket" is precisely the claim a dispute
// turns on.
func (e *Engine) refuse(tx Tx, base Result, verdict Verdict, scan Scan, stamp hlc.Timestamp, now time.Time) (decision, error) {
	base.Verdict = verdict
	base.Severity = verdict.Severity()
	base.Reason = verdict.Reason()

	if err := e.record(tx, base, scan, stamp); err != nil {
		return decision{}, err
	}
	if err := tx.StoreResult(scan.ScanID, base); err != nil {
		return decision{}, fmt.Errorf("engine: storing result: %w", err)
	}
	return decision{result: base}, nil
}

// record links one audit row into the hash chain and persists it, advancing the
// in-memory head only once the store has accepted it.
func (e *Engine) record(tx Tx, result Result, scan Scan, stamp hlc.Timestamp) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	row := audit.Link(e.head, e.rows+1, audit.Record{
		TicketID:   result.Ticket,
		Checkpoint: result.Checkpoint,
		Occurrence: result.Occurrence,
		ScanID:     result.ScanID,
		Device:     result.Device,
		Verdict:    string(result.Verdict),
		Direction:  result.Direction,
		Seat:       result.Seat,
		HLC:        stamp,
		Offline:    scan.OfflineAdmitted,
	})
	if err := tx.AppendRecord(row); err != nil {
		return fmt.Errorf("engine: appending audit row: %w", err)
	}
	if err := tx.SetAuditHead(row.RowHash, row.Seq); err != nil {
		return fmt.Errorf("engine: advancing audit head: %w", err)
	}
	// Only now, with the store having accepted both writes, does the in-memory
	// chain move. If the surrounding transaction rolls back after this point the
	// head is wrong until the next Recover, which is why Recover runs on every
	// boot rather than only on the first.
	e.head, e.rows = row.RowHash, row.Seq
	return nil
}

// admissionOf renders a stored redemption as the evidence a denial carries.
func admissionOf(r Redemption, v *venue.Venue) Admission {
	out := Admission{
		Checkpoint: r.Checkpoint,
		Device:     r.Device,
		Occurrence: r.Occurrence,
		Direction:  r.Direction,
		HLC:        r.HLC,
		At:         r.At,
		Offline:    r.Offline,
	}
	if cp, ok := v.Checkpoint(r.Checkpoint); ok {
		out.CheckpointName = cp.Name
	}
	return out
}
