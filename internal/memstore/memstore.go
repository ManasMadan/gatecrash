// Package memstore is an in-memory implementation of the redemption engine's
// store, used by the engine's own tests and by the deterministic simulator.
//
// It exists because the engine's interesting properties are about concurrency,
// partitions, crashes and power loss, and none of those are testable against a
// real SQLite file at the rate the simulator needs. Running thousands of seeded
// event-days per second requires a store that lives in a map.
//
// The risk with a second implementation of a linearization point is that it
// drifts from the real one and the tests stop meaning anything. That is what the
// conformance suite in internal/engine is for: both this store and the SQLite
// store are run against the same assertions, so a divergence is a test failure
// rather than a surprise at a gate.
package memstore

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/merkle"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// key identifies a redemption row uniquely. This composite is the whole
// guarantee: the map it indexes is the compare-and-set.
type key struct {
	ticket     ticket.ID
	checkpoint venue.CheckpointCode
	occurrence uint32
}

// Store is an in-memory engine.Store.
//
// Writes are serialised by a single mutex, which is the same shape as SQLite's
// single-writer model and therefore reproduces the property the engine relies
// on. Reads take the same lock: the simulator does not care about read
// concurrency, and a read-write mutex here would only invite a bug where a read
// transaction observes a half-applied write.
type Store struct {
	mu sync.Mutex

	tickets     map[ticket.ID]engine.Ticket
	devices     map[string]engine.Device
	redemptions map[key]engine.Redemption
	byTicket    map[ticket.ID][]engine.Redemption
	results     map[ticket.ID]engine.Result
	records     []audit.Record
	flags       []engine.DoubleUse

	seq       uint64
	auditHead merkle.Hash
	auditRows uint64

	closed bool

	// durable holds the last state considered flushed to disk. Cut() discards
	// everything written since, which is how the simulator models a power cut
	// mid-write on an SD card that lied about fsync.
	durable *snapshot

	// failWrites, when set, makes every Write fail. Used to simulate a store
	// that has gone away underneath a running box.
	failWrites error
}

// New returns an empty store.
func New() *Store {
	s := &Store{
		tickets:     make(map[ticket.ID]engine.Ticket),
		devices:     make(map[string]engine.Device),
		redemptions: make(map[key]engine.Redemption),
		byTicket:    make(map[ticket.ID][]engine.Redemption),
		results:     make(map[ticket.ID]engine.Result),
	}
	s.durable = s.snapshotLocked()
	return s
}

// PutTicket loads a ticket into the manifest.
func (s *Store) PutTicket(t engine.Ticket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickets[t.ID] = t
}

// PutDevice enrolls a scanner.
func (s *Store) PutDevice(d engine.Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[d.ID] = d
}

// Revoke marks a ticket revoked, as the dashboard's one-tap revocation does.
func (s *Store) Revoke(id ticket.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tickets[id]; ok {
		t.Revoked = true
		s.tickets[id] = t
	}
}

// RevokeDevice marks a scanner revoked, as happens when one is stolen.
func (s *Store) RevokeDevice(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devices[id]; ok {
		d.Revoked = true
		s.devices[id] = d
	}
}

// Records returns the audit log in sequence order.
func (s *Store) Records() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Record(nil), s.records...)
}

// Flags returns every detected double use.
func (s *Store) Flags() []engine.DoubleUse {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]engine.DoubleUse(nil), s.flags...)
}

// Admissions returns every recorded redemption in sequence order.
func (s *Store) Admissions() []engine.Redemption {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]engine.Redemption, 0, len(s.redemptions))
	for _, r := range s.redemptions {
		out = append(out, r)
	}
	// Sequence order, because callers use this to assert on ordering and a map
	// walk would make the assertion nondeterministic.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Seq < out[j-1].Seq; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// AdmitCount returns how many admissions exist for a ticket at a checkpoint.
// The simulator's central invariant is that this never exceeds one for a
// once-only checkpoint.
func (s *Store) AdmitCount(id ticket.ID, cp venue.CheckpointCode) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for k := range s.redemptions {
		if k.ticket == id && k.checkpoint == cp {
			count++
		}
	}
	return count
}

// Close makes every subsequent transaction fail.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
}

// FailWrites makes every Write return err until called again with nil.
func (s *Store) FailWrites(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWrites = err
}

// Flush marks the current state durable, as an fsync that actually reached the
// card would.
func (s *Store) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.durable = s.snapshotLocked()
}

// Cut simulates a power cut: everything written since the last Flush is lost.
//
// This is the model of an SD card that acknowledged a write it had not
// committed, which is the normal behaviour of cheap cards and the reason the
// real store runs SQLite with synchronous=FULL and ships its WAL elsewhere. The
// property the simulator asserts across a Cut is not that no data is lost — data
// is lost, that is the point — but that whatever survives is a consistent
// prefix, and that no scan the box acknowledged goes missing.
func (s *Store) Cut() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restoreLocked(s.durable)
}

// snapshot is a deep copy of the store's state.
type snapshot struct {
	redemptions map[key]engine.Redemption
	byTicket    map[ticket.ID][]engine.Redemption
	results     map[ticket.ID]engine.Result
	records     []audit.Record
	flags       []engine.DoubleUse
	seq         uint64
	auditHead   merkle.Hash
	auditRows   uint64
}

func (s *Store) snapshotLocked() *snapshot {
	out := &snapshot{
		redemptions: make(map[key]engine.Redemption, len(s.redemptions)),
		byTicket:    make(map[ticket.ID][]engine.Redemption, len(s.byTicket)),
		results:     make(map[ticket.ID]engine.Result, len(s.results)),
		records:     append([]audit.Record(nil), s.records...),
		flags:       append([]engine.DoubleUse(nil), s.flags...),
		seq:         s.seq,
		auditHead:   s.auditHead,
		auditRows:   s.auditRows,
	}
	for k, v := range s.redemptions {
		out.redemptions[k] = v
	}
	for k, v := range s.byTicket {
		out.byTicket[k] = append([]engine.Redemption(nil), v...)
	}
	for k, v := range s.results {
		out.results[k] = v
	}
	return out
}

func (s *Store) restoreLocked(from *snapshot) {
	s.redemptions = make(map[key]engine.Redemption, len(from.redemptions))
	for k, v := range from.redemptions {
		s.redemptions[k] = v
	}
	s.byTicket = make(map[ticket.ID][]engine.Redemption, len(from.byTicket))
	for k, v := range from.byTicket {
		s.byTicket[k] = append([]engine.Redemption(nil), v...)
	}
	s.results = make(map[ticket.ID]engine.Result, len(from.results))
	for k, v := range from.results {
		s.results[k] = v
	}
	s.records = append([]audit.Record(nil), from.records...)
	s.flags = append([]engine.DoubleUse(nil), from.flags...)
	s.seq, s.auditHead, s.auditRows = from.seq, from.auditHead, from.auditRows
}

// Write runs fn in a serialized transaction.
//
// Mutations are applied in place and each one records how to undo itself; a
// returned error replays the undo log in reverse. The obvious alternative —
// snapshot the store, mutate the copy, swap on success — is what this used to do,
// and it cost a full copy of every map on every scan: 3.7 MB and 1.2 ms per
// admission, which made the deterministic simulator quadratic and put ten million
// simulated scans out of reach. An undo log is O(changes per transaction).
//
// Applying in place also means a transaction reads its own writes, which is what
// the real SQLite store does and therefore what the engine is entitled to
// assume.
func (s *Store) Write(ctx context.Context, fn func(engine.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return engine.ErrStoreClosed
	}
	if s.failWrites != nil {
		return s.failWrites
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	tx := &tx{store: s, write: true}
	if err := fn(tx); err != nil {
		tx.rollback()
		return err
	}
	return nil
}

// Read runs fn against the committed state. The transaction refuses writes.
func (s *Store) Read(ctx context.Context, fn func(engine.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return engine.ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(&tx{store: s, write: false})
}

// ErrReadOnly is returned when a read transaction attempts a write.
var ErrReadOnly = errors.New("memstore: write attempted in a read transaction")

// tx is one transaction.
type tx struct {
	store *Store
	write bool

	// undo holds one reversal per mutation, replayed backwards on rollback.
	undo []func()
}

func (t *tx) rollback() {
	for i := len(t.undo) - 1; i >= 0; i-- {
		t.undo[i]()
	}
	t.undo = nil
}

func (t *tx) StoredResult(scanID ticket.ID) (engine.Result, bool, error) {
	result, ok := t.store.results[scanID]
	return result, ok, nil
}

func (t *tx) StoreResult(scanID ticket.ID, result engine.Result) error {
	if !t.write {
		return ErrReadOnly
	}
	previous, existed := t.store.results[scanID]
	t.store.results[scanID] = result
	t.undo = append(t.undo, func() {
		if existed {
			t.store.results[scanID] = previous
			return
		}
		delete(t.store.results, scanID)
	})
	return nil
}

func (t *tx) Ticket(id ticket.ID) (engine.Ticket, bool, error) {
	// Tickets and devices are manifest state rather than transactional state: the
	// manifest is loaded before doors and a scan never writes to it.
	found, ok := t.store.tickets[id]
	return found, ok, nil
}

func (t *tx) Device(id string) (engine.Device, bool, error) {
	found, ok := t.store.devices[id]
	return found, ok, nil
}

// TouchDevice writes outside the undo log, so a liveness update survives a
// rollback. That is deliberate and matches the SQLite store: device liveness is
// a monitoring signal, not part of the redemption decision, and making it
// transactional would mean a rolled-back scan erases the evidence that the
// scanner was talking to us at all.
func (t *tx) TouchDevice(id string, at time.Time) error {
	if !t.write {
		return ErrReadOnly
	}
	if d, ok := t.store.devices[id]; ok {
		d.LastSeen = at
		t.store.devices[id] = d
	}
	return nil
}

func (t *tx) Redemptions(id ticket.ID) ([]engine.Redemption, error) {
	return append([]engine.Redemption(nil), t.store.byTicket[id]...), nil
}

// InsertRedemption is the linearization point: an insert that does nothing on
// conflict, reporting which row won.
func (t *tx) InsertRedemption(r engine.Redemption) (bool, engine.Redemption, error) {
	if !t.write {
		return false, engine.Redemption{}, ErrReadOnly
	}
	k := key{ticket: r.TicketID, checkpoint: r.Checkpoint, occurrence: r.Occurrence}
	if winner, exists := t.store.redemptions[k]; exists {
		return false, winner, nil
	}
	t.store.redemptions[k] = r
	t.store.byTicket[r.TicketID] = append(t.store.byTicket[r.TicketID], r)
	t.undo = append(t.undo, func() {
		delete(t.store.redemptions, k)
		held := t.store.byTicket[r.TicketID]
		if len(held) > 0 {
			t.store.byTicket[r.TicketID] = held[:len(held)-1]
		}
	})
	return true, r, nil
}

func (t *tx) AppendRecord(r audit.Record) error {
	if !t.write {
		return ErrReadOnly
	}
	t.store.records = append(t.store.records, r)
	t.undo = append(t.undo, func() {
		t.store.records = t.store.records[:len(t.store.records)-1]
	})
	return nil
}

func (t *tx) FlagDoubleUse(f engine.DoubleUse) error {
	if !t.write {
		return ErrReadOnly
	}
	t.store.flags = append(t.store.flags, f)
	t.undo = append(t.undo, func() {
		t.store.flags = t.store.flags[:len(t.store.flags)-1]
	})
	return nil
}

func (t *tx) NextSeq() (uint64, error) {
	if !t.write {
		return 0, ErrReadOnly
	}
	t.store.seq++
	allocated := t.store.seq
	t.undo = append(t.undo, func() { t.store.seq = allocated - 1 })
	return allocated, nil
}

func (t *tx) AuditHead() (merkle.Hash, uint64, error) {
	return t.store.auditHead, t.store.auditRows, nil
}

func (t *tx) SetAuditHead(head merkle.Hash, rows uint64) error {
	if !t.write {
		return ErrReadOnly
	}
	previousHead, previousRows := t.store.auditHead, t.store.auditRows
	t.store.auditHead, t.store.auditRows = head, rows
	t.undo = append(t.undo, func() {
		t.store.auditHead, t.store.auditRows = previousHead, previousRows
	})
	return nil
}
