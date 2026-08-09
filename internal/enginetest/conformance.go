package enginetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/merkle"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// Loader is what a store implementation must provide so the harness can seed a
// manifest before it starts scanning. Seeding is not part of engine.Store
// because a scan never writes to the manifest, so it does not belong on the
// scan-path interface.
type Loader interface {
	engine.Store

	// PutTicket loads one ticket.
	PutTicket(engine.Ticket)

	// PutDevice enrolls one scanner.
	PutDevice(engine.Device)
}

// VerifyStore runs the store contract against an implementation.
//
// newStore must return a fresh, empty store on every call; the harness makes
// several and does not clean up after itself.
//
// Every assertion here is about the store, not about the engine's policy
// decisions: the compare-and-set, transaction atomicity, idempotency storage,
// sequence allocation and audit-head persistence. Policy lives in the engine's
// own tests, which run once rather than once per store.
func VerifyStore(t *testing.T, newStore func(*testing.T) Loader) {
	t.Helper()

	t.Run("compare and set admits exactly once", func(t *testing.T) {
		verifyCASOnce(t, newStore)
	})
	t.Run("compare and set is safe under concurrency", func(t *testing.T) {
		verifyCASConcurrent(t, newStore)
	})
	t.Run("a rolled back transaction leaves nothing behind", func(t *testing.T) {
		verifyRollback(t, newStore)
	})
	t.Run("idempotency keys survive and replay", func(t *testing.T) {
		verifyIdempotency(t, newStore)
	})
	t.Run("sequence numbers are gapless and monotonic", func(t *testing.T) {
		verifySequence(t, newStore)
	})
	t.Run("audit head persists and the chain verifies", func(t *testing.T) {
		verifyAuditHead(t, newStore)
	})
	t.Run("read transactions refuse writes", func(t *testing.T) {
		verifyReadOnly(t, newStore)
	})
	t.Run("a closed store fails cleanly", func(t *testing.T) {
		verifyClosed(t, newStore)
	})
}

// seed builds a fixture, loads it into a store, and returns an engine ready to
// scan.
func seed(t *testing.T, store Loader, mode engine.Mode, now func() time.Time) (*Fixture, *engine.Engine) {
	t.Helper()

	f := NewFixture(t)
	for _, ticketRecord := range f.Tickets {
		store.PutTicket(ticketRecord)
	}
	for _, device := range f.Devices() {
		store.PutDevice(device)
	}

	e, err := engine.New(f.Config(mode, now))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	return f, e
}

// during is a clock reading inside the event.
func during() time.Time { return Doors.Add(90 * time.Minute) }

// verifyCASOnce is the headline assertion: one ticket, one admission at a
// once-only checkpoint, and the loser is told who won.
func verifyCASOnce(t *testing.T, newStore func(*testing.T) Loader) {
	store := newStore(t)
	f, e := seed(t, store, engine.ModeStrict, during)
	ctx := context.Background()

	first, err := e.Scan(ctx, store, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: f.Payloads["ga-standing"],
		Checkpoint: "gate-north", Device: "scanner-north",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Verdict != engine.Admit {
		t.Fatalf("first scan gave %s (%s), want ADMIT", first.Verdict, first.Reason)
	}

	// A different scan id for the same ticket at the same door: this is reuse,
	// not a retry, and it must lose.
	second, err := e.Scan(ctx, store, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: f.Payloads["ga-standing"],
		Checkpoint: "gate-north", Device: "scanner-north-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Verdict != engine.AlreadyUsed {
		t.Fatalf("second scan gave %s, want ALREADY_USED", second.Verdict)
	}
	if second.Idempotent {
		t.Error("a genuine reuse was reported as an idempotent replay")
	}
	if second.Previous == nil {
		t.Fatal("ALREADY_USED carries no evidence of the winning admission")
	}
	if second.Previous.Device != "scanner-north" {
		t.Errorf("evidence names device %q, want scanner-north", second.Previous.Device)
	}
	if second.Previous.Checkpoint != "gate-north" {
		t.Errorf("evidence names checkpoint %q, want gate-north", second.Previous.Checkpoint)
	}
}

// verifyCASConcurrent is the property the README claims: ten scanners hammering
// one QR code produce exactly one admission.
func verifyCASConcurrent(t *testing.T, newStore func(*testing.T) Loader) {
	store := newStore(t)
	f, e := seed(t, store, engine.ModeStrict, during)
	ctx := context.Background()

	const racers = 10
	verdicts := make([]engine.Verdict, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			result, err := e.Scan(ctx, store, engine.Scan{
				ScanID: ticket.MustNewID(), Payload: f.Payloads["ga-standing"],
				Checkpoint: "gate-north", Device: "scanner-north",
				DeviceHLC: hlc.New(uint64(during().UnixMilli()), uint16(i)),
			})
			if err != nil {
				t.Error(err)
				return
			}
			verdicts[i] = result.Verdict
		}(i)
	}
	close(start)
	wg.Wait()

	admits := 0
	for i, verdict := range verdicts {
		switch verdict {
		case engine.Admit:
			admits++
		case engine.AlreadyUsed:
		default:
			t.Errorf("racer %d got %s, want ADMIT or ALREADY_USED", i, verdict)
		}
	}
	if admits != 1 {
		t.Fatalf("%d of %d concurrent scans were admitted, want exactly 1", admits, racers)
	}
}

// verifyRollback checks that a failed transaction leaves no trace. A store that
// half-applies a scan would leave the audit chain permanently broken.
func verifyRollback(t *testing.T, newStore func(*testing.T) Loader) {
	store := newStore(t)
	ctx := context.Background()

	sentinel := errors.New("deliberate failure")
	scanID := ticket.MustNewID()

	err := store.Write(ctx, func(tx engine.Tx) error {
		if _, err := tx.NextSeq(); err != nil {
			return err
		}
		if err := tx.StoreResult(scanID, engine.Result{Verdict: engine.Admit}); err != nil {
			return err
		}
		if _, _, err := tx.InsertRedemption(engine.Redemption{
			TicketID: ticket.MustNewID(), Checkpoint: "gate-north", Occurrence: 0,
		}); err != nil {
			return err
		}
		if err := tx.SetAuditHead(merkle.HashLeaf([]byte("nope")), 99); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write returned %v, want the sentinel error", err)
	}

	if err := store.Read(ctx, func(tx engine.Tx) error {
		if _, found, err := tx.StoredResult(scanID); err != nil {
			return err
		} else if found {
			t.Error("a rolled back transaction left a stored result behind")
		}
		head, rows, err := tx.AuditHead()
		if err != nil {
			return err
		}
		if rows != 0 || !head.IsZero() {
			t.Errorf("a rolled back transaction advanced the audit head to %s at %d rows", head, rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// And the sequence it consumed must not have leaked either: the delta stream
	// scanners resume from has to be gapless.
	if err := store.Write(ctx, func(tx engine.Tx) error {
		seq, err := tx.NextSeq()
		if err != nil {
			return err
		}
		if seq != 1 {
			t.Errorf("first sequence after a rollback is %d, want 1", seq)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// verifyIdempotency is the distinction most systems get wrong: a duplicated
// request is not a duplicated ticket.
func verifyIdempotency(t *testing.T, newStore func(*testing.T) Loader) {
	store := newStore(t)
	f, e := seed(t, store, engine.ModeStrict, during)
	ctx := context.Background()

	scanID := ticket.MustNewID()
	scan := engine.Scan{
		ScanID: scanID, Payload: f.Payloads["ga-standing"],
		Checkpoint: "gate-north", Device: "scanner-north",
	}

	first, err := e.Scan(ctx, store, scan)
	if err != nil {
		t.Fatal(err)
	}
	if first.Verdict != engine.Admit || first.Idempotent {
		t.Fatalf("first scan gave %s idempotent=%v", first.Verdict, first.Idempotent)
	}

	// The same scan id again, five times, as a flaky Wi-Fi link would.
	for i := 0; i < 5; i++ {
		replay, err := e.Scan(ctx, store, scan)
		if err != nil {
			t.Fatal(err)
		}
		if replay.Verdict != engine.Admit {
			t.Fatalf("replay %d gave %s, want the original ADMIT", i, replay.Verdict)
		}
		if !replay.Idempotent {
			t.Errorf("replay %d is not marked idempotent", i)
		}
		if replay.Seq != first.Seq {
			t.Errorf("replay %d has seq %d, want the original %d", i, replay.Seq, first.Seq)
		}
	}

	// Denials are idempotent too. A retried scan of a revoked ticket must not
	// produce a second audit row per retry, or a flapping link inflates the log.
	denyID := ticket.MustNewID()
	denyScan := engine.Scan{
		ScanID: denyID, Payload: f.Payloads["revoked"],
		Checkpoint: "gate-north", Device: "scanner-north",
	}
	firstDeny, err := e.Scan(ctx, store, denyScan)
	if err != nil {
		t.Fatal(err)
	}
	if firstDeny.Verdict != engine.Revoked {
		t.Fatalf("got %s, want REVOKED", firstDeny.Verdict)
	}
	replayDeny, err := e.Scan(ctx, store, denyScan)
	if err != nil {
		t.Fatal(err)
	}
	if !replayDeny.Idempotent || replayDeny.Verdict != engine.Revoked {
		t.Fatalf("replayed denial gave %s idempotent=%v", replayDeny.Verdict, replayDeny.Idempotent)
	}
}

func verifySequence(t *testing.T, newStore func(*testing.T) Loader) {
	store := newStore(t)
	ctx := context.Background()

	const rounds = 200
	seen := make(map[uint64]bool, rounds)
	var previous uint64

	for i := 0; i < rounds; i++ {
		if err := store.Write(ctx, func(tx engine.Tx) error {
			seq, err := tx.NextSeq()
			if err != nil {
				return err
			}
			if seq <= previous {
				t.Fatalf("sequence %d did not advance past %d", seq, previous)
			}
			if seen[seq] {
				t.Fatalf("sequence %d handed out twice", seq)
			}
			seen[seq] = true
			previous = seq
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if previous != rounds {
		t.Fatalf("last sequence is %d after %d allocations, so there is a gap", previous, rounds)
	}
}

func verifyAuditHead(t *testing.T, newStore func(*testing.T) Loader) {
	store := newStore(t)
	f, e := seed(t, store, engine.ModeStrict, during)
	ctx := context.Background()

	// Scan a handful of tickets, admits and denials mixed, so the chain has
	// something to say.
	for _, name := range []string{"ga-standing", "ga-block-a", "revoked", "ga-block-a", "ga-block-b"} {
		if _, err := e.Scan(ctx, store, engine.Scan{
			ScanID: ticket.MustNewID(), Payload: f.Payloads[name],
			Checkpoint: "gate-north", Device: "scanner-north",
		}); err != nil {
			t.Fatal(err)
		}
	}

	head, rows := e.AuditHead()
	if rows != 5 {
		t.Fatalf("chain has %d rows after 5 scans, want 5", rows)
	}

	var persistedHead merkle.Hash
	var persistedRows uint64
	if err := store.Read(ctx, func(tx engine.Tx) error {
		var err error
		persistedHead, persistedRows, err = tx.AuditHead()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if persistedHead != head || persistedRows != rows {
		t.Fatalf("persisted head %s at %d rows, engine has %s at %d", persistedHead, persistedRows, head, rows)
	}

	// A fresh engine over the same store must resume the same chain, which is
	// the reboot case.
	resumed, err := engine.New(f.Config(engine.ModeStrict, during))
	if err != nil {
		t.Fatal(err)
	}
	if err := resumed.Recover(ctx, store); err != nil {
		t.Fatal(err)
	}
	if resumedHead, resumedRows := resumed.AuditHead(); resumedHead != head || resumedRows != rows {
		t.Fatalf("after recovery the head is %s at %d rows, want %s at %d", resumedHead, resumedRows, head, rows)
	}

	// One more scan on the recovered engine must link to the pre-reboot chain.
	if _, err := resumed.Scan(ctx, store, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: f.Payloads["vip-pit"],
		Checkpoint: "gate-north", Device: "scanner-north",
	}); err != nil {
		t.Fatal(err)
	}
	if _, rows := resumed.AuditHead(); rows != 6 {
		t.Fatalf("chain has %d rows after the reboot scan, want 6", rows)
	}
}

func verifyReadOnly(t *testing.T, newStore func(*testing.T) Loader) {
	store := newStore(t)
	ctx := context.Background()

	// A read transaction that silently accepted writes would let a dashboard
	// query mutate the log, which is the one thing the audit design promises
	// cannot happen.
	if err := store.Read(ctx, func(tx engine.Tx) error {
		if err := tx.StoreResult(ticket.MustNewID(), engine.Result{}); err == nil {
			t.Error("a read transaction accepted StoreResult")
		}
		if _, _, err := tx.InsertRedemption(engine.Redemption{TicketID: ticket.MustNewID()}); err == nil {
			t.Error("a read transaction accepted InsertRedemption")
		}
		if err := tx.AppendRecord(audit.Record{}); err == nil {
			t.Error("a read transaction accepted AppendRecord")
		}
		if _, err := tx.NextSeq(); err == nil {
			t.Error("a read transaction accepted NextSeq")
		}
		if err := tx.SetAuditHead(merkle.Hash{}, 1); err == nil {
			t.Error("a read transaction accepted SetAuditHead")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Nothing leaked through.
	if err := store.Read(ctx, func(tx engine.Tx) error {
		_, rows, err := tx.AuditHead()
		if err != nil {
			return err
		}
		if rows != 0 {
			t.Errorf("audit head advanced to %d rows from a read transaction", rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func verifyClosed(t *testing.T, newStore func(*testing.T) Loader) {
	store := newStore(t)
	f, e := seed(t, store, engine.ModeStrict, during)
	ctx := context.Background()

	type closer interface{ Close() }
	c, ok := store.(closer)
	if !ok {
		t.Skip("store does not implement Close")
	}
	c.Close()

	// A box whose storage has gone away must return an error rather than
	// pretending to admit. The scanner then shows amber, which is exactly the
	// STRICT-mode behaviour the docs promise.
	if _, err := e.Scan(ctx, store, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: f.Payloads["ga-standing"],
		Checkpoint: "gate-north", Device: "scanner-north",
	}); err == nil {
		t.Fatal("a scan against a closed store reported success")
	}
}

// AssertChainVerifies replays a store's audit log and fails the test if it does
// not verify. Exported because the simulator and the SQLite tests both want it.
func AssertChainVerifies(t *testing.T, rows []audit.Record) {
	t.Helper()
	if err := audit.Verify(rows); err != nil {
		t.Fatalf("the audit chain does not verify: %v", err)
	}
}

// AssertNoDoubleAdmit fails the test if any ticket holds more than one admission
// at a once-only checkpoint. This is the invariant the whole system exists to
// maintain, and it is checked from the stored rows rather than from the verdicts
// the engine returned, so a bug that returns ADMIT twice while writing one row —
// or the reverse — is still caught.
func AssertNoDoubleAdmit(t *testing.T, v *venue.Venue, admissions []engine.Redemption) {
	t.Helper()

	type seat struct {
		id ticket.ID
		cp venue.CheckpointCode
	}
	seen := make(map[seat]int, len(admissions))
	for _, a := range admissions {
		cp, ok := v.Checkpoint(a.Checkpoint)
		if !ok || cp.Policy != venue.PolicyOnce {
			continue
		}
		key := seat{id: a.TicketID, cp: a.Checkpoint}
		seen[key]++
		if seen[key] > 1 {
			t.Fatalf("ticket %s was admitted %d times at once-only checkpoint %s", a.TicketID, seen[key], a.Checkpoint)
		}
	}
}
