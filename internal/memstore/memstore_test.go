package memstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/enginetest"
	"github.com/ManasMadan/gatecrash/internal/memstore"
	"github.com/ManasMadan/gatecrash/internal/ticket"
)

func TestConformance(t *testing.T) {
	enginetest.VerifyStore(t, func(*testing.T) enginetest.Loader { return memstore.New() })
}

func during() time.Time { return enginetest.Doors.Add(90 * time.Minute) }

// TestPowerCutLeavesAConsistentPrefix models the SD card that lied about fsync.
//
// Data is lost across the cut, and that is the scenario rather than a bug. What
// has to hold is that whatever survives is a consistent prefix whose hash chain
// still verifies, and that the box can resume from it and keep admitting. A
// chain that failed to verify after a power cut would make every post-event
// proof worthless, which is a far worse outcome than losing a few seconds of
// scans that the scanners' retry queues will re-deliver anyway.
func TestPowerCutLeavesAConsistentPrefix(t *testing.T) {
	store := memstore.New()
	ctx := context.Background()

	f := enginetest.NewFixture(t)
	f.Load(store)
	holders := f.IssueMany(t, 400)
	for _, issued := range holders {
		store.PutTicket(issued.Ticket)
	}

	e, err := engine.New(f.Config(engine.ModeStrict, during))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(ctx, store); err != nil {
		t.Fatal(err)
	}

	// Admit the first half, flush, admit the second half, then yank the power.
	const flushAfter = 200
	for i, issued := range holders {
		result, err := e.Scan(ctx, store, engine.Scan{
			ScanID: ticket.MustNewID(), Payload: issued.Payload,
			Checkpoint: "gate-north", Device: "scanner-north",
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Verdict != engine.Admit {
			t.Fatalf("holder %d got %s (%s)", i, result.Verdict, result.Reason)
		}
		if i == flushAfter-1 {
			store.Flush()
		}
	}
	if got := len(store.Records()); got != len(holders) {
		t.Fatalf("log has %d rows before the cut, want %d", got, len(holders))
	}

	store.Cut()

	survived := store.Records()
	if len(survived) != flushAfter {
		t.Fatalf("%d rows survived the cut, want the %d that were flushed", len(survived), flushAfter)
	}
	enginetest.AssertChainVerifies(t, survived)
	enginetest.AssertNoDoubleAdmit(t, f.Venue, store.Admissions())

	// The box reboots. Recovery has to pick up the surviving chain, not start a
	// second one from genesis.
	rebooted, err := engine.New(f.Config(engine.ModeStrict, during))
	if err != nil {
		t.Fatal(err)
	}
	if err := rebooted.Recover(ctx, store); err != nil {
		t.Fatal(err)
	}
	head, rows := rebooted.AuditHead()
	if rows != uint64(flushAfter) {
		t.Fatalf("recovered at %d rows, want %d", rows, flushAfter)
	}
	if head != survived[len(survived)-1].RowHash {
		t.Fatal("the recovered head is not the last surviving row's hash")
	}

	// Scans the cut erased get re-delivered by the scanners' retry queues and
	// must be admitted, because as far as those holders are concerned they never
	// got in.
	for _, issued := range holders[flushAfter:] {
		result, err := rebooted.Scan(ctx, store, engine.Scan{
			ScanID: ticket.MustNewID(), Payload: issued.Payload,
			Checkpoint: "gate-north", Device: "scanner-north",
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Verdict != engine.Admit {
			t.Fatalf("a re-delivered scan after recovery gave %s, want ADMIT", result.Verdict)
		}
	}
	enginetest.AssertChainVerifies(t, store.Records())
	enginetest.AssertNoDoubleAdmit(t, f.Venue, store.Admissions())
	if got := len(store.Admissions()); got != len(holders) {
		t.Fatalf("%d admissions after recovery, want %d", got, len(holders))
	}
}

// TestRepeatedPowerCutsNeverBreakTheChain is the cable-pull suite in miniature:
// a hundred cuts at arbitrary points, asserting the chain verifies every time.
// The real suite does this to physical hardware with a smart plug; this one runs
// in CI on every push.
func TestRepeatedPowerCutsNeverBreakTheChain(t *testing.T) {
	store := memstore.New()
	ctx := context.Background()

	f := enginetest.NewFixture(t)
	f.Load(store)

	for round := 0; round < 100; round++ {
		e, err := engine.New(f.Config(engine.ModeStrict, during))
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Recover(ctx, store); err != nil {
			t.Fatal(err)
		}

		// A handful of fresh holders per round, so each round writes new rows.
		for _, issued := range f.IssueMany(t, 5+round%7) {
			store.PutTicket(issued.Ticket)
			if _, err := e.Scan(ctx, store, engine.Scan{
				ScanID: ticket.MustNewID(), Payload: issued.Payload,
				Checkpoint: "gate-north", Device: "scanner-north",
			}); err != nil {
				t.Fatal(err)
			}
		}
		// Flush some rounds and not others, so the cut lands mid-write about
		// half the time.
		if round%2 == 0 {
			store.Flush()
		}
		store.Cut()

		enginetest.AssertChainVerifies(t, store.Records())
	}

	rows := store.Records()
	if len(rows) == 0 {
		t.Fatal("a hundred rounds produced no surviving rows, so the test proved nothing")
	}
	if err := audit.Verify(rows); err != nil {
		t.Fatalf("the final chain does not verify: %v", err)
	}
	enginetest.AssertNoDoubleAdmit(t, f.Venue, store.Admissions())
	t.Logf("%d rows survived 100 power cuts with an intact chain", len(rows))
}

func TestFailedWritesDoNotAdmit(t *testing.T) {
	store := memstore.New()
	ctx := context.Background()

	f := enginetest.NewFixture(t)
	f.Load(store)

	e, err := engine.New(f.Config(engine.ModeStrict, during))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(ctx, store); err != nil {
		t.Fatal(err)
	}

	store.FailWrites(engine.ErrStoreClosed)
	if _, err := e.Scan(ctx, store, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: f.Payloads["ga-standing"],
		Checkpoint: "gate-north", Device: "scanner-north",
	}); err == nil {
		t.Fatal("a scan succeeded while every write was failing")
	}
	if len(store.Admissions()) != 0 {
		t.Fatal("a failing store recorded an admission")
	}

	// And it recovers once storage comes back.
	store.FailWrites(nil)
	result, err := e.Scan(ctx, store, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: f.Payloads["ga-standing"],
		Checkpoint: "gate-north", Device: "scanner-north",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != engine.Admit {
		t.Fatalf("got %s after storage recovered, want ADMIT", result.Verdict)
	}
}
