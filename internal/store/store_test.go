package store_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/enginetest"
	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/incident"
	"github.com/ManasMadan/gatecrash/internal/manifest"
	"github.com/ManasMadan/gatecrash/internal/store"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"

	_ "modernc.org/sqlite"
)

func during() time.Time { return enginetest.Doors.Add(90 * time.Minute) }

// openTemp opens a store backed by a real file in a temp directory.
//
// A real file rather than :memory: because half of what this package does is
// about the file: WAL mode, checkpointing, integrity checks, and surviving a
// reopen. An in-memory test would pass while the on-disk behaviour was broken.
func openTemp(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gatecrash.db")
	s, err := store.Open(context.Background(), store.Options{
		Path: path, Now: during,
		// NORMAL rather than FULL: the tests are not fighting an SD card and
		// FULL makes the suite several times slower for no signal.
		Synchronous: "NORMAL",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestConformance runs the shared store contract. This is the assertion that
// keeps the SQLite store and the in-memory store honest about each other: they
// implement the same compare-and-set and the same transaction semantics, and a
// divergence is a test failure here rather than a surprise at a gate.
func TestConformance(t *testing.T) {
	enginetest.VerifyStore(t, func(t *testing.T) enginetest.Loader { return openTemp(t) })
}

func TestOpenAppliesPragmasAndSchema(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	if err := s.IntegrityCheck(ctx); err != nil {
		t.Fatalf("a fresh database failed its integrity check: %v", err)
	}
	// WAL mode is what lets a dashboard poll run during a write. Without it a
	// poll blocks a gate.
	if _, err := os.Stat(s.WALPath()); err != nil {
		t.Errorf("no write-ahead log at %s, so the database is not in WAL mode: %v", s.WALPath(), err)
	}
	if err := s.Checkpoint(ctx); err != nil {
		t.Fatalf("wal checkpoint failed: %v", err)
	}
}

func TestReopenKeepsEverything(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "gatecrash.db")

	f := enginetest.NewFixture(t)

	first, err := store.Open(ctx, store.Options{Path: path, Now: during, Synchronous: "NORMAL"})
	if err != nil {
		t.Fatal(err)
	}
	f.Load(first)

	e, err := engine.New(f.Config(engine.ModeStrict, during))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(ctx, first); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ga-standing", "ga-block-a", "crew"} {
		result, err := e.Scan(ctx, first, engine.Scan{
			ScanID: ticket.MustNewID(), Payload: f.Payloads[name],
			Checkpoint: "gate-north", Device: "scanner-north",
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Verdict != engine.Admit {
			t.Fatalf("%s got %s", name, result.Verdict)
		}
	}
	headBefore, rowsBefore := e.AuditHead()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen, as a reboot does.
	second, err := store.Open(ctx, store.Options{Path: path, Now: during, Synchronous: "NORMAL"})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	if err := second.IntegrityCheck(ctx); err != nil {
		t.Fatalf("integrity check after a reopen: %v", err)
	}
	rebooted, err := engine.New(f.Config(engine.ModeStrict, during))
	if err != nil {
		t.Fatal(err)
	}
	if err := rebooted.Recover(ctx, second); err != nil {
		t.Fatal(err)
	}
	head, rows := rebooted.AuditHead()
	if head != headBefore || rows != rowsBefore {
		t.Fatalf("after a reboot the chain is at %s/%d, want %s/%d", head, rows, headBefore, rowsBefore)
	}
	if err := second.Verify(ctx); err != nil {
		t.Fatalf("the chain does not verify after a reboot: %v", err)
	}

	// And the admissions are still there, so a re-scan is refused.
	result, err := rebooted.Scan(ctx, second, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: f.Payloads["ga-standing"],
		Checkpoint: "gate-north", Device: "scanner-north",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != engine.AlreadyUsed {
		t.Fatalf("after a reboot a used ticket got %s, want ALREADY_USED", result.Verdict)
	}
}

func TestIngestReplacesRatherThanMerges(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	signing, verifying, err := ticket.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	eventID := ticket.MustNewID()

	build := func(sequence uint64, ids []ticket.ID) manifest.Body {
		body := manifest.Body{
			Event: manifest.Event{ID: eventID, Name: "Test", Mode: engine.ModeStrict},
			Venue: venue.Plan{
				Zones:       []venue.Zone{{Code: "perimeter"}},
				Checkpoints: []venue.Checkpoint{{Code: "gate-north", Zone: "perimeter"}},
				Tiers:       []venue.Tier{{Code: "ga", Zones: []venue.ZoneCode{"perimeter"}}},
			},
			Devices:   []engine.Device{{ID: "scanner-north", Checkpoints: []venue.CheckpointCode{"gate-north"}}},
			Verifying: verifying,
			IssuedAt:  enginetest.Doors,
			Sequence:  sequence,
		}
		for _, id := range ids {
			body.Tickets = append(body.Tickets, engine.Ticket{
				ID: id, EventID: eventID, Tier: "ga",
				IssuedAt: enginetest.Doors.UnixMilli(), Format: engine.FormatStatic,
			})
		}
		return body
	}

	original := []ticket.ID{ticket.MustNewID(), ticket.MustNewID(), ticket.MustNewID()}
	if err := s.Ingest(ctx, build(1, original), "digest-1"); err != nil {
		t.Fatal(err)
	}
	total, byTier, err := s.TicketCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || byTier["ga"] != 3 {
		t.Fatalf("after the first ingest there are %d tickets", total)
	}

	// The second manifest drops one ticket. A merge would leave it admissible
	// forever, and "we cancelled that ticket and it still got in" is the worst
	// outcome this table has.
	if err := s.Ingest(ctx, build(2, original[:2]), "digest-2"); err != nil {
		t.Fatal(err)
	}
	total, _, err = s.TicketCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("after the second ingest there are %d tickets, want 2", total)
	}
	if err := s.Read(ctx, func(tx engine.Tx) error {
		if _, found, err := tx.Ticket(original[2]); err != nil {
			return err
		} else if found {
			t.Error("a ticket removed from the manifest is still loaded")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	digest, _, err := s.Meta(ctx, store.MetaManifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "digest-2" {
		t.Errorf("stored digest is %q", digest)
	}
	sequence, err := s.ManifestSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sequence != 2 {
		t.Errorf("stored sequence is %d", sequence)
	}

	_ = signing
}

// TestIngestRefusesToRollBack is the stale-USB-stick case. An old manifest must
// not undo a revocation.
func TestIngestRefusesToRollBack(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	_, verifying, err := ticket.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	eventID := ticket.MustNewID()
	body := manifest.Body{
		Event: manifest.Event{ID: eventID, Name: "Test", Mode: engine.ModeStrict},
		Venue: venue.Plan{
			Zones:       []venue.Zone{{Code: "perimeter"}},
			Checkpoints: []venue.Checkpoint{{Code: "gate-north", Zone: "perimeter"}},
			Tiers:       []venue.Tier{{Code: "ga", Zones: []venue.ZoneCode{"perimeter"}}},
		},
		Verifying: verifying, IssuedAt: enginetest.Doors, Sequence: 5,
	}
	if err := s.Ingest(ctx, body, "digest-5"); err != nil {
		t.Fatal(err)
	}

	body.Sequence = 4
	if err := s.Ingest(ctx, body, "digest-4"); !errors.Is(err, manifest.ErrStale) {
		t.Fatalf("got %v, want manifest.ErrStale", err)
	}
	// Re-ingesting the same sequence is fine: it happens when the same file is
	// applied twice, and it has to be idempotent rather than an error.
	body.Sequence = 5
	if err := s.Ingest(ctx, body, "digest-5"); err != nil {
		t.Fatalf("re-ingesting the same sequence failed: %v", err)
	}
}

func TestRevocationTakesEffectOnTheNextScan(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	f := enginetest.NewFixture(t)
	f.Load(s)
	e, err := engine.New(f.Config(engine.ModeStrict, during))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(ctx, s); err != nil {
		t.Fatal(err)
	}

	// The engine reads the device row on every scan rather than caching it, so a
	// stolen scanner stops working immediately rather than at the next restart.
	if err := s.RevokeDeviceContext(ctx, "scanner-north", true); err != nil {
		t.Fatal(err)
	}
	result, err := e.Scan(ctx, s, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: f.Payloads["ga-standing"],
		Checkpoint: "gate-north", Device: "scanner-north",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != engine.ScannerNotAuthorized {
		t.Fatalf("a revoked scanner got %s", result.Verdict)
	}

	// Same for tickets.
	if err := s.RevokeDeviceContext(ctx, "scanner-north", false); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeTicket(ctx, f.ID("ga-standing").Hex(), true); err != nil {
		t.Fatal(err)
	}
	result, err = e.Scan(ctx, s, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: f.Payloads["ga-standing"],
		Checkpoint: "gate-north", Device: "scanner-north",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != engine.Revoked {
		t.Fatalf("a revoked ticket got %s", result.Verdict)
	}

	if err := s.RevokeTicket(ctx, ticket.MustNewID().Hex(), true); err == nil {
		t.Error("revoking a ticket that does not exist reported success")
	}
	if err := s.RevokeDeviceContext(ctx, "nobody", true); err == nil {
		t.Error("revoking a device that does not exist reported success")
	}
}

// TestDeltasAndRedeemedSnapshotFeedAScannerMirror covers the two-step sync a
// scanner performs: a snapshot, then a delta stream from a sequence.
func TestDeltasAndRedeemedSnapshotFeedAScannerMirror(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	f := enginetest.NewFixture(t)
	f.Load(s)
	holders := f.IssueMany(t, 25)
	for _, issued := range holders {
		if err := s.PutTicketContext(ctx, issued.Ticket); err != nil {
			t.Fatal(err)
		}
	}
	e, err := engine.New(f.Config(engine.ModeStrict, during))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(ctx, s); err != nil {
		t.Fatal(err)
	}

	for _, issued := range holders {
		if _, err := e.Scan(ctx, s, engine.Scan{
			ScanID: ticket.MustNewID(), Payload: issued.Payload,
			Checkpoint: "gate-north", Device: "scanner-north",
		}); err != nil {
			t.Fatal(err)
		}
	}

	latest, err := s.LatestSeq(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if latest != 25 {
		t.Fatalf("latest sequence is %d, want 25", latest)
	}

	all, err := s.Deltas(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 25 {
		t.Fatalf("%d deltas from zero, want 25", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].Seq <= all[i-1].Seq {
			t.Fatal("deltas are not in sequence order, so a scanner would mirror them wrong")
		}
	}

	// A scanner resuming from halfway gets the tail and nothing else.
	tail, err := s.Deltas(ctx, all[9].Seq, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 15 {
		t.Fatalf("%d deltas after seq %d, want 15", len(tail), all[9].Seq)
	}

	// Paging, because handing a phone fifty thousand rows is how it dies.
	page, err := s.Deltas(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 10 {
		t.Fatalf("a limited query returned %d rows", len(page))
	}

	snapshot, seq, err := s.RedeemedIDs(ctx, "gate-north")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot) != 25 || seq != 25 {
		t.Fatalf("redeemed snapshot has %d ids at seq %d", len(snapshot), seq)
	}
	// A portal scanner does not need to know who came through the north gate.
	other, _, err := s.RedeemedIDs(ctx, "portal-lower")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("the portal's snapshot carries %d ids from another checkpoint", len(other))
	}
}

func TestSealAndAttendanceProof(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	f := enginetest.NewFixture(t)
	f.Load(s)
	holders := f.IssueMany(t, 50)
	for _, issued := range holders {
		if err := s.PutTicketContext(ctx, issued.Ticket); err != nil {
			t.Fatal(err)
		}
	}
	e, err := engine.New(f.Config(engine.ModeStrict, during))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(ctx, s); err != nil {
		t.Fatal(err)
	}
	for _, issued := range holders {
		if _, err := e.Scan(ctx, s, engine.Scan{
			ScanID: ticket.MustNewID(), Payload: issued.Payload,
			Checkpoint: "gate-north", Device: "scanner-north",
		}); err != nil {
			t.Fatal(err)
		}
	}

	sealed, err := s.Seal(ctx, hlc.New(uint64(during().UnixMilli()), 0))
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Rows != 50 {
		t.Fatalf("the seal covers %d rows, want 50", sealed.Rows)
	}

	stored, found, err := s.LatestSeal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("the seal was not persisted")
	}
	if stored.Root != sealed.Root || stored.Head != sealed.Head {
		t.Fatal("the persisted seal does not match the computed one")
	}

	// The settlement workflow: one ticket, proved against the published root by
	// somebody holding nothing else.
	proof, found, err := s.Attendance(ctx, holders[17].Ticket.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("no attendance proof for an admitted ticket")
	}
	if err := audit.VerifyAttendance(proof); err != nil {
		t.Fatalf("a real admission did not prove: %v", err)
	}

	// A ticket that never came through has no proof, rather than a proof of
	// nothing.
	if _, found, err := s.Attendance(ctx, ticket.MustNewID()); err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatal("produced an attendance proof for a ticket that never scanned")
	}

	// The full log verifies, and every row is present including the ones for
	// denials.
	if err := s.Verify(ctx); err != nil {
		t.Fatalf("the chain does not verify: %v", err)
	}
	rows, err := s.AuditRows(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 50 {
		t.Fatalf("%d audit rows, want 50", len(rows))
	}
}

func TestAuditRowsRoundTripEveryField(t *testing.T) {
	// A field that does not survive the database is a field the hash covers but
	// the log cannot reproduce, which would make the whole chain unverifiable
	// after a reboot.
	s := openTemp(t)
	ctx := context.Background()

	row := audit.Link(audit.GenesisHash(), 1, audit.Record{
		TicketID:   ticket.MustNewID(),
		Checkpoint: "portal-lower",
		Occurrence: 3,
		ScanID:     ticket.MustNewID(),
		Device:     "scanner-portal-lower",
		Verdict:    string(engine.Admit),
		Direction:  venue.DirectionIn,
		Seat:       venue.SeatRef{Section: "block-a", Row: "B", Seat: "7"},
		HLC:        hlc.New(1_750_000_000_123, 42),
		Offline:    true,
	})

	if err := s.Write(ctx, func(tx engine.Tx) error {
		if err := tx.AppendRecord(row); err != nil {
			return err
		}
		return tx.SetAuditHead(row.RowHash, row.Seq)
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.AuditRows(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d rows", len(rows))
	}
	got := rows[0]
	if got != row {
		t.Fatalf("the row changed on the way through the database:\n got %+v\nwant %+v", got, row)
	}
	if err := audit.Verify(rows); err != nil {
		t.Fatalf("the round-tripped row does not verify: %v", err)
	}
}

func TestIncidentsPersistAndRestore(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	compiled, err := venue.Compile(enginetest.VenuePlan())
	if err != nil {
		t.Fatal(err)
	}
	board := incident.NewBoard(incident.BoardConfig{
		Venue: compiled, Now: during,
		Persist: func(i incident.Incident) {
			if err := s.PutIncident(ctx, i); err != nil {
				t.Error(err)
			}
		},
	})

	open, err := board.Raise(incident.Report{Kind: incident.Crush, Checkpoint: "pit-gate", Device: "scanner-pit"})
	if err != nil {
		t.Fatal(err)
	}
	done, err := board.Raise(incident.Report{Kind: incident.NeedRelief, Checkpoint: "gate-north", Device: "scanner-north"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := board.Transition(done.ID, incident.Transition{Status: incident.Resolved, Actor: "control"}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.Incidents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d incidents persisted, want 2", len(rows))
	}

	// An alarm that vanishes when the box restarts is worse than one never
	// raised.
	rebooted := incident.NewBoard(incident.BoardConfig{Venue: compiled, Now: during})
	rebooted.Restore(rows)
	live := rebooted.Live()
	if len(live) != 1 || live[0].ID != open.ID {
		t.Fatalf("after a reboot the live list is %d incidents", len(live))
	}
	if live[0].Kind != incident.Crush || live[0].ZoneName == "" {
		t.Errorf("the restored incident lost detail: %+v", live[0])
	}

	// And the counter keeps ids unique across the reboot.
	next, err := s.NextIncidentSeq(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if next == 0 {
		t.Error("incident sequence did not advance")
	}
}

func TestSessionWindowSurvivesAReboot(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	opened := enginetest.Doors
	if err := s.OpenSession(ctx, opened); err != nil {
		t.Fatal(err)
	}
	// A reboot mid-event must not reset the session start, or the attendance
	// report claims doors opened whenever the box last crashed.
	if err := s.OpenSession(ctx, opened.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseSession(ctx, opened.Add(6*time.Hour)); err != nil {
		t.Fatal(err)
	}

	gotOpen, gotClose, err := s.SessionWindow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !gotOpen.Equal(opened) {
		t.Errorf("session opened at %s, want %s", gotOpen, opened)
	}
	if !gotClose.Equal(opened.Add(6 * time.Hour)) {
		t.Errorf("session closed at %s", gotClose)
	}
}

func TestFlagsArePersistedWithBothRecords(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	f := enginetest.NewFixture(t)
	f.Load(s)
	e, err := engine.New(f.Config(engine.ModeDegraded, during))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(ctx, s); err != nil {
		t.Fatal(err)
	}

	if _, err := e.Scan(ctx, s, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: f.Payloads["ga-standing"],
		Checkpoint: "gate-north", Device: "scanner-north",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Scan(ctx, s, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: f.Payloads["ga-standing"],
		Checkpoint: "gate-north", Device: "scanner-north-2", OfflineAdmitted: true,
	}); err != nil {
		t.Fatal(err)
	}

	flags, err := s.Flags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(flags) != 1 {
		t.Fatalf("%d flags stored, want 1", len(flags))
	}
	// Both records have to survive: a supervisor deciding what actually happened
	// needs to know which gate and which device each was.
	if flags[0].Winner.Device != "scanner-north" || flags[0].Loser.Device != "scanner-north-2" {
		t.Errorf("flag records winner=%q loser=%q", flags[0].Winner.Device, flags[0].Loser.Device)
	}
	if !flags[0].Loser.Offline {
		t.Error("the losing record did not survive as offline")
	}
}

// TestOpenRefusesAFutureSchema guards the upgrade path. Opening a database
// written by a newer box read-write with an older schema is how a database gets
// mangled, so the store refuses rather than trying.
func TestOpenRefusesAFutureSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "future.db")

	s, err := store.Open(ctx, store.Options{Path: path, Now: during, Synchronous: "NORMAL"})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Bump user_version behind the store's back, the way a newer binary would.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, "PRAGMA user_version = 999"); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Open(ctx, store.Options{Path: path, Now: during, Synchronous: "NORMAL"}); err == nil {
		t.Fatal("opened a database written by a newer box")
	}
}

func TestOpenRejectsAnEmptyPath(t *testing.T) {
	if _, err := store.Open(context.Background(), store.Options{}); err == nil {
		t.Fatal("Open accepted an empty path")
	}
}

func BenchmarkScanAdmitSQLite(b *testing.B) {
	ctx := context.Background()
	path := filepath.Join(b.TempDir(), "bench.db")
	s, err := store.Open(ctx, store.Options{Path: path, Now: during, Synchronous: "NORMAL"})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	t := &testing.T{}
	f := enginetest.NewFixture(t)
	f.Load(s)

	e, err := engine.New(f.Config(engine.ModeStrict, during))
	if err != nil {
		b.Fatal(err)
	}
	if err := e.Recover(ctx, s); err != nil {
		b.Fatal(err)
	}

	holders := make([]enginetest.Issued, 0, b.N)
	for i := 0; i < b.N; i++ {
		issued := f.Issue(t, "ga", venue.SeatRef{}, engine.FormatStatic)
		if err := s.PutTicketContext(ctx, issued.Ticket); err != nil {
			b.Fatal(err)
		}
		holders = append(holders, issued)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := e.Scan(ctx, s, engine.Scan{
			ScanID: ticket.MustNewID(), Payload: holders[i].Payload,
			Checkpoint: "gate-north", Device: "scanner-north",
		})
		if err != nil {
			b.Fatal(err)
		}
		if result.Verdict != engine.Admit {
			b.Fatalf("got %s", result.Verdict)
		}
	}
}
