package audit

import (
	"errors"
	"testing"

	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/merkle"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// buildLog appends n admissions and returns the chain and the rows to persist.
func buildLog(t *testing.T, n int) (*Chain, []Record) {
	t.Helper()
	chain := NewChain()
	rows := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		linked, err := chain.Append(Record{
			TicketID:   ticket.MustNewID(),
			Checkpoint: "gate-north",
			ScanID:     ticket.MustNewID(),
			Device:     "scanner-1",
			Verdict:    "ADMIT",
			Direction:  venue.DirectionIn,
			HLC:        hlc.New(uint64(1_750_000_000_000+i), 0),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		rows = append(rows, linked)
	}
	return chain, rows
}

func TestGenesisIsNotZero(t *testing.T) {
	// A zero genesis would let somebody delete row 1, renumber, and have the
	// chain still verify. The genesis has to be a value nobody can forge into a
	// prev_hash by accident.
	if GenesisHash().IsZero() {
		t.Fatal("the genesis hash is zero")
	}
}

func TestAppendLinksRowsAndAssignsSequence(t *testing.T) {
	chain, rows := buildLog(t, 5)

	if chain.Len() != 5 {
		t.Fatalf("chain length is %d, want 5", chain.Len())
	}
	if rows[0].Seq != 1 {
		t.Fatalf("first row has seq %d, want 1", rows[0].Seq)
	}
	if rows[0].PrevHash != GenesisHash() {
		t.Fatal("the first row does not point at the genesis hash")
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].Seq != uint64(i+1) {
			t.Errorf("row %d has seq %d", i, rows[i].Seq)
		}
		if rows[i].PrevHash != rows[i-1].RowHash {
			t.Errorf("row %d does not link to row %d", i, i-1)
		}
	}
	if chain.Head() != rows[len(rows)-1].RowHash {
		t.Fatal("the chain head is not the last row's hash")
	}
}

func TestAppendRejectsAnOutOfOrderSequence(t *testing.T) {
	chain := NewChain()
	if _, err := chain.Append(Record{Seq: 7, Verdict: "ADMIT"}); !errors.Is(err, ErrSequence) {
		t.Fatalf("got %v, want ErrSequence", err)
	}
	// A caller-supplied sequence that does match is accepted, because the engine
	// supplies one so the value it writes to SQLite cannot drift from the value
	// in the hash.
	if _, err := chain.Append(Record{Seq: 1, Verdict: "ADMIT"}); err != nil {
		t.Fatalf("a correct sequence was rejected: %v", err)
	}
}

func TestVerifyAcceptsAnUntouchedLog(t *testing.T) {
	_, rows := buildLog(t, 200)
	if err := Verify(rows); err != nil {
		t.Fatalf("an untouched log did not verify: %v", err)
	}
	if err := Verify(nil); err != nil {
		t.Fatalf("an empty log did not verify: %v", err)
	}
}

// TestVerifyCatchesEveryFormOfTampering is the test the whole package exists
// for. Each case is something an organizer with write access to the SQLite file
// would plausibly try on the morning after a disputed door split.
func TestVerifyCatchesEveryFormOfTampering(t *testing.T) {
	_, original := buildLog(t, 50)

	clone := func() []Record { return append([]Record(nil), original...) }

	t.Run("edit a row in place", func(t *testing.T) {
		rows := clone()
		rows[20].Verdict = "ALREADY_USED"
		if err := Verify(rows); !errors.Is(err, ErrBadRowHash) {
			t.Fatalf("got %v, want ErrBadRowHash", err)
		}
	})

	t.Run("edit a row and recompute its own hash", func(t *testing.T) {
		// The obvious next move: fix up the row hash so the row is
		// self-consistent. The link to the following row then breaks.
		rows := clone()
		rows[20].Verdict = "ALREADY_USED"
		rows[20].RowHash = merkle.Hash{}
		relinked := rows[20]
		relinked.RowHash = hashRow(relinked.PrevHash, relinked)
		rows[20] = relinked
		if err := Verify(rows); !errors.Is(err, ErrBrokenLink) {
			t.Fatalf("got %v, want ErrBrokenLink", err)
		}
	})

	t.Run("delete a row", func(t *testing.T) {
		rows := append(clone()[:20], clone()[21:]...)
		if err := Verify(rows); err == nil {
			t.Fatal("deleting a row verified clean")
		}
	})

	t.Run("delete a row and renumber", func(t *testing.T) {
		rows := append(clone()[:20], clone()[21:]...)
		for i := 20; i < len(rows); i++ {
			rows[i].Seq = uint64(i + 1)
		}
		if err := Verify(rows); !errors.Is(err, ErrBrokenLink) {
			t.Fatalf("got %v, want ErrBrokenLink", err)
		}
	})

	t.Run("insert a row", func(t *testing.T) {
		rows := clone()
		fake := rows[10]
		fake.TicketID = ticket.MustNewID()
		rows = append(rows[:11], append([]Record{fake}, rows[11:]...)...)
		if err := Verify(rows); err == nil {
			t.Fatal("inserting a row verified clean")
		}
	})

	t.Run("reorder two rows", func(t *testing.T) {
		rows := clone()
		rows[8], rows[9] = rows[9], rows[8]
		if err := Verify(rows); err == nil {
			t.Fatal("reordering two rows verified clean")
		}
	})

	t.Run("truncate the tail", func(t *testing.T) {
		// Truncation is the one edit a bare chain cannot detect on its own: a
		// prefix of a valid chain is itself a valid chain. This is exactly why
		// checkpoints exist and why the box publishes its head, and the
		// assertion here records that limitation honestly rather than pretending
		// otherwise.
		rows := clone()[:30]
		if err := Verify(rows); err != nil {
			t.Fatalf("a truncated prefix should still verify as a chain: %v", err)
		}
		// Against a published checkpoint it does not survive.
		full := clone()
		leaves := leavesOf(full)
		cp := Seal(leaves, full[len(full)-1].RowHash, hlc.New(1, 0))
		if err := VerifyCheckpoint(cp, rows); err == nil {
			t.Fatal("a truncated log verified against the full checkpoint")
		}
	})

	t.Run("swap in a whole forged log", func(t *testing.T) {
		// A completely fresh chain is internally consistent, which is the point
		// of publishing the root: it will not match.
		_, forged := buildLog(t, 50)
		if err := Verify(forged); err != nil {
			t.Fatalf("the forged log is not self-consistent, so the test proves nothing: %v", err)
		}
		real := clone()
		cp := Seal(leavesOf(real), real[len(real)-1].RowHash, hlc.New(1, 0))
		if err := VerifyCheckpoint(cp, forged); err == nil {
			t.Fatal("a forged log verified against the real checkpoint")
		}
	})
}

func TestVerifyReportsSequenceGaps(t *testing.T) {
	_, rows := buildLog(t, 10)
	rows[3].Seq = 99
	if err := Verify(rows); !errors.Is(err, ErrGap) {
		t.Fatalf("got %v, want ErrGap", err)
	}
}

// TestCanonicalEncodingIsUnambiguous is the reason every variable field carries
// a length prefix. Without one, two different admissions can produce identical
// canonical bytes, and a collision inside the chain is a hole in the guarantee.
func TestCanonicalEncodingIsUnambiguous(t *testing.T) {
	id, scan := ticket.MustNewID(), ticket.MustNewID()
	base := Record{Seq: 1, TicketID: id, ScanID: scan, HLC: hlc.New(1, 0)}

	first := base
	first.Device = "gate"
	first.Verdict = "ADMIT"

	second := base
	second.Device = "gateADMIT"
	second.Verdict = ""

	if string(first.Canonical()) == string(second.Canonical()) {
		t.Fatal("two different records encode to the same canonical bytes")
	}

	// The same field-shifting attack across the seat reference.
	third := base
	third.Seat = venue.SeatRef{Section: "block", Row: "a", Seat: "1"}
	fourth := base
	fourth.Seat = venue.SeatRef{Section: "blocka", Row: "", Seat: "1"}
	if string(third.Canonical()) == string(fourth.Canonical()) {
		t.Fatal("two different seat references encode to the same canonical bytes")
	}
}

func TestCanonicalEncodingCoversEveryField(t *testing.T) {
	// Anything not in the hash is not covered by the proof, so a field that can
	// be changed without changing the bytes is a field an organizer can rewrite
	// after the event.
	base := Record{
		Seq: 4, TicketID: ticket.MustNewID(), Checkpoint: "gate-north", Occurrence: 1,
		ScanID: ticket.MustNewID(), Device: "scanner-1", Verdict: "ADMIT",
		Direction: venue.DirectionIn, Seat: venue.SeatRef{Section: "block-a", Row: "A", Seat: "1"},
		HLC: hlc.New(1_750_000_000_000, 3), Offline: false,
	}
	reference := string(base.Canonical())

	for name, mutate := range map[string]func(Record) Record{
		"seq":        func(r Record) Record { r.Seq++; return r },
		"ticket":     func(r Record) Record { r.TicketID = ticket.MustNewID(); return r },
		"checkpoint": func(r Record) Record { r.Checkpoint = "gate-south"; return r },
		"occurrence": func(r Record) Record { r.Occurrence++; return r },
		"scan":       func(r Record) Record { r.ScanID = ticket.MustNewID(); return r },
		"device":     func(r Record) Record { r.Device = "scanner-2"; return r },
		"verdict":    func(r Record) Record { r.Verdict = "REVOKED"; return r },
		"direction":  func(r Record) Record { r.Direction = venue.DirectionOut; return r },
		"section":    func(r Record) Record { r.Seat.Section = "block-b"; return r },
		"row":        func(r Record) Record { r.Seat.Row = "B"; return r },
		"seat":       func(r Record) Record { r.Seat.Seat = "2"; return r },
		"hlc":        func(r Record) Record { r.HLC = hlc.New(1_750_000_000_001, 0); return r },
		"offline":    func(r Record) Record { r.Offline = true; return r },
	} {
		if string(mutate(base).Canonical()) == reference {
			t.Errorf("changing %s did not change the canonical bytes", name)
		}
	}
}

func TestCheckpointSealsAndVerifies(t *testing.T) {
	chain, rows := buildLog(t, 250)
	cp := Seal(leavesOf(rows), chain.Head(), hlc.New(1_750_000_000_000, 0))

	if cp.Rows != 250 || cp.Seq != 250 {
		t.Fatalf("checkpoint covers %d rows at seq %d, want 250", cp.Rows, cp.Seq)
	}
	if cp.Head != chain.Head() {
		t.Fatal("checkpoint head does not match the chain head")
	}
	if err := VerifyCheckpoint(cp, rows); err != nil {
		t.Fatalf("a freshly sealed checkpoint did not verify: %v", err)
	}
}

func TestCheckpointRejectsAModifiedLog(t *testing.T) {
	chain, rows := buildLog(t, 100)
	cp := Seal(leavesOf(rows), chain.Head(), hlc.New(1, 0))

	tampered := append([]Record(nil), rows...)
	tampered[42].Device = "scanner-9"
	if err := VerifyCheckpoint(cp, tampered); err == nil {
		t.Fatal("a checkpoint verified against a tampered log")
	}
}

func TestDueForCheckpointFollowsTheWindow(t *testing.T) {
	chain := NewChain()
	chain.SetCheckpointWindow(4)
	for i := 0; i < 3; i++ {
		if _, err := chain.Append(Record{Verdict: "ADMIT"}); err != nil {
			t.Fatal(err)
		}
	}
	if chain.DueForCheckpoint() {
		t.Fatal("due before the window filled")
	}
	if _, err := chain.Append(Record{Verdict: "ADMIT"}); err != nil {
		t.Fatal(err)
	}
	if !chain.DueForCheckpoint() {
		t.Fatal("not due after the window filled")
	}
	if len(chain.Pending()) != 4 {
		t.Fatalf("pending window holds %d leaves, want 4", len(chain.Pending()))
	}
	chain.MarkSealed()
	if chain.DueForCheckpoint() || len(chain.Pending()) != 0 {
		t.Fatal("the window was not cleared after sealing")
	}
	// Sealing must not disturb the chain itself.
	if chain.Len() != 4 {
		t.Fatalf("chain length is %d after sealing, want 4", chain.Len())
	}
}

// TestResumeContinuesTheChainAcrossAReboot is the power-cut case: the box comes
// back up, reads its head and sequence out of SQLite, and the next admission has
// to link to the last one from before the cut.
func TestResumeContinuesTheChainAcrossAReboot(t *testing.T) {
	chain, rows := buildLog(t, 7)

	resumed := Resume(chain.Head(), chain.Len(), chain.Pending())
	next, err := resumed.Append(Record{
		TicketID: ticket.MustNewID(), ScanID: ticket.MustNewID(),
		Checkpoint: "gate-north", Device: "scanner-1", Verdict: "ADMIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	if next.Seq != 8 {
		t.Fatalf("the row after a reboot has seq %d, want 8", next.Seq)
	}
	if next.PrevHash != rows[len(rows)-1].RowHash {
		t.Fatal("the row after a reboot does not link to the row before the cut")
	}
	if err := Verify(append(rows, next)); err != nil {
		t.Fatalf("the log across a reboot does not verify: %v", err)
	}
}

func TestResumeFromNothingStartsAtGenesis(t *testing.T) {
	resumed := Resume(merkle.Hash{}, 0, nil)
	first, err := resumed.Append(Record{Verdict: "ADMIT"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq != 1 || first.PrevHash != GenesisHash() {
		t.Fatalf("a fresh resume produced seq %d with prev %s", first.Seq, first.PrevHash)
	}
}

// TestAttendanceProvesOneAdmissionAgainstAPublishedRoot is the settlement
// workflow: the organizer publishes one 32-byte root, and any single admission
// can be proved against it by somebody holding nothing else.
func TestAttendanceProvesOneAdmissionAgainstAPublishedRoot(t *testing.T) {
	chain, rows := buildLog(t, 5000)
	leaves := leavesOf(rows)
	cp := Seal(leaves, chain.Head(), hlc.New(1, 0))

	const index = 3_141
	proof, err := merkle.Prove(leaves, index)
	if err != nil {
		t.Fatal(err)
	}
	attendance := Attendance{Record: rows[index], Proof: proof, Checkpoint: cp}

	if err := VerifyAttendance(attendance); err != nil {
		t.Fatalf("a real admission did not prove: %v", err)
	}
	if len(proof.Siblings) > 14 {
		t.Errorf("a proof over %d admissions carries %d siblings", len(rows), len(proof.Siblings))
	}

	t.Run("a forged record does not prove", func(t *testing.T) {
		bad := attendance
		bad.Record.Device = "scanner-9"
		if err := VerifyAttendance(bad); err == nil {
			t.Fatal("a forged record proved against the real root")
		}
	})
	t.Run("a real record under the wrong root does not prove", func(t *testing.T) {
		bad := attendance
		bad.Checkpoint.Root = merkle.HashLeaf([]byte("not the root"))
		if err := VerifyAttendance(bad); err == nil {
			t.Fatal("a record proved against an unrelated root")
		}
	})
	t.Run("a record that was never admitted does not prove", func(t *testing.T) {
		bad := attendance
		bad.Record.TicketID = ticket.MustNewID()
		if err := VerifyAttendance(bad); err == nil {
			t.Fatal("a ticket that never existed proved attendance")
		}
	})
}

func TestChainIsSafeForConcurrentReadsWhileAppending(t *testing.T) {
	chain := NewChain()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5000; i++ {
			if _, err := chain.Append(Record{Verdict: "ADMIT"}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			if chain.Len() != 5000 {
				t.Fatalf("chain length is %d, want 5000", chain.Len())
			}
			return
		default:
			// The dashboard reads these from its own goroutine; a torn read of a
			// 32-byte hash would show an operator a head that never existed.
			_ = chain.Head()
			_ = chain.Len()
			_ = chain.DueForCheckpoint()
		}
	}
}

// leavesOf recomputes the Merkle leaves for a set of rows, the way the store
// does when sealing.
func leavesOf(rows []Record) []merkle.Hash {
	out := make([]merkle.Hash, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Leaf())
	}
	return out
}

func BenchmarkAppend(b *testing.B) {
	chain := NewChain()
	record := Record{
		TicketID: ticket.MustNewID(), ScanID: ticket.MustNewID(),
		Checkpoint: "gate-north", Device: "scanner-1", Verdict: "ADMIT",
		Direction: venue.DirectionIn, HLC: hlc.New(1_750_000_000_000, 0),
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := chain.Append(record); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify10k(b *testing.B) {
	chain := NewChain()
	rows := make([]Record, 0, 10_000)
	for i := 0; i < 10_000; i++ {
		linked, err := chain.Append(Record{
			TicketID: ticket.MustNewID(), ScanID: ticket.MustNewID(),
			Checkpoint: "gate-north", Device: "scanner-1", Verdict: "ADMIT",
		})
		if err != nil {
			b.Fatal(err)
		}
		rows = append(rows, linked)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(rows); err != nil {
			b.Fatal(err)
		}
	}
}
