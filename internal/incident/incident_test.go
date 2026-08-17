package incident

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/venue"
)

// testVenue is the smallest venue that has two zones and a nested one, which is
// all the board's filtering needs.
func testVenue(t *testing.T) *venue.Venue {
	t.Helper()
	compiled, err := venue.Compile(venue.Plan{
		Zones: []venue.Zone{
			{Code: "perimeter", Name: "Festival Ground"},
			{Code: "arena", Name: "Arena", Parent: "perimeter", Restricted: true},
			{Code: "pit", Name: "Front Pit", Parent: "arena", Restricted: true},
		},
		Checkpoints: []venue.Checkpoint{
			{Code: "gate-north", Name: "North Gate", Zone: "perimeter"},
			{Code: "pit-gate", Name: "Pit Check", Zone: "pit"},
		},
		Tiers: []venue.Tier{{Code: "ga", Zones: []venue.ZoneCode{"perimeter", "arena", "pit"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// clock is a hand-driven wall clock so response times are exact.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func newBoard(t *testing.T) (*Board, *clock) {
	t.Helper()
	c := &clock{at: time.Date(2026, 8, 21, 22, 0, 0, 0, time.UTC)}
	return NewBoard(BoardConfig{Venue: testVenue(t), Now: c.now}), c
}

func TestRaiseFillsInWhereItCameFrom(t *testing.T) {
	board, _ := newBoard(t)

	// Somebody pressing the crush button is not going to fill in a form, so the
	// box fills the location in from the device's own checkpoint.
	i, err := board.Raise(Report{Kind: Crush, Checkpoint: "pit-gate", Device: "scanner-pit", QueueRate: 6})
	if err != nil {
		t.Fatal(err)
	}
	if i.ID != "INC-1" {
		t.Errorf("id is %q, want INC-1", i.ID)
	}
	if i.CheckpointName != "Pit Check" || i.Zone != "pit" || i.ZoneName != "Front Pit" {
		t.Errorf("location is %q / %q / %q", i.CheckpointName, i.Zone, i.ZoneName)
	}
	if i.Status != Open {
		t.Errorf("status is %s, want open", i.Status)
	}
	if i.Severity != Emergency {
		t.Errorf("a crush report is %s, want emergency", i.Severity)
	}
	if len(i.History) != 1 || i.History[0].Status != Open {
		t.Fatalf("history is %+v, want one open entry", i.History)
	}
	if i.History[0].Actor != "scanner-pit" {
		t.Errorf("the first history entry is attributed to %q", i.History[0].Actor)
	}
	if i.QueueRate != 6 {
		t.Errorf("queue rate is %v, want 6", i.QueueRate)
	}
}

func TestReporterMayEscalateButNeverDowngrade(t *testing.T) {
	board, _ := newBoard(t)

	// Escalating is allowed: the person in the crowd knows better than the table.
	up, err := board.Raise(Report{Kind: NeedStaff, Severity: Urgent, Checkpoint: "gate-north", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if up.Severity != Urgent {
		t.Errorf("escalated report is %s, want urgent", up.Severity)
	}

	// Downgrading is not. A button that can be quietly turned down is a button
	// that gets somebody hurt.
	down, err := board.Raise(Report{Kind: Crush, Severity: Info, Checkpoint: "gate-north", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if down.Severity != Emergency {
		t.Errorf("a crush report downgraded to %s", down.Severity)
	}
}

func TestRaiseIsIdempotentPerClientKey(t *testing.T) {
	board, _ := newBoard(t)

	// A bouncer jabbing the alarm on a flaky link.
	report := Report{Kind: Medical, Checkpoint: "gate-north", Device: "d1", ClientID: "abc"}
	first, err := board.Raise(report)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := board.Raise(report)
		if err != nil {
			t.Fatal(err)
		}
		if again.ID != first.ID {
			t.Fatalf("retry %d raised a second incident %s", i, again.ID)
		}
	}
	if got := len(board.List(Filter{})); got != 1 {
		t.Fatalf("%d incidents on the board, want 1", got)
	}
}

func TestValidateRejectsBadReports(t *testing.T) {
	board, _ := newBoard(t)

	if _, err := board.Raise(Report{Kind: "vibes", Device: "d1"}); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("got %v, want ErrUnknownKind", err)
	}
	// A human-raised incident must be attributed; an anonymous alarm cannot be
	// followed up and cannot be trusted.
	if _, err := board.Raise(Report{Kind: Medical}); !errors.Is(err, ErrNoDevice) {
		t.Errorf("got %v, want ErrNoDevice", err)
	}
	// The box's own signals have no device and are fine.
	if _, err := board.Raise(Report{Kind: GateOffline, Checkpoint: "gate-north"}); err != nil {
		t.Errorf("the box could not raise its own signal: %v", err)
	}
}

func TestValidateClampsSillyInput(t *testing.T) {
	report := Report{Kind: NeedStaff, Device: "d1", HeadCount: 9000, Note: string(make([]byte, 5000))}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if report.HeadCount != 50 {
		t.Errorf("head count clamped to %d, want 50", report.HeadCount)
	}
	if len(report.Note) > 500 {
		t.Errorf("note is %d bytes, want it truncated to 500", len(report.Note))
	}
}

func TestLifecycleIsAttributedAndRecorded(t *testing.T) {
	board, c := newBoard(t)

	raised, err := board.Raise(Report{Kind: Medical, Checkpoint: "gate-north", Device: "d1", Reporter: "Aditi"})
	if err != nil {
		t.Fatal(err)
	}

	c.advance(40 * time.Second)
	acked, err := board.Transition(raised.ID, Transition{Status: Acknowledged, Actor: "control"})
	if err != nil {
		t.Fatal(err)
	}
	if acked.Status != Acknowledged {
		t.Fatalf("status is %s", acked.Status)
	}

	c.advance(20 * time.Second)
	assigned, err := board.Transition(raised.ID, Transition{Status: Assigned, Actor: "control", AssignedTo: "medic-2"})
	if err != nil {
		t.Fatal(err)
	}
	if assigned.AssignedTo != "medic-2" {
		t.Errorf("assigned to %q", assigned.AssignedTo)
	}

	c.advance(4 * time.Minute)
	resolved, err := board.Transition(raised.ID, Transition{Status: Resolved, Actor: "medic-2", Note: "walked off, fine"})
	if err != nil {
		t.Fatal(err)
	}

	// Four transitions plus the open entry.
	if len(resolved.History) != 4 {
		t.Fatalf("history has %d entries, want 4: %+v", len(resolved.History), resolved.History)
	}
	for i, event := range resolved.History {
		if event.Actor == "" {
			t.Errorf("history entry %d is unattributed", i)
		}
	}

	// The numbers a post-event report and a liability question both need.
	ack, ok := resolved.AcknowledgedAfter()
	if !ok || ack != 40*time.Second {
		t.Errorf("acknowledged after %s, want 40s", ack)
	}
	fix, ok := resolved.ResolvedAfter()
	if !ok || fix != 5*time.Minute {
		t.Errorf("resolved after %s, want 5m", fix)
	}
}

func TestClosedIncidentsStayClosed(t *testing.T) {
	board, _ := newBoard(t)
	raised, err := board.Raise(Report{Kind: NeedRelief, Checkpoint: "gate-north", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := board.Transition(raised.ID, Transition{Status: Resolved, Actor: "control"}); err != nil {
		t.Fatal(err)
	}
	// Reopening is deliberately unsupported: the record is append-only, and a
	// recurrence is a new incident with its own response time.
	if _, err := board.Transition(raised.ID, Transition{Status: Acknowledged, Actor: "control"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v, want ErrClosed", err)
	}
}

func TestTransitionsNeedAnActorAndCancellingNeedsAReason(t *testing.T) {
	board, _ := newBoard(t)
	raised, err := board.Raise(Report{Kind: Fight, Checkpoint: "gate-north", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := board.Transition(raised.ID, Transition{Status: Acknowledged}); !errors.Is(err, ErrNoActor) {
		t.Errorf("got %v, want ErrNoActor", err)
	}
	// An inconvenient alarm must not be silently made to disappear.
	if _, err := board.Transition(raised.ID, Transition{Status: Cancelled, Actor: "control"}); !errors.Is(err, ErrNoteRequired) {
		t.Errorf("got %v, want ErrNoteRequired", err)
	}
	if _, err := board.Transition(raised.ID, Transition{Status: Cancelled, Actor: "control", Note: "false alarm, radio mixup"}); err != nil {
		t.Errorf("a cancellation with a reason was refused: %v", err)
	}
	if _, err := board.Transition("INC-999", Transition{Status: Acknowledged, Actor: "control"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// TestListPutsTheLoudestUnhandledThingFirst is the whole reason the board sorts
// at all. A dashboard ordered by time buries an unacknowledged crush alarm under
// nine requests for a tea break.
func TestListPutsTheLoudestUnhandledThingFirst(t *testing.T) {
	board, _ := newBoard(t)

	for i := 0; i < 9; i++ {
		if _, err := board.Raise(Report{Kind: NeedRelief, Checkpoint: "gate-north", Device: "d1"}); err != nil {
			t.Fatal(err)
		}
	}
	crush, err := board.Raise(Report{Kind: Crush, Checkpoint: "pit-gate", Device: "scanner-pit"})
	if err != nil {
		t.Fatal(err)
	}
	medical, err := board.Raise(Report{Kind: Medical, Checkpoint: "gate-north", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}

	listed := board.List(Filter{})
	if listed[0].ID != crush.ID {
		t.Fatalf("first listed is %s (%s), want the crush alarm %s", listed[0].ID, listed[0].Kind, crush.ID)
	}
	if listed[1].ID != medical.ID {
		t.Fatalf("second listed is %s (%s), want the medical alarm", listed[1].ID, listed[1].Kind)
	}

	loudest, ok := board.Loudest()
	if !ok || loudest.ID != crush.ID {
		t.Fatalf("loudest is %s, want %s", loudest.ID, crush.ID)
	}

	// Resolving the crush pushes it below every live item, however quiet.
	if _, err := board.Transition(crush.ID, Transition{Status: Resolved, Actor: "control"}); err != nil {
		t.Fatal(err)
	}
	listed = board.List(Filter{})
	if listed[0].ID != medical.ID {
		t.Fatalf("after resolving the crush, first listed is %s, want the medical alarm", listed[0].ID)
	}
	if last := listed[len(listed)-1]; last.ID != crush.ID {
		t.Fatalf("the resolved crush is at position %d, want last", len(listed)-1)
	}
}

func TestFilters(t *testing.T) {
	board, _ := newBoard(t)

	quiet, err := board.Raise(Report{Kind: NeedRelief, Checkpoint: "gate-north", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	loud, err := board.Raise(Report{Kind: Crush, Checkpoint: "pit-gate", Device: "scanner-pit"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := board.Transition(quiet.ID, Transition{Status: Resolved, Actor: "control"}); err != nil {
		t.Fatal(err)
	}

	t.Run("live only", func(t *testing.T) {
		got := board.List(Filter{LiveOnly: true})
		if len(got) != 1 || got[0].ID != loud.ID {
			t.Fatalf("live list is %v", ids(got))
		}
	})
	t.Run("by kind", func(t *testing.T) {
		got := board.List(Filter{Kinds: []Kind{Crush}})
		if len(got) != 1 || got[0].Kind != Crush {
			t.Fatalf("kind filter gave %v", ids(got))
		}
	})
	t.Run("by minimum severity", func(t *testing.T) {
		got := board.List(Filter{MinSeverity: Urgent})
		if len(got) != 1 || got[0].ID != loud.ID {
			t.Fatalf("severity filter gave %v", ids(got))
		}
	})
	t.Run("by zone, including nested zones", func(t *testing.T) {
		// A zone supervisor watching the arena must see the pit, because the pit
		// is inside the arena and that is where the crush happens.
		got := board.List(Filter{Zone: "arena"})
		if len(got) != 1 || got[0].ID != loud.ID {
			t.Fatalf("arena filter gave %v, want the pit incident", ids(got))
		}
		if got := board.List(Filter{Zone: "pit"}); len(got) != 1 {
			t.Fatalf("pit filter gave %v", ids(got))
		}
	})
	t.Run("since a sequence", func(t *testing.T) {
		got := board.List(Filter{Since: quiet.Seq})
		if len(got) != 1 || got[0].ID != loud.ID {
			t.Fatalf("since filter gave %v", ids(got))
		}
	})
}

func TestCounts(t *testing.T) {
	board, _ := newBoard(t)

	for _, kind := range []Kind{Crush, Medical, NeedStaff, NeedRelief} {
		if _, err := board.Raise(Report{Kind: kind, Checkpoint: "gate-north", Device: "d1"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := board.Transition("INC-1", Transition{Status: Acknowledged, Actor: "control"}); err != nil {
		t.Fatal(err)
	}
	if _, err := board.Transition("INC-2", Transition{Status: Resolved, Actor: "control"}); err != nil {
		t.Fatal(err)
	}

	counts := board.Counts()
	if counts.Open != 2 || counts.Acknowledged != 1 {
		t.Errorf("open=%d acknowledged=%d, want 2 and 1", counts.Open, counts.Acknowledged)
	}
	if counts.Emergency != 1 {
		t.Errorf("emergency=%d, want 1", counts.Emergency)
	}
	// The resolved medical alarm should not be counted as live.
	if counts.Urgent != 0 {
		t.Errorf("urgent=%d, want 0 once the medical alarm is resolved", counts.Urgent)
	}
}

// TestResponseSeparatesUnattendedFromNeverAcknowledged pins a distinction that
// matters on a live dashboard.
//
// "Never acknowledged" is a post-event judgement: an incident was closed and
// nobody had ever picked it up. "Unattended" is the live signal: it is open, past
// the grace period, and still nobody has. The first version of this counted every
// open incident as never-acknowledged, which meant an alarm raised four seconds ago
// was reported as a failure and the number an operator watches never read zero.
func TestResponseSeparatesUnattendedFromNeverAcknowledged(t *testing.T) {
	board, c := newBoard(t)

	// Two acknowledged promptly, one ignored entirely.
	fast, err := board.Raise(Report{Kind: Medical, Checkpoint: "gate-north", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	slow, err := board.Raise(Report{Kind: NeedStaff, Checkpoint: "gate-north", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := board.Raise(Report{Kind: NeedRelief, Checkpoint: "gate-north", Device: "d1"}); err != nil {
		t.Fatal(err)
	}

	c.advance(10 * time.Second)
	if _, err := board.Transition(fast.ID, Transition{Status: Acknowledged, Actor: "control"}); err != nil {
		t.Fatal(err)
	}
	c.advance(50 * time.Second)
	if _, err := board.Transition(slow.ID, Transition{Status: Acknowledged, Actor: "control"}); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Minute)
	if _, err := board.Transition(fast.ID, Transition{Status: Resolved, Actor: "medic"}); err != nil {
		t.Fatal(err)
	}

	response := board.Response()
	if response.Total != 3 {
		t.Errorf("total=%d, want 3", response.Total)
	}
	if response.Acked != 2 {
		t.Errorf("acked=%d, want 2", response.Acked)
	}
	// Still open, so it is unattended rather than never acknowledged: nobody has
	// closed the book on it yet.
	if response.NeverAcked != 0 {
		t.Errorf("never acknowledged=%d, want 0 while the incident is still open", response.NeverAcked)
	}
	if response.Unattended != 1 {
		t.Errorf("unattended=%d, want 1", response.Unattended)
	}
	if response.MedianAckSeconds != 35 {
		t.Errorf("median ack is %vs, want 35", response.MedianAckSeconds)
	}
	if response.WorstAckSeconds != 60 {
		t.Errorf("worst ack is %vs, want 60", response.WorstAckSeconds)
	}
	if response.Resolved != 1 || response.StillOpen != 2 {
		t.Errorf("resolved=%d open=%d", response.Resolved, response.StillOpen)
	}

	// A cancelled incident is not an unacknowledged one; counting it as such
	// would make the metric useless.
	cancelled, err := board.Raise(Report{Kind: Fight, Checkpoint: "gate-north", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := board.Transition(cancelled.ID, Transition{Status: Cancelled, Actor: "control", Note: "radio mixup"}); err != nil {
		t.Fatal(err)
	}
	if got := board.Response().NeverAcked; got != 0 {
		t.Errorf("never acknowledged=%d after a cancellation, want 0", got)
	}

	// Closing an unacknowledged incident is what makes it never-acknowledged: the
	// book is shut and nobody ever picked it up.
	unattended := board.Live()
	if len(unattended) == 0 {
		t.Fatal("expected a live incident to close")
	}
	if _, err := board.Transition(unattended[len(unattended)-1].ID,
		Transition{Status: Resolved, Actor: "control"}); err != nil {
		t.Fatal(err)
	}
	if got := board.Response().NeverAcked; got != 1 {
		t.Errorf("never acknowledged=%d after closing an unacknowledged incident, want 1", got)
	}
}

func TestSubscribersSeeEveryChange(t *testing.T) {
	board, _ := newBoard(t)

	var seen []Incident
	unsubscribe := board.Subscribe(func(i Incident) { seen = append(seen, i) })

	raised, err := board.Raise(Report{Kind: Crush, Checkpoint: "pit-gate", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := board.Transition(raised.ID, Transition{Status: Acknowledged, Actor: "control"}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("subscriber saw %d events, want 2", len(seen))
	}
	if seen[1].Status != Acknowledged {
		t.Errorf("the second event carries status %s", seen[1].Status)
	}

	unsubscribe()
	if _, err := board.Raise(Report{Kind: Medical, Checkpoint: "gate-north", Device: "d1"}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatal("an unsubscribed listener still received events")
	}
}

// TestRestoreKeepsAlarmsOpenAcrossAReboot is the case that matters most: an
// alarm that vanishes when the box restarts is worse than one never raised.
func TestRestoreKeepsAlarmsOpenAcrossAReboot(t *testing.T) {
	var persisted []Incident
	c := &clock{at: time.Date(2026, 8, 21, 22, 0, 0, 0, time.UTC)}
	board := NewBoard(BoardConfig{
		Venue: testVenue(t), Now: c.now,
		Persist: func(i Incident) { persisted = append(persisted, i) },
	})

	open, err := board.Raise(Report{Kind: Crush, Checkpoint: "pit-gate", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	closedOne, err := board.Raise(Report{Kind: NeedRelief, Checkpoint: "gate-north", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := board.Transition(closedOne.ID, Transition{Status: Resolved, Actor: "control"}); err != nil {
		t.Fatal(err)
	}

	// Latest state per id, which is what a store would hold.
	latest := make(map[ID]Incident)
	for _, i := range persisted {
		latest[i.ID] = i
	}
	var rows []Incident
	for _, i := range latest {
		rows = append(rows, i)
	}

	rebooted := NewBoard(BoardConfig{Venue: testVenue(t), Now: c.now})
	rebooted.Restore(rows)

	live := rebooted.Live()
	if len(live) != 1 || live[0].ID != open.ID {
		t.Fatalf("after a reboot the live list is %v, want just %s", ids(live), open.ID)
	}
	// And a new incident must not reuse an id from before the reboot.
	next, err := rebooted.Raise(Report{Kind: Medical, Checkpoint: "gate-north", Device: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if next.ID == open.ID || next.ID == closedOne.ID {
		t.Fatalf("a post-reboot incident reused the id %s", next.ID)
	}
	if next.Seq != 3 {
		t.Errorf("post-reboot sequence is %d, want 3", next.Seq)
	}
}

func TestBoardIsSafeForConcurrentUse(t *testing.T) {
	board, _ := newBoard(t)

	// Ten gates raising alarms while the control room works through them is the
	// normal case, not the edge case.
	var wg sync.WaitGroup
	for gate := 0; gate < 10; gate++ {
		wg.Add(1)
		go func(gate int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := board.Raise(Report{Kind: NeedStaff, Checkpoint: "gate-north", Device: "d1"}); err != nil {
					t.Error(err)
					return
				}
			}
		}(gate)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = board.Counts()
			_ = board.Live()
			_, _ = board.Loudest()
		}
	}()
	wg.Wait()

	if got := len(board.List(Filter{})); got != 500 {
		t.Fatalf("%d incidents raised, want 500", got)
	}
	// Ids must be unique even under contention, or two gates end up talking
	// about "INC-14" and meaning different things.
	seen := make(map[ID]bool, 500)
	for _, i := range board.List(Filter{}) {
		if seen[i.ID] {
			t.Fatalf("id %s was issued twice", i.ID)
		}
		seen[i.ID] = true
	}
}

func TestKindClassification(t *testing.T) {
	for _, kind := range []Kind{Medical, Crush, Fight, Fire, Evacuate} {
		if !IsAlarm(kind) {
			t.Errorf("%s is not classified as an alarm", kind)
		}
		if IsAutomatic(kind) {
			t.Errorf("%s is classified as automatic", kind)
		}
	}
	for _, kind := range []Kind{NeedStaff, NeedRelief, EquipmentFault} {
		if IsAlarm(kind) {
			t.Errorf("%s is classified as an alarm", kind)
		}
	}
	for _, kind := range []Kind{GateOffline, QueueSpike, OverCapacity, DoubleUseDetected, DegradedEntered} {
		if !IsAutomatic(kind) {
			t.Errorf("%s is not classified as automatic", kind)
		}
	}
	// Every kind the box advertises must be one it accepts, or the scanner draws
	// a button that raises an error.
	for _, kind := range Kinds() {
		report := Report{Kind: kind, Device: "d1"}
		if err := report.Validate(); err != nil {
			t.Errorf("advertised kind %s does not validate: %v", kind, err)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !Higher(Emergency, Urgent) || !Higher(Urgent, Warning) || !Higher(Warning, Info) {
		t.Error("severity ordering is wrong")
	}
	if Higher(Info, Emergency) {
		t.Error("info outranks emergency")
	}
}

func ids(list []Incident) []ID {
	out := make([]ID, 0, len(list))
	for _, i := range list {
		out = append(out, i.ID)
	}
	return out
}
