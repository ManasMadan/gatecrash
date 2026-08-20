package stats

import (
	"sync"
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

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

func testVenue(t *testing.T) *venue.Venue {
	t.Helper()
	compiled, err := venue.Compile(venue.Plan{
		Zones: []venue.Zone{
			{Code: "perimeter", Name: "Festival Ground", Capacity: 5000},
			{Code: "arena", Name: "Arena", Parent: "perimeter", Restricted: true, Capacity: 2000},
			{Code: "pit", Name: "Front Pit", Parent: "arena", Restricted: true, Capacity: 100},
			{Code: "concourse", Name: "Concourse", Parent: "perimeter"},
		},
		Sections: []venue.Section{
			{Code: "golden-circle", Name: "Golden Circle", Kind: venue.SectionStanding, Zone: "pit", Capacity: 100},
		},
		Checkpoints: []venue.Checkpoint{
			{Code: "gate-north", Name: "North Gate", Zone: "perimeter", Direction: venue.DirectionIn},
			{Code: "gate-south", Name: "South Gate", Zone: "perimeter", Direction: venue.DirectionIn},
			{Code: "gate-exit", Name: "Exit", Zone: "perimeter", Direction: venue.DirectionOut, Policy: venue.PolicyReEntry},
			{Code: "pit-gate", Name: "Pit Check", Zone: "pit", Direction: venue.DirectionIn},
		},
		Tiers: []venue.Tier{
			{Code: "ga", Name: "General Admission", Zones: []venue.ZoneCode{"perimeter", "arena"}, Colour: "#3B82F6"},
			{Code: "vip", Name: "VIP", Zones: []venue.ZoneCode{"perimeter", "arena", "pit"}, Colour: "#A855F7"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func newTracker(t *testing.T) (*Tracker, *clock) {
	t.Helper()
	c := &clock{at: time.Date(2026, 8, 21, 19, 0, 0, 0, time.UTC)}
	return New(Config{Venue: testVenue(t), Now: c.now}), c
}

// admit builds an admitted result. The tracker only reads a handful of fields,
// but building them properly keeps the tests honest about what it depends on.
func admit(at time.Time, gate venue.CheckpointCode, zone venue.ZoneCode, tier venue.TierCode, device string) engine.Result {
	return engine.Result{
		Verdict: engine.Admit, Severity: engine.SeverityAdmit,
		Checkpoint: gate, Zone: zone, Tier: tier, Device: device,
		Direction: venue.DirectionIn, Ticket: ticket.MustNewID(), At: at,
	}
}

func deny(at time.Time, gate venue.CheckpointCode, verdict engine.Verdict, device string) engine.Result {
	return engine.Result{
		Verdict: verdict, Severity: verdict.Severity(),
		Checkpoint: gate, Device: device, At: at,
	}
}

func TestOccupancyCountsNestedZones(t *testing.T) {
	tracker, c := newTracker(t)

	for i := 0; i < 100; i++ {
		tracker.Observe(admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north"))
	}
	for i := 0; i < 10; i++ {
		tracker.Observe(admit(c.now(), "pit-gate", "pit", "vip", "scanner-pit"))
	}

	// Somebody in the pit is in the arena and inside the perimeter. An arena
	// meter that ignored the pit would read low exactly when it mattered.
	if got := tracker.Occupancy("pit"); got != 10 {
		t.Errorf("pit occupancy is %d, want 10", got)
	}
	if got := tracker.Occupancy("arena"); got != 10 {
		t.Errorf("arena occupancy is %d, want 10 from the nested pit", got)
	}
	if got := tracker.Occupancy("perimeter"); got != 110 {
		t.Errorf("perimeter occupancy is %d, want 110", got)
	}

	snapshot := tracker.Snapshot()
	if snapshot.Inside != 110 {
		t.Errorf("headline inside count is %d, want 110", snapshot.Inside)
	}
	byCode := zonesByCode(snapshot.Zones)
	if byCode["arena"].Occupied != 10 {
		t.Errorf("arena reports %d occupied", byCode["arena"].Occupied)
	}
	if fill := byCode["pit"].Fill; fill < 0.099 || fill > 0.101 {
		t.Errorf("pit fill is %v, want 0.1", fill)
	}
}

func TestExitsDecrementOccupancy(t *testing.T) {
	tracker, c := newTracker(t)

	for i := 0; i < 50; i++ {
		tracker.Observe(admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north"))
	}
	for i := 0; i < 20; i++ {
		out := admit(c.now(), "gate-exit", "perimeter", "ga", "scanner-exit")
		out.Direction = venue.DirectionOut
		tracker.Observe(out)
	}

	if got := tracker.Occupancy("perimeter"); got != 30 {
		t.Fatalf("occupancy is %d after 50 in and 20 out, want 30", got)
	}
}

func TestOccupancyIsClampedRatherThanNegative(t *testing.T) {
	// Happens legitimately after a restore from a backup taken mid-event.
	// Clamping is honest; a negative headcount on a wall display is not.
	tracker, c := newTracker(t)
	out := admit(c.now(), "gate-exit", "perimeter", "ga", "scanner-exit")
	out.Direction = venue.DirectionOut
	tracker.Observe(out)

	if got := tracker.Occupancy("perimeter"); got != 0 {
		t.Fatalf("occupancy is %d, want 0", got)
	}
}

func TestOverCapacityIsFlagged(t *testing.T) {
	tracker, c := newTracker(t)
	for i := 0; i < 101; i++ {
		tracker.Observe(admit(c.now(), "pit-gate", "pit", "vip", "scanner-pit"))
	}

	byCode := zonesByCode(tracker.Snapshot().Zones)
	if !byCode["pit"].Over {
		t.Fatalf("pit at %d of %d is not flagged over capacity", byCode["pit"].Occupied, byCode["pit"].Capacity)
	}
	if byCode["arena"].Over {
		t.Error("the arena is flagged over capacity at 101 of 2000")
	}
	// A zone with no declared capacity reports no fill rather than a made-up one.
	if byCode["concourse"].Fill != 0 || byCode["concourse"].Over {
		t.Error("a zone with no declared capacity reported a fill")
	}
}

func TestDenialsAreCountedByVerdict(t *testing.T) {
	tracker, c := newTracker(t)

	tracker.Observe(admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north"))
	for i := 0; i < 7; i++ {
		tracker.Observe(deny(c.now(), "gate-north", engine.InvalidSig, "scanner-north"))
	}
	tracker.Observe(deny(c.now(), "gate-south", engine.AlreadyUsed, "scanner-south"))

	snapshot := tracker.Snapshot()
	if snapshot.Scans != 9 {
		t.Errorf("scans=%d, want 9", snapshot.Scans)
	}
	if snapshot.Denied != 8 {
		t.Errorf("denied=%d, want 8", snapshot.Denied)
	}
	// A wall of INVALID_SIG at one gate is the most useful diagnostic the
	// dashboard shows, and it is invisible if denials are dropped.
	if snapshot.Verdicts[engine.InvalidSig] != 7 {
		t.Errorf("INVALID_SIG count is %d, want 7", snapshot.Verdicts[engine.InvalidSig])
	}
	gates := gatesByCode(snapshot.Gates)
	if gates["gate-north"].Denied != 7 || gates["gate-north"].Admitted != 1 {
		t.Errorf("north gate reports %d admitted %d denied", gates["gate-north"].Admitted, gates["gate-north"].Denied)
	}
	// Denials must not inflate occupancy.
	if snapshot.Inside != 1 {
		t.Errorf("headline inside count is %d, want 1", snapshot.Inside)
	}
}

func TestRateMeasuresTheLastMinute(t *testing.T) {
	tracker, c := newTracker(t)

	// Exactly one admission in each of the window's buckets, so the expected
	// rate is exact rather than approximate and the test cannot drift.
	for bucket := 0; bucket < bucketCount; bucket++ {
		tracker.Observe(admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north"))
		if bucket < bucketCount-1 {
			c.advance(bucketWidth)
		}
	}

	if rate := tracker.GateRate("gate-north"); rate != float64(bucketCount) {
		t.Errorf("gate rate is %v, want %d per minute", rate, bucketCount)
	}

	// A gate that has not been touched has no rate at all rather than a zero
	// that came from somewhere.
	if rate := tracker.GateRate("gate-south"); rate != 0 {
		t.Errorf("an untouched gate reports a rate of %v", rate)
	}

	// Two minutes of silence, and the rate must fall to zero rather than
	// remembering a busy gate forever.
	c.advance(2 * rateWindow)
	if rate := tracker.GateRate("gate-north"); rate != 0 {
		t.Errorf("gate rate after two minutes of silence is %v, want 0", rate)
	}
}

func TestTrendIsOldestFirstAndWindowSized(t *testing.T) {
	tracker, c := newTracker(t)

	// One admission in the oldest bucket, three in the newest.
	tracker.Observe(admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north"))
	c.advance(rateWindow - bucketWidth)
	for i := 0; i < 3; i++ {
		tracker.Observe(admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north"))
	}

	trend := gatesByCode(tracker.Snapshot().Gates)["gate-north"].Trend
	if len(trend) != bucketCount {
		t.Fatalf("trend has %d buckets, want %d", len(trend), bucketCount)
	}
	if trend[len(trend)-1] != 3 {
		t.Errorf("newest bucket holds %d, want 3", trend[len(trend)-1])
	}
	total := 0
	for _, count := range trend {
		total += count
	}
	if total != 4 {
		t.Errorf("trend totals %d, want 4", total)
	}
}

// TestQuietNeedsAHistoryOfNotBeingQuiet is the distinction that keeps the flag
// meaningful. A gate with no queue is idle and fine; a gate that was doing forty
// a minute and has done none for two is a problem.
func TestQuietNeedsAHistoryOfNotBeingQuiet(t *testing.T) {
	tracker, c := newTracker(t)

	tracker.Observe(admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north"))
	c.advance(quietAfter + time.Second)

	gates := gatesByCode(tracker.Snapshot().Gates)
	if !gates["gate-north"].Quiet {
		t.Error("a gate that was working and has stopped is not flagged quiet")
	}
	// The south gate has never scanned anything. Flagging it would train
	// operators to ignore the flag.
	if gates["gate-south"].Quiet {
		t.Error("a gate that has never scanned is flagged quiet")
	}
}

func TestDeviceLiveness(t *testing.T) {
	tracker, c := newTracker(t)
	tracker.NameDevice("scanner-north", "North 1")

	tracker.Observe(admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north"))
	c.advance(30 * time.Second)
	tracker.Observe(admit(c.now(), "gate-south", "perimeter", "ga", "scanner-south"))
	c.advance(quietAfter + time.Second)

	devices := tracker.Snapshot().Devices
	if len(devices) != 2 {
		t.Fatalf("%d devices tracked, want 2", len(devices))
	}
	// Sorted, because a device list that reshuffles on every poll is unreadable.
	if devices[0].ID != "scanner-north" {
		t.Errorf("device list is not sorted: %s first", devices[0].ID)
	}
	if devices[0].Name != "North 1" {
		t.Errorf("device name is %q", devices[0].Name)
	}
	for _, device := range devices {
		if !device.Quiet {
			t.Errorf("%s is not flagged quiet after %s of silence", device.ID, quietAfter)
		}
	}
}

func TestTurnoutByTierAndSection(t *testing.T) {
	tracker, c := newTracker(t)
	tracker.SetIssued(500, map[venue.TierCode]int{"ga": 400, "vip": 100})

	// Turnout is counted at the outer gate, which is where an arrival happens.
	for i := 0; i < 120; i++ {
		tracker.Observe(admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north"))
	}
	for i := 0; i < 25; i++ {
		arrival := admit(c.now(), "gate-north", "perimeter", "vip", "scanner-north")
		arrival.Seat = venue.SeatRef{Section: "golden-circle"}
		tracker.Observe(arrival)

		// The same holder later reaches the pit, which is where the section fills.
		// Both are admissions; only one is an arrival and only one is a seat taken.
		seated := admit(c.now(), "pit-gate", "pit", "vip", "scanner-pit")
		seated.Seat = venue.SeatRef{Section: "golden-circle"}
		tracker.Observe(seated)
	}

	snapshot := tracker.Snapshot()
	if snapshot.Issued != 500 {
		t.Errorf("issued=%d, want 500", snapshot.Issued)
	}
	tiers := make(map[venue.TierCode]Tier, len(snapshot.Tiers))
	for _, tier := range snapshot.Tiers {
		tiers[tier.Code] = tier
	}
	if tiers["ga"].Admitted != 120 || tiers["ga"].Issued != 400 {
		t.Errorf("ga turnout is %d of %d", tiers["ga"].Admitted, tiers["ga"].Issued)
	}
	if tiers["vip"].Admitted != 25 || tiers["vip"].Issued != 100 {
		t.Errorf("vip turnout is %d of %d", tiers["vip"].Admitted, tiers["vip"].Issued)
	}
	if tiers["vip"].Colour == "" {
		t.Error("tier colour is missing, so the dashboard cannot key off it")
	}

	if len(snapshot.Sections) != 1 {
		t.Fatalf("%d sections reported", len(snapshot.Sections))
	}
	section := snapshot.Sections[0]
	if section.Admitted != 25 || section.Capacity != 100 {
		t.Errorf("section turnout is %d of %d", section.Admitted, section.Capacity)
	}
	if fill := section.Fill; fill < 0.249 || fill > 0.251 {
		t.Errorf("section fill is %v, want 0.25", fill)
	}
}

// TestRingSurvivesADrainingOfflineQueue is the reconciliation case. A scanner
// that was offline for twenty minutes drains its queue all at once; attributing
// those scans to twenty minutes ago would put them outside the window and make
// the box look idle at the exact moment it is busiest.
func TestRingSurvivesADrainingOfflineQueue(t *testing.T) {
	tracker, c := newTracker(t)
	c.advance(30 * time.Minute)

	stale := c.now().Add(-20 * time.Minute)
	for i := 0; i < 30; i++ {
		tracker.Observe(admit(stale, "gate-north", "perimeter", "ga", "scanner-north"))
	}

	if got := tracker.Occupancy("perimeter"); got != 30 {
		t.Fatalf("occupancy is %d, want 30", got)
	}
	if rate := tracker.GateRate("gate-north"); rate == 0 {
		t.Fatal("a draining offline queue registered no throughput at all")
	}
}

func TestTrackerIsSafeForConcurrentUse(t *testing.T) {
	tracker, c := newTracker(t)

	var wg sync.WaitGroup
	for writer := 0; writer < 8; writer++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				tracker.Observe(admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north"))
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = tracker.Snapshot()
			_ = tracker.Occupancy("perimeter")
			_ = tracker.GateRate("gate-north")
		}
	}()
	wg.Wait()

	if got := tracker.Occupancy("perimeter"); got != 4000 {
		t.Fatalf("occupancy is %d, want 4000", got)
	}
}

func TestSnapshotWithNoVenueDoesNotPanic(t *testing.T) {
	// The box serves a stats endpoint before a manifest is loaded, and a panic
	// there would take the whole binary down at the worst possible moment.
	tracker := New(Config{})
	tracker.Observe(engine.Result{Verdict: engine.Admit, Checkpoint: "gate-north", Zone: "perimeter"})
	snapshot := tracker.Snapshot()
	if snapshot.Scans != 1 {
		t.Fatalf("scans=%d, want 1", snapshot.Scans)
	}
}

func zonesByCode(zones []Zone) map[venue.ZoneCode]Zone {
	out := make(map[venue.ZoneCode]Zone, len(zones))
	for _, zone := range zones {
		out[zone.Code] = zone
	}
	return out
}

func gatesByCode(gates []Gate) map[venue.CheckpointCode]Gate {
	out := make(map[venue.CheckpointCode]Gate, len(gates))
	for _, gate := range gates {
		out[gate.Code] = gate
	}
	return out
}

func BenchmarkObserve(b *testing.B) {
	c := &clock{at: time.Date(2026, 8, 21, 19, 0, 0, 0, time.UTC)}
	compiled, err := venue.Compile(venue.Plan{
		Zones:       []venue.Zone{{Code: "perimeter", Capacity: 5000}},
		Checkpoints: []venue.Checkpoint{{Code: "gate-north", Zone: "perimeter"}},
		Tiers:       []venue.Tier{{Code: "ga", Zones: []venue.ZoneCode{"perimeter"}}},
	})
	if err != nil {
		b.Fatal(err)
	}
	tracker := New(Config{Venue: compiled, Now: c.now})
	result := admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tracker.Observe(result)
	}
}

// TestRehydrateRebuildsTheLivePictureAfterARestart is the safety case.
//
// The tracker is in memory and the box is expected to lose power. Before Rehydrate
// existed, a reboot brought the dashboard back reading "Inside 0" with the field
// full: the redemptions were safe in SQLite, but the occupancy number a safety
// officer reads off the wall had been silently reset to zero.
func TestRehydrateRebuildsTheLivePictureAfterARestart(t *testing.T) {
	before, c := newTracker(t)
	before.SetIssued(500, map[venue.TierCode]int{"ga": 400, "vip": 100})

	history := []engine.Result{}
	for i := 0; i < 40; i++ {
		history = append(history, admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north"))
	}
	for i := 0; i < 5; i++ {
		history = append(history, admit(c.now(), "pit-gate", "pit", "vip", "scanner-pit"))
	}
	history = append(history, deny(c.now(), "gate-north", engine.InvalidSig, "scanner-north"))
	for _, result := range history {
		before.Observe(result)
	}

	// The power goes out. A new process, a new tracker, the same log.
	after, _ := newTracker(t)
	after.SetIssued(500, map[venue.TierCode]int{"ga": 400, "vip": 100})
	for _, result := range history {
		after.Rehydrate(result)
	}

	live, restored := before.Snapshot(), after.Snapshot()
	if restored.Inside != live.Inside {
		t.Errorf("inside=%d after a restart, want %d", restored.Inside, live.Inside)
	}
	if restored.Scans != live.Scans || restored.Denied != live.Denied {
		t.Errorf("scans=%d denied=%d, want %d and %d",
			restored.Scans, restored.Denied, live.Scans, live.Denied)
	}
	if got := after.Occupancy("pit"); got != 5 {
		t.Errorf("pit occupancy=%d, want 5", got)
	}
	for i, tier := range restored.Tiers {
		if tier.Admitted != live.Tiers[i].Admitted {
			t.Errorf("%s turnout=%d, want %d", tier.Code, tier.Admitted, live.Tiers[i].Admitted)
		}
	}
}

// TestRehydrateDoesNotInventThroughput pins the other half of the bargain.
//
// Replaying three hours of scans into the rate rings at boot would show every gate
// running flat out at the instant the box came back, and would mark a gate that has
// genuinely stopped working as busy. A freshly booted box has no throughput
// history, and saying so is the honest answer.
func TestRehydrateDoesNotInventThroughput(t *testing.T) {
	tracker, c := newTracker(t)
	for i := 0; i < 200; i++ {
		tracker.Rehydrate(admit(c.now(), "gate-north", "perimeter", "ga", "scanner-north"))
	}

	if rate := tracker.GateRate("gate-north"); rate != 0 {
		t.Errorf("gate rate=%v straight after a restart, want 0", rate)
	}
	live := tracker.Snapshot()
	if live.Rate != 0 {
		t.Errorf("overall rate=%v straight after a restart, want 0", live.Rate)
	}
	for _, gate := range live.Gates {
		if gate.Quiet {
			t.Errorf("%s is marked quiet straight after a restart", gate.Code)
		}
	}
}
