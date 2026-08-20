// Package stats is the control room's live picture of the event.
//
// Everything here is derived from the redemption stream, kept in memory, and
// recomputed incrementally as admissions arrive. There is no aggregation query:
// a Raspberry Pi answering a dashboard poll must not scan a table of fifty
// thousand rows, and an operator watching a queue build needs the number to
// change in under a second rather than under a minute.
//
// The numbers chosen are the ones an event actually runs on. Not "total scans" —
// that is a vanity metric nobody acts on — but occupancy against capacity per
// zone, throughput per gate over the last minute, and whether a gate has gone
// quiet. Those three answer the only questions the back room asks all night:
// where are people, which door is struggling, and has something stopped working.
package stats

import (
	"sort"
	"sync"
	"time"

	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// rateWindow is how far back throughput is measured.
//
// One minute is a deliberate compromise. Shorter and the number jumps around so
// much that an operator cannot read a trend off it; longer and a gate that has
// just stopped working takes too long to look like it has stopped working.
const rateWindow = time.Minute

// bucketWidth is the resolution of the ring buffer behind the rate. Five-second
// buckets give twelve samples across the window, which is enough for a readable
// sparkline and cheap enough to keep per gate.
const bucketWidth = 5 * time.Second

const bucketCount = int(rateWindow / bucketWidth)

// quietAfter is how long a gate can go without a scan before the dashboard calls
// it quiet.
//
// This is not the same as offline. A gate with no queue is quiet and fine; a gate
// that was doing forty scans a minute and has done none for two is a problem.
// The distinction is drawn in Gate.Quiet, which requires both silence and a
// recent history of not being silent.
const quietAfter = 2 * time.Minute

// Live is the whole dashboard payload: one snapshot, one JSON object, one poll.
type Live struct {
	// Inside is how many people are currently inside the outermost zone, which is
	// the headline number on the wall display.
	//
	// Named for what it is rather than "admitted": it is an occupancy, so it goes
	// down when people leave, and it is not the same as the number of admissions
	// recorded. Conflating the two is how a dashboard ends up claiming more people
	// are present than bought tickets.
	Inside int `json:"inside"`

	// Issued is how many tickets exist, so the headline can be "3,412 of 5,000".
	Issued int `json:"issued"`

	// Scans is every scan the box has decided, admitted or not.
	Scans int `json:"scans"`

	// Denied counts refusals, broken out by verdict so an operator can see at a
	// glance whether the problem is forgeries, wrong doors, or a manifest that
	// was never loaded.
	Denied   int                    `json:"denied"`
	Verdicts map[engine.Verdict]int `json:"verdicts"`

	// Rate is admissions per minute across the whole event over the last window.
	Rate float64 `json:"rate"`

	Zones    []Zone    `json:"zones"`
	Gates    []Gate    `json:"gates"`
	Tiers    []Tier    `json:"tiers"`
	Sections []Section `json:"sections"`

	// Devices is the scanner roster with liveness, which is how the control room
	// notices a dead battery before the queue does.
	Devices []Device `json:"devices"`

	At time.Time `json:"at"`
}

// Zone is one zone's occupancy.
type Zone struct {
	Code     venue.ZoneCode `json:"code"`
	Name     string         `json:"name"`
	Kind     venue.ZoneKind `json:"kind"`
	Occupied int            `json:"occupied"`
	Capacity int            `json:"capacity,omitempty"`

	// Fill is occupancy as a fraction of capacity, absent when no capacity is
	// declared. The dashboard colours a zone off this and nothing else.
	Fill float64 `json:"fill,omitempty"`

	// Over reports occupancy past capacity, which raises an automatic incident.
	Over bool `json:"over,omitempty"`
}

// Gate is one checkpoint's throughput.
type Gate struct {
	Code venue.CheckpointCode `json:"code"`
	Name string               `json:"name"`
	Zone venue.ZoneCode       `json:"zone"`

	Admitted int `json:"admitted"`
	Denied   int `json:"denied"`

	// Rate is admissions per minute over the last window. The number a decision
	// to move staff is made on.
	Rate float64 `json:"rate"`

	// Trend is the per-bucket counts, oldest first, for the sparkline.
	Trend []int `json:"trend"`

	// LastScan is when this gate last decided anything.
	LastScan time.Time `json:"last_scan,omitzero"`

	// Quiet means this gate was working and has now stopped. A gate with no
	// queue is not quiet, it is idle, and flagging idle gates would train
	// operators to ignore the flag.
	Quiet bool `json:"quiet,omitempty"`
}

// Tier is one ticket class's turnout.
type Tier struct {
	Code     venue.TierCode `json:"code"`
	Name     string         `json:"name"`
	Colour   string         `json:"colour,omitempty"`
	Admitted int            `json:"admitted"`
	Issued   int            `json:"issued"`
}

// Section is one seating block's turnout, which is what tells a promoter whether
// the expensive seats actually showed up.
type Section struct {
	Code     venue.SectionCode `json:"code"`
	Name     string            `json:"name"`
	Zone     venue.ZoneCode    `json:"zone"`
	Admitted int               `json:"admitted"`
	Capacity int               `json:"capacity,omitempty"`
	Fill     float64           `json:"fill,omitempty"`
}

// Device is one scanner's liveness.
type Device struct {
	ID       string    `json:"id"`
	Name     string    `json:"name,omitempty"`
	Scans    int       `json:"scans"`
	LastSeen time.Time `json:"last_seen,omitzero"`
	Quiet    bool      `json:"quiet,omitempty"`
}

// Tracker accumulates the live picture.
//
// Safe for concurrent use: the engine's writer goroutine calls Observe while the
// dashboard's handlers call Snapshot. Observe takes a write lock for a few
// microseconds, which is well inside the scan latency budget.
type Tracker struct {
	mu sync.RWMutex

	venue *venue.Venue
	now   func() time.Time

	issued     int
	issuedTier map[venue.TierCode]int

	scans    int
	denied   int
	verdicts map[engine.Verdict]int

	// occupancy is a live count per zone, maintained by replaying direction:
	// inbound adds, outbound subtracts.
	occupancy map[venue.ZoneCode]int

	admittedByGate map[venue.CheckpointCode]int
	deniedByGate   map[venue.CheckpointCode]int
	lastScanByGate map[venue.CheckpointCode]time.Time
	trendByGate    map[venue.CheckpointCode]*ring

	admittedByTier    map[venue.TierCode]int
	admittedBySection map[venue.SectionCode]int

	deviceScans map[string]int
	deviceSeen  map[string]time.Time
	deviceNames map[string]string

	overall *ring
}

// Config configures a tracker.
type Config struct {
	Venue *venue.Venue

	// Now is the box's clock, injected so tests and the simulator can drive it.
	Now func() time.Time
}

// New returns an empty tracker.
func New(cfg Config) *Tracker {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Tracker{
		venue:             cfg.Venue,
		now:               cfg.Now,
		issuedTier:        make(map[venue.TierCode]int),
		verdicts:          make(map[engine.Verdict]int),
		occupancy:         make(map[venue.ZoneCode]int),
		admittedByGate:    make(map[venue.CheckpointCode]int),
		deniedByGate:      make(map[venue.CheckpointCode]int),
		lastScanByGate:    make(map[venue.CheckpointCode]time.Time),
		trendByGate:       make(map[venue.CheckpointCode]*ring),
		admittedByTier:    make(map[venue.TierCode]int),
		admittedBySection: make(map[venue.SectionCode]int),
		deviceScans:       make(map[string]int),
		deviceSeen:        make(map[string]time.Time),
		deviceNames:       make(map[string]string),
		overall:           newRing(),
	}
}

// SetIssued records the manifest's size so the dashboard can show turnout
// against tickets sold rather than a bare count.
func (t *Tracker) SetIssued(total int, byTier map[venue.TierCode]int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.issued = total
	t.issuedTier = make(map[venue.TierCode]int, len(byTier))
	for tier, count := range byTier {
		t.issuedTier[tier] = count
	}
}

// NameDevice records a scanner's display name, so the dashboard shows "North 1"
// rather than a device id.
func (t *Tracker) NameDevice(id, name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deviceNames[id] = name
}

// Observe folds one decided scan into the picture. Every scan is observed,
// admitted or not: a wall of INVALID_SIG at one gate is the single most useful
// diagnostic the dashboard can show, and it is invisible if denials are dropped.
func (t *Tracker) Observe(result engine.Result) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fold(result, true)
}

// Rehydrate folds a decision that happened before this process started.
//
// The tracker is in memory, and for a box whose whole design assumes it will lose
// power, in memory alone is not good enough. Before this existed, a reboot brought
// the dashboard back reading "Inside 0" with twenty thousand people in the field —
// the redemptions were safe in SQLite, but the number the safety officer reads off
// the wall had been reset to zero. An occupancy figure that a power cut silently
// zeroes is worse than no occupancy figure at all, because it is believed.
//
// The distinction from Observe is deliberate and is the reason this is a separate
// entry point rather than a flag: cumulative state is rebuilt, and the sliding
// throughput windows and per-gate liveness are not. Replaying three hours of scans
// into the rate rings at boot would show every gate running flat out at the moment
// the box came up, and would mark a genuinely dead gate as busy. A freshly booted
// box has no throughput history, and saying so is the honest answer.
func (t *Tracker) Rehydrate(result engine.Result) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fold(result, false)
}

// fold applies one decision. live distinguishes a scan happening now from one
// replayed at boot; see Rehydrate.
func (t *Tracker) fold(result engine.Result, live bool) {

	// Liveness and throughput are measured at processing time, not at the
	// scan's own timestamp.
	//
	// The difference matters when a scanner that was offline for twenty minutes
	// drains its queue: those scans really happened twenty minutes ago, and that
	// is what the audit row records, but the box is processing them now. Keying
	// the rate off the scan timestamp would drop the whole batch outside the
	// window and show an idle gate at the exact moment it is busiest, and would
	// flag a furiously reconciling scanner as quiet.
	now := t.now()

	t.scans++
	t.verdicts[result.Verdict]++
	if result.Device != "" {
		t.deviceScans[result.Device]++
		if live {
			t.deviceSeen[result.Device] = now
		}
	}
	if live && result.Checkpoint != "" {
		t.lastScanByGate[result.Checkpoint] = now
	}

	if !result.Verdict.Admitted() {
		t.denied++
		if result.Checkpoint != "" {
			t.deniedByGate[result.Checkpoint]++
		}
		return
	}

	t.admittedByGate[result.Checkpoint]++

	// Tier turnout counts arrivals at the event, not admissions. One ticket passes
	// several checkpoints in an evening — the outer gate, a portal, the pit — and
	// counting each one would report three times the turnout it actually had.
	//
	// "Arrived" is defined as an admission into a root zone, which is the outer
	// perimeter. That happens exactly once per ticket per event, needs no
	// per-ticket bookkeeping, and is the number a promoter means when they ask how
	// many VIPs showed up.
	if t.isRootZone(result.Zone) {
		t.admittedByTier[result.Tier]++
	}

	// Section fill counts admissions into the section's own zone, for the same
	// reason: a Block A holder scanning at the outer gate has not taken their seat
	// yet.
	if result.Seat.Section != "" && t.sectionZone(result.Seat.Section) == result.Zone {
		t.admittedBySection[result.Seat.Section]++
	}

	if live {
		trend, ok := t.trendByGate[result.Checkpoint]
		if !ok {
			trend = newRing()
			t.trendByGate[result.Checkpoint] = trend
		}
		trend.add(now)
		t.overall.add(now)
	}

	// Occupancy follows direction. An outbound scan decrements, which is what
	// keeps a capacity meter honest on a room people leave.
	if result.Direction == venue.DirectionOut {
		t.occupancy[result.Zone]--
		if t.occupancy[result.Zone] < 0 {
			// Can happen legitimately: the box was restored from a backup taken
			// after somebody entered, or an exit door was scanned for a person
			// admitted before the manifest was reloaded. Clamping is honest;
			// showing a negative headcount is not.
			t.occupancy[result.Zone] = 0
		}
		return
	}
	t.occupancy[result.Zone]++
}

// Snapshot renders the live picture.
//
// It takes the write lock rather than a read lock because the rate rings age
// themselves lazily: reading a rate rolls expired buckets away, which is a
// mutation. Rolling on read is what avoids needing a ticker per gate, and paying
// for it with an exclusive lock at dashboard-poll frequency is cheaper than
// either alternative.
func (t *Tracker) Snapshot() Live {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	out := Live{
		Issued:   t.issued,
		Scans:    t.scans,
		Denied:   t.denied,
		Verdicts: make(map[engine.Verdict]int, len(t.verdicts)),
		Rate:     t.overall.rate(now),
		At:       now,
	}
	for verdict, count := range t.verdicts {
		out.Verdicts[verdict] = count
	}

	if t.venue == nil {
		return out
	}

	for _, zone := range t.venue.Zones() {
		// A zone's headcount includes everybody in the zones nested inside it:
		// somebody in the pit is in the arena, and an arena meter that ignored
		// the pit would read low exactly when it mattered.
		occupied := t.nested(zone.Code)
		entry := Zone{
			Code: zone.Code, Name: zone.Name, Kind: zone.Kind,
			Occupied: occupied, Capacity: zone.Capacity,
		}
		if zone.Capacity > 0 {
			entry.Fill = float64(occupied) / float64(zone.Capacity)
			entry.Over = occupied > zone.Capacity
		}
		if zone.Parent == "" && occupied > out.Inside {
			// The headline number is the outermost zone's occupancy. A venue with
			// several roots takes the largest, which is the only reading that
			// cannot understate the crowd.
			out.Inside = occupied
		}
		out.Zones = append(out.Zones, entry)
	}

	for _, cp := range t.venue.Checkpoints() {
		gate := Gate{
			Code: cp.Code, Name: cp.Name, Zone: cp.Zone,
			Admitted: t.admittedByGate[cp.Code],
			Denied:   t.deniedByGate[cp.Code],
			LastScan: t.lastScanByGate[cp.Code],
		}
		if trend, ok := t.trendByGate[cp.Code]; ok {
			gate.Rate = trend.rate(now)
			gate.Trend = trend.buckets(now)
		} else {
			gate.Trend = make([]int, bucketCount)
		}
		// Quiet requires both silence and a history of not being silent, so an
		// idle gate with no queue is not flagged.
		if gate.Admitted+gate.Denied > 0 && !gate.LastScan.IsZero() && now.Sub(gate.LastScan) > quietAfter {
			gate.Quiet = true
		}
		out.Gates = append(out.Gates, gate)
	}

	for _, tier := range t.venue.Tiers() {
		out.Tiers = append(out.Tiers, Tier{
			Code: tier.Code, Name: tier.Name, Colour: tier.Colour,
			Admitted: t.admittedByTier[tier.Code],
			Issued:   t.issuedTier[tier.Code],
		})
	}

	for _, section := range t.venue.Sections() {
		capacity := t.venue.SectionCapacity(section.Code)
		entry := Section{
			Code: section.Code, Name: section.Name, Zone: section.Zone,
			Admitted: t.admittedBySection[section.Code], Capacity: capacity,
		}
		if capacity > 0 {
			entry.Fill = float64(entry.Admitted) / float64(capacity)
		}
		out.Sections = append(out.Sections, entry)
	}

	for id, count := range t.deviceScans {
		seen := t.deviceSeen[id]
		out.Devices = append(out.Devices, Device{
			ID: id, Name: t.deviceNames[id], Scans: count, LastSeen: seen,
			Quiet: !seen.IsZero() && now.Sub(seen) > quietAfter,
		})
	}
	// Map iteration order is random, and a device list that reshuffles on every
	// poll is unreadable.
	sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].ID < out.Devices[j].ID })

	return out
}

// isRootZone reports whether a zone is an outermost one, which is what "arrived
// at the event" means. Caller holds the lock.
func (t *Tracker) isRootZone(code venue.ZoneCode) bool {
	if t.venue == nil {
		return code != ""
	}
	zone, ok := t.venue.Zone(code)
	return ok && zone.Parent == ""
}

// sectionZone returns the zone a section sits in. Caller holds the lock.
func (t *Tracker) sectionZone(code venue.SectionCode) venue.ZoneCode {
	if t.venue == nil {
		return ""
	}
	section, ok := t.venue.Section(code)
	if !ok {
		return ""
	}
	return section.Zone
}

// nested returns a zone's occupancy including every zone inside it. Caller holds
// the lock.
func (t *Tracker) nested(root venue.ZoneCode) int {
	total := t.occupancy[root]
	for _, child := range t.venue.ZoneChildren(root) {
		total += t.nested(child)
	}
	return total
}

// Occupancy returns one zone's headcount including nested zones, which the
// engine's over-capacity check uses without building a whole snapshot.
func (t *Tracker) Occupancy(zone venue.ZoneCode) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.venue == nil {
		return t.occupancy[zone]
	}
	return t.nested(zone)
}

// GateRate returns one gate's admissions per minute, which is the figure a
// staffing request carries so the control room sees the pressure without asking.
func (t *Tracker) GateRate(code venue.CheckpointCode) float64 {
	// Write lock, for the same reason as Snapshot: reading a rate ages the ring.
	t.mu.Lock()
	defer t.mu.Unlock()
	trend, ok := t.trendByGate[code]
	if !ok {
		return 0
	}
	return trend.rate(t.now())
}

// ring is a fixed-size bucketed counter over the rate window.
//
// A ring rather than a slice of timestamps because a gate doing twenty scans a
// second for ninety minutes would otherwise accumulate a hundred thousand
// time.Time values per gate, and the box has 150 MB of RAM to work inside.
type ring struct {
	counts [bucketCount]int

	// start is the bucket index of the newest bucket, and stamp is the time it
	// began. Together they let the ring age itself lazily on read or write,
	// which avoids needing a ticker per gate.
	start int
	stamp time.Time
}

func newRing() *ring { return &ring{} }

// roll ages the ring forward to the bucket containing `at`, zeroing everything
// it passes over.
func (r *ring) roll(at time.Time) {
	if r.stamp.IsZero() {
		r.stamp = at.Truncate(bucketWidth)
		return
	}
	steps := int(at.Truncate(bucketWidth).Sub(r.stamp) / bucketWidth)
	if steps <= 0 {
		return
	}
	if steps >= bucketCount {
		// The whole window has elapsed; nothing survives.
		r.counts = [bucketCount]int{}
		r.start = 0
		r.stamp = at.Truncate(bucketWidth)
		return
	}
	for i := 0; i < steps; i++ {
		r.start = (r.start + 1) % bucketCount
		r.counts[r.start] = 0
	}
	r.stamp = r.stamp.Add(time.Duration(steps) * bucketWidth)
}

// add records one event at the current instant. Callers pass the box's clock
// rather than the event's own timestamp; see the note in Observe.
func (r *ring) add(at time.Time) {
	r.roll(at)
	r.counts[r.start]++
}

// rate returns events per minute over the window.
func (r *ring) rate(at time.Time) float64 {
	r.roll(at)
	total := 0
	for _, count := range r.counts {
		total += count
	}
	return float64(total) * float64(time.Minute) / float64(rateWindow)
}

// buckets returns the window's counts oldest first, for a sparkline.
func (r *ring) buckets(at time.Time) []int {
	r.roll(at)
	out := make([]int, 0, bucketCount)
	for i := 1; i <= bucketCount; i++ {
		out = append(out, r.counts[(r.start+i)%bucketCount])
	}
	return out
}
