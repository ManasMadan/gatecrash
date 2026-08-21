package simulation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/enginetest"
	"github.com/ManasMadan/gatecrash/internal/memstore"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// EventConfig describes one simulated event-day.
//
// Every field that could vary is here, and everything varies from the seed. A run
// is fully described by this struct, which is what makes "it failed on seed 41908"
// a complete bug report.
type EventConfig struct {
	Seed uint64

	// Tickets is how many tickets the event issued.
	Tickets int

	// Scanners is how many gate devices are working.
	Scanners int

	// Scans is how many scan attempts the run performs.
	Scans int

	// Mode is STRICT or DEGRADED. The invariants checked differ, because the
	// guarantees differ — that is the whole point of having two modes.
	Mode engine.Mode

	// Faults are the probabilities of each kind of thing going wrong, per scan.
	Faults Faults

	// Verbose logs every scan. Only useful when replaying a single failing seed.
	Verbose bool
}

// Faults are the injected failures, as per-scan probabilities.
//
// The defaults are deliberately far worse than a real event. A simulator tuned to
// realistic failure rates finds realistic bugs, which are the ones that would have
// been found anyway; the interesting bugs live where three unlikely things happen at
// once, and the only way to get there in a reasonable number of runs is to make each
// one likely.
type Faults struct {
	// Retry resends a scan the network already delivered, with the same scan id.
	// This is the ordinary case of a scanner that did not see the response, and it
	// must produce the original verdict rather than ALREADY_USED.
	Retry float64

	// Reuse presents the same ticket again at the same gate, with a fresh scan id.
	// A genuinely different scan of the same ticket, which must be refused.
	Reuse float64

	// Reorder holds a scan back and delivers it after later ones.
	Reorder float64

	// Offline marks a scan as already admitted by a scanner during a partition.
	// Only meaningful in DEGRADED, where it is the source of double uses.
	Offline float64

	// Skew moves one scanner's clock, so the HLC has something to reconcile.
	Skew float64

	// PowerCut drops everything written since the last durable point.
	PowerCut float64

	// WriteFail makes the store reject a write, as a full disk or a locked
	// database would.
	WriteFail float64
}

// DefaultFaults is the aggressive profile used by the sweep.
func DefaultFaults() Faults {
	return Faults{
		Retry:     0.08,
		Reuse:     0.10,
		Reorder:   0.05,
		Offline:   0.06,
		Skew:      0.03,
		PowerCut:  0.002,
		WriteFail: 0.01,
	}
}

// EventResult is what one event-day run observed.
type EventResult struct {
	Config EventConfig `json:"config"`

	Scans     int `json:"scans"`
	Admitted  int `json:"admitted"`
	Refused   int `json:"refused"`
	Errors    int `json:"errors"`
	PowerCuts int `json:"power_cuts"`
	Flagged   int `json:"flagged"`

	Verdicts map[engine.Verdict]int `json:"verdicts"`

	// Violations are the invariant failures. An empty list is the only acceptable
	// result, and the run is worthless if this is not checked.
	Violations []string `json:"violations,omitempty"`

	Duration time.Duration `json:"duration"`
}

// OK reports whether the run held every invariant.
func (r EventResult) OK() bool { return len(r.Violations) == 0 }

// String renders a result as one line for the sweep output.
func (r EventResult) String() string {
	status := "ok"
	if !r.OK() {
		status = fmt.Sprintf("FAILED (%d violations)", len(r.Violations))
	}
	return fmt.Sprintf("seed=%-8d mode=%-8s scans=%-6d admitted=%-6d refused=%-6d cuts=%-3d flagged=%-3d %s",
		r.Config.Seed, r.Config.Mode, r.Scans, r.Admitted, r.Refused, r.PowerCuts, r.Flagged, status)
}

func (c *EventConfig) withDefaults() {
	if c.Tickets <= 0 {
		c.Tickets = 200
	}
	if c.Scanners <= 0 {
		c.Scanners = 6
	}
	if c.Scans <= 0 {
		c.Scans = 2000
	}
	if c.Mode == "" {
		c.Mode = engine.ModeStrict
	}
}

// RunEvent simulates one event-day and checks the invariants.
//
// The engine, the store's transaction semantics and the audit chain are the real
// ones. What is faked is the world around them: the clock, the network, the
// scanners' willingness to retry, and the SD card's willingness to lie about having
// written something.
func RunEvent(cfg EventConfig) EventResult {
	cfg.withDefaults()
	started := time.Now()

	result := EventResult{Config: cfg, Verdicts: map[engine.Verdict]int{}}
	rng := NewRand(cfg.Seed)

	world, err := newWorld(cfg, rng)
	if err != nil {
		result.Violations = append(result.Violations, "could not build the world: "+err.Error())
		return result
	}

	// Scans that were held back by the reorder fault, to be delivered later.
	var delayed []engine.Scan

	// What the box told each scan id, so a retry can be checked against it. This is
	// the model of the scanner's own memory, and it is what makes the idempotency
	// invariant checkable.
	answered := map[ticket.ID]engine.Result{}

	// Admissions the box acknowledged. Used after a power cut to assert that nothing
	// acknowledged went missing.
	acknowledged := map[string]engine.Result{}

	for i := 0; i < cfg.Scans; i++ {
		draw := rng.Derive(uint64(i))

		scan, ok := world.nextScan(draw, answered, cfg.Faults)
		if !ok {
			continue
		}

		// Reordering: hold this one back and send an older one instead.
		if draw.Chance(cfg.Faults.Reorder) {
			delayed = append(delayed, scan)
			if len(delayed) < 4 {
				continue
			}
			scan, delayed = delayed[0], delayed[1:]
		}

		if draw.Chance(cfg.Faults.WriteFail) {
			world.store.FailWrites(errors.New("simulated disk failure"))
		}

		world.advance(draw)
		result.Scans++

		outcome, err := world.engine.Scan(context.Background(), world.store, scan)
		world.store.FailWrites(nil)

		if err != nil {
			// A rejected write is a correct outcome, not a violation: the box refused
			// to acknowledge something it could not durably record. What would be a
			// violation is admitting somebody and then losing the record, which is
			// what the acknowledged map below checks.
			result.Errors++
			continue
		}

		result.Verdicts[outcome.Verdict]++
		if outcome.Verdict.Admitted() {
			result.Admitted++
			key := fmt.Sprintf("%s|%s|%d", outcome.Ticket, outcome.Checkpoint, outcome.Occurrence)
			acknowledged[key] = outcome
		} else {
			result.Refused++
		}

		// The idempotency invariant, checked on every retry rather than at the end: a
		// scanner that resends the same scan id must get the same answer back. If this
		// ever differs, a network retry has been counted as a second use, which at a
		// real gate means turning somebody away for the crime of bad Wi-Fi.
		if previous, seen := answered[scan.ScanID]; seen {
			if previous.Verdict != outcome.Verdict {
				result.Violations = append(result.Violations, fmt.Sprintf(
					"idempotency: scan %s first returned %s and then %s",
					scan.ScanID, previous.Verdict, outcome.Verdict))
			}
		} else {
			answered[scan.ScanID] = outcome
			world.order = append(world.order, scan.ScanID)
		}

		// Durable after every decided scan, not only after admissions.
		//
		// This is what synchronous=FULL means in the real store: the transaction that
		// records a refusal is committed as firmly as the one that records an
		// admission. Flushing only on admit modelled a weaker box than the one that
		// exists, and the simulator duly reported an idempotency violation for it — a
		// retry of a refused scan, after a power cut had eaten the stored refusal,
		// re-decided and came back with a different reason. The engine was right and
		// the model was wrong.
		world.store.Flush()

		if draw.Chance(cfg.Faults.PowerCut) {
			world.store.Cut()
			result.PowerCuts++

			// The box comes back and recovers its chain, exactly as serve does at
			// boot. A failure here is a real bug: it means the box cannot restart.
			if err := world.engine.Recover(context.Background(), world.store); err != nil {
				result.Violations = append(result.Violations,
					"the box could not recover after a power cut: "+err.Error())
			}
			checkAcknowledgedSurvived(world, acknowledged, &result)
		}
	}

	// Anything still held back gets delivered at the end, so the reorder fault does
	// not silently reduce the number of scans that actually happened.
	for _, scan := range delayed {
		world.advance(rng)
		if _, err := world.engine.Scan(context.Background(), world.store, scan); err != nil {
			result.Errors++
		}
	}

	checkInvariants(world, cfg, &result)
	result.Flagged = len(world.store.Flags())
	result.Duration = time.Since(started)
	return result
}

// world is the fake event: an engine, a store, tickets, gates and scanners.
type world struct {
	engine *engine.Engine
	store  *memstore.Store

	tickets  []ticket.ID
	payloads map[ticket.ID]string
	tiers    map[ticket.ID]venue.TierCode
	seats    map[ticket.ID]venue.SeatRef

	gates    []venue.CheckpointCode
	scanners []string

	// skew is each scanner's clock error. Injected because in a field nobody's
	// clock is right, and the HLC exists precisely so that being wrong does not
	// break causality.
	skew map[string]time.Duration

	// order is the scan ids the box has answered, in order, so a retry can pick one
	// uniformly without sorting a map.
	order []ticket.ID

	clock time.Time
	venue *venue.Venue
}

// newWorld builds the fake event.
func newWorld(cfg EventConfig, rng *Rand) (*world, error) {
	plan := enginetest.VenuePlan()
	compiled, err := venue.Compile(plan)
	if err != nil {
		return nil, fmt.Errorf("the simulator's venue does not compile: %w", err)
	}

	signing, verifying, err := ticket.GenerateSigningKey()
	if err != nil {
		return nil, err
	}
	root, err := ticket.NewMasterKey()
	if err != nil {
		return nil, err
	}
	eventID := ticket.MustNewID()
	master, err := ticket.DeriveEventMaster(root, eventID)
	if err != nil {
		return nil, err
	}

	w := &world{
		store:    memstore.New(),
		payloads: map[ticket.ID]string{},
		tiers:    map[ticket.ID]venue.TierCode{},
		seats:    map[ticket.ID]venue.SeatRef{},
		skew:     map[string]time.Duration{},
		clock:    enginetest.Doors.Add(15 * time.Minute),
		venue:    compiled,
	}

	// Tiers in the proportions a real event sells them, so the simulator spends its
	// scans where the interesting decisions are rather than distributing them
	// evenly across a roster nobody buys.
	for i := 0; i < cfg.Tickets; i++ {
		stream := rng.Derive(uint64(100_000 + i))

		tier := venue.TierCode("ga")
		var seat venue.SeatRef
		switch {
		case stream.Chance(0.02):
			tier = "crew"
		case stream.Chance(0.15):
			tier = "vip"
			seat = venue.SeatRef{Section: "golden-circle"}
		case stream.Chance(0.5):
			row := "A"
			if stream.Chance(0.5) {
				row = "B"
			}
			seat = venue.SeatRef{Section: "block-a", Row: row, Seat: itoa(1 + stream.Intn(10))}
		}

		// The GC1 payload carries only the ticket id and the signature — the claims
		// the signature covers are reconstructed by the box from its own stored
		// record. So the tier and the issue time here have to be exactly the ones
		// stored below, or every scan comes back INVALID_SIG. That is what makes
		// storing the signature rather than the private key safe, and it is also the
		// easiest thing in the whole system to get subtly wrong.
		id := ticket.MustNewID()
		issuedAt := enginetest.Doors.Add(-24 * time.Hour).UnixMilli()
		payload, err := ticket.SignGC1(signing, ticket.Claims{
			EventID:  eventID,
			TicketID: id,
			Tier:     string(tier),
			IssuedAt: issuedAt,
		})
		if err != nil {
			return nil, err
		}

		w.tickets = append(w.tickets, id)
		w.payloads[id] = payload
		w.tiers[id] = tier
		w.seats[id] = seat
		w.store.PutTicket(engine.Ticket{
			ID: id, EventID: eventID, Tier: tier, Seat: seat,
			IssuedAt: issuedAt, Format: engine.FormatStatic,
		})
	}

	for _, checkpoint := range compiled.Checkpoints() {
		w.gates = append(w.gates, checkpoint.Code)
	}
	sort.Slice(w.gates, func(i, j int) bool { return w.gates[i] < w.gates[j] })

	for i := 0; i < cfg.Scanners; i++ {
		id := fmt.Sprintf("dev-%02d", i)
		w.scanners = append(w.scanners, id)
		// Every scanner can work any gate, which is the harder case to get right: it
		// means two devices can race on the same ticket at the same door.
		w.store.PutDevice(engine.Device{ID: id, Name: id, Checkpoints: w.gates})
	}

	w.engine, err = engine.New(engine.Config{
		EventID:   eventID,
		Venue:     compiled,
		Verifying: verifying,
		Master:    master,
		Mode:      cfg.Mode,
		Now:       func() time.Time { return w.clock },
	})
	if err != nil {
		return nil, err
	}
	if err := w.engine.Recover(context.Background(), w.store); err != nil {
		return nil, err
	}
	w.store.Flush()
	return w, nil
}

// advance moves the box's clock forward by a small random amount.
func (w *world) advance(rng *Rand) {
	w.clock = w.clock.Add(time.Duration(rng.Between(50, 900)) * time.Millisecond)
}

// nextScan builds the next scan attempt, applying the retry and reuse faults.
func (w *world) nextScan(rng *Rand, answered map[ticket.ID]engine.Result, faults Faults) (engine.Scan, bool) {
	if len(w.tickets) == 0 || len(w.gates) == 0 {
		return engine.Scan{}, false
	}

	// A retry of something already sent: same scan id, same everything.
	//
	// Picked from an insertion-ordered slice rather than by sorting the map's keys.
	// Sorting was O(n log n) on a set that grows to thousands, on a path taken
	// several hundred times a run, and it was most of the cost of a run — which
	// matters because the value of this simulator is in how many event-days it can
	// get through.
	if len(w.order) > 0 && rng.Chance(faults.Retry) {
		previous := answered[w.order[rng.Intn(len(w.order))]]

		return engine.Scan{
			ScanID:     previous.ScanID,
			Payload:    w.payloads[previous.Ticket],
			Checkpoint: previous.Checkpoint,
			Device:     previous.Device,
			DeviceHLC:  w.engine.Clock().Now(),
			ObservedAt: w.clock,
		}, true
	}

	id := w.tickets[rng.Intn(len(w.tickets))]
	device := w.scanners[rng.Intn(len(w.scanners))]

	// Skew a scanner's clock. The HLC exists so that this cannot break causality,
	// and this is what tests that claim.
	if rng.Chance(faults.Skew) {
		w.skew[device] = time.Duration(rng.Between(-120, 120)) * time.Second
	}

	scan := engine.Scan{
		ScanID:     ticket.MustNewID(),
		Payload:    w.payloads[id],
		Checkpoint: w.pickGate(rng, id),
		Device:     device,
		DeviceHLC:  w.engine.Clock().Now(),
		ObservedAt: w.clock.Add(w.skew[device]),
	}

	// In DEGRADED a scanner admits from its own mirror during a partition and tells
	// the box afterwards. That is the only way a double use can happen, and
	// detecting every one of them is the mode's entire guarantee.
	if faults.Offline > 0 && rng.Chance(faults.Offline) {
		scan.OfflineAdmitted = true
	}
	return scan, true
}

// pickGate chooses where this ticket is presented.
//
// Weighted towards the gate the ticket should actually use, with a healthy minority
// of wrong doors — because a wrong door is a decision the engine has to get right,
// not an error, and a simulator that only ever presents correct tickets at correct
// gates exercises one branch.
func (w *world) pickGate(rng *Rand, id ticket.ID) venue.CheckpointCode {
	if rng.Chance(0.35) {
		return w.gates[rng.Intn(len(w.gates))]
	}

	switch seat := w.seats[id]; {
	case seat.Section == "block-a":
		if rng.Chance(0.5) {
			return "gate-north"
		}
		return "portal-lower"
	case seat.Section == "golden-circle":
		if rng.Chance(0.4) {
			return "gate-north"
		}
		return "pit-gate"
	default:
		if rng.Chance(0.5) {
			return "gate-north"
		}
		return "arena-general"
	}
}

// checkAcknowledgedSurvived asserts that a power cut lost nothing the box had
// acknowledged.
//
// This is the durability guarantee, and it is the one an organizer cares about: the
// box may lose the last few milliseconds of work, but it must never lose a scan it
// told a guard was fine. Anything else means somebody walks in twice.
func checkAcknowledgedSurvived(w *world, acknowledged map[string]engine.Result, result *EventResult) {
	present := map[string]bool{}
	for _, redemption := range w.store.Admissions() {
		present[fmt.Sprintf("%s|%s|%d", redemption.TicketID, redemption.Checkpoint, redemption.Occurrence)] = true
	}

	keys := make([]string, 0, len(acknowledged))
	for key := range acknowledged {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if !present[key] {
			result.Violations = append(result.Violations, fmt.Sprintf(
				"durability: admission %s was acknowledged and then lost in a power cut", key))
			// One report is enough. A cut that lost one row lost a suffix of them, and
			// a hundred identical violations obscure the seed that produced them.
			return
		}
	}
}

// checkInvariants is the whole point of the simulator.
func checkInvariants(w *world, cfg EventConfig, result *EventResult) {
	admissions := w.store.Admissions()

	// 1. No two admissions for the same ticket at a once-only checkpoint.
	//
	// This is the exactly-once guarantee, and it is the reason the redemption table
	// has the primary key it has. In STRICT it must hold absolutely; in DEGRADED a
	// violation is permitted only if it is flagged, which is checked below.
	type doorKey struct {
		id ticket.ID
		cp venue.CheckpointCode
	}
	counted := map[doorKey]int{}
	for _, admission := range admissions {
		counted[doorKey{admission.TicketID, admission.Checkpoint}]++
	}

	flagged := map[ticket.ID]bool{}
	for _, flag := range w.store.Flags() {
		flagged[flag.TicketID] = true
	}

	for key, count := range counted {
		if count <= 1 {
			continue
		}
		checkpoint, ok := w.venue.Checkpoint(key.cp)
		if !ok || checkpoint.Policy != venue.PolicyOnce {
			// Re-entry and counted checkpoints are supposed to admit more than once.
			continue
		}
		if cfg.Mode == engine.ModeStrict {
			result.Violations = append(result.Violations, fmt.Sprintf(
				"strict: ticket %s admitted %d times at once-only checkpoint %s",
				key.id, count, key.cp))
			continue
		}
		// DEGRADED admits that a double use can happen under partition. What it
		// promises is that every one is detected, so an undetected one is the
		// violation.
		if !flagged[key.id] {
			result.Violations = append(result.Violations, fmt.Sprintf(
				"degraded: ticket %s used %d times at %s and was never flagged",
				key.id, count, key.cp))
		}
	}

	// 2. The audit chain is unbroken.
	//
	// Every decision is chained, so a break means either a bug in the linking or a
	// power cut that left a torn write — and the whole point of the chain is that
	// neither can happen silently.
	records := w.store.Records()
	if err := audit.Verify(records); err != nil {
		result.Violations = append(result.Violations, "audit chain: "+err.Error())
	}

	// 3. Every admission has an audit row.
	//
	// A redemption without a row is an admission nobody can prove happened, which is
	// exactly the claim a dispute turns on.
	rows := map[string]bool{}
	for _, record := range records {
		if engine.Verdict(record.Verdict).Admitted() {
			rows[fmt.Sprintf("%s|%s|%d", record.TicketID, record.Checkpoint, record.Occurrence)] = true
		}
	}
	for _, admission := range admissions {
		key := fmt.Sprintf("%s|%s|%d", admission.TicketID, admission.Checkpoint, admission.Occurrence)
		if !rows[key] {
			result.Violations = append(result.Violations, fmt.Sprintf(
				"audit: admission %s has no audit row", key))
			break
		}
	}

	// 4. The chain's sequence numbers are dense and ordered.
	//
	// A gap means a row was lost; a repeat means one was written twice. Both are
	// invisible to a hash-chain check on its own, because a chain over a subset of
	// rows still verifies.
	for i, record := range records {
		if record.Seq != uint64(i+1) {
			result.Violations = append(result.Violations, fmt.Sprintf(
				"audit: row %d carries sequence %d", i+1, record.Seq))
			break
		}
	}

	// 5. The HLC never went backwards.
	//
	// Scanners' clocks are deliberately skewed by up to two minutes in either
	// direction, and the hybrid logical clock's entire job is that the log's order
	// survives that.
	for i := 1; i < len(records); i++ {
		if records[i].HLC < records[i-1].HLC {
			result.Violations = append(result.Violations, fmt.Sprintf(
				"hlc: row %d has timestamp %d, before row %d's %d",
				records[i].Seq, records[i].HLC, records[i-1].Seq, records[i-1].HLC))
			break
		}
	}
}

// itoa without strconv, matching the fixture's own helper. Kept local because
// pulling in a formatting dependency for one integer is not worth the import.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// SweepEvents runs many seeded event-days and returns the failures.
//
// The return is only the failures on purpose. A sweep of ten thousand runs that
// returned ten thousand results would bury the one that matters, and the one that
// matters is fully described by its seed.
func SweepEvents(base EventConfig, seeds int) []EventResult {
	var failures []EventResult
	for seed := 0; seed < seeds; seed++ {
		cfg := base
		cfg.Seed = base.Seed + uint64(seed)
		if result := RunEvent(cfg); !result.OK() {
			failures = append(failures, result)
		}
	}
	return failures
}
