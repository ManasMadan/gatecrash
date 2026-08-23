package simulation

import (
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/engine"
)

// TestTheSameSeedProducesTheSameRun is the property everything else depends on.
// A simulator that finds a rare bug and cannot reproduce it has found nothing.
func TestTheSameSeedProducesTheSameRun(t *testing.T) {
	cfg := EventConfig{Seed: 1234, Tickets: 40, Scans: 200, Faults: DefaultFaults()}

	first, second := RunEvent(cfg), RunEvent(cfg)

	if first.Scans != second.Scans || first.Admitted != second.Admitted ||
		first.Refused != second.Refused || first.PowerCuts != second.PowerCuts {
		t.Errorf("two runs of seed %d disagree:\n %+v\n %+v", cfg.Seed, first, second)
	}
	for verdict, count := range first.Verdicts {
		if second.Verdicts[verdict] != count {
			t.Errorf("verdict %s: %d then %d", verdict, count, second.Verdicts[verdict])
		}
	}
}

// TestDifferentSeedsProduceDifferentRuns, or the sweep is running the same run
// thousands of times and proving nothing.
func TestDifferentSeedsProduceDifferentRuns(t *testing.T) {
	base := EventConfig{Tickets: 40, Scans: 200, Faults: DefaultFaults()}

	seen := map[int]bool{}
	for seed := uint64(1); seed <= 8; seed++ {
		cfg := base
		cfg.Seed = seed
		seen[RunEvent(cfg).Admitted] = true
	}
	if len(seen) < 4 {
		t.Errorf("eight seeds produced only %d distinct admission counts", len(seen))
	}
}

// TestTheSimulatorActuallyAdmitsPeople.
//
// The invariants are all of the form "this bad thing never happened", so a run that
// refuses everything satisfies every one of them and proves nothing. This is the
// guard against a green sweep that means nothing — which is exactly what the first
// version of this simulator produced, because the payloads it signed did not match
// the ticket records it stored and every single scan came back INVALID_SIG.
func TestTheSimulatorActuallyAdmitsPeople(t *testing.T) {
	result := RunEvent(EventConfig{Seed: 1, Tickets: 60, Scans: 600, Faults: DefaultFaults()})

	if result.Admitted == 0 {
		t.Fatal("no scan was admitted, so every invariant passes vacuously")
	}
	if float64(result.Admitted)/float64(result.Scans) < 0.05 {
		t.Errorf("only %d of %d scans were admitted", result.Admitted, result.Scans)
	}
	if result.Verdicts[engine.InvalidSig] > 0 {
		t.Errorf("%d scans failed signature verification, which means the world is misbuilt",
			result.Verdicts[engine.InvalidSig])
	}
}

// TestTheSimulatorExercisesTheInterestingRefusals. A run that only ever produced
// ADMIT and ALREADY_USED would leave most of the engine untested.
func TestTheSimulatorExercisesTheInterestingRefusals(t *testing.T) {
	result := RunEvent(EventConfig{Seed: 3, Tickets: 80, Scans: 1200, Faults: DefaultFaults()})

	for _, verdict := range []engine.Verdict{
		engine.Admit,
		engine.AlreadyUsed,
		engine.PrerequisiteMissing,
		engine.WrongDoor,
	} {
		if result.Verdicts[verdict] == 0 {
			t.Errorf("no scan produced %s", verdict)
		}
	}
}

// TestStrictNeverAdmitsTwice is the guarantee STRICT exists to make.
func TestStrictNeverAdmitsTwice(t *testing.T) {
	for seed := uint64(1); seed <= 12; seed++ {
		result := RunEvent(EventConfig{
			Seed: seed, Mode: engine.ModeStrict,
			Tickets: 50, Scans: 400, Faults: DefaultFaults(),
		})
		if !result.OK() {
			t.Errorf("seed %d: %v", seed, result.Violations)
		}
	}
}

// TestDegradedDetectsEveryDoubleUse is the guarantee DEGRADED makes instead.
//
// Prevention is impossible under partition — that is CAP, not a bug — so what is
// promised is that every double use is detected, with both records attached.
func TestDegradedDetectsEveryDoubleUse(t *testing.T) {
	sawFlags := false
	for seed := uint64(1); seed <= 12; seed++ {
		result := RunEvent(EventConfig{
			Seed: seed, Mode: engine.ModeDegraded,
			Tickets: 50, Scans: 400, Faults: DefaultFaults(),
		})
		if !result.OK() {
			t.Errorf("seed %d: %v", seed, result.Violations)
		}
		if result.Flagged > 0 {
			sawFlags = true
		}
	}
	if !sawFlags {
		t.Error("no double use was ever flagged, so the detection path is untested")
	}
}

// TestPowerCutsHappenAndAreSurvived. The invariant checker verifies that nothing
// acknowledged was lost; this checks that cuts actually occur, since an invariant
// about power cuts is worthless if none are injected.
func TestPowerCutsHappenAndAreSurvived(t *testing.T) {
	faults := DefaultFaults()
	faults.PowerCut = 0.05

	result := RunEvent(EventConfig{Seed: 9, Tickets: 40, Scans: 400, Faults: faults})
	if result.PowerCuts == 0 {
		t.Fatal("no power cut was injected at a 5% rate over 400 scans")
	}
	if !result.OK() {
		t.Errorf("%d power cuts broke an invariant: %v", result.PowerCuts, result.Violations)
	}
}

// TestAViolationIsActuallyReported guards the checker itself.
//
// Every other test here asserts that nothing failed, which is also what a checker
// that never reports anything would produce. This one hands it a world that has
// definitely broken a rule and insists it says so.
func TestAViolationIsActuallyReported(t *testing.T) {
	cfg := EventConfig{Seed: 1, Tickets: 10, Scans: 50}
	cfg.withDefaults()

	rng := NewRand(cfg.Seed)
	world, err := newWorld(cfg, rng)
	if err != nil {
		t.Fatal(err)
	}

	var result EventResult
	// A fabricated acknowledgement for an admission the store has never heard of,
	// which is precisely the durability failure the checker exists to catch.
	checkAcknowledgedSurvived(world, map[string]engine.Result{
		"NOSUCHTICKET|gate-north|0": {},
	}, &result)

	if result.OK() {
		t.Fatal("the checker accepted a lost acknowledged admission")
	}
}

// TestCrowdRunsAreReproducible, same reasoning as the event simulator.
func TestCrowdRunsAreReproducible(t *testing.T) {
	cfg := CrowdConfig{Nodes: 40, Width: 40, Height: 30, Messages: 4, Duration: 20 * time.Second, Seed: 5}

	first, second := RunCrowd(cfg), RunCrowd(cfg)
	if first.Delivered != second.Delivered || first.Transmissions != second.Transmissions {
		t.Errorf("two crowd runs of one seed disagree: %.4f/%d vs %.4f/%d",
			first.Delivered, first.Transmissions, second.Delivered, second.Transmissions)
	}
}

// TestACrowdDeliversMessages, so a delivery figure of zero cannot pass unnoticed.
func TestACrowdDeliversMessages(t *testing.T) {
	result := RunCrowd(CrowdConfig{
		Nodes: 120, Width: 40, Height: 30, Range: 20,
		Messages: 6, Duration: 30 * time.Second, K: 3, Seed: 11,
	})

	if result.Delivered < 0.8 {
		t.Errorf("delivered %.1f%% in a well-connected crowd", result.Delivered*100)
	}
	if result.Transmissions == 0 {
		t.Fatal("nothing was transmitted")
	}
	if result.MedianLatency <= 0 || result.MedianLatency > 5*time.Second {
		t.Errorf("median latency is %s", result.MedianLatency)
	}
}

// TestDenserCrowdsRelayLessOften is the density-adaptive rule, measured.
//
// The airtime per message must grow far slower than the crowd. If it grows in step,
// the rule is not working and the protocol is a broadcast storm with extra steps.
func TestDenserCrowdsRelayLessOften(t *testing.T) {
	base := CrowdConfig{
		Width: 40, Height: 30, Range: 20,
		Messages: 5, Duration: 30 * time.Second, K: 3, Seed: 13,
	}

	sparse, dense := base, base
	sparse.Nodes = 100
	dense.Nodes = 800

	sparseResult, denseResult := RunCrowd(sparse), RunCrowd(dense)

	if denseResult.RelayProbability >= sparseResult.RelayProbability {
		t.Errorf("relay probability did not fall with density: %.4f at %d nodes, %.4f at %d",
			sparseResult.RelayProbability, sparse.Nodes, denseResult.RelayProbability, dense.Nodes)
	}

	// Airtime must grow sub-linearly in the size of the crowd. Growing in step would
	// mean every extra phone adds a transmission, which is the broadcast storm this
	// parameter exists to avoid.
	crowdRatio := float64(dense.Nodes) / float64(sparse.Nodes)
	airtimeRatio := denseResult.TransmissionsPerMessage / sparseResult.TransmissionsPerMessage
	if airtimeRatio >= crowdRatio {
		t.Errorf("airtime per message grew %.1fx for %.0fx the crowd, so the density rule is not holding",
			airtimeRatio, crowdRatio)
	}

	// And the number that protects batteries: each phone's own share of the airtime
	// has to fall as the crowd grows. Total airtime rising sub-linearly is not enough
	// on its own — it is the per-phone figure that drains a battery, and that is what
	// somebody at a festival actually experiences.
	sparsePerPhone := sparseResult.TransmissionsPerMessage / float64(sparse.Nodes)
	densePerPhone := denseResult.TransmissionsPerMessage / float64(dense.Nodes)
	if densePerPhone >= sparsePerPhone {
		t.Errorf("each phone transmits %.4f times per message at %d nodes and %.4f at %d — it should fall",
			sparsePerPhone, sparse.Nodes, densePerPhone, dense.Nodes)
	}
	t.Logf("per phone per message: %.4f transmissions at %d nodes, %.4f at %d",
		sparsePerPhone, sparse.Nodes, densePerPhone, dense.Nodes)
	t.Logf("%d nodes: %.0f tx/msg at p=%.3f; %d nodes: %.0f tx/msg at p=%.3f",
		sparse.Nodes, sparseResult.TransmissionsPerMessage, sparseResult.RelayProbability,
		dense.Nodes, denseResult.TransmissionsPerMessage, denseResult.RelayProbability)
}

// TestRandIsUniformEnough. A biased source would skew every parameter sweep in a
// way that looks like a result.
func TestRandIsUniformEnough(t *testing.T) {
	r := NewRand(42)

	const draws = 200_000
	buckets := [10]int{}
	for i := 0; i < draws; i++ {
		value := r.Float64()
		if value < 0 || value >= 1 {
			t.Fatalf("Float64 returned %v", value)
		}
		buckets[int(value*10)]++
	}
	for i, count := range buckets {
		if count < draws/10*9/10 || count > draws/10*11/10 {
			t.Errorf("bucket %d holds %d of %d draws", i, count, draws)
		}
	}

	// Intn must not be biased low, which is what a modulo would do.
	counts := map[int]int{}
	for i := 0; i < 60_000; i++ {
		counts[r.Intn(7)]++
	}
	for value, count := range counts {
		if count < 7_000 || count > 10_500 {
			t.Errorf("Intn(7) returned %d %d times out of 60000", value, count)
		}
	}
}

// TestDerivedStreamsAreIndependent. Without this, adding one node to a crowd
// changes every other node's behaviour and a density sweep measures nothing.
func TestDerivedStreamsAreIndependent(t *testing.T) {
	root := NewRand(7)
	first := root.Derive(1).Uint64()
	second := root.Derive(2).Uint64()
	again := root.Derive(1).Uint64()

	if first == second {
		t.Error("two labels produced the same stream")
	}
	if first != again {
		t.Error("the same label produced a different stream the second time")
	}
}

func BenchmarkEventDay(b *testing.B) {
	for i := 0; i < b.N; i++ {
		result := RunEvent(EventConfig{
			Seed: uint64(i), Tickets: 200, Scans: 1000, Faults: DefaultFaults(),
		})
		if !result.OK() {
			b.Fatalf("seed %d: %v", i, result.Violations)
		}
	}
}
