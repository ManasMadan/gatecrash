package bloom

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"testing"
)

// keys returns n distinct 16-byte keys, shaped like the ticket ids the filter
// actually holds.
func keys(seed int64, n int) [][]byte {
	random := rand.New(rand.NewSource(seed))
	out := make([][]byte, n)
	for i := range out {
		key := make([]byte, 16)
		random.Read(key)
		out[i] = key
	}
	return out
}

func TestNoFalseNegatives(t *testing.T) {
	// The one property the gate's correctness rests on. A false negative would
	// mean a scanner rejecting a real ticket offline, with no round trip to the
	// box to catch it, and the attendee would simply not get in.
	added := keys(1, 20_000)
	f, err := New(len(added), 1e-6)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range added {
		f.Add(key)
	}
	for i, key := range added {
		if !f.Test(key) {
			t.Fatalf("key %d was added but does not test present", i)
		}
	}
}

func TestFalsePositiveRateIsWithinTheDesignTarget(t *testing.T) {
	const (
		count  = 50_000
		target = 1e-6
		trials = 2_000_000
	)
	added := keys(2, count)
	f, err := New(count, target)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range added {
		f.Add(key)
	}

	// Probe with keys that were definitely not added.
	absent := rand.New(rand.NewSource(3))
	probe := make([]byte, 16)
	hits := 0
	for i := 0; i < trials; i++ {
		absent.Read(probe)
		if f.Test(probe) {
			hits++
		}
	}

	observed := float64(hits) / float64(trials)
	// A 5x band. The point is to catch a broken probe sequence (which shows up
	// as orders of magnitude, not percent), not to assert a statistic that will
	// flake.
	if observed > target*5 {
		t.Errorf("observed false positive rate %g against a %g target (%d hits in %d probes)", observed, target, hits, trials)
	}
	t.Logf("observed %g against a %g target; density %.4f, estimate %g, %d bytes",
		observed, target, f.Density(), f.FalsePositiveRate(), f.Size())
}

// TestFiftyThousandTicketsCostsAboutTheAdvertisedPayload guards the number the
// README publishes. If a change to the sizing maths moves this, the claim is
// wrong and the sync-time budget in the docs is wrong with it.
func TestFiftyThousandTicketsCostsAboutTheAdvertisedPayload(t *testing.T) {
	f, err := New(50_000, 1e-6)
	if err != nil {
		t.Fatal(err)
	}
	const advertised = 175 * 1024
	size := f.Size()
	if size < advertised*9/10 || size > advertised*11/10 {
		t.Errorf("a 50k-ticket filter is %d bytes, but the README advertises about %d", size, advertised)
	}
}

func TestSizingFollowsTheOptimalFormula(t *testing.T) {
	// m = -n·ln(p)/(ln2)^2 for n=50000, p=1e-6 is 1,437,759 bits, and
	// k = (m/n)·ln2 is 20.
	m, k, err := Sizing(50_000, 1e-6)
	if err != nil {
		t.Fatal(err)
	}
	if m < 1_437_000 || m > 1_438_500 {
		t.Errorf("m = %d, want about 1,437,759", m)
	}
	if k != 20 {
		t.Errorf("k = %d, want 20", k)
	}
}

func TestSizingClampsKIntoAUsefulRange(t *testing.T) {
	// A very loose rate rounds k down to zero, and a filter with no hash
	// functions matches everything, which would make every scan a round trip.
	_, k, err := Sizing(1000, 0.9)
	if err != nil {
		t.Fatal(err)
	}
	if k < 1 {
		t.Fatalf("k = %d, want at least 1", k)
	}
	// An absurdly tight rate would otherwise ask for dozens of memory probes on
	// the gate's hot path for no measurable accuracy.
	_, k, err = Sizing(1000, 1e-30)
	if err != nil {
		t.Fatal(err)
	}
	if k > 30 {
		t.Fatalf("k = %d, want the cap at 30", k)
	}
}

func TestSizingRejectsNonsense(t *testing.T) {
	for name, tc := range map[string]struct {
		expected int
		rate     float64
	}{
		"zero elements":     {0, 0.01},
		"negative elements": {-5, 0.01},
		"zero rate":         {100, 0},
		"rate of one":       {100, 1},
		"negative rate":     {100, -0.5},
	} {
		if _, _, err := Sizing(tc.expected, tc.rate); err == nil {
			t.Errorf("%s: Sizing accepted it", name)
		}
	}
}

func TestEmptyFilterMatchesNothing(t *testing.T) {
	f, err := New(1000, 1e-6)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys(4, 1000) {
		if f.Test(key) {
			t.Fatal("an empty filter matched a key")
		}
	}
	if f.Len() != 0 || f.Density() != 0 || f.FalsePositiveRate() != 0 {
		t.Fatalf("an empty filter reports len=%d density=%g rate=%g", f.Len(), f.Density(), f.FalsePositiveRate())
	}
}

// TestBuildsAreDeterministicAcrossInstances is what lets a scanner detect a
// stale filter by comparing bytes. Two boxes given the same ticket list must
// produce byte-identical filters, which is the reason the hash is FNV-1a with a
// fixed seed rather than the stdlib's randomly seeded maphash.
func TestBuildsAreDeterministicAcrossInstances(t *testing.T) {
	added := keys(5, 5_000)

	build := func() []byte {
		f, err := New(len(added), 1e-6)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range added {
			f.Add(key)
		}
		encoded, err := f.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}

	if first, second := build(), build(); !bytes.Equal(first, second) {
		t.Fatal("two builds over the same keys produced different bytes")
	}
}

func TestInsertionOrderDoesNotChangeTheFilter(t *testing.T) {
	added := keys(6, 3_000)

	forward, err := New(len(added), 1e-6)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range added {
		forward.Add(key)
	}

	backward, err := New(len(added), 1e-6)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(added) - 1; i >= 0; i-- {
		backward.Add(added[i])
	}

	first, err := forward.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	second, err := backward.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("insertion order changed the filter bytes")
	}
}

func TestWireRoundTrip(t *testing.T) {
	added := keys(7, 10_000)
	original, err := New(len(added), 1e-5)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range added {
		original.Add(key)
	}

	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != original.Size() {
		t.Fatalf("Size() says %d bytes but MarshalBinary produced %d", original.Size(), len(encoded))
	}

	var decoded Filter
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Bits() != original.Bits() || decoded.Hashes() != original.Hashes() || decoded.Len() != original.Len() {
		t.Fatalf("decoded m=%d k=%d n=%d, want m=%d k=%d n=%d",
			decoded.Bits(), decoded.Hashes(), decoded.Len(),
			original.Bits(), original.Hashes(), original.Len())
	}
	// Every key must still be present after a trip over the wire, or a scanner
	// that reloaded its filter would start rejecting real tickets.
	for i, key := range added {
		if !decoded.Test(key) {
			t.Fatalf("key %d went missing over the wire", i)
		}
	}
}

func TestUnmarshalRejectsCorruptInput(t *testing.T) {
	f, err := New(1000, 1e-6)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys(8, 1000) {
		f.Add(key)
	}
	valid, err := f.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	corrupt := func(mutate func([]byte)) []byte {
		out := bytes.Clone(valid)
		mutate(out)
		return out
	}

	for name, input := range map[string][]byte{
		"empty":          {},
		"header only":    valid[:headerLen-1],
		"bad magic":      corrupt(func(b []byte) { copy(b, "NOPE") }),
		"bad version":    corrupt(func(b []byte) { b[4] = 99 }),
		"zero k":         corrupt(func(b []byte) { b[5] = 0 }),
		"zero m":         corrupt(func(b []byte) { binary.LittleEndian.PutUint64(b[14:], 0) }),
		"truncated body": valid[:len(valid)-8],
		"body too long":  append(bytes.Clone(valid), make([]byte, 8)...),
		// The guard that matters most: a header claiming a huge bit count must
		// be rejected before anything is allocated, or a hostile manifest can
		// talk a scanner into an out-of-memory kill at the gate.
		"absurd bit count": corrupt(func(b []byte) { binary.LittleEndian.PutUint64(b[14:], 1<<40) }),
	} {
		var decoded Filter
		if err := decoded.UnmarshalBinary(input); err == nil {
			t.Errorf("%s: UnmarshalBinary accepted corrupt input", name)
		} else if !errors.Is(err, ErrBadWire) {
			t.Errorf("%s: got %v, want an ErrBadWire", name, err)
		}
	}
}

func TestDensityAndEstimateTrackReality(t *testing.T) {
	// A filter loaded to its design point should land near 50% density, which is
	// what the optimal-k result arranges. Wildly off means the probe sequence is
	// clustering.
	const count = 20_000
	f, err := New(count, 1e-6)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys(9, count) {
		f.Add(key)
	}
	if density := f.Density(); density < 0.4 || density > 0.6 {
		t.Errorf("density is %.3f at the design point, want near 0.5", density)
	}
	if estimate := f.FalsePositiveRate(); estimate > 1e-5 {
		t.Errorf("estimated rate at the design point is %g, want near 1e-6", estimate)
	}
}

func TestOverloadedFilterDegradesVisibly(t *testing.T) {
	// Filling a filter far past its sizing must not break correctness, but it
	// must be visible: the dashboard shows density so an operator can tell that
	// the manifest grew and the filter did not.
	f, err := New(1_000, 1e-6)
	if err != nil {
		t.Fatal(err)
	}
	added := keys(10, 20_000)
	for _, key := range added {
		f.Add(key)
	}
	for i, key := range added {
		if !f.Test(key) {
			t.Fatalf("key %d lost from an overloaded filter, which would break the gate", i)
		}
	}
	if f.Density() < 0.9 {
		t.Errorf("a 20x overloaded filter reports density %.3f, which does not look overloaded", f.Density())
	}
}

func BenchmarkTestPresent(b *testing.B) {
	added := keys(11, 50_000)
	f, err := New(len(added), 1e-6)
	if err != nil {
		b.Fatal(err)
	}
	for _, key := range added {
		f.Add(key)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !f.Test(added[i%len(added)]) {
			b.Fatal("false negative")
		}
	}
}

func BenchmarkTestAbsent(b *testing.B) {
	f, err := New(50_000, 1e-6)
	if err != nil {
		b.Fatal(err)
	}
	for _, key := range keys(12, 50_000) {
		f.Add(key)
	}
	probes := keys(13, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Test(probes[i%len(probes)])
	}
}
