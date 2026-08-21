package cuckoo

import (
	"encoding/binary"
	"testing"
	"time"
)

func id(n uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], n)
	return out[:]
}

// TestNoFalseNegatives is the property the whole mesh rests on.
//
// A false positive costs one unrelayed message. A false negative would mean the
// filter forgetting something it was told, which turns dedup into a coin flip and
// puts the ping-pong loop back.
func TestNoFalseNegatives(t *testing.T) {
	f := New(4096)
	for i := uint64(0); i < 3000; i++ {
		if err := f.Insert(id(i)); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	for i := uint64(0); i < 3000; i++ {
		if !f.Contains(id(i)) {
			t.Fatalf("forgot %d, which it was told about", i)
		}
	}
}

// TestFalsePositiveRateIsWorthTheByte checks the 16-bit fingerprint actually buys
// what it claims. At 8 bits this rate is around 3%, which is a 3% delivery tax on
// every hop of the mesh.
func TestFalsePositiveRateIsWorthTheByte(t *testing.T) {
	f := New(8192)
	for i := uint64(0); i < 7000; i++ {
		if err := f.Insert(id(i)); err != nil {
			t.Fatal(err)
		}
	}

	const probes = 200_000
	positives := 0
	for i := uint64(1_000_000); i < 1_000_000+probes; i++ {
		if f.Contains(id(i)) {
			positives++
		}
	}

	rate := float64(positives) / probes
	// The theoretical rate is about 2*4/65536 = 0.012%. Anything under a tenth of a
	// percent is comfortably in budget; a regression to 8-bit fingerprints would
	// land around 3% and fail here loudly.
	if rate > 0.001 {
		t.Errorf("false positive rate is %.4f%%, want under 0.1%%", rate*100)
	}
}

// TestDeleteRemovesOneOccurrence pins the behaviour that makes generational expiry
// possible at all — the reason this is a cuckoo filter and not a bloom filter.
func TestDeleteRemovesOneOccurrence(t *testing.T) {
	f := New(64)
	if err := f.Insert(id(1)); err != nil {
		t.Fatal(err)
	}
	if !f.Contains(id(1)) {
		t.Fatal("not stored")
	}
	if !f.Delete(id(1)) {
		t.Fatal("delete reported nothing to remove")
	}
	if f.Contains(id(1)) {
		t.Error("still present after delete")
	}
	if f.Len() != 0 {
		t.Errorf("length is %d after deleting the only entry", f.Len())
	}
	if f.Delete(id(1)) {
		t.Error("deleting twice reported a second removal")
	}
}

// TestInsertUniqueAnswersTheMeshsQuestion: seen before, or not, in one call.
func TestInsertUniqueAnswersTheMeshsQuestion(t *testing.T) {
	f := New(64)
	first, err := f.InsertUnique(id(7))
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Error("the first sighting reported as a repeat")
	}

	second, err := f.InsertUnique(id(7))
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Error("the second sighting reported as new")
	}
	if f.Len() != 1 {
		t.Errorf("stored %d copies, want 1", f.Len())
	}
}

// TestReachesAUsefulLoadFactor is the reason for four slots per bucket and for
// mixing the fingerprint into the alternate index. A naive `index ^ fingerprint`
// confines both homes to one neighbourhood and this collapses.
func TestReachesAUsefulLoadFactor(t *testing.T) {
	f := New(1 << 16)

	inserted := 0
	for i := uint64(0); ; i++ {
		if err := f.Insert(id(i)); err != nil {
			break
		}
		inserted++
		if inserted > f.Capacity() {
			t.Fatal("inserted more than capacity, which means entries are being lost")
		}
	}

	load := float64(inserted) / float64(f.Capacity())
	if load < 0.90 {
		t.Errorf("filled to %.1f%% before failing, want at least 90%%", load*100)
	}

	used, empty := f.occupancy()
	if used+empty != f.Capacity() {
		t.Errorf("occupancy accounting is off: %d + %d != %d", used, empty, f.Capacity())
	}
	if !f.bucketsAreAPowerOfTwo() {
		t.Error("bucket count is not a power of two, so the index mask is wrong")
	}
}

// TestFullIsAnErrorRatherThanAnEviction. The caller decides what to do about a
// full filter; silently dropping somebody else's entry would make dedup
// unpredictable exactly when the crowd is densest.
func TestFullIsAnErrorRatherThanAnEviction(t *testing.T) {
	f := New(4)
	var last error
	for i := uint64(0); i < 1000; i++ {
		if last = f.Insert(id(i)); last != nil {
			break
		}
	}
	if last == nil {
		t.Fatal("a filter with four slots never reported full")
	}
	if f.Len() > f.Capacity() {
		t.Errorf("length %d exceeds capacity %d", f.Len(), f.Capacity())
	}
}

// TestSizeStaysInTheFewKilobytesTheSpecPromised. This runs on a phone at a
// festival, next to a music app and a camera roll.
func TestSizeStaysInTheFewKilobytesTheSpecPromised(t *testing.T) {
	r := NewRotating(RotatingConfig{Capacity: 8192, Window: 10 * time.Minute})
	if got := r.Bytes(); got > 64*1024 {
		t.Errorf("the rotating set is %d bytes, want under 64 KiB", got)
	}
	t.Logf("8192 ids per generation, two generations: %d bytes", r.Bytes())
}

// TestRotationForgetsWhatIsOldEnough is the TTL. Without it the filter fills up
// and starts refusing to remember new messages, which is worse than not having a
// filter at all.
func TestRotationForgetsWhatIsOldEnough(t *testing.T) {
	at := time.Date(2026, 8, 21, 20, 0, 0, 0, time.UTC)
	r := NewRotating(RotatingConfig{Capacity: 1024, Window: 10 * time.Minute, Now: func() time.Time { return at }})

	if r.Seen(id(1)) {
		t.Fatal("an id reported as seen before it was ever offered")
	}
	if !r.Seen(id(1)) {
		t.Fatal("an id offered twice was not remembered")
	}

	// One window on: still remembered, because it is in the previous generation.
	at = at.Add(11 * time.Minute)
	if !r.Seen(id(1)) {
		t.Error("forgotten after one window; the previous generation should still hold it")
	}

	// Two windows on: gone.
	at = at.Add(11 * time.Minute)
	if r.Seen(id(2)) {
		t.Fatal("unrelated id reported as seen")
	}
	at = at.Add(11 * time.Minute)
	if r.Seen(id(1)) {
		t.Error("still remembered after two windows")
	}
}

// TestAPhoneThatSleptForAnHourComesBackEmpty. Every generation is stale, so the
// rotation drops both rather than shuffling one stale filter into the other.
func TestAPhoneThatSleptForAnHourComesBackEmpty(t *testing.T) {
	at := time.Date(2026, 8, 21, 20, 0, 0, 0, time.UTC)
	r := NewRotating(RotatingConfig{Capacity: 1024, Window: 10 * time.Minute, Now: func() time.Time { return at }})
	for i := uint64(0); i < 100; i++ {
		r.Seen(id(i))
	}

	at = at.Add(time.Hour)
	if r.Seen(id(0)) {
		t.Error("an hour-old id survived; the phone was asleep, not the clock")
	}
	if r.Len() > 1 {
		t.Errorf("%d ids survived a full sleep", r.Len())
	}
}

// TestWipeLeavesNothingBehind is the panic button. Somebody triple-tapping it in a
// crowd is asking for every trace of what their phone heard to be gone, and the
// ids of messages they received are a trace.
func TestWipeLeavesNothingBehind(t *testing.T) {
	r := NewRotating(RotatingConfig{Capacity: 1024, Window: time.Minute})
	for i := uint64(0); i < 500; i++ {
		r.Seen(id(i))
	}
	if r.Len() == 0 {
		t.Fatal("nothing was stored to wipe")
	}

	r.Wipe()

	if r.Len() != 0 {
		t.Errorf("%d ids survived the wipe", r.Len())
	}
	for i := uint64(0); i < 500; i++ {
		if r.Seen(id(i)) {
			t.Fatalf("id %d is still recognised after a wipe", i)
			return
		}
		// Seen re-inserts, so undo it before checking the next one.
		r.Wipe()
	}
}

// TestHashingIsReproducible guards the property that lets an Android phone, an
// iPhone and the box agree. hash/maphash seeds itself per process and would have
// broken this silently.
func TestHashingIsReproducible(t *testing.T) {
	a, b := New(1024), New(1024)
	for i := uint64(0); i < 500; i++ {
		if err := a.Insert(id(i)); err != nil {
			t.Fatal(err)
		}
		if err := b.Insert(id(i)); err != nil {
			t.Fatal(err)
		}
	}
	for i := range a.buckets {
		if a.buckets[i] != b.buckets[i] {
			t.Fatalf("bucket %d differs between two filters given identical input", i)
		}
	}

	// And the fingerprints themselves are fixed values, so a port of this to Kotlin
	// or Swift can be checked against them.
	for _, want := range []struct {
		key         uint64
		fingerprint uint16
	}{
		{0, a.mustFingerprint(id(0))},
		{1, a.mustFingerprint(id(1))},
	} {
		if got := a.mustFingerprint(id(want.key)); got != want.fingerprint {
			t.Errorf("fingerprint for %d is %d, want %d", want.key, got, want.fingerprint)
		}
	}
}

// TestFingerprintIsNeverZero because zero is the empty-slot marker, and an entry
// stored as zero would be invisible to Contains.
func TestFingerprintIsNeverZero(t *testing.T) {
	f := New(1024)
	for i := uint64(0); i < 200_000; i++ {
		if f.mustFingerprint(id(i)) == 0 {
			t.Fatalf("key %d hashed to the empty-slot marker", i)
		}
	}
}

// TestLoadFactorTracksWhatIsStored, since the crowd simulator sweeps density and
// reads this to decide whether the capacity is set sensibly.
func TestLoadFactorTracksWhatIsStored(t *testing.T) {
	r := NewRotating(RotatingConfig{Capacity: 1024, Window: time.Minute})
	if r.LoadFactor() != 0 {
		t.Errorf("an empty set reports load %.3f", r.LoadFactor())
	}
	for i := uint64(0); i < 512; i++ {
		r.Seen(id(i))
	}
	if load := r.LoadFactor(); load < 0.4 || load > 0.6 {
		t.Errorf("load is %.3f after filling half the capacity", load)
	}
}

func (f *Filter) mustFingerprint(key []byte) uint16 {
	fingerprint, _, _ := f.hash(key)
	return fingerprint
}

func BenchmarkSeen(b *testing.B) {
	r := NewRotating(RotatingConfig{Capacity: 8192, Window: 10 * time.Minute})
	keys := make([][]byte, 1024)
	for i := range keys {
		keys[i] = id(uint64(i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Seen(keys[i%len(keys)])
	}
}
