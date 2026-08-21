// Package cuckoo is the "have I seen this already" filter behind mesh flooding.
//
// A flooding mesh works by every phone rebroadcasting what it hears. Without a
// memory of what it has already rebroadcast, one message ping-pongs between two
// phones forever, and in a crowd the airtime is gone in seconds. Dedup is not an
// optimisation here; it is the thing that stops the protocol eating itself.
//
// A cuckoo filter rather than a Bloom filter, for one reason: entries have to
// expire. Ten minutes after a message was sent, nobody is going to relay it again,
// and remembering it forever means the filter fills up and starts refusing to
// remember new ones. Bloom filters cannot forget. A cuckoo filter can delete, and
// this package uses that to expire whole generations at once — which is cheaper
// than deleting entries one at a time and needs no per-entry timestamp.
//
// The other constraint is size. This runs on a phone in somebody's pocket alongside
// a music festival, so the target is a few kilobytes, not a few megabytes.
package cuckoo

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"time"
)

// slotsPerBucket is the cuckoo filter's associativity.
//
// Four is the standard choice and it is standard for a good reason: at four slots
// a cuckoo filter reaches about 95% occupancy before inserts start failing, where
// two slots stalls around 84%. Eight buys another point or two of load factor and
// costs a wider scan on every lookup, which is the wrong trade on a phone.
const slotsPerBucket = 4

// maxKicks bounds the eviction chain on insert.
//
// An insert that finds both candidate buckets full evicts a resident fingerprint
// and re-homes it, which may evict another. The chain is almost always one or two
// long; it only grows when the filter is nearly full. 500 is the usual bound and it
// exists to turn "this filter is full" from an infinite loop into an error.
const maxKicks = 500

// ErrFull means the filter could not find a home for a fingerprint.
//
// This is not a corruption or a bug. It means the filter is at capacity, and the
// caller's options are to accept the message without remembering it (which risks
// relaying it twice) or to drop it. Returning an error rather than silently
// evicting somebody else's entry keeps that decision with the caller.
var ErrFull = errors.New("cuckoo: filter is full")

// Filter is a cuckoo filter over 16-bit fingerprints.
//
// 16 bits rather than the more common 8: a false positive here means a message
// this phone has never seen is treated as already seen and is never relayed. At
// eight bits that happens to roughly 3% of messages, which in a mesh whose whole
// delivery guarantee is "best effort, many paths" is a 3% tax on every hop. At
// sixteen it is about one in eight thousand, for one extra byte per entry.
//
// Not safe for concurrent use. The mesh router owns one and drives it from a single
// goroutine, which is simpler to reason about than a lock on the hot path.
type Filter struct {
	buckets [][slotsPerBucket]uint16
	mask    uint64
	count   int
}

// New returns a filter sized for at least capacity entries.
//
// The bucket count is rounded up to a power of two, because the bucket index is
// taken with a mask rather than a modulo — a modulo by a non-power-of-two is a
// division, and this is on the path of every packet the radio hears.
func New(capacity int) *Filter {
	buckets := 1
	for buckets*slotsPerBucket < capacity {
		buckets <<= 1
	}
	return &Filter{
		buckets: make([][slotsPerBucket]uint16, buckets),
		mask:    uint64(buckets - 1),
	}
}

// Len is how many fingerprints are stored.
func (f *Filter) Len() int { return f.count }

// Capacity is how many fingerprints fit, at 100% occupancy.
//
// Inserts start failing before this — around 95% — which is inherent to the
// structure rather than a shortcoming of this implementation.
func (f *Filter) Capacity() int { return len(f.buckets) * slotsPerBucket }

// Bytes is the filter's footprint, for the size claims in the docs.
func (f *Filter) Bytes() int { return len(f.buckets) * slotsPerBucket * 2 }

// Reset empties the filter without reallocating, which is how a generation is
// recycled. Allocating a fresh one every rotation would hand the garbage collector
// a few kilobytes every few minutes for no reason.
func (f *Filter) Reset() {
	for i := range f.buckets {
		f.buckets[i] = [slotsPerBucket]uint16{}
	}
	f.count = 0
}

// Insert remembers a key.
//
// Inserting the same key twice stores it twice, which is deliberate: that is what
// makes Delete correct when two different keys collide on the same fingerprint and
// bucket. Callers that only care whether a key is present should check Contains
// first, which is what InsertUnique does.
func (f *Filter) Insert(key []byte) error {
	fingerprint, i1, i2 := f.hash(key)

	if f.insertInto(i1, fingerprint) || f.insertInto(i2, fingerprint) {
		f.count++
		return nil
	}

	// Both homes are full, so start evicting. The victim is chosen from the second
	// bucket and re-homed in its alternate, which may evict another, and so on.
	//
	// The victim slot is derived rather than random, so two machines given the same
	// inserts end up with byte-identical filters — a port of this to Kotlin or Swift
	// can be checked against a fixture instead of against a probability.
	//
	// It has to vary with the kick count, though. Always evicting slot zero is
	// reproducible and useless: the chain falls into a two-position cycle almost
	// immediately and the filter reports itself full at around 73% occupancy rather
	// than 95%. Mixing the kick number in is what breaks the cycle.
	index := i2
	for kick := 0; kick < maxKicks; kick++ {
		slot := int(splitmix(uint64(kick)^uint64(fingerprint)) % slotsPerBucket)
		victim := f.buckets[index][slot]
		f.buckets[index][slot] = fingerprint
		fingerprint = victim

		index = f.alternate(index, fingerprint)
		if f.insertInto(index, fingerprint) {
			f.count++
			return nil
		}
	}

	// The chain ran out. The fingerprint currently in hand has been displaced and
	// is not stored anywhere, so the filter has lost one entry — the count is
	// decremented to say so rather than quietly over-reporting.
	f.count--
	return ErrFull
}

// InsertUnique remembers a key and reports whether it was new.
//
// This is the mesh's actual question: "is this a message I have already handled,
// and if not, remember it". One call rather than a Contains followed by an Insert,
// because the two would hash the key twice on the hot path.
func (f *Filter) InsertUnique(key []byte) (bool, error) {
	fingerprint, i1, i2 := f.hash(key)
	if f.containsAt(i1, fingerprint) || f.containsAt(i2, fingerprint) {
		return false, nil
	}
	if err := f.Insert(key); err != nil {
		return false, err
	}
	return true, nil
}

// Contains reports whether the key was probably inserted.
//
// No false negatives: a key that was inserted and not deleted always reports true.
// False positives happen at roughly 2 * slotsPerBucket / 2^16, about one in eight
// thousand.
func (f *Filter) Contains(key []byte) bool {
	fingerprint, i1, i2 := f.hash(key)
	return f.containsAt(i1, fingerprint) || f.containsAt(i2, fingerprint)
}

// Delete forgets one occurrence of a key.
//
// It can delete a different key that happened to share a fingerprint and a bucket.
// That is the documented cost of a filter that stores fingerprints rather than
// keys, and for the mesh it is harmless: the consequence is relaying one message a
// second time.
func (f *Filter) Delete(key []byte) bool {
	fingerprint, i1, i2 := f.hash(key)
	if f.deleteAt(i1, fingerprint) || f.deleteAt(i2, fingerprint) {
		f.count--
		return true
	}
	return false
}

func (f *Filter) insertInto(index uint64, fingerprint uint16) bool {
	for slot := range f.buckets[index] {
		if f.buckets[index][slot] == 0 {
			f.buckets[index][slot] = fingerprint
			return true
		}
	}
	return false
}

func (f *Filter) containsAt(index uint64, fingerprint uint16) bool {
	for _, stored := range f.buckets[index] {
		if stored == fingerprint {
			return true
		}
	}
	return false
}

func (f *Filter) deleteAt(index uint64, fingerprint uint16) bool {
	for slot, stored := range f.buckets[index] {
		if stored == fingerprint {
			f.buckets[index][slot] = 0
			return true
		}
	}
	return false
}

// hash derives the fingerprint and both candidate buckets for a key.
//
// The hash is written out here rather than taken from hash/maphash, which seeds
// itself per process: two phones would derive different fingerprints for the same
// message id and the filters would be incomparable. Every byte of this has to be
// reproducible on an Android phone, an iPhone and the box, so it is spelled out.
func (f *Filter) hash(key []byte) (fingerprint uint16, i1, i2 uint64) {
	sum := fnv1a(key)

	// The fingerprint comes from the high bits and the bucket index from the low
	// ones, so the two are not correlated. Zero is the empty-slot marker, so a
	// fingerprint that hashes to zero is nudged to one — that costs one extra
	// collision in 65,536 and avoids an "is this slot empty" flag per slot.
	fingerprint = uint16(sum >> 48)
	if fingerprint == 0 {
		fingerprint = 1
	}

	i1 = sum & f.mask
	i2 = f.alternate(i1, fingerprint)
	return fingerprint, i1, i2
}

// alternate is the partial-key cuckoo trick: a fingerprint's second home is
// derived from its first home and the fingerprint itself, so a displaced entry can
// be re-homed without knowing the key it came from.
//
// The fingerprint is spread with a mixing step before the xor. A bare
// `index ^ fingerprint` only ever changes the low sixteen bits of the index, so in
// a filter with more than 65,536 buckets every entry's two homes land in the same
// small neighbourhood and the load factor collapses.
func (f *Filter) alternate(index uint64, fingerprint uint16) uint64 {
	return (index ^ splitmix(uint64(fingerprint))) & f.mask
}

// fnv1a is FNV-1a, 64-bit. Small, fast, dependency-free, and identical on every
// platform — which is the only property that matters here.
func fnv1a(data []byte) uint64 {
	const (
		offset = 14695981039346656037
		prime  = 1099511628211
	)
	hash := uint64(offset)
	for _, b := range data {
		hash ^= uint64(b)
		hash *= prime
	}
	// FNV-1a's low bits are weak and this uses the low bits as a bucket index, so
	// finish with a mixing step. Same reasoning as the bloom package.
	return splitmix(hash)
}

// splitmix is the SplitMix64 finaliser: a bijection that spreads every input bit
// across the whole word.
func splitmix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// Rotating is a set of message ids that forgets anything older than its window.
//
// Two generations rather than a timestamp per entry. On rotation the older
// generation is dropped wholesale, which is one Reset rather than a scan, and
// lookups check both. The cost is that an entry lives somewhere between one and two
// windows depending on when it arrived — which for "have I relayed this in the last
// ten minutes" is a distinction without a difference.
//
// Not safe for concurrent use, same as Filter.
type Rotating struct {
	current  *Filter
	previous *Filter

	window   time.Duration
	rotateAt time.Time
	now      func() time.Time
}

// RotatingConfig configures a rotating set.
type RotatingConfig struct {
	// Capacity is how many ids one generation holds. The set holds between this and
	// twice this before the window elapses.
	Capacity int

	// Window is how long an id is remembered, at minimum.
	Window time.Duration

	// Now is the clock, injected so the simulator can run a ten-hour festival in a
	// millisecond and so tests do not sleep.
	Now func() time.Time
}

// NewRotating returns a rotating set.
func NewRotating(cfg RotatingConfig) *Rotating {
	if cfg.Capacity <= 0 {
		cfg.Capacity = 8192
	}
	if cfg.Window <= 0 {
		cfg.Window = 10 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Rotating{
		current:  New(cfg.Capacity),
		previous: New(cfg.Capacity),
		window:   cfg.Window,
		rotateAt: cfg.Now().Add(cfg.Window),
		now:      cfg.Now,
	}
}

// Seen reports whether an id has been seen inside the window, and records it if
// not.
//
// One call for the mesh's one question. The insert is best effort: a full
// generation means the id is not remembered, which risks one duplicate relay, and
// that is a far better failure than refusing to handle the message.
func (r *Rotating) Seen(id []byte) bool {
	r.maybeRotate()

	if r.current.Contains(id) || r.previous.Contains(id) {
		return true
	}
	// Deliberately ignoring ErrFull. Rotation is what recovers from a full
	// generation, and there is nothing useful to do about it at this call site.
	_ = r.current.Insert(id)
	return false
}

// Bytes is the whole set's footprint.
func (r *Rotating) Bytes() int { return r.current.Bytes() + r.previous.Bytes() }

// Len is how many ids are currently remembered across both generations.
func (r *Rotating) Len() int { return r.current.Len() + r.previous.Len() }

// Wipe forgets everything, immediately.
//
// This is the panic wipe. Somebody triple-tapping the panic button in a crowd is
// asking for every trace of what their phone has heard to be gone, and a filter
// that still holds the ids of messages they received is a trace.
func (r *Rotating) Wipe() {
	r.current.Reset()
	r.previous.Reset()
	r.rotateAt = r.now().Add(r.window)
}

func (r *Rotating) maybeRotate() {
	now := r.now()
	if now.Before(r.rotateAt) {
		return
	}

	// A phone that was asleep for an hour comes back with several windows elapsed.
	// One rotation is enough — both generations are stale, so both are dropped —
	// and looping would just Reset the same two filters repeatedly.
	if now.Sub(r.rotateAt) >= r.window {
		r.current.Reset()
		r.previous.Reset()
	} else {
		r.previous, r.current = r.current, r.previous
		r.current.Reset()
	}
	r.rotateAt = now.Add(r.window)
}

// MessageID is the 8-byte random id a mesh frame carries.
//
// Eight bytes because it goes in every frame and a frame is at most ~200 bytes on
// the wire. At 64 bits, a crowd producing a million messages an hour has about a
// one in 37 million chance of a collision in a ten-minute window, and a collision
// costs one undelivered message.
type MessageID [8]byte

// Bytes returns the id as a slice, for the filter.
func (id MessageID) Bytes() []byte { return id[:] }

// Uint64 returns the id as an integer, for logs and maps.
func (id MessageID) Uint64() uint64 { return binary.BigEndian.Uint64(id[:]) }

// SeenID is Seen for a MessageID, without the caller reaching for a slice.
func (r *Rotating) SeenID(id MessageID) bool { return r.Seen(id[:]) }

// LoadFactor is how full the current generation is, as a fraction.
//
// Exposed because it is the number that says whether Capacity was set sensibly for
// a given crowd: the crowd simulator sweeps density and watches this.
func (r *Rotating) LoadFactor() float64 {
	capacity := r.current.Capacity()
	if capacity == 0 {
		return 0
	}
	return float64(r.current.Len()) / float64(capacity)
}

// occupancy is used by the tests to assert the structure is spreading entries
// rather than piling them into a few buckets.
func (f *Filter) occupancy() (used, empty int) {
	for _, bucket := range f.buckets {
		for _, stored := range bucket {
			if stored == 0 {
				empty++
			} else {
				used++
			}
		}
	}
	return used, empty
}

// popcount of the bucket count, used to assert the power-of-two invariant in
// tests. Kept here so the invariant is stated next to the mask it justifies.
func (f *Filter) bucketsAreAPowerOfTwo() bool {
	return bits.OnesCount(uint(len(f.buckets))) == 1
}
