// Package bloom implements the Bloom filter a scanner uses to reject unknown
// tickets without talking to the box.
//
// The filter is the reason a gate stays fast and a gate DoS is boring. A
// scanner downloads one filter over the valid ticket ids at doors; from then on,
// a random QR code off the internet, a supermarket barcode, or a script firing
// garbage payloads is rejected on the device in microseconds with zero network
// traffic. For fifty thousand tickets at a one-in-a-million false positive rate
// the filter is about 175 KB, which is a rounding error on a phone and a single
// round trip over venue Wi-Fi.
//
// What a false positive costs is worth being precise about, because it is the
// only reason this is safe: a false positive means the scanner believes an id
// might be valid, so it asks the box, which knows for certain. A Bloom filter
// with no false negatives is exactly the right shape for this problem — it can
// only ever be over-cautious, never wrong in the direction that admits someone.
package bloom

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
)

// Filter is an immutable-after-build Bloom filter.
//
// Concurrent Test calls are safe; Add is not, because building happens once on
// one goroutine at manifest time and adding a lock would cost every gate a
// contended atomic on the hot path for no benefit.
type Filter struct {
	bits []uint64

	// m is the number of bits, k the number of hash functions.
	m uint64
	k uint64

	// n counts what has been added, so Density and FalsePositiveRate can report
	// the filter's actual state rather than its design target.
	n uint64

	// seed makes the hash functions deterministic across processes. The
	// scanner never rehashes — it receives the filter, not the ids — but the
	// simulator builds and queries filters in separate goroutines and needs
	// them to agree, and a debuggable filter is one you can rebuild byte for
	// byte from the same input.
	seed uint64
}

// DefaultSeed is the hash seed used for every filter Gatecrash ships. It is
// fixed rather than random because a filter is a wire artifact: two boxes given
// the same ticket list must produce identical bytes, so that a scanner can
// notice its filter is stale by comparing hashes.
const DefaultSeed uint64 = 0x9E3779B97F4A7C15

// Sizing computes the filter dimensions for an expected element count and a
// target false positive rate, using the standard optimal-k result:
//
//	m = -n·ln(p) / (ln 2)²    k = (m/n)·ln 2
//
// Both are rounded up. A filter that is slightly too big has a slightly better
// false positive rate than requested, which is the correct direction to err.
func Sizing(expected int, falsePositiveRate float64) (bitCount, hashes uint64, err error) {
	if expected <= 0 {
		return 0, 0, fmt.Errorf("bloom: expected element count must be positive, got %d", expected)
	}
	if falsePositiveRate <= 0 || falsePositiveRate >= 1 {
		return 0, 0, fmt.Errorf("bloom: false positive rate must be between 0 and 1, got %g", falsePositiveRate)
	}

	n := float64(expected)
	ln2 := math.Ln2
	m := math.Ceil(-n * math.Log(falsePositiveRate) / (ln2 * ln2))
	k := math.Ceil(m / n * ln2)

	// One hash minimum: at very loose rates the formula rounds to zero, and a
	// filter with no hash functions matches everything.
	if k < 1 {
		k = 1
	}
	// Cap k. Past about 30 the marginal accuracy is nil and each one costs a
	// memory probe on the gate's hot path.
	if k > 30 {
		k = 30
	}
	return uint64(m), uint64(k), nil
}

// New returns an empty filter sized for the expected element count and target
// false positive rate.
func New(expected int, falsePositiveRate float64) (*Filter, error) {
	m, k, err := Sizing(expected, falsePositiveRate)
	if err != nil {
		return nil, err
	}
	return &Filter{
		bits: make([]uint64, (m+63)/64),
		m:    m,
		k:    k,
		seed: DefaultSeed,
	}, nil
}

// Add inserts a key. Not safe for concurrent use.
func (f *Filter) Add(key []byte) {
	first, second := f.hash(key)
	for i := uint64(0); i < f.k; i++ {
		index := (first + i*second) % f.m
		f.bits[index/64] |= 1 << (index % 64)
	}
	f.n++
}

// Test reports whether a key may be present. A false result is definitive: the
// key was never added. A true result means "ask the box".
func (f *Filter) Test(key []byte) bool {
	first, second := f.hash(key)
	for i := uint64(0); i < f.k; i++ {
		index := (first + i*second) % f.m
		if f.bits[index/64]&(1<<(index%64)) == 0 {
			return false
		}
	}
	return true
}

// FNV-1a 64 constants.
const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
)

// hash derives the two 64-bit values the k probes are built from.
//
// Kirsch-Mitzenmacher double hashing: g_i(x) = h1(x) + i·h2(x). Two hashes
// instead of k gives the same asymptotic false positive rate at a fraction of
// the cost, which matters because this runs on the scanner for every frame the
// camera decodes.
//
// FNV-1a rather than maphash: maphash seeds itself randomly per process, so two
// boxes handed the same ticket list would produce different filters and a
// scanner could never tell a stale filter from a fresh one. FNV-1a is
// deterministic, allocation-free, and inlined here so the hot path does not
// construct a hash.Hash per lookup. Its avalanche is poor on its own, which is
// what the splitmix finalizer is for.
//
// There is no adversarial-input concern: the ids being hashed are the
// organizer's own, and an attacker who could grind out collisions would win
// only the ability to make a scanner ask the box about a ticket the box then
// rejects.
func (f *Filter) hash(key []byte) (first, second uint64) {
	h := uint64(fnvOffset64) ^ f.seed
	for _, b := range key {
		h ^= uint64(b)
		h *= fnvPrime64
	}
	first = mix(h)
	// A second, independent value from the same pass. Mixing the seed in again
	// gives a different function without walking the key twice.
	second = mix(first ^ f.seed)
	// h2 must be odd and non-zero, or the probe sequence degenerates: an even
	// h2 can only ever reach half the bits, and a zero h2 makes all k probes
	// hit the same bit.
	second |= 1
	return first, second
}

// mix is splitmix64's finalizer: cheap, and good enough to decorrelate the two
// hash values.
func mix(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 27
	x *= 0x94D049BB133111EB
	x ^= x >> 31
	return x
}

// Len returns the number of keys added.
func (f *Filter) Len() int { return int(f.n) }

// Bits returns the filter's size in bits.
func (f *Filter) Bits() uint64 { return f.m }

// Hashes returns the number of probes per lookup.
func (f *Filter) Hashes() uint64 { return f.k }

// Density is the fraction of bits set. Published on the dashboard because it is
// the honest health signal for a filter: a filter over 80% dense is being asked
// to hold more than it was sized for and its real false positive rate has
// drifted away from the one on the tin.
func (f *Filter) Density() float64 {
	set := 0
	for _, word := range f.bits {
		set += bits.OnesCount64(word)
	}
	return float64(set) / float64(f.m)
}

// FalsePositiveRate estimates the filter's current rate from its observed
// density rather than from its design target, using (1 - e^(-kn/m))^k.
func (f *Filter) FalsePositiveRate() float64 {
	if f.n == 0 {
		return 0
	}
	exponent := -float64(f.k) * float64(f.n) / float64(f.m)
	return math.Pow(1-math.Exp(exponent), float64(f.k))
}

// Wire format. The header is fixed width and little-endian so a JavaScript
// scanner can parse it with a DataView in four reads and no dependencies.
//
//	magic    4 bytes  "GCBF"
//	version  1 byte
//	k        1 byte
//	seed     8 bytes
//	m        8 bytes  bit count
//	n        8 bytes  element count
//	bits     ceil(m/64) * 8 bytes
const (
	headerLen = 30
	wireMagic = "GCBF"
	wireV1    = 1
)

// ErrBadWire is returned for input that is not a Gatecrash Bloom filter.
var ErrBadWire = errors.New("bloom: bad wire format")

// MarshalBinary serialises the filter for transport in a manifest.
func (f *Filter) MarshalBinary() ([]byte, error) {
	if f.k > 255 {
		return nil, fmt.Errorf("bloom: %d hash functions does not fit the wire format", f.k)
	}
	out := make([]byte, 0, headerLen+len(f.bits)*8)
	out = append(out, wireMagic...)
	out = append(out, wireV1, byte(f.k))
	out = binary.LittleEndian.AppendUint64(out, f.seed)
	out = binary.LittleEndian.AppendUint64(out, f.m)
	out = binary.LittleEndian.AppendUint64(out, f.n)
	for _, word := range f.bits {
		out = binary.LittleEndian.AppendUint64(out, word)
	}
	return out, nil
}

// UnmarshalBinary parses a filter produced by MarshalBinary.
func (f *Filter) UnmarshalBinary(data []byte) error {
	if len(data) < headerLen {
		return fmt.Errorf("%w: %d bytes is shorter than the header", ErrBadWire, len(data))
	}
	if string(data[:4]) != wireMagic {
		return fmt.Errorf("%w: bad magic %q", ErrBadWire, data[:4])
	}
	if data[4] != wireV1 {
		return fmt.Errorf("%w: unsupported version %d", ErrBadWire, data[4])
	}

	k := uint64(data[5])
	seed := binary.LittleEndian.Uint64(data[6:14])
	m := binary.LittleEndian.Uint64(data[14:22])
	n := binary.LittleEndian.Uint64(data[22:30])

	if k == 0 {
		return fmt.Errorf("%w: zero hash functions would match everything", ErrBadWire)
	}
	if m == 0 {
		return fmt.Errorf("%w: zero bits", ErrBadWire)
	}

	words := (m + 63) / 64
	// Guard the allocation before making it: a corrupt or hostile header must
	// not be able to talk a scanner into allocating a gigabyte.
	if uint64(len(data)-headerLen) != words*8 {
		return fmt.Errorf("%w: header declares %d bits (%d words) but the body is %d bytes",
			ErrBadWire, m, words, len(data)-headerLen)
	}

	bitWords := make([]uint64, words)
	for i := range bitWords {
		bitWords[i] = binary.LittleEndian.Uint64(data[headerLen+i*8:])
	}
	f.bits, f.m, f.k, f.n, f.seed = bitWords, m, k, n, seed
	return nil
}

// Size returns the marshalled size in bytes, so a manifest can report its own
// payload cost without serialising twice.
func (f *Filter) Size() int { return headerLen + len(f.bits)*8 }
