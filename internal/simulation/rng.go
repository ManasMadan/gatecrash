// Package simulation is the deterministic simulator: a whole event, or a whole
// crowd, driven by a seed.
//
// Two simulators live here and they answer different questions.
//
// The event simulator (Run) drives the real redemption engine against a fake world
// where the network partitions, scanners crash mid-scan, the box loses power, and
// clocks disagree. It asserts the guarantees: never two admissions for one ticket in
// STRICT, never an undetected double use in DEGRADED, never a broken audit chain.
// Thousands of seeded event-days, and any failure replays byte for byte from its
// seed.
//
// The crowd simulator (RunCrowd) drives thousands of copies of the mesh router
// against a model of people walking around a field with radios that collide. It
// answers the question the mesh's one tunable parameter depends on: what does the
// relay constant have to be for a message to cross a crowd without the crowd's
// airtime disappearing.
//
// # Determinism is the whole point
//
// Nothing here reads the wall clock, the global random source, the filesystem or
// the network. Every source of variation arrives through an explicitly seeded PRNG
// and an explicitly advanced clock, which is what makes a failure reproducible from
// a single integer. A simulator that finds a rare bug and cannot reproduce it has
// found nothing.
package simulation

import "math"

// Rand is a deterministic pseudo-random source.
//
// SplitMix64: sixty-four bits of state, one multiply-xor-shift finaliser per draw,
// and no global anything. Not cryptographically strong and it does not need to be —
// its whole job is to be reproducible from a seed.
//
// Written out rather than taken from math/rand for two reasons. The obvious one is
// that math/rand's algorithm is not part of its compatibility promise, so a run
// recorded today might not replay on a later Go. The less obvious one is that a
// simulator wants many independent streams — one per node, one per gate — and
// deriving a fresh stream from a seed and a label is trivial here and awkward there.
type Rand struct {
	state uint64
}

// NewRand seeds a source.
func NewRand(seed uint64) *Rand {
	// The seed is mixed before use so that seeds 1, 2 and 3 produce genuinely
	// unrelated streams. Without this, a sweep over consecutive seeds explores a
	// much smaller space than it looks like it does.
	return &Rand{state: splitmix(seed ^ 0x2545f4914f6cdd1d)}
}

// Derive returns an independent stream, labelled.
//
// Each simulated node gets its own stream from the run's single seed, so a node's
// behaviour depends on its own draws and not on how many draws its neighbours
// happened to make first. Without that, adding one node to a crowd changes every
// other node's behaviour and a sweep over density measures nothing.
func (r *Rand) Derive(label uint64) *Rand {
	return &Rand{state: splitmix(r.state ^ splitmix(label))}
}

// Uint64 returns the next value.
func (r *Rand) Uint64() uint64 {
	r.state += 0x9e3779b97f4a7c15
	return splitmix(r.state)
}

// Float64 returns a value in [0,1).
//
// Built from the top 53 bits, which is the mantissa width of a float64. Taking the
// low bits instead is the classic mistake: it makes the result coarser than it
// looks and correlates it with the generator's weakest bits.
func (r *Rand) Float64() float64 {
	return float64(r.Uint64()>>11) / (1 << 53)
}

// Intn returns a value in [0,n).
//
// Rejection sampling rather than a modulo. A modulo biases the low values whenever
// n does not divide 2^64, which for a simulator sweeping parameters is a systematic
// error rather than noise.
func (r *Rand) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	limit := uint64(n)
	// The largest multiple of limit that fits, expressed without writing 2^64 —
	// which does not fit in a uint64. Draws below this threshold are discarded.
	threshold := -limit % limit
	for {
		value := r.Uint64()
		if value >= threshold {
			return int(value % limit)
		}
	}
}

// Perm returns a permutation of [0,n), Fisher-Yates.
func (r *Rand) Perm(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Normal returns a standard normal draw, Box-Muller.
//
// Used for the radio model's fading. Real signal strength at a fixed distance
// varies by several decibels as people move and bodies block the path, and a model
// with a hard range cutoff and no fading produces a suspiciously tidy delivery
// curve that no field test would reproduce.
func (r *Rand) Normal() float64 {
	// Guard against log(0), which happens once in 2^53 draws and would produce an
	// infinity that quietly poisons a whole run.
	u1 := r.Float64()
	if u1 <= 0 {
		u1 = math.SmallestNonzeroFloat64
	}
	u2 := r.Float64()
	return math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
}

// Chance reports whether an event with probability p happened.
func (r *Rand) Chance(p float64) bool {
	switch {
	case p <= 0:
		return false
	case p >= 1:
		return true
	default:
		return r.Float64() < p
	}
}

// Between returns a value in [low, high).
func (r *Rand) Between(low, high float64) float64 {
	if high <= low {
		return low
	}
	return low + r.Float64()*(high-low)
}

func splitmix(x uint64) uint64 {
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}
