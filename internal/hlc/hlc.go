// Package hlc implements hybrid logical clocks as described in "Logical
// Physical Clocks and Consistent Snapshots in Globally Distributed Databases"
// (Kulkarni et al., 2014).
//
// Gatecrash needs a causally consistent total order across scanners and boxes
// whose wall clocks are wrong. A Raspberry Pi has no battery-backed RTC and
// there is no NTP on an air-gapped venue LAN, so absolute time is not
// available and not required: every ordering decision in the redemption engine,
// the audit log and the multi-box merge is made against an HLC, never against
// time.Now.
//
// A Timestamp packs a 48-bit millisecond component and a 16-bit logical
// counter into a single uint64, which makes it sortable as an integer, storable
// as a SQLite INTEGER and comparable without allocating.
package hlc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// counterBits is the width of the logical counter. 16 bits gives 65,536
	// events inside a single millisecond before the physical component has to
	// be borrowed against, which is roughly 4,000x the peak scan rate of the
	// busiest gate we have ever measured.
	counterBits = 16

	// maxCounter is the largest representable logical counter.
	maxCounter = (1 << counterBits) - 1

	// maxWallMillis is the largest representable physical component. 2^48 ms is
	// the year 10889; the packing outlives the format.
	maxWallMillis = (1 << 48) - 1
)

// Timestamp is a packed hybrid logical clock reading: the high 48 bits are
// milliseconds, the low 16 bits are the logical counter.
//
// The zero Timestamp is the beginning of time and sorts before every real
// reading, which is what makes it a usable "no previous event" sentinel.
type Timestamp uint64

// New packs a wall-clock millisecond value and a counter into a Timestamp.
// Both components are clamped rather than wrapped: silently wrapping a clock
// would break the total order, and a clamped clock is at least monotone.
func New(wallMillis uint64, counter uint16) Timestamp {
	if wallMillis > maxWallMillis {
		wallMillis = maxWallMillis
	}
	return Timestamp(wallMillis<<counterBits | uint64(counter))
}

// Wall returns the physical component in milliseconds.
func (t Timestamp) Wall() uint64 { return uint64(t) >> counterBits }

// Counter returns the logical component.
func (t Timestamp) Counter() uint16 { return uint16(uint64(t) & maxCounter) }

// Time renders the physical component as a time.Time. This is for humans
// reading logs only: the value is the box's belief about wall time, which on a
// Pi with no RTC may be wildly wrong. Never make a decision on it.
func (t Timestamp) Time() time.Time {
	return time.UnixMilli(int64(t.Wall())).UTC()
}

// Before reports whether t happened before u in the total order.
func (t Timestamp) Before(u Timestamp) bool { return t < u }

// String renders the canonical wire form, "<wall>.<counter>", which sorts
// lexically for equal-width wall components and is trivially greppable in
// logs. Timestamp is transported as this string in JSON and as the raw uint64
// in SQLite.
func (t Timestamp) String() string {
	return strconv.FormatUint(t.Wall(), 10) + "." + strconv.FormatUint(uint64(t.Counter()), 10)
}

// MarshalText implements encoding.TextMarshaler so Timestamp round-trips
// through JSON as a string. It deliberately is not a JSON number: 64-bit
// integers do not survive a trip through JavaScript's number type, and both
// the scanner and the dashboard are JavaScript.
func (t Timestamp) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (t *Timestamp) UnmarshalText(b []byte) error {
	parsed, err := Parse(string(b))
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}

// ErrMalformed is returned by Parse for input that is not "<wall>.<counter>".
var ErrMalformed = errors.New("hlc: malformed timestamp")

// Parse reads the canonical wire form produced by Timestamp.String.
func Parse(s string) (Timestamp, error) {
	wallText, counterText, found := strings.Cut(s, ".")
	if !found {
		return 0, fmt.Errorf("%w: %q: want <wall>.<counter>", ErrMalformed, s)
	}
	wall, err := strconv.ParseUint(wallText, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q: bad wall component: %v", ErrMalformed, s, err)
	}
	if wall > maxWallMillis {
		return 0, fmt.Errorf("%w: %q: wall component exceeds 48 bits", ErrMalformed, s)
	}
	counter, err := strconv.ParseUint(counterText, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%w: %q: bad counter component: %v", ErrMalformed, s, err)
	}
	return New(wall, uint16(counter)), nil
}

// Clock is a hybrid logical clock. It is safe for concurrent use: every scan
// handler, SSE publish and replication frame draws from the same instance, so
// contention on a single mutex is cheaper than reasoning about per-goroutine
// clocks that would need merging anyway.
type Clock struct {
	// now is the physical clock. It is injected rather than being time.Now so
	// the deterministic simulator can drive it, which is the whole reason the
	// redemption engine is testable at all (see internal/simulation).
	now func() time.Time

	mu   sync.Mutex
	last Timestamp
}

// NewClock returns a Clock reading from the given physical clock. A nil now
// falls back to time.Now, which is what production uses.
func NewClock(now func() time.Time) *Clock {
	if now == nil {
		now = time.Now
	}
	return &Clock{now: now}
}

// physicalMillis reads the injected clock, clamped into the representable
// range. A physical clock that reads before the epoch (which a Pi with a dead
// RTC genuinely does on first boot) becomes 0 rather than a negative wall
// component, and the logical counter carries the ordering until NTP or a
// scanner hands us a plausible time.
func (c *Clock) physicalMillis() uint64 {
	millis := c.now().UnixMilli()
	if millis < 0 {
		return 0
	}
	if uint64(millis) > maxWallMillis {
		return maxWallMillis
	}
	return uint64(millis)
}

// Now returns the next timestamp from this clock. Successive calls are strictly
// increasing even when the physical clock is frozen or running backwards,
// which is the property the audit log's ordering depends on.
func (c *Clock) Now() Timestamp {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tick(c.physicalMillis())
}

// tick advances the clock to at least physical. Caller holds c.mu.
func (c *Clock) tick(physical uint64) Timestamp {
	if physical > c.last.Wall() {
		c.last = New(physical, 0)
		return c.last
	}
	c.last = bump(c.last)
	return c.last
}

// Update merges a timestamp observed on an inbound message and returns the
// clock's new reading, which is the timestamp to stamp on any message sent as
// a consequence. This is the receive half of the HLC algorithm and is what
// makes causality transitive across the whole venue: a scan that a scanner
// observed after seeing a redemption delta can never be ordered before it.
func (c *Clock) Update(remote Timestamp) Timestamp {
	c.mu.Lock()
	defer c.mu.Unlock()

	physical := c.physicalMillis()
	local := c.last

	switch highest := max3(local.Wall(), remote.Wall(), physical); {
	case highest == local.Wall() && highest == remote.Wall():
		// Both logical clocks already sit in this millisecond; take the higher
		// counter and step past it.
		counter := local.Counter()
		if remote.Counter() > counter {
			counter = remote.Counter()
		}
		c.last = bump(New(highest, counter))
	case highest == local.Wall():
		c.last = bump(local)
	case highest == remote.Wall():
		c.last = bump(remote)
	default:
		// The physical clock moved past both; the counter can reset.
		c.last = New(physical, 0)
	}
	return c.last
}

// Last returns the clock's current reading without advancing it. Used by the
// dashboard's diagnostics panel and by the simulator's invariant checks.
func (c *Clock) Last() Timestamp {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// bump returns the next timestamp after t within the same millisecond, rolling
// into the next millisecond when the counter saturates. Borrowing from the
// physical component keeps the clock strictly monotone at the cost of running
// slightly ahead of wall time, which is the correct trade: an HLC is allowed to
// lead the physical clock, it is never allowed to repeat a value.
func bump(t Timestamp) Timestamp {
	if t.Counter() == maxCounter {
		return New(t.Wall()+1, 0)
	}
	return New(t.Wall(), t.Counter()+1)
}

func max3(a, b, c uint64) uint64 {
	if b > a {
		a = b
	}
	if c > a {
		a = c
	}
	return a
}
