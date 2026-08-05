package hlc

import (
	"math/rand"
	"sync"
	"testing"
	"time"
)

// fakeClock is a hand-driven physical clock. Every HLC test uses one; none of
// them read the real time, which is why they are not flaky.
type fakeClock struct {
	mu     sync.Mutex
	millis int64
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return time.UnixMilli(f.millis)
}

func (f *fakeClock) set(millis int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.millis = millis
}

func TestPackRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		wall    uint64
		counter uint16
	}{
		{0, 0},
		{1, 1},
		{1750000000000, 0},
		{1750000000000, maxCounter},
		{maxWallMillis, maxCounter},
	} {
		got := New(tc.wall, tc.counter)
		if got.Wall() != tc.wall || got.Counter() != tc.counter {
			t.Errorf("New(%d, %d) unpacked to (%d, %d)", tc.wall, tc.counter, got.Wall(), got.Counter())
		}
	}
}

func TestNewClampsRatherThanWraps(t *testing.T) {
	// A wrapped wall component would sort before every existing timestamp and
	// silently corrupt the audit log's order. Clamping keeps it monotone.
	got := New(maxWallMillis+9000, 3)
	if got.Wall() != maxWallMillis {
		t.Fatalf("wall = %d, want clamp to %d", got.Wall(), uint64(maxWallMillis))
	}
	if got.Counter() != 3 {
		t.Fatalf("counter = %d, want 3", got.Counter())
	}
}

func TestNowIsStrictlyMonotoneUnderAFrozenPhysicalClock(t *testing.T) {
	physical := &fakeClock{millis: 1_750_000_000_000}
	c := NewClock(physical.now)

	previous := c.Now()
	for i := 0; i < 5000; i++ {
		next := c.Now()
		if !previous.Before(next) {
			t.Fatalf("iteration %d: %s did not advance past %s", i, next, previous)
		}
		previous = next
	}
}

func TestNowIsStrictlyMonotoneWhenTheClockRunsBackwards(t *testing.T) {
	// NTP-less Pis do this on every reboot: the clock jumps to whatever the
	// filesystem's last-write time was, which is in the past.
	physical := &fakeClock{millis: 1_750_000_000_000}
	c := NewClock(physical.now)

	previous := c.Now()
	for step := 0; step < 100; step++ {
		physical.set(1_750_000_000_000 - int64(step)*1000)
		next := c.Now()
		if !previous.Before(next) {
			t.Fatalf("step %d: %s did not advance past %s", step, next, previous)
		}
		previous = next
	}
}

func TestNowSurvivesAPreEpochClock(t *testing.T) {
	// First boot with a dead RTC genuinely reads before 1970 on some images.
	physical := &fakeClock{millis: -86_400_000}
	c := NewClock(physical.now)

	first := c.Now()
	if first.Wall() != 0 {
		t.Fatalf("wall = %d, want 0 for a pre-epoch clock", first.Wall())
	}
	if second := c.Now(); !first.Before(second) {
		t.Fatalf("%s did not advance past %s", second, first)
	}
}

func TestCounterSaturationBorrowsAMillisecond(t *testing.T) {
	physical := &fakeClock{millis: 1000}
	c := NewClock(physical.now)
	c.last = New(1000, maxCounter)

	got := c.Now()
	if got.Wall() != 1001 || got.Counter() != 0 {
		t.Fatalf("got %s, want 1001.0 after counter saturation", got)
	}
}

func TestUpdateDominatesARemoteTimestampFromTheFuture(t *testing.T) {
	physical := &fakeClock{millis: 1000}
	c := NewClock(physical.now)

	remote := New(9_000_000, 7)
	got := c.Update(remote)

	if !remote.Before(got) {
		t.Fatalf("Update(%s) returned %s, which does not dominate the remote reading", remote, got)
	}
	if got.Wall() != remote.Wall() || got.Counter() != remote.Counter()+1 {
		t.Fatalf("got %s, want the remote millisecond with the counter stepped once", got)
	}
}

func TestUpdateTakesTheHigherCounterWhenBothClocksShareAMillisecond(t *testing.T) {
	physical := &fakeClock{millis: 5000}
	c := NewClock(physical.now)
	c.last = New(5000, 4)

	got := c.Update(New(5000, 11))
	if got.Wall() != 5000 || got.Counter() != 12 {
		t.Fatalf("got %s, want 5000.12", got)
	}
}

func TestUpdateResetsTheCounterOncePhysicalTimePassesBothClocks(t *testing.T) {
	physical := &fakeClock{millis: 5000}
	c := NewClock(physical.now)
	c.last = New(4000, 900)

	got := c.Update(New(4500, 3))
	if got.Wall() != 5000 || got.Counter() != 0 {
		t.Fatalf("got %s, want 5000.0", got)
	}
}

// TestUpdatePreservesCausalityAcrossSkewedNodes is the property the redemption
// engine actually relies on: if node A stamps an event, sends it to B, and B
// stamps a consequence, the consequence sorts after the cause no matter how
// wrong either wall clock is.
func TestUpdatePreservesCausalityAcrossSkewedNodes(t *testing.T) {
	random := rand.New(rand.NewSource(7))

	// Three nodes with clocks spread over a two-hour skew, which is worse than
	// anything we have seen in the field.
	physicals := []*fakeClock{
		{millis: 1_750_000_000_000},
		{millis: 1_750_000_000_000 - 3_600_000},
		{millis: 1_750_000_000_000 + 3_600_000},
	}
	clocks := make([]*Clock, len(physicals))
	for i, p := range physicals {
		clocks[i] = NewClock(p.now)
	}

	type message struct {
		stamp Timestamp
		cause Timestamp
	}
	var sent []message

	for step := 0; step < 20000; step++ {
		sender := random.Intn(len(clocks))

		// Every node's clock drifts a little each step, sometimes backwards.
		physicals[sender].set(physicals[sender].now().UnixMilli() + int64(random.Intn(7)) - 2)

		var cause Timestamp
		var stamp Timestamp
		if len(sent) > 0 && random.Intn(2) == 0 {
			// Deliver an arbitrary earlier message and stamp the consequence.
			cause = sent[random.Intn(len(sent))].stamp
			stamp = clocks[sender].Update(cause)
		} else {
			stamp = clocks[sender].Now()
		}

		if cause != 0 && !cause.Before(stamp) {
			t.Fatalf("step %d: consequence %s did not sort after its cause %s", step, stamp, cause)
		}
		sent = append(sent, message{stamp: stamp, cause: cause})
	}
}

func TestClockIsSafeForConcurrentUse(t *testing.T) {
	physical := &fakeClock{millis: 1_750_000_000_000}
	c := NewClock(physical.now)

	const goroutines, perGoroutine = 8, 2000
	seen := make(chan Timestamp, goroutines*perGoroutine)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if i%3 == 0 {
					seen <- c.Update(New(1_750_000_000_000, uint16(i)))
				} else {
					seen <- c.Now()
				}
			}
		}(g)
	}
	wg.Wait()
	close(seen)

	unique := make(map[Timestamp]struct{}, goroutines*perGoroutine)
	for stamp := range seen {
		if _, duplicate := unique[stamp]; duplicate {
			t.Fatalf("timestamp %s handed out twice", stamp)
		}
		unique[stamp] = struct{}{}
	}
	if len(unique) != goroutines*perGoroutine {
		t.Fatalf("got %d unique timestamps, want %d", len(unique), goroutines*perGoroutine)
	}
}

func TestParseRoundTripsString(t *testing.T) {
	for _, want := range []Timestamp{0, New(1, 0), New(1_750_000_000_000, 4095), New(maxWallMillis, maxCounter)} {
		got, err := Parse(want.String())
		if err != nil {
			t.Fatalf("Parse(%q): %v", want.String(), err)
		}
		if got != want {
			t.Fatalf("Parse(%q) = %s, want %s", want.String(), got, want)
		}
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		"",
		"1750000000000",
		"nope.0",
		"1750000000000.nope",
		"1750000000000.65536", // counter overflows 16 bits
		"281474976710656.0",   // wall overflows 48 bits
		"-1.0",
	} {
		if got, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %s, want an error", in, got)
		}
	}
}

func TestTextMarshalRoundTrip(t *testing.T) {
	want := New(1_750_000_123_456, 9)
	text, err := want.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var got Timestamp
	if err := got.UnmarshalText(text); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip gave %s, want %s", got, want)
	}
}

func BenchmarkNow(b *testing.B) {
	c := NewClock(time.Now)
	for i := 0; i < b.N; i++ {
		_ = c.Now()
	}
}
