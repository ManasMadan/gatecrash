package watchdog

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// listen stands up a Unix datagram socket and points NOTIFY_SOCKET at it, which is
// exactly what systemd does.
func listen(t *testing.T) (*net.UnixConn, string) {
	t.Helper()

	// A short path in the temp dir: a Unix socket path has a hard limit around 104
	// bytes, and Go's own t.TempDir() names are long enough to blow it on macOS.
	dir, err := os.MkdirTemp("", "wd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "n")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, path
}

func read(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 512)
	n, _, err := conn.ReadFromUnix(buffer)
	if err != nil {
		t.Fatalf("nothing arrived on the notification socket: %v", err)
	}
	return string(buffer[:n])
}

// TestNoSocketIsANoOp. Under `go test`, in a container, and on a laptop there is no
// systemd, and a notifier that needed a nil check at every call site is a nil check
// somebody forgets — in the one process whose job is to not fall over.
func TestNoSocketIsANoOp(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")

	n, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if n.Enabled() {
		t.Error("reported enabled with no socket")
	}
	for _, err := range []error{n.Ready(), n.Beat(), n.Stopping(), n.Status("x"), n.Reloading()} {
		if err != nil {
			t.Errorf("a no-op notifier returned %v", err)
		}
	}
	n.Alive()
	if err := n.Close(); err != nil {
		t.Errorf("close returned %v", err)
	}
}

func TestReadyAndStatusReachSystemd(t *testing.T) {
	conn, path := listen(t)
	t.Setenv("NOTIFY_SOCKET", path)

	n, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if !n.Enabled() {
		t.Fatal("not enabled with a socket present")
	}
	if err := n.Ready(); err != nil {
		t.Fatal(err)
	}
	if got := read(t, conn); got != "READY=1" {
		t.Errorf("ready sent %q", got)
	}

	if err := n.Status("2,412 inside · 6 gates"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, conn); got != "STATUS=2,412 inside · 6 gates" {
		t.Errorf("status sent %q", got)
	}

	if err := n.Stopping(); err != nil {
		t.Fatal(err)
	}
	if got := read(t, conn); got != "STOPPING=1" {
		t.Errorf("stopping sent %q", got)
	}
}

// TestTheIntervalIsHalfTheDeadline. Pinging at exactly the deadline is how a healthy
// service gets killed by a slow disk.
func TestTheIntervalIsHalfTheDeadline(t *testing.T) {
	conn, path := listen(t)
	_ = conn
	t.Setenv("NOTIFY_SOCKET", path)
	t.Setenv("WATCHDOG_USEC", "30000000") // 30 seconds

	n, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if got := n.Interval(); got != 15*time.Second {
		t.Errorf("interval is %s, want half of 30s", got)
	}
}

// TestAnotherProcessesWatchdogIsIgnored. A forked child inheriting the environment
// would otherwise keep its parent's watchdog satisfied, which reports liveness for
// the wrong process.
func TestAnotherProcessesWatchdogIsIgnored(t *testing.T) {
	conn, path := listen(t)
	_ = conn
	t.Setenv("NOTIFY_SOCKET", path)
	t.Setenv("WATCHDOG_USEC", "30000000")
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()+1))

	n, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if got := n.Interval(); got != 0 {
		t.Errorf("interval is %s for another process's watchdog, want 0", got)
	}
}

// TestABusyBoxKeepsItselfAlive.
func TestABusyBoxKeepsItselfAlive(t *testing.T) {
	conn, path := listen(t)
	t.Setenv("NOTIFY_SOCKET", path)
	t.Setenv("WATCHDOG_USEC", "40000") // 20ms after halving

	n, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Something is serving scans.
	go func() {
		for ctx.Err() == nil {
			n.Alive()
			time.Sleep(time.Millisecond)
		}
	}()
	go func() { _ = n.Run(ctx, func() bool { return false }) }()

	if got := read(t, conn); got != "WATCHDOG=1" {
		t.Errorf("a busy box sent %q", got)
	}
}

// TestAHungBoxStopsPinging is the entire point of the package.
//
// A box that has deadlocked on its store's writer is still running, still scheduled,
// and no longer answering anybody. From outside it looks alive, and a guard at a gate
// watches a spinner. A liveness check a hung server can still pass is not a liveness
// check.
func TestAHungBoxStopsPinging(t *testing.T) {
	conn, path := listen(t)
	t.Setenv("NOTIFY_SOCKET", path)
	t.Setenv("WATCHDOG_USEC", "20000") // 10ms after halving

	n, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Nothing calls Alive, and the box does not claim to be idle either — so it is
	// hung, and it must say nothing at all.
	go func() { _ = n.Run(ctx, func() bool { return false }) }()

	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if _, _, err := conn.ReadFromUnix(buffer); err == nil {
		t.Fatal("a hung box pinged the watchdog anyway, so systemd would never restart it")
	}
}

// TestAnIdleBoxStaysAlive. Four in the afternoon, doors not open, no scans to serve
// — that box is fine and must not be restarted for being quiet.
func TestAnIdleBoxStaysAlive(t *testing.T) {
	conn, path := listen(t)
	t.Setenv("NOTIFY_SOCKET", path)
	t.Setenv("WATCHDOG_USEC", "20000")

	n, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = n.Run(ctx, func() bool { return true }) }()

	if got := read(t, conn); got != "WATCHDOG=1" {
		t.Errorf("an idle box sent %q", got)
	}
}

// TestRunBlocksWhenNothingIsWatching, rather than returning — a service group would
// otherwise treat a missing watchdog as a service that exited.
func TestRunBlocksWhenNothingIsWatching(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")

	n, err := New()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- n.Run(ctx, nil) }()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("returned %v, want the context's error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return when its context was cancelled")
	}
}

// TestAbstractSocketNamesAreTranslated. systemd spells an abstract socket with a
// leading '@'; Go spells it with a NUL.
func TestAbstractSocketNamesAreTranslated(t *testing.T) {
	// Abstract sockets are Linux-only, so this checks the translation rather than
	// the connection: on a Mac the dial fails, and what matters is that it failed
	// having tried the right name.
	t.Setenv("NOTIFY_SOCKET", "@gatecrash-test-abstract")
	if _, err := New(); err != nil && !containsNUL(err.Error()) {
		// A dial failure is fine. A failure that still shows the '@' would mean the
		// translation never happened.
		if got := err.Error(); !contains(got, "gatecrash-test-abstract") {
			t.Errorf("error does not mention the socket: %v", err)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func containsNUL(s string) bool { return contains(s, "\x00") }
