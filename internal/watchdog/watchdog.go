// Package watchdog talks to systemd's notification socket.
//
// Three messages matter and they are all one line of text on a Unix datagram
// socket: "I am up", "I am still here", and "I am going down on purpose".
//
// Written out rather than taken from a library because the protocol is genuinely
// this small, and because the alternative — go-systemd — brings a dependency tree
// for a socket write. That trade would be arguable in most projects; here the whole
// binary is meant to be one static file cross-compiled for a Raspberry Pi, and every
// dependency is a thing that can fail to build for arm64.
//
// # Why a watchdog at all
//
// A box that has crashed is easy: systemd restarts it. The dangerous failure is a
// box that is still running and no longer answering — a deadlock on the store's
// writer mutex, a goroutine leak that has eaten the heap, an SD card that has gone
// read-only and left every write blocking. From outside, that box looks alive. A
// guard at a gate watches a spinner and nobody knows why.
//
// The heartbeat is sent from the same path that serves scans, so it stops when scans
// stop. That is the whole design: a liveness check that a hung server can still pass
// is not a liveness check.
//
// Everything here degrades to a no-op when NOTIFY_SOCKET is unset, which is the case
// under `go test`, in a container without systemd, and on a developer's laptop.
package watchdog

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// Notifier sends state to systemd.
//
// The zero value is a working no-op, so callers never have to check whether systemd
// is present. That matters more than it sounds: a nil check at every call site is a
// nil check somebody forgets, and the failure mode is a nil dereference in the
// process whose job is to not fall over.
type Notifier struct {
	conn *net.UnixConn

	// interval is how often systemd expects a ping, already halved. See Interval.
	interval time.Duration

	// alive is set by the serving path and cleared by the ticker. A ping is only
	// sent when something set it, so a server that has stopped serving stops
	// pinging.
	alive atomic.Bool
}

// New connects to the notification socket named by NOTIFY_SOCKET.
//
// Returns a working no-op notifier and no error when the variable is unset. An
// absent socket is not a failure — it means nothing is watching, which is the normal
// case everywhere except a systemd unit.
func New() (*Notifier, error) {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return &Notifier{}, nil
	}

	// A leading '@' means an abstract socket, which is spelled with a NUL in Go.
	if address[0] == '@' {
		address = "\x00" + address[1:]
	}

	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		return nil, fmt.Errorf("watchdog: connecting to %q: %w", os.Getenv("NOTIFY_SOCKET"), err)
	}

	return &Notifier{conn: conn, interval: intervalFromEnvironment()}, nil
}

// Enabled reports whether anything is listening.
func (n *Notifier) Enabled() bool { return n != nil && n.conn != nil }

// Interval is how often Beat should be called.
//
// Half of what systemd asked for. The unit says WatchdogSec=30s, meaning systemd
// kills the process if it hears nothing for thirty seconds; pinging every fifteen
// leaves room for one ping to be late without the box being restarted in the middle
// of an event. Pinging at exactly the deadline is how a healthy service gets killed
// by a slow disk.
func (n *Notifier) Interval() time.Duration {
	if !n.Enabled() || n.interval <= 0 {
		return 0
	}
	return n.interval
}

// intervalFromEnvironment reads WATCHDOG_USEC and halves it.
//
// WATCHDOG_PID is checked too. systemd sets it to the PID it expects pings from, and
// a forked child inheriting the environment would otherwise cheerfully keep the
// parent's watchdog satisfied — which is a liveness check that reports on the wrong
// process.
func intervalFromEnvironment() time.Duration {
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0
	}

	micros, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || micros <= 0 {
		return 0
	}
	return time.Duration(micros) * time.Microsecond / 2
}

// Ready tells systemd the box is up and serving.
//
// Sent after the listeners are bound and the manifest is loaded, not at the top of
// main. With Type=notify, systemd holds dependent units until this arrives, so
// sending it early means "ready" describes a process that cannot yet answer a scan.
func (n *Notifier) Ready() error { return n.send("READY=1") }

// Reloading tells systemd a reload is in progress, and Ready ends it.
func (n *Notifier) Reloading() error {
	return n.send(fmt.Sprintf("RELOADING=1\nMONOTONIC_USEC=%d", monotonicMicros()))
}

// Stopping tells systemd the box is shutting down on purpose.
//
// Worth sending: without it, a deliberate shutdown and a crash look identical in the
// journal, and after an event somebody will be trying to work out which one happened
// at 23:14.
func (n *Notifier) Stopping() error { return n.send("STOPPING=1") }

// Status sets the one-line status shown by `systemctl status`.
//
// The box puts the numbers an operator would otherwise have to open a dashboard for:
// how many are inside, how many gates are connected. `systemctl status gatecrash`
// over SSH is the only tool available when the dashboard is what has broken.
func (n *Notifier) Status(text string) error {
	return n.send("STATUS=" + text)
}

// Alive marks the process as having done real work.
//
// Called from the scan path. Run only sends a ping when this has been set since the
// last one, which is what makes the heartbeat mean "still serving" rather than
// "still scheduled".
func (n *Notifier) Alive() {
	if n == nil {
		return
	}
	n.alive.Store(true)
}

// Beat sends one keepalive immediately, regardless of Alive.
//
// Used at boot to start the clock, and by tests. The periodic path is Run.
func (n *Notifier) Beat() error { return n.send("WATCHDOG=1") }

// Run pings systemd until the context is cancelled.
//
// The rule: ping only if something called Alive since the last tick. An idle box at
// four in the afternoon has no scans to serve, so Idle below keeps it alive without
// pretending it is busy — while a box whose serving loop has deadlocked stops
// setting the flag, misses its deadline, and gets restarted.
func (n *Notifier) Run(ctx context.Context, idle func() bool) error {
	interval := n.Interval()
	if interval <= 0 {
		// Nothing is watching, or this is not the process systemd is watching. Block
		// until cancelled rather than returning, so the caller's service group does
		// not treat a missing watchdog as a service that exited.
		<-ctx.Done()
		return ctx.Err()
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Swapped rather than loaded: the flag has to be cleared so the next tick
			// asks the same question again.
			served := n.alive.Swap(false)
			if !served && idle != nil && !idle() {
				// Not serving and not legitimately idle. Say nothing, and let systemd
				// draw the conclusion.
				continue
			}
			if err := n.Beat(); err != nil {
				return err
			}
		}
	}
}

// Close releases the socket.
func (n *Notifier) Close() error {
	if !n.Enabled() {
		return nil
	}
	return n.conn.Close()
}

func (n *Notifier) send(message string) error {
	if !n.Enabled() {
		return nil
	}
	if _, err := n.conn.Write([]byte(message)); err != nil {
		return fmt.Errorf("watchdog: notifying systemd: %w", err)
	}
	return nil
}

// started is the process's own reference point for MONOTONIC_USEC.
//
// systemd wants a CLOCK_MONOTONIC reading, and Go does not expose one. The value is
// only compared against other readings from the same process, so an offset from
// process start satisfies it — and unlike a wall-clock reading it cannot go backwards
// when the box finally reaches an NTP server and jumps three hours.
var started = time.Now()

func monotonicMicros() int64 { return int64(time.Since(started) / time.Microsecond) }
