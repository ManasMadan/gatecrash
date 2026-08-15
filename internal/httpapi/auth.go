package httpapi

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ManasMadan/gatecrash/internal/enroll"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// deviceHandler is a handler that has an authenticated scanner.
type deviceHandler func(http.ResponseWriter, *http.Request, enroll.Device)

// device wraps a handler with scanner authentication and per-device rate
// limiting.
func (a *API) device(next deviceHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r)
		if token == "" {
			// A bare 401 with a WWW-Authenticate header, so a scanner whose token
			// was revoked knows to run the enrollment ceremony again rather than
			// retrying forever.
			w.Header().Set("WWW-Authenticate", `Bearer realm="gatecrash"`)
			writeError(w, http.StatusUnauthorized, "no_token", "This scanner is not signed in.")
			return
		}

		found, ok := a.deps.Registry.Authenticate(token)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="gatecrash", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "bad_token", "This scanner is not signed in here. Scan the enrollment code again.")
			return
		}

		if !a.limiter.allow(found.ID) {
			// Retry-After so a scanner backs off rather than hammering. The value
			// is one second because the limiter's window is one second, and a
			// scanner that waits longer than it needs to is a queue.
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "Slow down.")
			return
		}

		next(w, r, found)
	})
}

// admin wraps a handler with organizer authentication.
func (a *API) admin(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r)
		if token == "" {
			// The dashboard is opened in a browser, so the token can also arrive
			// as a query parameter: an operator pastes one URL and is in. It is
			// logged nowhere and the dashboard immediately moves it into
			// sessionStorage, which is the least-bad option for a device with no
			// keyboard and a projector behind it.
			token = r.URL.Query().Get("token")
		}
		// Constant time, because this is the one credential that grants
		// revocation, manifest ingest and the signed export.
		if subtle.ConstantTimeCompare([]byte(token), []byte(a.deps.AdminToken)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="gatecrash-admin"`)
			writeError(w, http.StatusUnauthorized, "bad_token", "Not signed in.")
			return
		}
		next(w, r)
	})
}

// bearer extracts a bearer token from the Authorization header.
func bearer(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	value, found := strings.CutPrefix(header, "Bearer ")
	if !found {
		// Case-insensitive, because at least one HTTP client in the wild sends
		// "bearer" and debugging that is an afternoon nobody should spend.
		if value, found = strings.CutPrefix(header, "bearer "); !found {
			return ""
		}
	}
	return strings.TrimSpace(value)
}

// authorizedFor reports whether a device may act at a checkpoint.
//
// Checked here as well as in the engine. The engine's check is the authority — it
// runs inside the transaction and cannot be bypassed — but rejecting at the edge
// means a misconfigured scanner gets a clear 403 instead of a verdict, and the
// audit log is not filled with rows from a device that should not have been
// talking to this endpoint at all.
func authorizedFor(device enroll.Device, checkpoint venue.CheckpointCode) bool {
	for _, allowed := range device.Checkpoints {
		if allowed == checkpoint {
			return true
		}
	}
	return false
}

// Rate limiting.
//
// One token bucket per device, refilled continuously. The numbers come from the
// spec's own scale sanity check: a busy gate peaks at 15 to 20 scans per second
// across the whole venue, so a single device sustaining 30 is either a barcode gun
// somebody is holding down or an attack. Either way the correct response is to
// slow it down rather than to let it crowd out the other gates.
const (
	// rateBurst is how many requests a device may make instantaneously.
	//
	// Sixty, because a scanner draining an offline queue after a partition legitimately
	// bursts, and refusing that would turn a heal into a stall.
	rateBurst = 60

	// ratePerSecond is the sustained rate.
	ratePerSecond = 30
)

// limiter holds one bucket per device.
type limiter struct {
	now func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, buckets: make(map[string]*bucket)}
}

// allow reports whether a request may proceed, consuming a token.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	held, ok := l.buckets[key]
	if !ok {
		// A new device starts full, so its first burst is not penalised.
		l.buckets[key] = &bucket{tokens: rateBurst - 1, last: now}
		return true
	}

	elapsed := now.Sub(held.last).Seconds()
	if elapsed > 0 {
		held.tokens = min(rateBurst, held.tokens+elapsed*ratePerSecond)
		held.last = now
	}
	if held.tokens < 1 {
		return false
	}
	held.tokens--
	return true
}
