// Package ssehub fans redemption deltas and incidents out to scanners and the
// dashboard over Server-Sent Events.
//
// SSE rather than WebSockets, for three reasons that all come down to the venue.
// It is one-directional, which is all this needs — scans go up over POST, deltas
// come down. It reconnects by itself, including on Android's aggressive Wi-Fi
// handoffs, and it resumes from a sequence with no application code. And it is
// plain HTTP, so it survives every middlebox a venue's network has accumulated.
//
// The hard requirement is the one that shapes the whole design: a slow client must
// never slow down a gate. The engine publishes deltas on the writer's goroutine,
// immediately after the transaction commits, so anything that blocks there blocks
// every gate in the venue. So each subscriber gets a bounded buffer, and a
// subscriber that fills its buffer is disconnected rather than waited for. It
// reconnects and resumes from its last sequence, which is exactly what the resume
// protocol is for.
package ssehub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Tuning.
const (
	// bufferSize is how many events a subscriber may fall behind by before it is
	// disconnected.
	//
	// Two hundred is about twenty seconds of a very busy gate. Big enough to
	// absorb a phone's radio hiccup, small enough that the memory cost of a
	// hundred connected devices is a few megabytes, and small enough that a truly
	// stuck client is dropped quickly rather than accumulating an unbounded
	// backlog nobody will ever read.
	bufferSize = 200

	// HeartbeatInterval is how often a comment line is sent to keep the
	// connection alive.
	//
	// Fifteen seconds, because consumer access points and mobile carriers idle out
	// silent connections in anything from thirty seconds upwards, and a scanner
	// whose stream died silently believes its mirror is current when it is not.
	HeartbeatInterval = 15 * time.Second
)

// Event is one message on the stream.
type Event struct {
	// Kind is the SSE event name: "redemption", "incident", "stats", "config".
	Kind string

	// Seq is the resume point. Sent as the SSE id field, so a reconnecting client
	// gets Last-Event-ID for free from the browser's own EventSource.
	Seq uint64

	// Data is the JSON payload.
	Data any
}

// Replayer supplies events a reconnecting subscriber missed.
//
// The hub holds no history of its own: the redemption log is already durable in
// SQLite, and a second in-memory copy would be one more thing to get out of step.
type Replayer func(ctx context.Context, since uint64) ([]Event, error)

// Hub fans events out.
type Hub struct {
	log *slog.Logger

	mu          sync.RWMutex
	subscribers map[int]*subscriber
	nextID      int

	// closed stops new subscriptions during shutdown.
	closed bool

	// dropped counts subscribers disconnected for falling behind, surfaced on the
	// dashboard because it is the signal that a device or the network is in
	// trouble.
	dropped uint64
}

// subscriber is one connected client.
type subscriber struct {
	events chan Event

	// hangUp is closed to tell the serving goroutine to disconnect. A separate
	// channel rather than closing events, because closing events would race with
	// a concurrent Publish sending into it.
	hangUp     chan struct{}
	hangUpOnce sync.Once

	// filter, when set, decides which events this subscriber receives. A gate
	// scanner does not need the incident feed for the whole venue.
	filter func(Event) bool
}

// New builds a hub.
func New(logger *slog.Logger) *Hub {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Hub{log: logger, subscribers: make(map[int]*subscriber)}
}

// Publish sends an event to every matching subscriber.
//
// Never blocks. This runs on the engine's writer goroutine immediately after a
// transaction commits, so a blocking send here would stall every gate in the
// venue. A subscriber whose buffer is full is disconnected and left to reconnect
// and resume, which is what the resume protocol exists for.
func (h *Hub) Publish(event Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for id, sub := range h.subscribers {
		if sub.filter != nil && !sub.filter(event) {
			continue
		}
		select {
		case sub.events <- event:
		default:
			// Close the channel to signal the serving goroutine to hang up. The
			// map entry is removed by that goroutine's deferred unsubscribe, so
			// this does not mutate the map under a read lock.
			h.log.Warn("ssehub: disconnecting a subscriber that fell behind",
				"subscriber", id, "buffer", bufferSize)
			h.dropSlow(sub)
		}
	}
}

// dropSlow marks a subscriber for disconnection.
//
// Signalled by closing a dedicated channel rather than the event channel, because
// closing the event channel would race with a concurrent Publish on another
// goroutine sending into it.
func (h *Hub) dropSlow(sub *subscriber) {
	sub.hangUpOnce.Do(func() { close(sub.hangUp) })
}

// Subscribers returns how many clients are connected, for the dashboard.
func (h *Hub) Subscribers() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subscribers)
}

// Dropped returns how many subscribers have been disconnected for falling
// behind. A number that climbs is the signal that a device or the venue network
// is in trouble.
func (h *Hub) Dropped() uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.dropped
}

// Close disconnects every subscriber and refuses new ones.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.closed = true
	for _, sub := range h.subscribers {
		h.dropSlow(sub)
	}
}

// subscribe registers a client.
func (h *Hub) subscribe(filter func(Event) bool) (int, *subscriber, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return 0, nil, false
	}
	id := h.nextID
	h.nextID++
	sub := &subscriber{
		events: make(chan Event, bufferSize),
		hangUp: make(chan struct{}),
		filter: filter,
	}
	h.subscribers[id] = sub
	return id, sub, true
}

func (h *Hub) unsubscribe(id int, slow bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subscribers, id)
	if slow {
		h.dropped++
	}
}

// HandlerOptions configure one stream.
type HandlerOptions struct {
	// Replay supplies missed events for a client resuming from a sequence.
	Replay Replayer

	// Filter decides which events this client receives.
	Filter func(Event) bool

	// Heartbeat overrides the keepalive interval.
	Heartbeat time.Duration
}

// Handler serves one SSE stream.
func (h *Hub) Handler(opts HandlerOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache, no-store")
		w.Header().Set("Connection", "keep-alive")
		// Without this, an intermediate proxy may buffer the whole stream and the
		// scanner receives nothing until the connection closes. Venues have
		// proxies nobody remembers installing.
		w.Header().Set("X-Accel-Buffering", "no")

		id, sub, ok := h.subscribe(opts.Filter)
		if !ok {
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		}
		slow := false
		defer func() { h.unsubscribe(id, slow) }()

		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		// Replay first, then live events. Subscribing before replaying is
		// deliberate: an event committed between the replay query and the
		// subscription would otherwise be lost, and the buffer absorbs the overlap.
		// A client may see one event twice across a reconnect, which is why every
		// event carries a sequence and the clients are idempotent on it.
		if opts.Replay != nil {
			if since, ok := resumeFrom(r); ok {
				missed, err := opts.Replay(r.Context(), since)
				if err != nil {
					h.log.Warn("ssehub: replay failed", "since", since, "error", err)
				}
				for _, event := range missed {
					if opts.Filter != nil && !opts.Filter(event) {
						continue
					}
					if err := write(w, event); err != nil {
						if errors.Is(err, ErrUnencodable) {
							h.log.Error("ssehub: skipping an event that will not encode",
								"seq", event.Seq, "error", err)
							continue
						}
						return
					}
				}
				flusher.Flush()
			}
		}

		heartbeat := opts.Heartbeat
		if heartbeat <= 0 {
			heartbeat = HeartbeatInterval
		}
		ticker := time.NewTicker(heartbeat)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return

			case <-sub.hangUp:
				slow = true
				return

			case event := <-sub.events:
				if err := write(w, event); err != nil {
					if !errors.Is(err, ErrUnencodable) {
						return
					}
					h.log.Error("ssehub: skipping an event that will not encode",
						"seq", event.Seq, "error", err)
				}
				// Drain whatever else is buffered before flushing, so a burst of
				// admissions costs one syscall rather than one per scan.
				drained := true
				for drained {
					select {
					case next := <-sub.events:
						if err := write(w, next); err != nil {
							if !errors.Is(err, ErrUnencodable) {
								return
							}
							h.log.Error("ssehub: skipping an event that will not encode",
								"seq", next.Seq, "error", err)
						}
					default:
						drained = false
					}
				}
				flusher.Flush()

			case <-ticker.C:
				// A comment line: valid SSE, ignored by every client, and enough
				// to keep a middlebox from idling the connection out.
				if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	})
}

// resumeFrom reads the resume point from the request.
//
// Both the Last-Event-ID header and a `from` query parameter are accepted. The
// header is what a browser's EventSource sends automatically on reconnect; the
// query parameter is what a native app uses, because it manages its own retry and
// wants the resume point to be explicit rather than implicit in a header it has to
// remember to set.
func resumeFrom(r *http.Request) (uint64, bool) {
	if header := r.Header.Get("Last-Event-ID"); header != "" {
		if seq, err := strconv.ParseUint(header, 10, 64); err == nil {
			return seq, true
		}
	}
	if query := r.URL.Query().Get("from"); query != "" {
		if seq, err := strconv.ParseUint(query, 10, 64); err == nil {
			return seq, true
		}
	}
	return 0, false
}

// ErrUnencodable means one event could not be marshalled.
//
// Distinguished from a write failure because the two want opposite handling: a broken
// connection means stop, and a payload that will not encode means skip this one and
// carry on. Tearing down every gate's stream over one bad row would turn a bug in one
// event into an outage.
var ErrUnencodable = errors.New("ssehub: event payload will not encode")

// write emits one event in SSE framing.
func write(w http.ResponseWriter, event Event) error {
	payload, err := json.Marshal(event.Data)
	if err != nil {
		// Reported rather than swallowed. This used to return nil, which kept the
		// stream alive and meant nobody ever found out — a bug that is invisible is a
		// bug that stays.
		return fmt.Errorf("%w: %w", ErrUnencodable, err)
	}
	if event.Seq > 0 {
		if _, err := fmt.Fprintf(w, "id: %d\n", event.Seq); err != nil {
			return err
		}
	}
	if event.Kind != "" {
		if _, err := fmt.Fprintf(w, "event: %s\n", event.Kind); err != nil {
			return err
		}
	}
	// One data line. The payload is JSON with no literal newlines, so it does not
	// need the multi-line data folding the SSE spec allows.
	_, err = fmt.Fprintf(w, "data: %s\n\n", payload)
	return err
}
