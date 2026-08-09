package incident

import (
	"sort"
	"sync"
	"time"

	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// Board is the control room's incident list.
//
// It lives in memory and is written through to storage by a persist callback,
// which is the opposite of how the redemption engine works and deliberately so.
// A redemption is a financial fact that must survive a power cut at any cost; an
// open incident is a live conversation, and the failure mode that matters is not
// losing a row, it is the dashboard being slow to show an alarm. So reads are
// lock-free-ish and cheap, and durability is best-effort behind them.
//
// Every method is safe for concurrent use. Ten gates raising alarms while the
// control room acknowledges them is the normal case, not the edge case.
type Board struct {
	mu       sync.RWMutex
	byID     map[ID]Incident
	byClient map[string]ID
	order    []ID
	seq      uint64

	venue *venue.Venue
	clock *hlc.Clock
	now   func() time.Time

	// persist is called after every change, on the caller's goroutine, so a slow
	// store slows the caller rather than silently dropping the write.
	persist func(Incident)

	listenersMu sync.RWMutex
	listeners   map[int]func(Incident)
	nextID      int
}

// BoardConfig configures a board.
type BoardConfig struct {
	Venue *venue.Venue
	Clock *hlc.Clock

	// Now is the box's clock, injected so the simulator can drive it and so
	// response-time assertions are not flaky.
	Now func() time.Time

	// Persist is called with every created or changed incident. Optional: a
	// board with no persistence still works and simply forgets across a reboot,
	// which is what the simulator wants.
	Persist func(Incident)
}

// NewBoard returns an empty board.
func NewBoard(cfg BoardConfig) *Board {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	clock := cfg.Clock
	if clock == nil {
		clock = hlc.NewClock(cfg.Now)
	}
	return &Board{
		byID:      make(map[ID]Incident),
		byClient:  make(map[string]ID),
		venue:     cfg.Venue,
		clock:     clock,
		now:       cfg.Now,
		persist:   cfg.Persist,
		listeners: make(map[int]func(Incident)),
	}
}

// Restore loads incidents from storage on boot, preserving their ids and
// sequence numbers. An event that reboots mid-incident must come back with the
// incident still open, because an alarm that vanishes when the box restarts is
// worse than one that was never raised.
func (b *Board) Restore(incidents []Incident) {
	b.mu.Lock()
	defer b.mu.Unlock()

	sorted := append([]Incident(nil), incidents...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Seq < sorted[j].Seq })

	for _, i := range sorted {
		b.byID[i.ID] = i
		b.order = append(b.order, i.ID)
		if i.Seq > b.seq {
			b.seq = i.Seq
		}
	}
}

// Subscribe registers a callback for every created or changed incident, and
// returns a function that unregisters it. Callbacks must not block: the SSE hub
// hands off to a buffered channel and returns.
func (b *Board) Subscribe(fn func(Incident)) func() {
	b.listenersMu.Lock()
	id := b.nextID
	b.nextID++
	b.listeners[id] = fn
	b.listenersMu.Unlock()

	return func() {
		b.listenersMu.Lock()
		delete(b.listeners, id)
		b.listenersMu.Unlock()
	}
}

func (b *Board) announce(i Incident) {
	if b.persist != nil {
		b.persist(i)
	}
	b.listenersMu.RLock()
	defer b.listenersMu.RUnlock()
	for _, fn := range b.listeners {
		fn(i)
	}
}

// Raise records a new incident.
//
// A report carrying a client id that has already been seen returns the existing
// incident unchanged, so a bouncer jabbing the alarm button on a flaky link
// raises one incident rather than four.
func (b *Board) Raise(report Report) (Incident, error) {
	if err := report.Validate(); err != nil {
		return Incident{}, err
	}

	b.mu.Lock()
	if report.ClientID != "" {
		if existing, ok := b.byClient[report.ClientID]; ok {
			found := b.byID[existing]
			b.mu.Unlock()
			return found, nil
		}
	}

	b.seq++
	now := b.now()
	stamp := b.clock.Now()

	i := Incident{
		ID:         FormatID(b.seq),
		Kind:       report.Kind,
		Severity:   report.Severity,
		Status:     Open,
		Checkpoint: report.Checkpoint,
		Device:     report.Device,
		Reporter:   report.Reporter,
		Note:       report.Note,
		HeadCount:  report.HeadCount,
		QueueRate:  report.QueueRate,
		RaisedHLC:  stamp,
		RaisedAt:   now,
		Seq:        b.seq,
		History:    []Event{{Status: Open, Actor: reporterOf(report), HLC: stamp, At: now}},
	}

	// Fill in the location from the venue rather than from the report. The gate
	// knows where it is; the person pressing the button should not have to say.
	if b.venue != nil && report.Checkpoint != "" {
		if cp, ok := b.venue.Checkpoint(report.Checkpoint); ok {
			i.CheckpointName = cp.Name
			i.Zone = cp.Zone
			if zone, ok := b.venue.Zone(cp.Zone); ok {
				i.ZoneName = zone.Name
			}
		}
	}

	b.byID[i.ID] = i
	b.order = append(b.order, i.ID)
	if report.ClientID != "" {
		b.byClient[report.ClientID] = i.ID
	}
	b.mu.Unlock()

	b.announce(i)
	return i, nil
}

// reporterOf names who raised an incident, for the first history entry.
func reporterOf(r Report) string {
	switch {
	case r.Reporter != "":
		return r.Reporter
	case r.Device != "":
		return r.Device
	default:
		return "box"
	}
}

// Transition moves an incident along its lifecycle.
func (b *Board) Transition(id ID, t Transition) (Incident, error) {
	b.mu.Lock()
	current, ok := b.byID[id]
	if !ok {
		b.mu.Unlock()
		return Incident{}, ErrNotFound
	}

	updated, err := Apply(current, t, b.now(), b.clock.Now())
	if err != nil {
		b.mu.Unlock()
		return current, err
	}
	b.byID[id] = updated
	b.mu.Unlock()

	b.announce(updated)
	return updated, nil
}

// Get returns one incident.
func (b *Board) Get(id ID) (Incident, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	found, ok := b.byID[id]
	return found, ok
}

// Filter narrows a listing.
type Filter struct {
	// LiveOnly returns only incidents that still need attention.
	LiveOnly bool

	// Kinds, when non-empty, restricts to these kinds.
	Kinds []Kind

	// Zone, when set, restricts to incidents in this zone or any zone nested
	// inside it, which is how a zone supervisor gets their own view.
	Zone venue.ZoneCode

	// MinSeverity drops anything quieter.
	MinSeverity Severity

	// Since returns only incidents raised after this sequence, so the dashboard
	// can poll incrementally.
	Since uint64
}

// List returns matching incidents.
//
// The order is what the control room needs to see rather than chronological:
// live before closed, then loudest first, then oldest first inside a severity.
// A dashboard sorted purely by time buries an unacknowledged crush alarm under
// nine requests for a tea break.
func (b *Board) List(f Filter) []Incident {
	b.mu.RLock()
	defer b.mu.RUnlock()

	wanted := make(map[Kind]bool, len(f.Kinds))
	for _, kind := range f.Kinds {
		wanted[kind] = true
	}

	out := make([]Incident, 0, len(b.order))
	for _, id := range b.order {
		i := b.byID[id]
		switch {
		case f.LiveOnly && !i.Status.Live():
			continue
		case len(wanted) > 0 && !wanted[i.Kind]:
			continue
		case i.Seq <= f.Since:
			continue
		case f.MinSeverity != "" && rank(i.Severity) < rank(f.MinSeverity):
			continue
		case f.Zone != "" && !b.inZone(i, f.Zone):
			continue
		}
		out = append(out, i)
	}

	sort.SliceStable(out, func(x, y int) bool {
		left, right := out[x], out[y]
		if left.Status.Live() != right.Status.Live() {
			return left.Status.Live()
		}
		if rank(left.Severity) != rank(right.Severity) {
			return rank(left.Severity) > rank(right.Severity)
		}
		return left.Seq < right.Seq
	})
	return out
}

// inZone reports whether an incident sits inside a zone or anything nested in it.
func (b *Board) inZone(i Incident, zone venue.ZoneCode) bool {
	if i.Zone == zone {
		return true
	}
	if b.venue == nil {
		return false
	}
	return b.venue.SatisfiesZone(i.Zone, zone)
}

// Live returns every incident that still needs attention.
func (b *Board) Live() []Incident { return b.List(Filter{LiveOnly: true}) }

// Loudest returns the most severe live incident, which is what the dashboard's
// banner and the scanner's status strip both show.
func (b *Board) Loudest() (Incident, bool) {
	live := b.Live()
	if len(live) == 0 {
		return Incident{}, false
	}
	return live[0], true
}

// Counts summarises the board for a status strip: how many live incidents there
// are at each severity. Cheap enough to include in every SSE heartbeat.
type Counts struct {
	Open         int `json:"open"`
	Acknowledged int `json:"acknowledged"`
	Assigned     int `json:"assigned"`
	Emergency    int `json:"emergency"`
	Urgent       int `json:"urgent"`
	Warning      int `json:"warning"`
	Info         int `json:"info"`
}

// Counts returns the live-incident summary.
func (b *Board) Counts() Counts {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var out Counts
	for _, id := range b.order {
		i := b.byID[id]
		if !i.Status.Live() {
			continue
		}
		switch i.Status {
		case Open:
			out.Open++
		case Acknowledged:
			out.Acknowledged++
		case Assigned:
			out.Assigned++
		}
		switch i.Severity {
		case Emergency:
			out.Emergency++
		case Urgent:
			out.Urgent++
		case Warning:
			out.Warning++
		default:
			out.Info++
		}
	}
	return out
}

// Response summarises how quickly the control room reacted. Published in the
// post-event report, because a system that measures its own response times is
// the only kind that improves them.
type Response struct {
	Total     int `json:"total"`
	Acked     int `json:"acknowledged"`
	Resolved  int `json:"resolved"`
	StillOpen int `json:"still_open"`
	Cancelled int `json:"cancelled"`

	// Never acknowledged. The number that matters, and the reason this struct
	// exists: an alert nobody picked up is the failure this whole package is
	// designed to make visible.
	NeverAcked int `json:"never_acknowledged"`

	MedianAckSeconds float64 `json:"median_ack_seconds"`
	WorstAckSeconds  float64 `json:"worst_ack_seconds"`
	MedianFixSeconds float64 `json:"median_fix_seconds"`
}

// Response computes the response summary.
func (b *Board) Response() Response {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var out Response
	var acks, fixes []float64

	for _, id := range b.order {
		i := b.byID[id]
		out.Total++
		switch i.Status {
		case Cancelled:
			out.Cancelled++
		case Resolved:
			out.Resolved++
		default:
			out.StillOpen++
		}
		if elapsed, ok := i.AcknowledgedAfter(); ok {
			out.Acked++
			acks = append(acks, elapsed.Seconds())
		} else if i.Status != Cancelled {
			out.NeverAcked++
		}
		if elapsed, ok := i.ResolvedAfter(); ok {
			fixes = append(fixes, elapsed.Seconds())
		}
	}

	out.MedianAckSeconds = median(acks)
	out.MedianFixSeconds = median(fixes)
	for _, seconds := range acks {
		if seconds > out.WorstAckSeconds {
			out.WorstAckSeconds = seconds
		}
	}
	return out
}

// median returns the middle value, or zero for an empty set. Sorting a copy so a
// caller's slice is never reordered underneath them.
func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}
