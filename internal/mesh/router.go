package mesh

import (
	"math"
	"sort"
	"time"

	"github.com/ManasMadan/gatecrash/internal/cuckoo"
)

// Router decides what to do with every frame the radio hears.
//
// It holds no keys and decrypts nothing. That separation is deliberate: this is the
// part that has to be right under load, it is the part the crowd simulator drives
// five thousand copies of, and mixing decryption in would make it impossible to
// test the flooding behaviour without also standing up a key for every simulated
// phone.
//
// Not safe for concurrent use. One radio, one goroutine, one router.
type Router struct {
	cfg Config

	seen      *cuckoo.Rotating
	neighbors *density
	carry     *carrier

	stats Stats
}

// Config configures a router.
type Config struct {
	// K is the relay constant: the target number of nodes in any neighbourhood that
	// rebroadcast a given message.
	//
	// This is the one number that decides whether the mesh works. The relay
	// probability is min(1, K/neighbours), so in a sparse crowd everybody relays and
	// in a packed pit roughly K phones per neighbourhood do. Too low and messages
	// die in the middle of a field; too high and the band saturates.
	//
	// Three is the default, from the crowd simulator: it holds above 95% delivery
	// from fifty to five thousand nodes while keeping airtime roughly flat as
	// density rises. Two drops off badly past a thousand nodes; five costs about
	// 60% more airtime for under a point of delivery.
	K float64

	// TTL is the hop limit put on frames this node originates.
	TTL uint8

	// DedupCapacity is how many message ids to remember per generation.
	DedupCapacity int

	// DedupWindow is how long a message id is remembered. Ten minutes: long enough
	// that a message circulating a large venue cannot come back around, short enough
	// that the filter does not fill.
	DedupWindow time.Duration

	// NeighborWindow is how far back distinct senders are counted to estimate
	// density.
	//
	// Thirty seconds. Shorter and the estimate swings wildly as people walk past,
	// which makes the relay probability jump around; longer and it lags a crowd
	// arriving through a gate, which is exactly when the estimate needs to be right.
	NeighborWindow time.Duration

	// CarryFor is how long a relayed message is kept to re-offer to newly seen
	// peers, which is what carries a message between two clusters of people who
	// never hear each other directly.
	CarryFor time.Duration

	// CarryLimit bounds the store-and-forward buffer, in frames.
	CarryLimit int

	// MaxJitter is the largest delay before a rebroadcast.
	//
	// Without jitter, every phone that decides to relay transmits at the same
	// instant, and on a shared medium simultaneous transmissions are collisions
	// rather than deliveries. Spreading them over a window is most of what makes
	// flooding work in a crowd at all.
	MaxJitter time.Duration

	// Now is the clock, injected so the simulator can run a festival in a second.
	Now func() time.Time

	// Random returns a value in [0,1). Injected so a simulator run is replayable
	// from its seed — a relay decision that depends on the global random source
	// cannot be reproduced from a failure report.
	Random func() float64
}

func (c *Config) withDefaults() {
	if c.K <= 0 {
		c.K = 3
	}
	if c.TTL == 0 || c.TTL > MaxTTL {
		c.TTL = MaxTTL
	}
	if c.DedupCapacity <= 0 {
		c.DedupCapacity = 8192
	}
	if c.DedupWindow <= 0 {
		c.DedupWindow = 10 * time.Minute
	}
	if c.NeighborWindow <= 0 {
		c.NeighborWindow = 30 * time.Second
	}
	if c.CarryFor <= 0 {
		c.CarryFor = 2 * time.Minute
	}
	if c.CarryLimit <= 0 {
		c.CarryLimit = 64
	}
	if c.MaxJitter <= 0 {
		c.MaxJitter = 250 * time.Millisecond
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	// Random is deliberately not defaulted here. New fills it in, so that the choice
	// of a global random source — which is what makes a run unreplayable — is made in
	// one visible place rather than hidden among the other defaults.
}

// New builds a router.
func New(cfg Config) *Router {
	cfg.withDefaults()
	if cfg.Random == nil {
		cfg.Random = defaultRandom
	}

	return &Router{
		cfg: cfg,
		seen: cuckoo.NewRotating(cuckoo.RotatingConfig{
			Capacity: cfg.DedupCapacity,
			Window:   cfg.DedupWindow,
			Now:      cfg.Now,
		}),
		neighbors: &density{window: cfg.NeighborWindow, seen: map[PeerID]time.Time{}},
		carry:     &carrier{limit: cfg.CarryLimit, hold: cfg.CarryFor},
	}
}

// PeerID is however the platform identifies the device a frame came from.
//
// A string rather than a MAC address, because neither platform will give you one:
// Android reports a rotating address and iOS reports an opaque per-app identifier.
// Both rotate, which is good for the people carrying the phones and fine here — the
// router only counts distinct values inside a thirty-second window, and an
// identifier that rotates every fifteen minutes is stable enough for that.
type PeerID string

// Decision is what the router concluded about a frame.
type Decision struct {
	// Deliver is true when this node should try to decrypt and show the frame.
	Deliver bool

	// Relay is true when this node should rebroadcast it.
	Relay bool

	// Hopped is the frame to rebroadcast, with its TTL already decremented. Only
	// meaningful when Relay is true.
	Hopped Frame

	// After is how long to wait before rebroadcasting. Always non-zero when
	// relaying: see Config.MaxJitter.
	After time.Duration

	// Why records the reason, for the simulator's output and for the app's debug
	// screen. Not for control flow.
	Why string
}

// Stats counts what a router has done, for the simulator and the debug screen.
type Stats struct {
	Heard      int
	Duplicate  int
	Delivered  int
	Relayed    int
	Suppressed int
	Expired    int
	Malformed  int
}

// Stats returns a copy of the counters.
func (r *Router) Stats() Stats { return r.stats }

// Observe records that a frame was heard from a peer, for the density estimate.
//
// Called for every frame including duplicates, and that is the point: duplicates
// are the best available signal of how many phones are within radio range, which is
// exactly what the relay probability needs.
func (r *Router) Observe(peer PeerID) {
	r.neighbors.observe(peer, r.cfg.Now())
}

// Neighbors is the current density estimate.
func (r *Router) Neighbors() int { return r.neighbors.count(r.cfg.Now()) }

// RelayProbability is the chance this node rebroadcasts an ordinary frame right
// now.
//
// Exposed because it is the number the crowd simulator sweeps and the number the
// app's debug screen shows. In a field of five people it is 1; in a pit of five
// hundred it is around 0.006, and the message still crosses the pit because there
// are five hundred phones each rolling that die.
func (r *Router) RelayProbability() float64 {
	neighbors := r.neighbors.count(r.cfg.Now())
	if neighbors <= 0 {
		// Nothing heard yet. Relay unconditionally: a node that hears nobody is
		// either alone or at the edge of the crowd, and the edge is exactly where a
		// message needs carrying.
		return 1
	}
	return math.Min(1, r.cfg.K/float64(neighbors))
}

// Handle decides what to do with a frame that just arrived.
//
// The order matters and is the whole algorithm:
//
//  1. Count the sender towards density, whatever else happens.
//  2. Drop anything already seen — this is what stops a message circulating.
//  3. Deliver it locally.
//  4. Decide whether to relay, and if so with what delay.
func (r *Router) Handle(frame Frame, from PeerID) Decision {
	r.stats.Heard++
	r.Observe(from)

	if frame.Version != Version {
		r.stats.Malformed++
		return Decision{Why: "unknown protocol version"}
	}

	// Dedup before anything expensive. In a crowd a phone hears the same message
	// from a dozen neighbours, and every one of those is a decryption it should not
	// pay for.
	if r.seen.SeenID(frame.ID) {
		r.stats.Duplicate++
		return Decision{Why: "already seen"}
	}

	decision := Decision{Deliver: true, Why: "new message"}
	r.stats.Delivered++

	if !frame.Kind.Relayable() {
		decision.Why = "delivered, " + frame.Kind.String() + " frames are never relayed"
		return decision
	}

	hopped, alive := frame.Hop()
	if !alive {
		r.stats.Expired++
		decision.Why = "delivered, hop limit reached"
		return decision
	}

	// Organizer announcements ignore the density rule. "Lost child at the mixer
	// desk" has to cross a saturated field, and that is worth the airtime — which is
	// also why the priority flag is not available to attendee traffic.
	if frame.Priority() {
		decision.Relay = true
		decision.Hopped = hopped
		decision.After = r.jitter()
		decision.Why = "delivered and relayed at priority"
		r.stats.Relayed++
		r.carry.add(hopped, r.cfg.Now())
		return decision
	}

	if r.cfg.Random() < r.RelayProbability() {
		decision.Relay = true
		decision.Hopped = hopped
		decision.After = r.jitter()
		decision.Why = "delivered and relayed"
		r.stats.Relayed++
		r.carry.add(hopped, r.cfg.Now())
		return decision
	}

	// Not relaying, but still worth carrying: if this node walks into a cluster
	// that has not heard the message, it can offer it there. This is how a message
	// crosses a thirty-metre gap between two groups of people that never hear each
	// other, which is BLE mesh's worst real-world failure.
	r.stats.Suppressed++
	r.carry.add(hopped, r.cfg.Now())
	decision.Why = "delivered, relay suppressed by density"
	return decision
}

// Originate prepares a frame this node is sending for the first time.
//
// The id is recorded as seen straight away, so a copy that comes back from a
// neighbour is recognised as a duplicate rather than delivered to the sender as a
// new message.
func (r *Router) Originate(frame Frame) Frame {
	frame.Version = Version
	if frame.TTL == 0 || frame.TTL > r.cfg.TTL {
		frame.TTL = r.cfg.TTL
	}
	r.seen.SeenID(frame.ID)
	r.carry.add(frame, r.cfg.Now())
	return frame
}

// Carried returns the frames worth offering to a peer that has just come into
// range, freshest first.
//
// Freshest first because a phone that has just walked up may only be in range for
// a few seconds, and a two-minute-old message matters less than a ten-second-old
// one.
func (r *Router) Carried() []Frame {
	return r.carry.list(r.cfg.Now())
}

// Wipe forgets everything: seen ids, carried frames, and the density estimate.
//
// The panic wipe. Somebody triple-tapping in a crowd wants no trace of what their
// phone heard, and a store-and-forward buffer holding other people's ciphertext is
// a trace even though it cannot be read.
func (r *Router) Wipe() {
	r.seen.Wipe()
	r.carry.reset()
	r.neighbors.reset()
}

// jitter is the delay before a rebroadcast.
//
// Uniform over the window. Without it, every node that decided to relay transmits
// at once and they collide instead of delivering; that is most of what makes
// flooding work on a shared medium.
func (r *Router) jitter() time.Duration {
	return time.Duration(r.cfg.Random() * float64(r.cfg.MaxJitter))
}

// density estimates how many phones are within radio range.
//
// Distinct peers heard in a sliding window, which is the only estimate available
// without asking anybody anything. It undercounts a silent crowd — a hundred phones
// listening and not transmitting look like an empty field — and that failure is in
// the safe direction: undercounting raises the relay probability, so a quiet crowd
// relays more, and the moment anybody transmits the estimate corrects.
type density struct {
	window time.Duration
	seen   map[PeerID]time.Time
}

func (d *density) observe(peer PeerID, at time.Time) {
	if peer == "" {
		// A frame with no attributable sender — a simulator injection, or a platform
		// that did not report one. Counting it would inflate the estimate with a
		// single phantom neighbour.
		return
	}
	d.seen[peer] = at
	d.sweep(at)
}

func (d *density) count(at time.Time) int {
	d.sweep(at)
	return len(d.seen)
}

// sweep drops peers not heard inside the window.
//
// Done on every observation rather than on a timer. The map is bounded by how many
// phones are in radio range, which is hundreds at worst, so this is cheaper than
// owning a ticker — and a ticker on a phone is a wakeup, which is battery.
func (d *density) sweep(at time.Time) {
	cutoff := at.Add(-d.window)
	for peer, last := range d.seen {
		if last.Before(cutoff) {
			delete(d.seen, peer)
		}
	}
}

func (d *density) reset() { d.seen = map[PeerID]time.Time{} }

// carrier is the store-and-forward buffer.
type carrier struct {
	limit int
	hold  time.Duration

	frames []carried
	next   uint64
}

type carried struct {
	frame Frame
	at    time.Time

	// seq breaks ties. A phone coming out of a radio callback adds several frames
	// within the same clock reading, and without a tiebreaker "freshest first"
	// silently degrades to insertion order — which is oldest first, the opposite of
	// what a peer that may only be in range for two seconds needs.
	seq uint64
}

func (c *carrier) add(frame Frame, at time.Time) {
	c.expire(at)

	// Replace an existing copy of the same message rather than holding two. Two
	// copies of one message in a buffer of sixty-four is a wasted slot, and the only
	// thing that differs between them is a TTL that the receiver re-checks anyway.
	c.next++
	for i := range c.frames {
		if c.frames[i].frame.ID == frame.ID {
			c.frames[i] = carried{frame: frame, at: at, seq: c.next}
			return
		}
	}

	c.frames = append(c.frames, carried{frame: frame, at: at, seq: c.next})
	if len(c.frames) > c.limit {
		// Drop the oldest. A full buffer means this phone is in a busy crowd, where
		// the old messages have almost certainly propagated already and the new ones
		// have not.
		c.frames = c.frames[len(c.frames)-c.limit:]
	}
}

func (c *carrier) list(at time.Time) []Frame {
	c.expire(at)

	out := make([]Frame, 0, len(c.frames))
	ordered := make([]carried, len(c.frames))
	copy(ordered, c.frames)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].at.Equal(ordered[j].at) {
			return ordered[i].seq > ordered[j].seq
		}
		return ordered[i].at.After(ordered[j].at)
	})
	for _, entry := range ordered {
		out = append(out, entry.frame)
	}
	return out
}

func (c *carrier) expire(at time.Time) {
	cutoff := at.Add(-c.hold)
	keep := c.frames[:0]
	for _, entry := range c.frames {
		if entry.at.After(cutoff) {
			keep = append(keep, entry)
		}
	}
	c.frames = keep
}

func (c *carrier) reset() { c.frames = nil }

// ID is a small accessor used by the simulator's logs.
func (d Decision) ID() uint64 { return idOf(d.Hopped.ID) }
