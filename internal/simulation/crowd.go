package simulation

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/ManasMadan/gatecrash/internal/cuckoo"
	"github.com/ManasMadan/gatecrash/internal/mesh"
)

// CrowdConfig describes a crowd and the radios in it.
type CrowdConfig struct {
	// Nodes is how many phones are in the field.
	Nodes int

	// Width and Height are the field's size in metres.
	//
	// Density is what actually matters — nodes per square metre — and it is the
	// product of these and Nodes. A hall is 60x40; a festival field is 300x200. The
	// interesting regime is the pit: five hundred people in 30x20 metres, where
	// every phone hears almost every other phone and naive flooding dies.
	Width, Height float64

	// Range is the radio range in metres at which delivery is even odds.
	//
	// Not a hard cutoff. BLE indoors is quoted as 10 to 30 metres, and the reason
	// that range is so wide is that it depends on what is between the two radios —
	// which at a concert is bodies. Fading is modelled around this figure rather
	// than pretending there is a circle inside which everything arrives.
	Range float64

	// Speed is how fast people walk, in metres per second, as a range.
	//
	// Random waypoint mobility: pick a destination, walk to it, pause, repeat. It
	// is the standard model and it is wrong in a specific way worth naming — real
	// crowds move in correlated groups towards stages and bars rather than
	// independently towards random points — so the numbers here are a lower bound on
	// clustering and therefore an optimistic estimate of how easily a message
	// crosses the field.
	MinSpeed, MaxSpeed float64

	// PauseMax is the longest a simulated person stands still.
	PauseMax time.Duration

	// K is the mesh relay constant under test. This is the parameter the whole
	// simulator exists to sweep.
	K float64

	// Messages is how many messages are originated during the run, spread over the
	// duration and across random senders.
	Messages int

	// Duration is how long the simulated event runs.
	Duration time.Duration

	// Step is the simulation tick.
	//
	// 100ms. Short enough that a walking person moves under 20cm per tick, so
	// mobility is smooth; long enough that a five-thousand-node run over ten minutes
	// is six thousand ticks rather than six million.
	Step time.Duration

	// Boxes are venue boxes acting as super-nodes: fixed positions, always relaying
	// at priority, and bridged to each other over the LAN.
	//
	// This is the mesh's answer to its worst real failure — two clusters of people
	// thirty metres apart who never hear each other — and the simulator exists partly
	// to measure how much it buys.
	Boxes []Position

	// CollisionWindow is how close in time two transmissions have to be to collide
	// at a shared receiver.
	//
	// A BLE advertisement is a fraction of a millisecond on air, but the receiver is
	// scanning on a duty cycle and hops channels, so the window in which two
	// transmissions from different neighbours actually spoil each other is far wider
	// than the airtime. A millisecond is a deliberately pessimistic stand-in for a
	// PHY model this simulator does not pretend to have.
	CollisionWindow time.Duration

	// CarryFor is how long a node holds a message to offer to peers it meets later,
	// and how long a peer has to be unheard before it counts as newly met.
	CarryFor time.Duration

	// CarryOffer is how many carried messages to offer one newly met peer.
	//
	// Bounded, because meeting somebody in a busy field would otherwise mean
	// transmitting the whole buffer at them — which is a burst of airtime at exactly
	// the moment two clusters are merging and the band is already busy.
	CarryOffer int

	// Seed makes the run reproducible.
	Seed uint64
}

// Position is a point in the field, in metres.
type Position struct {
	X, Y float64
}

func (p Position) distance(other Position) float64 {
	dx, dy := p.X-other.X, p.Y-other.Y
	return math.Sqrt(dx*dx + dy*dy)
}

func (c *CrowdConfig) withDefaults() {
	if c.Nodes <= 0 {
		c.Nodes = 500
	}
	if c.Width <= 0 {
		c.Width = 120
	}
	if c.Height <= 0 {
		c.Height = 80
	}
	if c.Range <= 0 {
		c.Range = 20
	}
	if c.MinSpeed <= 0 {
		c.MinSpeed = 0.3
	}
	if c.MaxSpeed <= 0 {
		c.MaxSpeed = 1.4
	}
	if c.PauseMax <= 0 {
		c.PauseMax = 30 * time.Second
	}
	if c.K <= 0 {
		c.K = 3
	}
	if c.Messages <= 0 {
		c.Messages = 20
	}
	if c.Duration <= 0 {
		c.Duration = 5 * time.Minute
	}
	if c.Step <= 0 {
		c.Step = 100 * time.Millisecond
	}
	if c.CollisionWindow <= 0 {
		c.CollisionWindow = time.Millisecond
	}
	if c.CarryFor <= 0 {
		c.CarryFor = 2 * time.Minute
	}
	if c.CarryOffer <= 0 {
		c.CarryOffer = 4
	}
}

// CrowdResult is what one crowd run measured.
type CrowdResult struct {
	Config CrowdConfig `json:"config"`

	// Delivered is the fraction of (message, node) pairs where the node received the
	// message at all. The headline number: the spec's target is 95% at 500 nodes in
	// one hall.
	Delivered float64 `json:"delivered"`

	// DeliveredWithin is the fraction delivered inside the deadline, which is the
	// number that matters for "lost child at the mixer desk".
	DeliveredWithin float64 `json:"delivered_within"`

	// Deadline is the window DeliveredWithin measures against.
	Deadline time.Duration `json:"deadline"`

	// MedianLatency and P95Latency are how long delivery took, over the pairs that
	// were delivered at all.
	MedianLatency time.Duration `json:"median_latency"`
	P95Latency    time.Duration `json:"p95_latency"`

	// Transmissions is the total number of radio transmissions. This is the airtime
	// cost, and it is the number that has to stay bounded as density rises — the
	// whole point of the density-adaptive rule.
	Transmissions int `json:"transmissions"`

	// TransmissionsPerMessage is airtime normalised, so runs with different message
	// counts can be compared.
	TransmissionsPerMessage float64 `json:"transmissions_per_message"`

	// Collisions is how many receptions were spoiled by a simultaneous transmission
	// from another neighbour.
	Collisions int `json:"collisions"`

	// Duplicates is how many times a node heard a message it had already seen. Pure
	// waste, and the number the dedup filter's existence is justified by.
	Duplicates int `json:"duplicates"`

	// AverageNeighbors is the mean density estimate at the moments relay decisions
	// were actually taken.
	//
	// Sampled at the decision rather than at the end of the run, which is the only
	// version that means anything. Messages are originated in the first half of the
	// run and propagate in under a second, so the end of a run is minutes of silence
	// during which every node has correctly forgotten every neighbour — measuring
	// there reported zero neighbours and a relay probability of 1 for every
	// configuration, which made the density rule look like it never engaged.
	AverageNeighbors float64 `json:"average_neighbors"`

	// RelayProbability is the mean relay probability at those same moments. This is
	// the number the density rule is judged by.
	RelayProbability float64 `json:"relay_probability"`

	// Hops is the mean number of hops a delivered message took.
	Hops float64 `json:"hops"`
}

// String renders a result as one line, for the sweep table.
func (r CrowdResult) String() string {
	return fmt.Sprintf(
		"nodes=%-5d k=%-4.1f delivered=%5.1f%% within-%s=%5.1f%% median=%-7s p95=%-7s tx/msg=%-8.0f collisions=%-7d neighbours=%.0f p=%.3f",
		r.Config.Nodes, r.Config.K, r.Delivered*100, r.Deadline, r.DeliveredWithin*100,
		r.MedianLatency.Round(time.Millisecond), r.P95Latency.Round(time.Millisecond),
		r.TransmissionsPerMessage, r.Collisions, r.AverageNeighbors, r.RelayProbability)
}

// node is one simulated phone.
type node struct {
	id     int
	at     Position
	target Position
	speed  float64
	pause  time.Duration

	router *mesh.Router
	rand   *Rand

	// isBox marks a venue box: fixed in place, relays at priority, and bridged to
	// the other boxes over the LAN.
	isBox bool

	// received records when this node first saw each message, for the latency
	// numbers, and how many hops it had taken to get there.
	received map[cuckoo.MessageID]time.Duration
	hops     map[cuckoo.MessageID]int

	// pending are relays this node has decided to make but has not yet transmitted,
	// because of the jitter delay.
	pending []scheduled

	// met records when this node last heard from each peer, so a peer that has just
	// walked into range can be recognised as new.
	met map[int]time.Duration

	// clock is this node's current simulated offset.
	//
	// On the node rather than shared, because each router asks for the time through
	// its own injected closure. A shared variable would work today and would break
	// silently the moment the simulation ran nodes concurrently.
	clock time.Duration
}

type scheduled struct {
	frame mesh.Frame
	at    time.Duration
}

// transmission is one frame going out at one instant.
type transmission struct {
	from  int
	frame mesh.Frame
	at    time.Duration
}

// RunCrowd simulates a crowd and returns what it measured.
//
// A discrete-time simulation rather than a discrete-event one. Events would be more
// efficient, and a tick is far easier to reason about when the thing being modelled
// is "everybody moves a little and some radios talk" — and at these sizes the tick
// loop is fast enough that the difference does not matter.
func RunCrowd(cfg CrowdConfig) CrowdResult {
	cfg.withDefaults()

	root := NewRand(cfg.Seed)
	nodes := make([]*node, 0, cfg.Nodes+len(cfg.Boxes))

	for i := 0; i < cfg.Nodes; i++ {
		stream := root.Derive(uint64(i))
		nodes = append(nodes, newNode(i, cfg, stream, false, Position{
			X: stream.Between(0, cfg.Width),
			Y: stream.Between(0, cfg.Height),
		}))
	}
	for i, at := range cfg.Boxes {
		stream := root.Derive(uint64(1_000_000 + i))
		nodes = append(nodes, newNode(cfg.Nodes+i, cfg, stream, true, at))
	}

	// When each message is originated, and by whom. Decided up front so that the
	// schedule does not depend on how the run unfolds — otherwise two runs of the
	// same seed with different K would send different messages and the comparison
	// would be meaningless.
	schedule := make([]struct {
		at   time.Duration
		from int
		id   cuckoo.MessageID
	}, cfg.Messages)
	for i := range schedule {
		stream := root.Derive(uint64(2_000_000 + i))
		schedule[i].at = time.Duration(stream.Float64() * float64(cfg.Duration) * 0.5)
		schedule[i].from = stream.Intn(len(nodes))
		binary.BigEndian.PutUint64(schedule[i].id[:], uint64(i)+1)
	}
	sort.SliceStable(schedule, func(i, j int) bool { return schedule[i].at < schedule[j].at })

	result := CrowdResult{Config: cfg, Deadline: 10 * time.Second}
	radio := root.Derive(9_999_999)
	var samples densitySamples

	next := 0
	for now := time.Duration(0); now < cfg.Duration; now += cfg.Step {
		var airborne []transmission

		// Originate whatever is due.
		for next < len(schedule) && schedule[next].at <= now {
			entry := schedule[next]
			next++

			sender := nodes[entry.from]
			frame := sender.router.Originate(mesh.Frame{
				Kind: mesh.KindChannel,
				ID:   entry.id,
				Body: []byte("simulated"),
			})
			sender.received[entry.id] = now
			airborne = append(airborne, transmission{from: sender.id, frame: frame, at: entry.at})

			// A box originating a frame marks it, and boxes relay at priority.
			if sender.isBox {
				frame.Flags |= mesh.FlagBoxOrigin | mesh.FlagPriority
			}
		}

		// Anything whose jitter has elapsed goes out now.
		for _, n := range nodes {
			keep := n.pending[:0]
			for _, entry := range n.pending {
				if entry.at <= now {
					// Sent at the instant it was scheduled for, not at the tick
					// boundary. The jitter that spreads relays apart is measured in
					// tens of milliseconds and the tick is 100ms, so rounding every
					// transmission to the tick throws the jitter away — and with it
					// the entire point of having jitter.
					airborne = append(airborne, transmission{from: n.id, frame: entry.frame, at: entry.at})
					continue
				}
				keep = append(keep, entry)
			}
			n.pending = keep
		}

		// Move everybody. Done after transmissions are collected and before they are
		// delivered, so that within one tick a frame travels the distance that was
		// there when it was sent.
		for _, n := range nodes {
			n.move(cfg, now)
		}

		result.Transmissions += len(airborne)
		deliver(cfg, nodes, airborne, radio, now, &result, &samples)

		// The LAN bridge between boxes: a frame a box heard is re-transmitted by
		// every other box, instantly and without airtime, which is what a wired
		// backhaul buys.
		bridge(cfg, nodes, airborne, now)
	}

	summarise(cfg, nodes, schedule, &result)
	if samples.count > 0 {
		result.AverageNeighbors = samples.neighbors / float64(samples.count)
		result.RelayProbability = samples.probability / float64(samples.count)
	}
	return result
}

func newNode(id int, cfg CrowdConfig, stream *Rand, isBox bool, at Position) *node {
	n := &node{
		id:       id,
		at:       at,
		isBox:    isBox,
		rand:     stream,
		received: map[cuckoo.MessageID]time.Duration{},
		hops:     map[cuckoo.MessageID]int{},
		met:      map[int]time.Duration{},
	}
	n.target = Position{X: stream.Between(0, cfg.Width), Y: stream.Between(0, cfg.Height)}
	n.speed = stream.Between(cfg.MinSpeed, cfg.MaxSpeed)

	n.router = mesh.New(mesh.Config{
		K:              cfg.K,
		CarryFor:       cfg.CarryFor,
		Now:            func() time.Time { return simEpoch.Add(n.clock) },
		Random:         stream.Float64,
		NeighborWindow: 30 * time.Second,
		MaxJitter:      250 * time.Millisecond,
	})
	return n
}

// simEpoch is an arbitrary fixed instant. The routers want a time.Time and the
// simulation works in offsets, so this is the origin they are measured from. Fixed
// rather than time.Now, because a simulator that reads the wall clock is a
// simulator whose runs do not reproduce.
var simEpoch = time.Date(2026, 8, 21, 21, 0, 0, 0, time.UTC)

// move advances a node one tick along its random-waypoint path.
func (n *node) move(cfg CrowdConfig, now time.Duration) {
	n.clock = now

	if n.isBox {
		return
	}
	if n.pause > 0 {
		n.pause -= cfg.Step
		return
	}

	step := n.speed * cfg.Step.Seconds()
	distance := n.at.distance(n.target)
	if distance <= step {
		// Arrived. Stand still for a while, then pick a new destination — the pause
		// is what makes the model produce clusters rather than a uniform smear.
		n.at = n.target
		n.pause = time.Duration(n.rand.Float64() * float64(cfg.PauseMax))
		n.target = Position{
			X: n.rand.Between(0, cfg.Width),
			Y: n.rand.Between(0, cfg.Height),
		}
		n.speed = n.rand.Between(cfg.MinSpeed, cfg.MaxSpeed)
		return
	}

	n.at.X += (n.target.X - n.at.X) / distance * step
	n.at.Y += (n.target.Y - n.at.Y) / distance * step
}

// deliver works out who heard what, and hands it to their routers.
// densitySamples accumulates the density readings taken at relay decisions.
type densitySamples struct {
	neighbors   float64
	probability float64
	count       int
}

func deliver(cfg CrowdConfig, nodes []*node, airborne []transmission, radio *Rand, now time.Duration, result *CrowdResult, samples *densitySamples) {
	if len(airborne) == 0 {
		return
	}

	// A uniform grid over the field, so a receiver only considers transmitters that
	// could possibly reach it.
	//
	// Without this the tick is O(nodes x transmissions), which at five thousand
	// phones is a few million distance checks per tick and several billion per run —
	// the difference between a sweep that finishes while you watch and one that does
	// not finish at all. The cell is the maximum reach, so everything audible is in
	// the receiver's own cell or one of the eight around it.
	cell := cfg.Range * 2.5
	grid := map[[2]int][]transmission{}
	for _, tx := range airborne {
		at := nodes[indexOf(nodes, tx.from)].at
		grid[cellOf(at, cell)] = append(grid[cellOf(at, cell)], tx)
	}

	var heard []transmission
	for _, receiver := range nodes {
		// Who is in earshot of this receiver, out of everything transmitted this
		// tick.
		heard = heard[:0]
		home := cellOf(receiver.at, cell)
		for dx := -1; dx <= 1; dx++ {
			for dy := -1; dy <= 1; dy++ {
				for _, tx := range grid[[2]int{home[0] + dx, home[1] + dy}] {
					if tx.from == receiver.id {
						continue
					}
					if !reaches(cfg, nodes[indexOf(nodes, tx.from)].at, receiver.at, radio) {
						continue
					}
					heard = append(heard, tx)
				}
			}
		}
		if len(heard) == 0 {
			continue
		}

		// Every transmission in earshot counts towards the receiver's density
		// estimate, including the ones it could not decode.
		//
		// A collision is the strongest possible evidence that the band is busy, so
		// throwing it away is exactly backwards. The first version of this only
		// observed decoded frames, which in a dense crowd meant almost nothing was
		// observed, the estimate stayed at zero, the relay probability stayed at one,
		// and the density-adaptive rule — the entire subject of this simulation —
		// never engaged. The measured effect was a feedback loop: more relays, more
		// collisions, fewer observations, more relays.
		for _, tx := range heard {
			receiver.router.Observe(mesh.PeerID(strconv.Itoa(tx.from)))
		}

		// Collisions. Two transmissions arriving within the collision window at the
		// same receiver spoil each other and neither is decoded. This is the part a
		// naive flooding model leaves out, and it is why airtime matters: halving the
		// number of transmitters can raise delivery rather than lower it.
		//
		// Compared pairwise on the actual transmission instants, not per tick. A tick
		// is 100ms and the window is a millisecond, so treating a tick as one instant
		// models a collision domain a hundred times wider than the radio's.
		// A fresh slice rather than heard[:0]: the receiver's `heard` buffer is
		// reused across receivers, and writing into it while iterating it would
		// overwrite entries not yet examined.
		decodable := make([]transmission, 0, len(heard))
		for i, tx := range heard {
			collided := false
			for j, other := range heard {
				if i == j {
					continue
				}
				if abs(tx.at-other.at) < cfg.CollisionWindow {
					collided = true
					break
				}
			}
			if collided {
				result.Collisions++
				continue
			}
			decodable = append(decodable, tx)
		}

		for _, tx := range decodable {
			// Sampled before the decision, because this is the density the router is
			// about to base it on.
			samples.neighbors += float64(receiver.router.Neighbors())
			samples.probability += receiver.router.RelayProbability()
			samples.count++

			// A peer this node has not heard for a while has just walked into range,
			// which is the moment the store-and-forward buffer is for: it may be
			// carrying messages this peer's whole cluster has never heard. Without
			// this the carry buffer is dead weight in the simulation and the sparse,
			// disconnected field — where it matters most — looks worse than it is.
			if newPeer(receiver, tx.from, now, cfg) && receiver.router.ShouldOfferCarry() {
				for i, carried := range receiver.router.Carried() {
					if i >= cfg.CarryOffer {
						break
					}
					hopped, alive := carried.Hop()
					if !alive {
						continue
					}
					receiver.pending = append(receiver.pending, scheduled{
						frame: hopped,
						// Spread out, so meeting somebody does not produce a burst
						// that collides with itself.
						at: now + time.Duration(float64(i+1)*float64(cfg.Step)) +
							time.Duration(receiver.rand.Float64()*float64(cfg.Step)),
					})
				}
			}
			receiver.met[tx.from] = now

			decision := receiver.router.Handle(tx.frame, mesh.PeerID(strconv.Itoa(tx.from)))
			if decision.Deliver {
				if _, already := receiver.received[tx.frame.ID]; !already {
					receiver.received[tx.frame.ID] = now
					// The TTL counts down from the limit, so what is left of it says
					// how far the frame has come.
					receiver.hops[tx.frame.ID] = int(mesh.MaxTTL - tx.frame.TTL)
				}
			} else {
				result.Duplicates++
			}
			if decision.Relay {
				receiver.pending = append(receiver.pending, scheduled{
					frame: decision.Hopped,
					at:    now + decision.After,
				})
			}
		}
	}
}

// bridge re-transmits from every box a frame that any box heard.
func bridge(cfg CrowdConfig, nodes []*node, airborne []transmission, now time.Duration) {
	if len(cfg.Boxes) < 2 {
		return
	}

	for _, tx := range airborne {
		for _, n := range nodes {
			if !n.isBox || n.id == tx.from {
				continue
			}
			// The box re-broadcasts on its own radio at priority, which is what makes
			// a box worth having: it ignores the density rule and it is not subject to
			// somebody walking away.
			hopped, alive := tx.frame.Hop()
			if !alive {
				continue
			}
			hopped.Flags |= mesh.FlagPriority | mesh.FlagBoxOrigin
			n.pending = append(n.pending, scheduled{frame: hopped, at: now + cfg.Step})
		}
	}
}

// reaches models whether a transmission is decoded at a distance.
//
// A logistic curve around the nominal range plus a normal fading term, rather than
// a hard cutoff. Real signal strength at a fixed distance swings by several
// decibels as bodies move through the path, and a hard cutoff produces a delivery
// curve far tidier than any field test would show — which would make this
// simulator's numbers look more trustworthy than they are.
func reaches(cfg CrowdConfig, from, to Position, radio *Rand) bool {
	distance := from.distance(to)
	if distance > cfg.Range*2.5 {
		// Far outside range. Short-circuited rather than evaluated, because this is
		// the overwhelming majority of pairs in a large field and it is the whole cost
		// of the tick loop.
		return false
	}

	// Fading, in effective metres.
	effective := distance + radio.Normal()*cfg.Range*0.15
	if effective <= 0 {
		return true
	}
	// Even odds at the nominal range, falling off steeply either side.
	p := 1 / (1 + math.Exp((effective-cfg.Range)/(cfg.Range*0.12)))
	return radio.Chance(p)
}

// indexOf maps a node id to its slot. Ids are assigned densely from zero, so this
// is the identity — but it is written down rather than assumed, because the boxes
// are appended after the phones and an off-by-one there would silently attribute
// transmissions to the wrong position in the field.
// newPeer reports whether this is a peer the node has not heard for a while, which
// is the moment its carry buffer is worth offering.
func newPeer(n *node, from int, now time.Duration, cfg CrowdConfig) bool {
	last, known := n.met[from]
	return !known || now-last > cfg.CarryFor
}

func cellOf(at Position, size float64) [2]int {
	return [2]int{int(math.Floor(at.X / size)), int(math.Floor(at.Y / size))}
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func indexOf(nodes []*node, id int) int {
	if id >= 0 && id < len(nodes) && nodes[id].id == id {
		return id
	}
	for i, n := range nodes {
		if n.id == id {
			return i
		}
	}
	return 0
}

func summarise(cfg CrowdConfig, nodes []*node, schedule []struct {
	at   time.Duration
	from int
	id   cuckoo.MessageID
}, result *CrowdResult) {
	var latencies []time.Duration
	pairs, delivered, within, totalHops := 0, 0, 0, 0

	for _, entry := range schedule {
		for _, n := range nodes {
			if n.id == entry.from {
				continue
			}
			pairs++
			at, ok := n.received[entry.id]
			if !ok {
				continue
			}
			delivered++
			latency := at - entry.at
			latencies = append(latencies, latency)
			totalHops += n.hops[entry.id]
			if latency <= result.Deadline {
				within++
			}
		}
	}

	if pairs > 0 {
		result.Delivered = float64(delivered) / float64(pairs)
		result.DeliveredWithin = float64(within) / float64(pairs)
	}
	if delivered > 0 {
		result.Hops = float64(totalHops) / float64(delivered)
	}
	if cfg.Messages > 0 {
		result.TransmissionsPerMessage = float64(result.Transmissions) / float64(cfg.Messages)
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if len(latencies) > 0 {
		result.MedianLatency = latencies[len(latencies)/2]
		result.P95Latency = latencies[int(float64(len(latencies))*0.95)]
	}

}

// Sweep runs the crowd simulator across a set of relay constants and node counts.
//
// This is the artefact: a table of delivery ratio and airtime against density and
// K, which is what a claim like "95% delivery at festival density" has to be backed
// by. Published in the docs as a graph.
func Sweep(base CrowdConfig, nodeCounts []int, ks []float64) []CrowdResult {
	out := make([]CrowdResult, 0, len(nodeCounts)*len(ks))
	for _, nodes := range nodeCounts {
		for _, k := range ks {
			cfg := base
			cfg.Nodes = nodes
			cfg.K = k
			out = append(out, RunCrowd(cfg))
		}
	}
	return out
}
