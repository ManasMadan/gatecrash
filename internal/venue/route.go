package venue

import (
	"container/heap"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

// WalkSpeedMetresPerSecond is the speed used to turn a distance into a walking
// time.
//
// An unobstructed adult walks at about 1.35 m/s. Inside a venue at doors-close,
// in a crowd, on a concourse with people stopping to look at their phones, the
// observed figure is nearer 0.9. Using the optimistic number would produce an
// estimate that is wrong in the direction that makes people miss the opening
// act, so this sits at the pessimistic end and the docs say why.
const WalkSpeedMetresPerSecond = 0.95

// RouteOptions constrains a route.
type RouteOptions struct {
	// StepFree refuses stair edges. A route requested step-free either comes
	// back step-free or comes back as an error; silently including a staircase
	// for someone who told us they cannot use one is the worst possible
	// failure mode in this package.
	StepFree bool

	// AllowedZones restricts which zones the route may pass through. Nil means
	// unrestricted. Callers pass the ticket holder's entitlement here, which is
	// what stops the app from cheerfully routing a general-admission holder
	// through backstage because it happens to be shorter.
	AllowedZones map[ZoneCode]bool
}

// Leg is one step of a route, phrased the way a steward would say it.
type Leg struct {
	From NodeID   `json:"from"`
	To   NodeID   `json:"to"`
	Kind EdgeKind `json:"kind"`

	// Instruction is the human sentence for this leg.
	Instruction string `json:"instruction"`

	// Distance is in map units, Metres is the same distance converted when the
	// venue declares a scale. Metres is zero for a venue with no scale, and the
	// app then shows relative progress instead of inventing numbers.
	Distance float64 `json:"distance"`
	Metres   float64 `json:"metres,omitempty"`

	// LevelChange is the number of levels this leg climbs or descends.
	LevelChange int `json:"level_change,omitempty"`

	Note string `json:"note,omitempty"`
}

// Route is a path through the venue.
type Route struct {
	Nodes []NodeID `json:"nodes"`
	Legs  []Leg    `json:"legs"`

	Distance float64 `json:"distance"`
	Metres   float64 `json:"metres,omitempty"`

	// Seconds is the estimated walking time, absent when the venue declares no
	// scale.
	Seconds int `json:"seconds,omitempty"`

	// StepFree reports whether the returned route avoids stairs. It is computed
	// from the legs rather than copied from the request, so a caller can trust
	// it even when it did not ask.
	StepFree bool `json:"step_free"`
}

// ErrNoRoute is returned when no path exists under the given constraints. It is
// a distinct error because the UI response differs: an unreachable destination
// under StepFree means "ask a steward", while an unreachable destination
// generally means the plan is wrong.
var ErrNoRoute = errors.New("venue: no route")

// Route computes the shortest path between two walk-graph nodes.
//
// Dijkstra rather than A*: venue graphs are hundreds of nodes, not millions, so
// the heuristic buys nothing measurable and a straight-line heuristic would be
// wrong anyway across levels, where the useful distance is stairs and lifts
// rather than metres.
func (v *Venue) Route(from, to NodeID, opts RouteOptions) (Route, error) {
	if _, ok := v.nodes[from]; !ok {
		return Route{}, codeError("map node", string(from), "route origin does not exist")
	}
	if _, ok := v.nodes[to]; !ok {
		return Route{}, codeError("map node", string(to), "route destination does not exist")
	}
	if from == to {
		return Route{Nodes: []NodeID{from}, StepFree: true}, nil
	}
	if !v.zoneAllowed(from, opts) {
		return Route{}, fmt.Errorf("%w: origin %q is outside the allowed zones", ErrNoRoute, from)
	}
	if !v.zoneAllowed(to, opts) {
		return Route{}, fmt.Errorf("%w: destination %q is outside the allowed zones", ErrNoRoute, to)
	}

	previous, err := v.dijkstra(from, to, opts)
	if err != nil {
		return Route{}, err
	}

	path := []NodeID{to}
	for at := to; at != from; {
		at = previous[at]
		path = append(path, at)
	}
	// Walk back to front.
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return v.describe(path), nil
}

// queued is a Dijkstra frontier entry.
type queued struct {
	node NodeID
	cost float64
}

// frontier is a min-heap on cost. Hand-rolled because container/heap wants an
// interface and this is the only priority queue in the codebase.
type frontier []queued

func (f frontier) Len() int           { return len(f) }
func (f frontier) Less(i, j int) bool { return f[i].cost < f[j].cost }
func (f frontier) Swap(i, j int)      { f[i], f[j] = f[j], f[i] }
func (f *frontier) Push(x any)        { *f = append(*f, x.(queued)) }
func (f *frontier) Pop() any          { old := *f; last := old[len(old)-1]; *f = old[:len(old)-1]; return last }

func (v *Venue) dijkstra(from, to NodeID, opts RouteOptions) (map[NodeID]NodeID, error) {
	best := map[NodeID]float64{from: 0}
	previous := make(map[NodeID]NodeID, len(v.nodes))
	settled := make(map[NodeID]bool, len(v.nodes))

	queue := &frontier{{node: from, cost: 0}}
	heap.Init(queue)

	for queue.Len() > 0 {
		current := heap.Pop(queue).(queued)
		if settled[current.node] {
			continue
		}
		settled[current.node] = true
		if current.node == to {
			return previous, nil
		}

		// Sort the arcs so that two equal-cost paths always resolve to the same
		// one. A route that changes between page loads reads as a bug even when
		// both answers are correct.
		arcs := append([]arc(nil), v.adjacency[current.node]...)
		sort.Slice(arcs, func(i, j int) bool {
			if arcs[i].cost != arcs[j].cost {
				return arcs[i].cost < arcs[j].cost
			}
			return arcs[i].to < arcs[j].to
		})

		for _, a := range arcs {
			if opts.StepFree && !a.kind.StepFree() {
				continue
			}
			if !v.zoneAllowed(a.to, opts) {
				continue
			}
			cost := current.cost + a.cost
			if existing, seen := best[a.to]; seen && existing <= cost {
				continue
			}
			best[a.to] = cost
			previous[a.to] = current.node
			heap.Push(queue, queued{node: a.to, cost: cost})
		}
	}

	if opts.StepFree {
		return nil, fmt.Errorf("%w: no step-free path from %q to %q", ErrNoRoute, from, to)
	}
	return nil, fmt.Errorf("%w: from %q to %q", ErrNoRoute, from, to)
}

// zoneAllowed reports whether a node may be entered under the options. A node
// with no zone is public circulation and always allowed.
func (v *Venue) zoneAllowed(id NodeID, opts RouteOptions) bool {
	if opts.AllowedZones == nil {
		return true
	}
	zone := v.nodes[id].Zone
	if zone == "" {
		return true
	}
	return opts.AllowedZones[zone]
}

// describe turns a node path into legs with human instructions.
func (v *Venue) describe(path []NodeID) Route {
	route := Route{Nodes: path, StepFree: true}
	scale := v.plan.Map.MetresPerUnit

	for i := 0; i+1 < len(path); i++ {
		from, to := v.nodes[path[i]], v.nodes[path[i+1]]
		a := v.arcBetween(path[i], path[i+1])

		leg := Leg{
			From:        path[i],
			To:          path[i+1],
			Kind:        a.kind,
			Distance:    a.distance,
			LevelChange: to.Level - from.Level,
			Note:        a.note,
		}
		if scale > 0 {
			leg.Metres = a.distance * scale
		}
		// A turn is only meaningful when there is a previous leg to turn
		// relative to; the first instruction gets a landmark instead.
		var incoming *Node
		if i > 0 {
			previous := v.nodes[path[i-1]]
			incoming = &previous
		}
		leg.Instruction = instruction(incoming, from, to, a, leg)

		if !a.kind.StepFree() {
			route.StepFree = false
		}
		route.Distance += a.distance
		route.Metres += leg.Metres
		route.Legs = append(route.Legs, leg)
	}

	if route.Metres > 0 {
		route.Seconds = int(math.Ceil(route.Metres / WalkSpeedMetresPerSecond))
	}
	return route
}

// arcBetween returns the resolved edge joining two adjacent path nodes.
func (v *Venue) arcBetween(from, to NodeID) arc {
	for _, a := range v.adjacency[from] {
		if a.to == to {
			return a
		}
	}
	// Unreachable for a path produced by dijkstra, but returning a zero arc is
	// better than panicking inside a request handler at a gate.
	return arc{to: to, kind: EdgeWalk, distance: dist(v.nodes[from].Position, v.nodes[to].Position)}
}

// instruction writes one leg's sentence.
//
// The wording is deliberately plain and landmark-first. Attendees read these
// while walking, in the dark, on a phone held at hip height, so a sentence that
// names a thing they can see beats a compass bearing they cannot.
func instruction(incoming *Node, from, to Node, a arc, leg Leg) string {
	destination := nodeLabel(to)

	switch a.kind {
	case EdgeStair:
		if leg.LevelChange > 0 {
			return "Take the stairs up to " + destination
		}
		if leg.LevelChange < 0 {
			return "Take the stairs down to " + destination
		}
		return "Take the steps to " + destination
	case EdgeLift:
		if leg.LevelChange != 0 {
			return fmt.Sprintf("Take the lift to level %d for %s", to.Level, destination)
		}
		return "Take the lift to " + destination
	case EdgeRamp:
		return "Follow the ramp to " + destination
	case EdgeDoor:
		return "Go through the doors to " + destination
	}

	if incoming == nil {
		return "Head for " + destination
	}
	switch turnOf(incoming.Position, from.Position, to.Position) {
	case turnLeft:
		return "Bear left towards " + destination
	case turnRight:
		return "Bear right towards " + destination
	case turnBack:
		return "Turn around and head for " + destination
	default:
		return "Continue to " + destination
	}
}

// nodeLabel is the human name for a node, falling back to something readable
// when the plan gave it none.
func nodeLabel(node Node) string {
	if node.Name != "" {
		return node.Name
	}
	switch node.Kind {
	case NodeGate:
		return "the gate"
	case NodePortal:
		return "the portal"
	case NodeAisle:
		return "the aisle"
	case NodeConcourse:
		return "the concourse"
	case NodeSeatBlock:
		return "your block"
	case NodeAmenity:
		return "the facility"
	default:
		return strings.ReplaceAll(string(node.ID), "-", " ")
	}
}

// turn classifies a change of direction.
type turn int

const (
	turnStraight turn = iota
	turnLeft
	turnRight
	turnBack
)

// turnOf classifies the turn made at b when arriving from a and leaving for c.
// The map's Y axis grows downward, matching SVG, so a positive cross product is
// a right turn rather than a left one.
func turnOf(a, b, c Point) turn {
	inX, inY := b.X-a.X, b.Y-a.Y
	outX, outY := c.X-b.X, c.Y-b.Y

	inLength, outLength := math.Hypot(inX, inY), math.Hypot(outX, outY)
	if inLength == 0 || outLength == 0 {
		return turnStraight
	}
	inX, inY = inX/inLength, inY/inLength
	outX, outY = outX/outLength, outY/outLength

	dot := inX*outX + inY*outY
	cross := inX*outY - inY*outX

	switch {
	// Roughly within 25 degrees of straight ahead is not worth mentioning.
	case dot > 0.9:
		return turnStraight
	case dot < -0.7:
		return turnBack
	case cross > 0:
		return turnRight
	default:
		return turnLeft
	}
}
