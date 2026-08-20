package venue

import (
	"errors"
	"fmt"
	"math"
	"sort"
)

// Venue is a compiled, validated, immutable venue graph.
//
// Everything expensive or error-prone is done once here at boot: codes are
// normalised, references are resolved, the zone tree is checked for cycles,
// bulk-authored rows have their seats laid out, and the walk graph is turned
// into adjacency lists. What remains at request time is map lookups, which is
// what lets a gate answer a scan in under a millisecond of box-side work.
type Venue struct {
	zones       map[ZoneCode]Zone
	sections    map[SectionCode]Section
	checkpoints map[CheckpointCode]Checkpoint
	tiers       map[TierCode]Tier
	amenities   map[string]Amenity
	nodes       map[NodeID]Node

	// zoneOrder and friends preserve authoring order so the dashboard and the
	// map draw things in the order the organizer wrote them, which is almost
	// always the order that makes sense to them.
	zoneOrder       []ZoneCode
	sectionOrder    []SectionCode
	checkpointOrder []CheckpointCode
	tierOrder       []TierCode
	amenityOrder    []string

	// ancestors[z] is z followed by its parents outward to the root. Precomputed
	// because entitlement checks walk it on every single scan.
	ancestors map[ZoneCode][]ZoneCode

	// children[z] is the zones nested directly inside z.
	children map[ZoneCode][]ZoneCode

	// tierZones[t] is the closure of zones tier t may enter, expanded through
	// nesting. A grant on a parent becomes an explicit grant on every
	// descendant here, so TierAdmits is one map lookup rather than a tree walk.
	tierZones map[TierCode]map[ZoneCode]bool

	// seats[section][row][number] resolves a SeatRef in three lookups.
	seats map[SectionCode]map[string]map[string]Seat

	// rowOrder[section] keeps rows in authoring order for the seat map.
	rowOrder map[SectionCode][]string

	// adjacency is the walk graph, already deduplicated and with distances
	// filled in.
	adjacency map[NodeID][]arc

	// checkpointsByZone answers "which doors admit into this zone".
	checkpointsByZone map[ZoneCode][]CheckpointCode

	// sectionsByZone answers "what is inside this zone".
	sectionsByZone map[ZoneCode][]SectionCode

	// entrancesBySection is the section's own list, with a fallback to every
	// "in" checkpoint on its zone when the organizer did not name any.
	entrancesBySection map[SectionCode][]CheckpointCode

	plan Plan
}

// arc is one directed walk-graph edge with its cost resolved.
type arc struct {
	to       NodeID
	kind     EdgeKind
	distance float64
	cost     float64
	note     string
}

// Compile validates a plan and returns an immutable venue.
//
// It is strict on purpose. A venue plan is authored once, days before doors,
// by someone who will not be reading logs during the event; every misspelled
// zone code caught here is a gate that would otherwise have denied everybody
// at 8pm with nobody able to work out why.
func Compile(plan Plan) (*Venue, error) {
	v := &Venue{
		zones:              make(map[ZoneCode]Zone, len(plan.Zones)),
		sections:           make(map[SectionCode]Section, len(plan.Sections)),
		checkpoints:        make(map[CheckpointCode]Checkpoint, len(plan.Checkpoints)),
		tiers:              make(map[TierCode]Tier, len(plan.Tiers)),
		amenities:          make(map[string]Amenity, len(plan.Amenities)),
		nodes:              make(map[NodeID]Node, len(plan.Map.Nodes)),
		ancestors:          make(map[ZoneCode][]ZoneCode, len(plan.Zones)),
		children:           make(map[ZoneCode][]ZoneCode),
		tierZones:          make(map[TierCode]map[ZoneCode]bool, len(plan.Tiers)),
		seats:              make(map[SectionCode]map[string]map[string]Seat),
		rowOrder:           make(map[SectionCode][]string),
		adjacency:          make(map[NodeID][]arc),
		checkpointsByZone:  make(map[ZoneCode][]CheckpointCode),
		sectionsByZone:     make(map[ZoneCode][]SectionCode),
		entrancesBySection: make(map[SectionCode][]CheckpointCode),
	}

	if err := v.loadZones(plan.Zones); err != nil {
		return nil, err
	}
	if err := v.loadNodes(plan.Map.Nodes); err != nil {
		return nil, err
	}
	if err := v.loadEdges(plan.Map.Edges); err != nil {
		return nil, err
	}
	if err := v.loadSections(plan.Sections); err != nil {
		return nil, err
	}
	if err := v.loadCheckpoints(plan.Checkpoints); err != nil {
		return nil, err
	}
	if err := v.loadTiers(plan.Tiers); err != nil {
		return nil, err
	}
	if err := v.loadAmenities(plan.Amenities); err != nil {
		return nil, err
	}
	if err := v.resolveSectionEntrances(); err != nil {
		return nil, err
	}
	v.deriveCapacities()

	// Rebuild the plan from the normalised values so that Plan() round-trips
	// through Compile without drifting: the manifest the box re-exports after
	// an event has to be the same venue everyone agreed on before it.
	v.plan = v.exportPlan(plan.Map)
	return v, nil
}

func (v *Venue) loadZones(zones []Zone) error {
	if len(zones) == 0 {
		return errors.New("venue: a plan needs at least one zone")
	}
	for _, zone := range zones {
		zone.Code = ZoneCode(normalizeCode(string(zone.Code)))
		zone.Parent = ZoneCode(normalizeCode(string(zone.Parent)))
		if !validCode(string(zone.Code)) {
			return codeError("zone", string(zone.Code), "codes are lowercase letters, digits, hyphen and underscore, up to 48 characters")
		}
		if _, exists := v.zones[zone.Code]; exists {
			return codeError("zone", string(zone.Code), "declared twice")
		}
		if zone.Name == "" {
			zone.Name = string(zone.Code)
		}
		if zone.Kind == "" {
			zone.Kind = ZoneArena
		}
		if zone.Capacity < 0 {
			return codeError("zone", string(zone.Code), "capacity cannot be negative")
		}
		if len(zone.Shape) > 0 && len(zone.Shape) < 3 {
			return codeError("zone", string(zone.Code), "a shape needs at least three points")
		}
		v.zones[zone.Code] = zone
		v.zoneOrder = append(v.zoneOrder, zone.Code)
	}

	// Parents must exist, and the tree must be a tree.
	for _, code := range v.zoneOrder {
		zone := v.zones[code]
		if zone.Parent == "" {
			continue
		}
		if zone.Parent == code {
			return codeError("zone", string(code), "is its own parent")
		}
		if _, ok := v.zones[zone.Parent]; !ok {
			return codeError("zone", string(code), fmt.Sprintf("parent %q does not exist", zone.Parent))
		}
		v.children[zone.Parent] = append(v.children[zone.Parent], code)
	}
	for _, code := range v.zoneOrder {
		chain, err := v.walkAncestors(code)
		if err != nil {
			return err
		}
		v.ancestors[code] = chain
	}
	return nil
}

// walkAncestors returns code followed by its parents outward to the root,
// erroring on a cycle. A cycle in the zone tree would make entitlement checks
// loop forever, which at a gate means a hung scanner.
func (v *Venue) walkAncestors(code ZoneCode) ([]ZoneCode, error) {
	chain := []ZoneCode{code}
	seen := map[ZoneCode]bool{code: true}
	for parent := v.zones[code].Parent; parent != ""; parent = v.zones[parent].Parent {
		if seen[parent] {
			return nil, codeError("zone", string(code), "is part of a parent cycle")
		}
		seen[parent] = true
		chain = append(chain, parent)
	}
	return chain, nil
}

func (v *Venue) loadNodes(nodes []Node) error {
	for _, node := range nodes {
		node.ID = NodeID(normalizeCode(string(node.ID)))
		node.Zone = ZoneCode(normalizeCode(string(node.Zone)))
		if !validCode(string(node.ID)) {
			return codeError("map node", string(node.ID), "invalid id")
		}
		if _, exists := v.nodes[node.ID]; exists {
			return codeError("map node", string(node.ID), "declared twice")
		}
		if node.Zone != "" {
			if _, ok := v.zones[node.Zone]; !ok {
				return codeError("map node", string(node.ID), fmt.Sprintf("zone %q does not exist", node.Zone))
			}
		}
		if node.Kind == "" {
			node.Kind = NodeJunction
		}
		v.nodes[node.ID] = node
	}
	return nil
}

func (v *Venue) loadEdges(edges []Edge) error {
	// seen deduplicates directed pairs. Authoring a corridor twice is common
	// when two people edit the plan, and a duplicated edge would make the
	// router's distances arbitrary between equal paths.
	seen := make(map[[2]NodeID]bool, len(edges)*2)

	add := func(from, to NodeID, e Edge) {
		if seen[[2]NodeID{from, to}] {
			return
		}
		seen[[2]NodeID{from, to}] = true

		distance := e.Distance
		if distance <= 0 {
			distance = dist(v.nodes[from].Position, v.nodes[to].Position)
		}
		cost := e.Cost
		if cost <= 0 {
			cost = 1
		}
		v.adjacency[from] = append(v.adjacency[from], arc{
			to:       to,
			kind:     e.Kind,
			distance: distance,
			cost:     distance * cost,
			note:     e.Note,
		})
	}

	for _, edge := range edges {
		edge.From = NodeID(normalizeCode(string(edge.From)))
		edge.To = NodeID(normalizeCode(string(edge.To)))
		if _, ok := v.nodes[edge.From]; !ok {
			return codeError("map edge", string(edge.From), "from node does not exist")
		}
		if _, ok := v.nodes[edge.To]; !ok {
			return codeError("map edge", string(edge.To), "to node does not exist")
		}
		if edge.From == edge.To {
			return codeError("map edge", string(edge.From), "joins a node to itself")
		}
		if edge.Kind == "" {
			edge.Kind = EdgeWalk
		}
		add(edge.From, edge.To, edge)
		if !edge.OneWay {
			add(edge.To, edge.From, edge)
		}
	}
	return nil
}

func (v *Venue) loadSections(sections []Section) error {
	for _, section := range sections {
		section.Code = SectionCode(normalizeCode(string(section.Code)))
		section.Zone = ZoneCode(normalizeCode(string(section.Zone)))
		if !validCode(string(section.Code)) {
			return codeError("section", string(section.Code), "invalid code")
		}
		if _, exists := v.sections[section.Code]; exists {
			return codeError("section", string(section.Code), "declared twice")
		}
		if _, ok := v.zones[section.Zone]; !ok {
			return codeError("section", string(section.Code), fmt.Sprintf("zone %q does not exist", section.Zone))
		}
		if section.Name == "" {
			section.Name = string(section.Code)
		}
		if section.Kind == "" {
			section.Kind = SectionStanding
		}
		section.Node = NodeID(normalizeCode(string(section.Node)))
		if section.Node != "" {
			if _, ok := v.nodes[section.Node]; !ok {
				return codeError("section", string(section.Code), fmt.Sprintf("map node %q does not exist", section.Node))
			}
		}

		switch section.Kind {
		case SectionSeated, SectionTable:
			if len(section.Rows) == 0 {
				return codeError("section", string(section.Code), "a seated section needs rows")
			}
		case SectionStanding, SectionBox:
			if section.Capacity <= 0 {
				return codeError("section", string(section.Code), "a standing or box section needs a capacity")
			}
		default:
			return codeError("section", string(section.Code), fmt.Sprintf("unknown kind %q", section.Kind))
		}

		if err := v.loadRows(&section); err != nil {
			return err
		}

		v.sections[section.Code] = section
		v.sectionOrder = append(v.sectionOrder, section.Code)
		v.sectionsByZone[section.Zone] = append(v.sectionsByZone[section.Zone], section.Code)
	}
	return nil
}

// loadRows validates a section's rows and lays out any seats that were authored
// without positions. Bulk authoring is the normal case: a two-thousand-seat
// stand is written as thirty rows with a start point, an end point and a seat
// count, and this is what turns that into two thousand drawable seats.
func (v *Venue) loadRows(section *Section) error {
	if len(section.Rows) == 0 {
		return nil
	}
	rows := make(map[string]map[string]Seat, len(section.Rows))
	order := make([]string, 0, len(section.Rows))

	for i := range section.Rows {
		row := &section.Rows[i]
		if row.Label == "" {
			return codeError("section", string(section.Code), fmt.Sprintf("row %d has no label", i))
		}
		if _, exists := rows[row.Label]; exists {
			return codeError("section", string(section.Code), fmt.Sprintf("row %q declared twice", row.Label))
		}
		if len(row.Seats) == 0 {
			return codeError("section", string(section.Code), fmt.Sprintf("row %q has no seats", row.Label))
		}
		row.Aisle = NodeID(normalizeCode(string(row.Aisle)))
		if row.Aisle != "" {
			if _, ok := v.nodes[row.Aisle]; !ok {
				return codeError("section", string(section.Code), fmt.Sprintf("row %q aisle node %q does not exist", row.Label, row.Aisle))
			}
		}

		layoutRow(row)

		seats := make(map[string]Seat, len(row.Seats))
		for j := range row.Seats {
			seat := &row.Seats[j]
			if seat.Number == "" {
				return codeError("section", string(section.Code), fmt.Sprintf("row %q has a seat with no number", row.Label))
			}
			if _, exists := seats[seat.Number]; exists {
				return codeError("section", string(section.Code), fmt.Sprintf("row %q seat %q declared twice", row.Label, seat.Number))
			}
			if seat.Kind == "" {
				seat.Kind = SeatStandard
			}
			seats[seat.Number] = *seat
		}
		rows[row.Label] = seats
		order = append(order, row.Label)
	}

	v.seats[section.Code] = rows
	v.rowOrder[section.Code] = order
	return nil
}

// layoutRow fills in seat positions for a row authored with geometry instead of
// per-seat coordinates. Seats are spread along a quadratic bezier from Start to
// End whose sagitta is Curve, which is a close enough approximation of how real
// stands are built that the drawn map matches the photograph.
func layoutRow(row *Row) {
	needs := false
	for _, seat := range row.Seats {
		if seat.Position == (Point{}) {
			needs = true
			break
		}
	}
	if !needs || (row.Start == Point{} && row.End == Point{}) {
		return
	}

	// Control point sits perpendicular to the chord at its midpoint, offset to
	// the left of the direction of travel. A quadratic bezier's sagitta is half
	// its control offset, so the offset is doubled to make Curve mean the
	// distance an engineer drawing the stand would measure.
	//
	// The map's Y axis grows downward, matching SVG, so the left-hand normal of
	// (dx, dy) is (dy, -dx). Getting this sign wrong bows every row away from
	// the stage, which looks obviously wrong on the drawn map and is the reason
	// there is a test asserting the direction.
	mid := Point{X: (row.Start.X + row.End.X) / 2, Y: (row.Start.Y + row.End.Y) / 2}
	control := mid
	if row.Curve != 0 {
		dx, dy := row.End.X-row.Start.X, row.End.Y-row.Start.Y
		length := math.Hypot(dx, dy)
		if length > 0 {
			control = Point{X: mid.X + dy/length*row.Curve*2, Y: mid.Y - dx/length*row.Curve*2}
		}
	}

	count := len(row.Seats)
	for i := range row.Seats {
		if row.Seats[i].Position != (Point{}) {
			continue
		}
		t := 0.5
		if count > 1 {
			t = float64(i) / float64(count-1)
		}
		row.Seats[i].Position = bezier(row.Start, control, row.End, t)
	}
}

// bezier evaluates a quadratic bezier at t.
func bezier(start, control, end Point, t float64) Point {
	u := 1 - t
	return Point{
		X: u*u*start.X + 2*u*t*control.X + t*t*end.X,
		Y: u*u*start.Y + 2*u*t*control.Y + t*t*end.Y,
	}
}

func (v *Venue) loadCheckpoints(checkpoints []Checkpoint) error {
	if len(checkpoints) == 0 {
		return errors.New("venue: a plan needs at least one checkpoint")
	}
	for _, cp := range checkpoints {
		cp.Code = CheckpointCode(normalizeCode(string(cp.Code)))
		cp.Zone = ZoneCode(normalizeCode(string(cp.Zone)))
		if !validCode(string(cp.Code)) {
			return codeError("checkpoint", string(cp.Code), "invalid code")
		}
		if _, exists := v.checkpoints[cp.Code]; exists {
			return codeError("checkpoint", string(cp.Code), "declared twice")
		}
		if _, ok := v.zones[cp.Zone]; !ok {
			return codeError("checkpoint", string(cp.Code), fmt.Sprintf("zone %q does not exist", cp.Zone))
		}
		if cp.Name == "" {
			cp.Name = string(cp.Code)
		}
		if cp.Direction == "" {
			cp.Direction = DirectionIn
		}
		if cp.Policy == "" {
			cp.Policy = PolicyOnce
		}
		switch cp.Direction {
		case DirectionIn, DirectionOut, DirectionBoth:
		default:
			return codeError("checkpoint", string(cp.Code), fmt.Sprintf("unknown direction %q", cp.Direction))
		}
		switch cp.Policy {
		case PolicyOnce:
			if cp.CountLimit != 0 {
				return codeError("checkpoint", string(cp.Code), "a once checkpoint cannot have a count limit")
			}
		case PolicyReEntry:
			// Unlimited passes on an inbound-only door means occupancy can only
			// ever grow, so the dashboard's headcount becomes fiction. Exits and
			// bidirectional doors are both fine.
			if cp.Direction == DirectionIn {
				return codeError("checkpoint", string(cp.Code), "re-entry needs an outbound or bidirectional checkpoint, otherwise occupancy only ever grows")
			}
		case PolicyCounted:
			if cp.CountLimit <= 0 {
				return codeError("checkpoint", string(cp.Code), "a counted checkpoint needs a positive count limit")
			}
		default:
			return codeError("checkpoint", string(cp.Code), fmt.Sprintf("unknown policy %q", cp.Policy))
		}
		if !cp.OpensAt.IsZero() && !cp.ClosesAt.IsZero() && !cp.ClosesAt.After(cp.OpensAt) {
			return codeError("checkpoint", string(cp.Code), "closes at or before it opens")
		}

		for i, required := range cp.Requires {
			required = ZoneCode(normalizeCode(string(required)))
			if _, ok := v.zones[required]; !ok {
				return codeError("checkpoint", string(cp.Code), fmt.Sprintf("required zone %q does not exist", required))
			}
			if required == cp.Zone {
				return codeError("checkpoint", string(cp.Code), "requires the zone it admits into, which nobody can ever satisfy")
			}
			cp.Requires[i] = required
		}
		for i, section := range cp.Sections {
			section = SectionCode(normalizeCode(string(section)))
			if _, ok := v.sections[section]; !ok {
				return codeError("checkpoint", string(cp.Code), fmt.Sprintf("section %q does not exist", section))
			}
			cp.Sections[i] = section
		}
		for i, tier := range cp.Tiers {
			cp.Tiers[i] = TierCode(normalizeCode(string(tier)))
		}
		cp.Node = NodeID(normalizeCode(string(cp.Node)))
		if cp.Node != "" {
			node, ok := v.nodes[cp.Node]
			if !ok {
				return codeError("checkpoint", string(cp.Code), fmt.Sprintf("map node %q does not exist", cp.Node))
			}
			// A checkpoint that names a walk-graph node already has a location, so
			// take it rather than asking the organizer to write the same
			// coordinates twice. Two copies of one fact is two chances to disagree,
			// and the way it disagrees is a gate drawn in the wrong place on a map
			// somebody is using to find that gate. An explicit Position still wins:
			// several doors can share one node, and a plan that separates them on
			// the map is saying something the graph does not.
			if cp.Position == (Point{}) {
				cp.Position = node.Position
			}
		}

		v.checkpoints[cp.Code] = cp
		v.checkpointOrder = append(v.checkpointOrder, cp.Code)
		v.checkpointsByZone[cp.Zone] = append(v.checkpointsByZone[cp.Zone], cp.Code)
	}
	return nil
}

func (v *Venue) loadTiers(tiers []Tier) error {
	if len(tiers) == 0 {
		return errors.New("venue: a plan needs at least one tier")
	}
	for _, tier := range tiers {
		tier.Code = TierCode(normalizeCode(string(tier.Code)))
		if !validCode(string(tier.Code)) {
			return codeError("tier", string(tier.Code), "invalid code")
		}
		if _, exists := v.tiers[tier.Code]; exists {
			return codeError("tier", string(tier.Code), "declared twice")
		}
		if tier.Name == "" {
			tier.Name = string(tier.Code)
		}
		if len(tier.Zones) == 0 {
			return codeError("tier", string(tier.Code), "entitles the holder to no zones, which is a ticket to nowhere")
		}

		granted := make(map[ZoneCode]bool)
		for i, zone := range tier.Zones {
			zone = ZoneCode(normalizeCode(string(zone)))
			if _, ok := v.zones[zone]; !ok {
				return codeError("tier", string(tier.Code), fmt.Sprintf("zone %q does not exist", zone))
			}
			tier.Zones[i] = zone
			// Expand the grant down the tree so the entitlement check at a gate
			// is one map lookup instead of a walk. The expansion stops at any
			// restricted zone, which is what keeps a grant on the outer
			// perimeter from quietly including the backstage nested inside it.
			for _, descendant := range v.inheritableFrom(zone) {
				granted[descendant] = true
			}
		}
		v.tiers[tier.Code] = tier
		v.tierOrder = append(v.tierOrder, tier.Code)
		v.tierZones[tier.Code] = granted
	}

	// Checkpoint tier restrictions can only be checked once every tier exists.
	for _, code := range v.checkpointOrder {
		for _, tier := range v.checkpoints[code].Tiers {
			if _, ok := v.tiers[tier]; !ok {
				return codeError("checkpoint", string(code), fmt.Sprintf("restricted to tier %q, which does not exist", tier))
			}
		}
	}
	return nil
}

// descendantsOf returns a zone and every zone nested inside it, ignoring
// restrictions. Used for the physical questions — capacity, "is this person
// somewhere inside the arena" — where nesting is a fact about geometry rather
// than a statement about permission.
func (v *Venue) descendantsOf(root ZoneCode) []ZoneCode {
	out := []ZoneCode{root}
	for i := 0; i < len(out); i++ {
		out = append(out, v.children[out[i]]...)
	}
	return out
}

// inheritableFrom returns the zones an explicit grant on root also confers: root
// itself plus its descendants, pruned at every restricted zone. Used for the
// permission question, where the answer has to fail closed.
func (v *Venue) inheritableFrom(root ZoneCode) []ZoneCode {
	out := []ZoneCode{root}
	for i := 0; i < len(out); i++ {
		for _, child := range v.children[out[i]] {
			if v.zones[child].Restricted {
				continue
			}
			out = append(out, child)
		}
	}
	return out
}

func (v *Venue) loadAmenities(amenities []Amenity) error {
	for _, amenity := range amenities {
		amenity.ID = normalizeCode(amenity.ID)
		amenity.Zone = ZoneCode(normalizeCode(string(amenity.Zone)))
		if !validCode(amenity.ID) {
			return codeError("amenity", amenity.ID, "invalid id")
		}
		if _, exists := v.amenities[amenity.ID]; exists {
			return codeError("amenity", amenity.ID, "declared twice")
		}
		if _, ok := v.zones[amenity.Zone]; !ok {
			return codeError("amenity", amenity.ID, fmt.Sprintf("zone %q does not exist", amenity.Zone))
		}
		if amenity.Kind == "" {
			return codeError("amenity", amenity.ID, "has no kind")
		}
		if amenity.Name == "" {
			amenity.Name = string(amenity.Kind)
		}
		amenity.Node = NodeID(normalizeCode(string(amenity.Node)))
		if amenity.Node != "" {
			if _, ok := v.nodes[amenity.Node]; !ok {
				return codeError("amenity", amenity.ID, fmt.Sprintf("map node %q does not exist", amenity.Node))
			}
		} else {
			// Snap to the nearest node inside the same zone so the amenity can
			// be routed to rather than merely pinned. Organizers place pins by
			// eye and should not have to hand-wire every toilet to the graph.
			amenity.Node = v.nearestNodeInZone(amenity.Position, amenity.Zone)
		}
		if !amenity.OpenFrom.IsZero() && !amenity.OpenTo.IsZero() && !amenity.OpenTo.After(amenity.OpenFrom) {
			return codeError("amenity", amenity.ID, "closes at or before it opens")
		}
		v.amenities[amenity.ID] = amenity
		v.amenityOrder = append(v.amenityOrder, amenity.ID)
	}
	return nil
}

// nearestNodeInZone returns the closest walk-graph node inside the given zone
// or any zone nested inside it, or the empty id when the venue has no graph.
func (v *Venue) nearestNodeInZone(at Point, zone ZoneCode) NodeID {
	var best NodeID
	bestDistance := math.Inf(1)
	within := make(map[ZoneCode]bool)
	for _, code := range v.descendantsOf(zone) {
		within[code] = true
	}
	// Resolve ties by sorted id rather than by map order so two equally close
	// nodes pick the same winner on every boot. A venue that reshuffles its own
	// amenity routing between restarts is impossible to support.
	ids := make([]NodeID, 0, len(v.nodes))
	for id := range v.nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		node := v.nodes[id]
		if node.Zone != "" && !within[node.Zone] {
			continue
		}
		if d := dist(at, node.Position); d < bestDistance {
			best, bestDistance = id, d
		}
	}
	return best
}

// resolveSectionEntrances fills in each section's entrance list, defaulting to
// every inbound checkpoint on the section's own zone. Most venues never name
// entrances per section; stadiums always do.
func (v *Venue) resolveSectionEntrances() error {
	for _, code := range v.sectionOrder {
		section := v.sections[code]

		if len(section.Entrances) > 0 {
			for i, entrance := range section.Entrances {
				entrance = CheckpointCode(normalizeCode(string(entrance)))
				cp, ok := v.checkpoints[entrance]
				if !ok {
					return codeError("section", string(code), fmt.Sprintf("entrance %q does not exist", entrance))
				}
				if cp.Direction == DirectionOut {
					return codeError("section", string(code), fmt.Sprintf("entrance %q is an exit", entrance))
				}
				section.Entrances[i] = entrance
			}
			v.sections[code] = section
			v.entrancesBySection[code] = section.Entrances
			continue
		}

		var inferred []CheckpointCode
		for _, candidate := range v.checkpointsByZone[section.Zone] {
			if v.checkpoints[candidate].Direction != DirectionOut {
				inferred = append(inferred, candidate)
			}
		}
		v.entrancesBySection[code] = inferred
	}
	return nil
}

// deriveCapacities fills in a zone capacity from its sections when the
// organizer left it blank. A seated zone knows exactly how many people fit;
// making them retype the number is how the two numbers end up disagreeing.
func (v *Venue) deriveCapacities() {
	for _, code := range v.zoneOrder {
		zone := v.zones[code]
		if zone.Capacity > 0 {
			continue
		}
		total := 0
		for _, sectionCode := range v.sectionsByZone[code] {
			total += v.SectionCapacity(sectionCode)
		}
		if total > 0 {
			zone.Capacity = total
			v.zones[code] = zone
		}
	}
}

// exportPlan rebuilds a Plan from the normalised, compiled state.
func (v *Venue) exportPlan(m Map) Plan {
	plan := Plan{Map: m}
	for _, code := range v.zoneOrder {
		plan.Zones = append(plan.Zones, v.zones[code])
	}
	for _, code := range v.sectionOrder {
		plan.Sections = append(plan.Sections, v.sections[code])
	}
	for _, code := range v.checkpointOrder {
		plan.Checkpoints = append(plan.Checkpoints, v.checkpoints[code])
	}
	for _, code := range v.tierOrder {
		plan.Tiers = append(plan.Tiers, v.tiers[code])
	}
	for _, id := range v.amenityOrder {
		plan.Amenities = append(plan.Amenities, v.amenities[id])
	}
	return plan
}

// dist is straight-line distance in map units.
func dist(a, b Point) float64 { return math.Hypot(b.X-a.X, b.Y-a.Y) }
