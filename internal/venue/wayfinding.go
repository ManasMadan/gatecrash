package venue

import (
	"fmt"
	"sort"
	"time"
)

// Wayfinding answers the two questions attendees actually ask — "where do I go
// now" and "where is the nearest one of those" — and the question gate staff
// ask, which is "where do I send this person next".
//
// All of it is computed on the box from the compiled venue and the ticket's
// redemption history. None of it needs the internet, which is the point: the
// moment somebody is lost is the moment the cell tower is saturated.

// Step is one place an attendee can go next.
type Step struct {
	Checkpoint CheckpointCode `json:"checkpoint"`
	Name       string         `json:"name"`
	Lane       string         `json:"lane,omitempty"`

	Zone     ZoneCode `json:"zone"`
	ZoneName string   `json:"zone_name"`

	// Ready means every prerequisite is already satisfied and the checkpoint is
	// open, so the attendee can walk up and be admitted.
	Ready bool `json:"ready"`

	// Missing lists the zones that still have to be entered first. This is what
	// turns a denial into a direction: not "you cannot come in" but "you need to
	// be inside the arena first, which is that way".
	Missing []ZoneCode `json:"missing,omitempty"`

	// Closed means the checkpoint is outside its opening hours.
	Closed bool `json:"closed,omitempty"`

	// OpensAt is when a closed checkpoint starts accepting scans.
	OpensAt time.Time `json:"opens_at,omitzero"`

	Position Point  `json:"position,omitzero"`
	Node     NodeID `json:"node,omitempty"`

	// Route is how to walk there from wherever the attendee is now, when the
	// caller supplied a position and the venue has a walk graph.
	Route *Route `json:"route,omitempty"`
}

// Destination is where a seated ticket is ultimately headed.
type Destination struct {
	Section     SectionCode `json:"section"`
	SectionName string      `json:"section_name"`
	Seat        SeatRef     `json:"seat,omitzero"`
	SeatLabel   string      `json:"seat_label,omitempty"`
	SeatKind    SeatKind    `json:"seat_kind,omitempty"`

	// ViewNote and SeatNote are the honest disclosures: restricted view, step
	// up on entry, behind the mix position.
	ViewNote string `json:"view_note,omitempty"`
	SeatNote string `json:"seat_note,omitempty"`

	// Entrances are the doors that serve this section, in preference order.
	Entrances []CheckpointCode `json:"entrances,omitempty"`

	Position Point  `json:"position,omitzero"`
	Node     NodeID `json:"node,omitempty"`

	Route *Route `json:"route,omitempty"`
}

// Guidance is the whole answer to "where do I go", assembled for one ticket.
type Guidance struct {
	Tier     TierCode `json:"tier"`
	TierName string   `json:"tier_name"`
	Colour   string   `json:"colour,omitempty"`

	// Entitled is every zone this tier may enter; Admitted is every zone this
	// ticket has actually been admitted into so far.
	Entitled []ZoneCode `json:"entitled"`
	Admitted []ZoneCode `json:"admitted,omitempty"`

	// Next are the checkpoints the attendee can walk up to right now.
	Next []Step `json:"next"`

	// Later are checkpoints they are entitled to but cannot use yet, each
	// carrying what is still missing. Showing these is what makes a multi-stage
	// venue legible instead of feeling arbitrary.
	Later []Step `json:"later,omitempty"`

	// Destination is set for seated tickets.
	Destination *Destination `json:"destination,omitempty"`

	// Arrived means the attendee is already inside everywhere this ticket can
	// take them, so the app switches from directions to amenities.
	Arrived bool `json:"arrived"`
}

// GuidanceRequest is the input to Guidance.
type GuidanceRequest struct {
	Tier TierCode
	Seat SeatRef

	// Admitted is the set of zones this ticket has already been admitted into,
	// which the engine reads from the redemption table.
	Admitted []ZoneCode

	// From is where the attendee is standing, used to route each step. Empty
	// means routes are omitted and only the names are returned, which is what
	// happens before the first scan when nobody knows where they are.
	From NodeID

	// StepFree threads the attendee's accessibility preference through every
	// route in the answer.
	StepFree bool

	// At is the instant to evaluate opening hours against, taken from the box's
	// clock.
	At time.Time
}

// Guidance computes where a ticket may go next.
func (v *Venue) Guidance(req GuidanceRequest) (Guidance, error) {
	tier, ok := v.tiers[req.Tier]
	if !ok {
		return Guidance{}, codeError("tier", string(req.Tier), "does not exist")
	}

	admitted := make(map[ZoneCode]bool, len(req.Admitted))
	for _, zone := range req.Admitted {
		admitted[zone] = true
	}

	allowed := make(map[ZoneCode]bool, len(v.tierZones[req.Tier]))
	for zone := range v.tierZones[req.Tier] {
		allowed[zone] = true
	}
	routeOpts := RouteOptions{StepFree: req.StepFree, AllowedZones: allowed}

	out := Guidance{
		Tier:     tier.Code,
		TierName: tier.Name,
		Colour:   tier.Colour,
		Entitled: v.TierZones(req.Tier),
		Admitted: req.Admitted,
	}

	for _, code := range v.checkpointOrder {
		cp := v.checkpoints[code]

		// Exits are not destinations. Nobody opens the map to be told where the
		// way out is until they want the way out, and that is a different screen.
		if cp.Direction == DirectionOut {
			continue
		}
		if !v.TierAdmits(req.Tier, cp.Zone) {
			continue
		}
		if !v.CheckpointServes(code, req.Tier, req.Seat) {
			continue
		}
		// Somewhere already entered under a once-only policy is behind them.
		if cp.Policy == PolicyOnce && v.alreadyInside(cp.Zone, admitted) {
			continue
		}

		step := Step{
			Checkpoint: code,
			Name:       cp.Name,
			Lane:       cp.Lane,
			Zone:       cp.Zone,
			ZoneName:   v.zones[cp.Zone].Name,
			Position:   cp.Position,
			Node:       cp.Node,
		}
		for _, required := range cp.Requires {
			if !v.satisfiedBy(required, admitted) {
				step.Missing = append(step.Missing, required)
			}
		}
		if !req.At.IsZero() && !v.CheckpointOpen(code, req.At) {
			step.Closed = true
			step.OpensAt = cp.OpensAt
		}
		step.Ready = len(step.Missing) == 0 && !step.Closed

		if req.From != "" && cp.Node != "" && v.HasWalkGraph() {
			if route, err := v.Route(req.From, cp.Node, routeOpts); err == nil {
				step.Route = &route
			}
		}

		if step.Ready {
			out.Next = append(out.Next, step)
		} else {
			out.Later = append(out.Later, step)
		}
	}

	// Nearest first when we know where they are, otherwise authoring order,
	// which is normally the organizer's own idea of the sensible order.
	if req.From != "" {
		sortStepsByRoute(out.Next)
		sortStepsByRoute(out.Later)
	}

	if destination, err := v.destination(req, routeOpts); err != nil {
		return Guidance{}, err
	} else if destination != nil {
		out.Destination = destination
	}

	out.Arrived = len(out.Next) == 0 && len(out.Later) == 0
	return out, nil
}

// sortStepsByRoute puts the closest reachable step first. Steps with no route
// sort last, because a step we cannot route to is a step we cannot recommend.
func sortStepsByRoute(steps []Step) {
	sort.SliceStable(steps, func(i, j int) bool {
		left, right := steps[i].Route, steps[j].Route
		switch {
		case left == nil && right == nil:
			return false
		case left == nil:
			return false
		case right == nil:
			return true
		default:
			return left.Distance < right.Distance
		}
	})
}

// alreadyInside reports whether the ticket has been admitted into a zone or
// anywhere nested inside it.
func (v *Venue) alreadyInside(zone ZoneCode, admitted map[ZoneCode]bool) bool {
	for _, descendant := range v.descendantsOf(zone) {
		if admitted[descendant] {
			return true
		}
	}
	return false
}

// satisfiedBy reports whether a prerequisite on `required` is met by the set of
// zones already admitted, counting admissions into nested zones.
func (v *Venue) satisfiedBy(required ZoneCode, admitted map[ZoneCode]bool) bool {
	for zone := range admitted {
		if v.SatisfiesZone(zone, required) {
			return true
		}
	}
	return false
}

// destination builds the seated-ticket destination block.
func (v *Venue) destination(req GuidanceRequest, opts RouteOptions) (*Destination, error) {
	if req.Seat.IsZero() {
		return nil, nil
	}
	section, ok := v.sections[req.Seat.Section]
	if !ok {
		return nil, codeError("section", string(req.Seat.Section), "does not exist")
	}

	out := &Destination{
		Section:     section.Code,
		SectionName: section.Name,
		Seat:        req.Seat,
		SeatLabel:   req.Seat.String(),
		ViewNote:    section.ViewNote,
		Entrances:   v.entrancesBySection[section.Code],
	}
	if seat, found := v.Seat(req.Seat); found {
		out.SeatKind = seat.Kind
		out.SeatNote = seat.Note
		out.Position = seat.Position
	} else if len(section.Shape) > 0 {
		out.Position = centroid(section.Shape)
	}
	out.Node = v.seatAnchor(req.Seat)

	if req.From != "" && out.Node != "" && v.HasWalkGraph() {
		if route, err := v.Route(req.From, out.Node, opts); err == nil {
			out.Route = &route
		}
	}
	return out, nil
}

// seatAnchor returns the walk-graph node an attendee arrives at for a seat: the
// row's own aisle if it has one, then the section's node, then whatever node is
// nearest inside the section's zone.
func (v *Venue) seatAnchor(ref SeatRef) NodeID {
	section, ok := v.sections[ref.Section]
	if !ok {
		return ""
	}
	for _, row := range section.Rows {
		if row.Label == ref.Row && row.Aisle != "" {
			return row.Aisle
		}
	}
	if section.Node != "" {
		return section.Node
	}
	if seat, found := v.Seat(ref); found {
		return v.nearestNodeInZone(seat.Position, section.Zone)
	}
	if len(section.Shape) > 0 {
		return v.nearestNodeInZone(centroid(section.Shape), section.Zone)
	}
	return ""
}

// NearbyAmenity is one amenity with the route to it.
type NearbyAmenity struct {
	Amenity Amenity `json:"amenity"`
	Route   *Route  `json:"route,omitempty"`

	// Open reports whether it is open at the instant asked about. A closed
	// amenity is still listed, greyed out, because "the water point is over
	// there but it shuts at 1am" is more useful than hiding it.
	Open bool `json:"open"`
}

// NearestAmenitiesRequest is the input to NearestAmenities.
type NearestAmenitiesRequest struct {
	// Kinds filters what to look for. Empty means everything.
	Kinds []AmenityKind

	// From is where the attendee is standing. Required: "nearest" is
	// meaningless without it.
	From NodeID

	// Tier restricts results to amenities the holder can actually reach.
	Tier TierCode

	// AccessibleOnly returns only amenities marked step-free or accessible.
	AccessibleOnly bool

	StepFree bool

	// Limit caps the results. Zero means five, which is what fits on a phone
	// screen without scrolling.
	Limit int

	At time.Time
}

// NearestAmenities answers "where is the nearest toilet", routed, offline.
//
// It sorts by walking distance along the graph rather than by straight-line
// distance, because in a venue the two are frequently unrelated: the toilet
// forty metres away on the far side of a barrier is a five minute walk, and
// telling somebody to go there is how they end up somewhere else entirely.
func (v *Venue) NearestAmenities(req NearestAmenitiesRequest) ([]NearbyAmenity, error) {
	if req.From == "" {
		return nil, fmt.Errorf("venue: nearest amenities needs a starting node")
	}
	if _, ok := v.nodes[req.From]; !ok {
		return nil, codeError("map node", string(req.From), "starting node does not exist")
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 5
	}

	wanted := make(map[AmenityKind]bool, len(req.Kinds))
	for _, kind := range req.Kinds {
		wanted[kind] = true
	}

	var allowed map[ZoneCode]bool
	if req.Tier != "" {
		if _, ok := v.tiers[req.Tier]; !ok {
			return nil, codeError("tier", string(req.Tier), "does not exist")
		}
		allowed = make(map[ZoneCode]bool, len(v.tierZones[req.Tier]))
		for zone := range v.tierZones[req.Tier] {
			allowed[zone] = true
		}
	}
	opts := RouteOptions{StepFree: req.StepFree, AllowedZones: allowed}

	var found []NearbyAmenity
	for _, id := range v.amenityOrder {
		amenity := v.amenities[id]
		if len(wanted) > 0 && !wanted[amenity.Kind] {
			continue
		}
		if req.AccessibleOnly && !amenity.Accessible {
			continue
		}
		if allowed != nil && !allowed[amenity.Zone] {
			continue
		}

		entry := NearbyAmenity{Amenity: amenity, Open: amenityOpen(amenity, req.At)}
		if amenity.Node != "" && v.HasWalkGraph() {
			route, err := v.Route(req.From, amenity.Node, opts)
			if err != nil {
				// Unreachable under these constraints is a reason to leave it
				// out, not a reason to fail the whole request: a step-free user
				// asking for toilets should get the reachable ones.
				continue
			}
			entry.Route = &route
		}
		found = append(found, entry)
	}

	sort.SliceStable(found, func(i, j int) bool {
		left, right := found[i].Route, found[j].Route
		// Open beats closed regardless of distance.
		if found[i].Open != found[j].Open {
			return found[i].Open
		}
		switch {
		case left == nil && right == nil:
			return false
		case left == nil:
			return false
		case right == nil:
			return true
		default:
			return left.Distance < right.Distance
		}
	})

	if len(found) > limit {
		found = found[:limit]
	}
	return found, nil
}

// amenityOpen reports whether an amenity is open at an instant. An amenity with
// no declared hours is always open, and a zero instant means we were not told
// what time it is, which also counts as open.
func amenityOpen(a Amenity, at time.Time) bool {
	if at.IsZero() {
		return true
	}
	if !a.OpenFrom.IsZero() && at.Before(a.OpenFrom) {
		return false
	}
	if !a.OpenTo.IsZero() && at.After(a.OpenTo) {
		return false
	}
	return true
}

// centroid is the average of a polygon's vertices. Not the true area centroid,
// which for a convex-ish venue block differs by a couple of metres and is not
// worth the code: this is used to place a pin, not to balance a plate.
func centroid(shape Polygon) Point {
	if len(shape) == 0 {
		return Point{}
	}
	var sum Point
	for _, point := range shape {
		sum.X += point.X
		sum.Y += point.Y
	}
	return Point{X: sum.X / float64(len(shape)), Y: sum.Y / float64(len(shape))}
}
