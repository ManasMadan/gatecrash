// Package venue models the physical shape of an event: the zones an attendee
// can be inside, the seated sections and standing pits inside those zones, the
// checkpoints that let people in and out, the ticket tiers that entitle them to
// go places, the amenities they will need to find, and a walkable graph joining
// all of it together.
//
// Two things make this more than a list of doors.
//
// First, access is a graph, not a flag. A festival is an outer perimeter, then
// an arena, then a pit that needs a wristband, then a backstage nobody without
// a crew tier ever sees. Getting into the pit requires already being inside the
// arena, and that ordering is a safety property rather than a nicety: a pit
// reachable directly from the street is an uncontrolled crush risk and the fire
// marshal will ask about it.
//
// Second, "where do I go" is a routing question. An attendee holding Block C
// Row 14 Seat 22 does not want a pin on a map, they want to be told which gate,
// which portal, which aisle, and whether there are stairs. So the map carries a
// real node-and-edge walk graph and the router runs a shortest path over it,
// with a step-free variant for anyone who needs one.
//
// A compiled Venue is immutable and shared by every request handler. It is
// built once at boot from the signed manifest and never mutated, which is why
// none of the lookup methods take a lock.
package venue

import (
	"fmt"
	"strings"
	"time"
)

// Code types. These are separate named types rather than bare strings because
// the engine passes several of them around together, and mixing up a zone code
// and a checkpoint code is exactly the sort of bug that admits someone to the
// wrong place.
type (
	// ZoneCode identifies a zone. Lowercase, hyphenated, and stable across the
	// event's life because it ends up on printed signage.
	ZoneCode string

	// CheckpointCode identifies a control point. This is what staff call the
	// door: "gate-3", "portal-c-lower", "backstage-stairs".
	CheckpointCode string

	// TierCode identifies a ticket class: "ga", "vip", "artist", "crew".
	TierCode string

	// SectionCode identifies a seating block or a standing pit: "block-c",
	// "golden-circle", "north-stand".
	SectionCode string

	// NodeID identifies a vertex in the walk graph.
	NodeID string
)

func (c ZoneCode) String() string       { return string(c) }
func (c CheckpointCode) String() string { return string(c) }
func (c TierCode) String() string       { return string(c) }
func (c SectionCode) String() string    { return string(c) }
func (c NodeID) String() string         { return string(c) }

// ZoneKind is a coarse classification used for map styling and for the
// dashboard's occupancy grouping. It carries no access-control meaning: what a
// tier may enter is decided only by Tier.Zones.
type ZoneKind string

// The zone kinds Gatecrash knows how to draw and group.
const (
	ZonePerimeter ZoneKind = "perimeter" // inside the event, outside the gates
	ZoneConcourse ZoneKind = "concourse"
	ZoneArena     ZoneKind = "arena"
	ZoneStand     ZoneKind = "stand"
	ZoneStage     ZoneKind = "stage"
	ZonePit       ZoneKind = "pit"
	ZoneLounge    ZoneKind = "lounge"
	ZoneBackstage ZoneKind = "backstage"
	ZoneCampsite  ZoneKind = "campsite"
	ZoneFoodCourt ZoneKind = "food-court"
	ZoneParking   ZoneKind = "parking"
	ZoneService   ZoneKind = "service" // crew-only working areas
)

// Point is a position on the venue map in map units. The origin is the top
// left and Y grows downward, matching SVG, so the attendee app draws the whole
// venue without transforming anything.
type Point struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// Polygon is a closed ring of points describing a footprint. Three points
// minimum; the ring closes implicitly, so the first point is not repeated.
type Polygon []Point

// Zone is an area an attendee can be inside.
type Zone struct {
	Code ZoneCode `json:"code"`
	Name string   `json:"name"`
	Kind ZoneKind `json:"kind"`

	// Parent nests this zone inside another. Nesting is what makes tier grants
	// tractable: granting "arena" grants everything inside the arena, so a VIP
	// tier does not need editing when the organizer adds a bar next week.
	Parent ZoneCode `json:"parent,omitempty"`

	// Restricted stops this zone, and everything nested inside it, from being
	// inherited by a grant on an ancestor. It has to be granted by name.
	//
	// Without this flag the convenience of cascading grants becomes a security
	// hole the first time somebody nests the backstage inside the perimeter:
	// every general-admission ticket would inherit it. The rule is that
	// cascading is for convenience among peers and restricted zones opt out, so
	// the dangerous direction always fails closed.
	Restricted bool `json:"restricted,omitempty"`

	// Capacity is the zone's safe occupancy. Zero means unstated, which is
	// honest for an open field and a lie for a room; the dashboard shows an
	// occupancy meter only for zones that declare a number. For a zone whose
	// sections are fully seated, Compile fills this in from the seat count if
	// the organizer left it blank.
	Capacity int `json:"capacity,omitempty"`

	// Shape is the zone's footprint. Optional: a venue with no floor plan still
	// runs an event, it just has no map view.
	Shape Polygon `json:"shape,omitempty"`

	// Colour overrides the kind's default map colour, so the map can match the
	// organizer's own signage. This matters more than it sounds: an attendee
	// told to find the green gate should see a green gate.
	Colour string `json:"colour,omitempty"`
}

// SectionKind is how people occupy a section, which decides whether tickets in
// it carry a seat and how the map draws it.
type SectionKind string

// The section kinds.
const (
	// SectionSeated has numbered rows and seats. Tickets carry a seat.
	SectionSeated SectionKind = "seated"

	// SectionStanding is a pit or a lawn: capacity, no seat numbers.
	SectionStanding SectionKind = "standing"

	// SectionTable is cabaret or club seating: named tables with a headcount
	// each, so a ticket carries a table but not a seat within it.
	SectionTable SectionKind = "table"

	// SectionBox is a private box, sold whole. Occupancy is the box's capacity.
	SectionBox SectionKind = "box"
)

// Seated reports whether tickets in a section of this kind carry a specific
// seat.
func (k SectionKind) Seated() bool { return k == SectionSeated || k == SectionTable }

// SeatKind describes an individual seat, mostly so the attendee app can be
// honest about it before someone buys.
type SeatKind string

// The seat kinds.
const (
	SeatStandard SeatKind = "standard"

	// SeatAccessible is a wheelchair space. Reached by a step-free route by
	// definition, which the router asserts rather than assumes.
	SeatAccessible SeatKind = "accessible"

	// SeatCompanion sits beside an accessible space and is sold with it.
	SeatCompanion SeatKind = "companion"

	// SeatRestricted has a pillar, a speaker stack or a camera platform in the
	// way. Saying so up front is worth more than the seat's face value.
	SeatRestricted SeatKind = "restricted-view"
)

// Seat is one numbered place to sit.
type Seat struct {
	// Number is the seat label as printed on the seat itself. A string, not an
	// integer, because real venues number seats "1", "1A", "12B" and "R2-04",
	// and an integer would quietly renumber somebody's row.
	Number string `json:"number"`

	Kind SeatKind `json:"kind,omitempty"`

	// Position is the seat's location on the map. Optional in bulk-generated
	// rows, where Compile lays seats out along the row's own geometry.
	Position Point `json:"position,omitzero"`

	// Blocked takes the seat out of sale and out of occupancy without deleting
	// it: broken seats, sightline kills, and the seats a sound desk eats.
	Blocked bool `json:"blocked,omitempty"`

	// Note is shown to the holder. "Behind the mix position", "step up on
	// entry", "sold as a pair".
	Note string `json:"note,omitempty"`
}

// Row is a line of seats within a section.
type Row struct {
	// Label is the row as printed, again a string: rows go "A".."Z" then "AA",
	// and some venues skip I and O on purpose.
	Label string `json:"label"`

	Seats []Seat `json:"seats,omitempty"`

	// Start and End describe the row's geometry. When Seats carry no positions,
	// Compile spaces them evenly along this segment, which is how a
	// two-thousand-seat stand is authored in a few dozen lines instead of two
	// thousand.
	Start Point `json:"start,omitzero"`
	End   Point `json:"end,omitzero"`

	// Curve bows the row, in map units of sagitta. Zero is a straight row.
	//
	// A positive value bows to the left of the direction of travel from Start to
	// End, negative to the right. For a row authored left to right in a stand
	// facing a stage at the top of the map, positive curves towards the stage,
	// which is how real stands are built; a seat map that draws them straight is
	// immediately recognisable as fake.
	Curve float64 `json:"curve,omitempty"`

	// Aisle is the walk-graph node an attendee arrives at to enter this row,
	// normally the aisle at one end. Optional; Compile falls back to the
	// section's own node.
	Aisle NodeID `json:"aisle,omitempty"`
}

// Section is a seating block, a standing pit, a set of tables or a box.
type Section struct {
	Code SectionCode `json:"code"`
	Name string      `json:"name"`
	Kind SectionKind `json:"kind"`

	// Zone the section sits inside. Access to a section is exactly access to
	// its zone: sections are geometry and inventory, zones are permission.
	Zone ZoneCode `json:"zone"`

	Rows []Row `json:"rows,omitempty"`

	// Capacity is used for standing and box sections, where there are no seats
	// to count.
	Capacity int `json:"capacity,omitempty"`

	Shape  Polygon `json:"shape,omitempty"`
	Colour string  `json:"colour,omitempty"`

	// Entrances are the checkpoints that serve this section: the vomitories,
	// portals or gates an attendee for this block should be sent to. The router
	// prefers whichever of these is closest along the walk graph, and the
	// scanner uses the list to tell someone at the wrong portal where to go.
	Entrances []CheckpointCode `json:"entrances,omitempty"`

	// Node is where the section attaches to the walk graph, used when a row
	// declares no aisle of its own.
	Node NodeID `json:"node,omitempty"`

	// ViewNote is shown to every holder in the section: "standing only",
	// "restricted view", "no re-entry after the interval".
	ViewNote string `json:"view_note,omitempty"`
}

// SeatRef points at one specific place to sit. It is what a seated ticket
// carries and what the scanner shouts at the usher.
type SeatRef struct {
	Section SectionCode `json:"section"`
	Row     string      `json:"row,omitempty"`
	Seat    string      `json:"seat,omitempty"`
}

// IsZero reports whether the reference is unset, which is the normal state for
// a general-admission ticket.
func (r SeatRef) IsZero() bool { return r.Section == "" && r.Row == "" && r.Seat == "" }

// String renders the reference the way the scanner shows it and the way an
// usher says it out loud.
func (r SeatRef) String() string {
	switch {
	case r.IsZero():
		return ""
	case r.Row == "" && r.Seat == "":
		return string(r.Section)
	case r.Seat == "":
		return string(r.Section) + " row " + r.Row
	default:
		return string(r.Section) + " row " + r.Row + " seat " + r.Seat
	}
}

// Direction is which way a checkpoint moves an attendee.
type Direction string

// The three checkpoint directions.
const (
	// DirectionIn admits into the checkpoint's zone.
	DirectionIn Direction = "in"

	// DirectionOut releases from the checkpoint's zone, which is how occupancy
	// stays honest on a room with a hard capacity.
	DirectionOut Direction = "out"

	// DirectionBoth is one physical door doing both, with the scanner showing
	// an in/out toggle. Common in practice and a frequent source of miscounts
	// in systems that do not model it.
	DirectionBoth Direction = "both"
)

// Policy is how many times one ticket may pass one checkpoint.
type Policy string

// The three checkpoint policies.
const (
	// PolicyOnce is the classic turnstile: one ticket, one admission, ever.
	// This is the policy the exactly-once guarantee is stated over.
	PolicyOnce Policy = "once"

	// PolicyReEntry allows unlimited passes, alternating in and out. The food
	// court, the campsite and the smoking area, where stepping out and coming
	// back is not an offence.
	PolicyReEntry Policy = "re-entry"

	// PolicyCounted allows a fixed number of passes: drink tokens, meal
	// vouchers, "two guest passes per artist".
	PolicyCounted Policy = "counted"
)

// Checkpoint is a place where a ticket is scanned.
type Checkpoint struct {
	Code CheckpointCode `json:"code"`
	Name string         `json:"name"`

	// Zone this checkpoint controls. An "in" checkpoint admits into it, an
	// "out" checkpoint releases from it.
	Zone ZoneCode `json:"zone"`

	Direction Direction `json:"direction"`
	Policy    Policy    `json:"policy"`

	// CountLimit is the number of passes allowed under PolicyCounted, ignored
	// otherwise.
	CountLimit int `json:"count_limit,omitempty"`

	// Requires lists zones the ticket must already have been admitted into
	// before this checkpoint will admit it. This is the sequencing rule: the
	// pit requires the arena, the backstage stairs require the backstage
	// corridor, and anyone appearing at the pit without having entered the
	// arena is either lost or over a fence.
	//
	// A prerequisite is satisfied by an admission into the named zone or into
	// any zone nested inside it.
	Requires []ZoneCode `json:"requires,omitempty"`

	// Tiers restricts which tiers this checkpoint serves, on top of the tier's
	// zone entitlement. Empty means every entitled tier.
	//
	// Entitlement and routing are different questions. A VIP is entitled to the
	// arena, but the organizer may still want VIPs through the VIP door so the
	// general queue stays short, and staff at the general door should be able to
	// say "wrong door, go left" instead of "denied".
	Tiers []TierCode `json:"tiers,omitempty"`

	// Sections restricts the checkpoint to holders of specific sections, which
	// is what a stadium vomitory is: Portal C serves Blocks C1 to C4 and
	// nothing else.
	Sections []SectionCode `json:"sections,omitempty"`

	// OpensAt and ClosesAt bound when the checkpoint accepts scans. Zero means
	// unbounded. A closed checkpoint gets its own verdict rather than a flat
	// denial, because "doors are not open yet" is not the attendee's fault and
	// staff need to say something different.
	OpensAt  time.Time `json:"opens_at,omitzero"`
	ClosesAt time.Time `json:"closes_at,omitzero"`

	Position Point `json:"position,omitzero"`

	// Node is the checkpoint's vertex in the walk graph. Routes start here.
	Node NodeID `json:"node,omitempty"`

	// Lane labels which physical lane of a multi-lane gate this is. It is
	// printed on the scanner's home screen so staff can confirm the device in
	// their hand belongs to the door they are standing at.
	Lane string `json:"lane,omitempty"`
}

// Tier is a ticket class and the zones it entitles the holder to.
type Tier struct {
	Code TierCode `json:"code"`
	Name string   `json:"name"`

	// Zones the tier may enter. A grant on a parent zone covers every
	// descendant.
	Zones []ZoneCode `json:"zones"`

	// Colour is the tier's wristband colour, rendered as the dominant band on
	// the scanner's verdict screen. Gate staff match the screen against the
	// physical wristband without reading anything, which is the only check that
	// works reliably at two in the morning.
	Colour string `json:"colour,omitempty"`

	// Priority orders tiers in the dashboard and decides who a targeted mesh
	// announcement reaches first. Higher is more privileged.
	Priority int `json:"priority,omitempty"`
}

// AmenityKind is what an attendee is looking for. The set is closed because
// each kind has a hand-drawn icon in the attendee app; an open string would
// render as a blank pin, which is worse than not showing it at all.
type AmenityKind string

// The amenity kinds the attendee app can draw.
const (
	AmenityWashroom   AmenityKind = "washroom"
	AmenityFood       AmenityKind = "food"
	AmenityBar        AmenityKind = "bar"
	AmenityWater      AmenityKind = "water"
	AmenityMedical    AmenityKind = "medical"
	AmenityExit       AmenityKind = "exit"
	AmenityInfo       AmenityKind = "info"
	AmenityLostFound  AmenityKind = "lost-found"
	AmenityCharging   AmenityKind = "charging"
	AmenityATM        AmenityKind = "atm"
	AmenitySmoking    AmenityKind = "smoking"
	AmenityMerch      AmenityKind = "merch"
	AmenityCloakroom  AmenityKind = "cloakroom"
	AmenityAccessible AmenityKind = "accessible"
)

// Amenity is a point of interest on the venue map.
//
// This is the least glamorous table in the system and the one attendees use
// most. "Where is the nearest toilet" is the most common question at every
// event ever held, and answering it offline, routed, on a phone with no bars,
// is something nobody else at this price point offers.
type Amenity struct {
	ID   string      `json:"id"`
	Kind AmenityKind `json:"kind"`
	Name string      `json:"name"`

	// Zone the amenity sits inside. Used to hide amenities an attendee cannot
	// reach: showing a backstage toilet to a general-admission holder is a
	// small cruelty.
	Zone ZoneCode `json:"zone"`

	Position Point `json:"position"`

	// Node attaches the amenity to the walk graph so it can be routed to
	// rather than merely pinned. Optional; Compile snaps it to the nearest node
	// in its own zone when unset.
	Node NodeID `json:"node,omitempty"`

	Note string `json:"note,omitempty"`

	// Accessible marks step-free access, an accessible stall or a lowered
	// counter. Attendees filter on this and the filter has to be honest, so an
	// unset value renders as "not stated" rather than as "no".
	Accessible bool `json:"accessible,omitempty"`

	// OpenFrom and OpenTo bound the amenity's hours. The food court closing at
	// 1am is something an attendee at 1:05am would have liked to know.
	OpenFrom time.Time `json:"open_from,omitzero"`
	OpenTo   time.Time `json:"open_to,omitzero"`
}

// NodeKind classifies a walk-graph vertex. The router uses it to write
// turn-by-turn directions that sound like a human wrote them, and the
// accessibility filter uses it to refuse stairs.
type NodeKind string

// The walk-graph node kinds.
const (
	NodeGate      NodeKind = "gate"
	NodeConcourse NodeKind = "concourse"
	NodePortal    NodeKind = "portal" // the vomitory where a stand opens up
	NodeAisle     NodeKind = "aisle"
	NodeStair     NodeKind = "stair"
	NodeLift      NodeKind = "lift"
	NodeRamp      NodeKind = "ramp"
	NodeAmenity   NodeKind = "amenity"
	NodeSeatBlock NodeKind = "seat-block"
	NodeJunction  NodeKind = "junction"
)

// Node is a vertex in the walk graph: a place you can stand on the way to
// somewhere else.
type Node struct {
	ID       NodeID   `json:"id"`
	Kind     NodeKind `json:"kind"`
	Position Point    `json:"position"`

	// Zone the node sits in. Routing never crosses into a zone the attendee is
	// not entitled to, which is what stops the app from cheerfully directing a
	// general-admission holder through backstage because it is shorter.
	Zone ZoneCode `json:"zone,omitempty"`

	// Name is a human landmark used in directions: "north concourse", "portal
	// C", "the big screen".
	Name string `json:"name,omitempty"`

	// Level is the floor or tier. Used to say "up one level" and to notice that
	// a route without a lift is not step-free.
	Level int `json:"level,omitempty"`
}

// EdgeKind classifies a walk-graph edge, which decides the wording of the
// direction and whether the step-free router will use it.
type EdgeKind string

// The walk-graph edge kinds.
const (
	EdgeWalk  EdgeKind = "walk"
	EdgeStair EdgeKind = "stair"
	EdgeLift  EdgeKind = "lift"
	EdgeRamp  EdgeKind = "ramp"
	EdgeDoor  EdgeKind = "door"
)

// StepFree reports whether this kind of edge can be used by someone who cannot
// take stairs.
func (k EdgeKind) StepFree() bool { return k != EdgeStair }

// Edge joins two nodes. Edges are bidirectional unless OneWay is set, because
// almost every corridor is, and the exceptions are the interesting part: a
// one-way exit stair during egress, a turnstile you cannot walk back through.
type Edge struct {
	From NodeID   `json:"from"`
	To   NodeID   `json:"to"`
	Kind EdgeKind `json:"kind,omitempty"`

	// Distance in map units. Zero means "compute it from the node positions",
	// which is what almost every edge does; an explicit value is for the cases
	// where the straight line lies, such as a ramp that switches back twice.
	Distance float64 `json:"distance,omitempty"`

	// Cost multiplies the distance for routing purposes without changing the
	// distance reported to the attendee. This is how a narrow corridor that
	// jams at doors-close gets deprioritised: the honest metres stay honest,
	// but the router stops sending everybody down it.
	Cost float64 `json:"cost,omitempty"`

	OneWay bool `json:"one_way,omitempty"`

	// Note is surfaced in the direction: "through the double doors", "past the
	// merch stand".
	Note string `json:"note,omitempty"`
}

// Map is the venue's drawable, walkable floor plan. Every Point in the plan is
// in this map's units.
type Map struct {
	Width  float64 `json:"width"`
	Height float64 `json:"height"`

	// Outline is the venue boundary, drawn under everything else.
	Outline Polygon `json:"outline,omitempty"`

	// Stage is the thing everybody orients by. Drawn distinctly and used as the
	// reference for row curvature and for "facing the stage" in directions.
	Stage Polygon `json:"stage,omitempty"`

	// Nodes and Edges are the walk graph. A venue may omit them, in which case
	// the map still draws and wayfinding degrades to naming the right gate and
	// section without turn-by-turn steps.
	Nodes []Node `json:"nodes,omitempty"`
	Edges []Edge `json:"edges,omitempty"`

	// MetresPerUnit converts map units to metres so the app can say "about 120
	// metres" and "roughly a three minute walk". Zero means distances are shown
	// in relative terms only, which is better than inventing a scale.
	MetresPerUnit float64 `json:"metres_per_unit,omitempty"`

	// NorthDegrees rotates the compass rose. Attendees orient off landmarks
	// rather than north, but crew radioing "the north gate" need the map to
	// agree with them.
	NorthDegrees float64 `json:"north_degrees,omitempty"`
}

// Plan is the authoring form of a venue: flat lists, no indexes, exactly what
// an organizer writes in JSON and what the presale service embeds in a signed
// manifest. Compile turns it into a Venue.
type Plan struct {
	Zones       []Zone       `json:"zones"`
	Sections    []Section    `json:"sections,omitempty"`
	Checkpoints []Checkpoint `json:"checkpoints"`
	Tiers       []Tier       `json:"tiers"`
	Amenities   []Amenity    `json:"amenities,omitempty"`
	Map         Map          `json:"map,omitzero"`
}

// normalizeCode lowercases and trims a code. Codes are compared exactly
// everywhere else, so normalising once at compile time is what stops "Gate-3"
// and "gate-3" from becoming two different doors.
func normalizeCode(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// validCode reports whether a code is safe to put in a URL, a QR payload, a
// printed sign and a SQLite row. Deliberately narrow.
func validCode(s string) bool {
	if s == "" || len(s) > 48 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// codeError formats the one error shape this package's validation produces.
func codeError(kind, code, why string) error {
	return fmt.Errorf("venue: %s %q: %s", kind, code, why)
}
