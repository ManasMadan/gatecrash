package venue

import "time"

// testPlan is a small but structurally complete venue: an outer perimeter, a
// concourse, a seated arena with two blocks on two levels, a pit that requires
// the arena, and a backstage nobody but crew sees. It exists because every
// interesting behaviour in this package is about the relationships between
// those things, and a plan with one gate proves nothing.
//
//	         ┌──────────────── perimeter ────────────────┐
//	gate-north ──► concourse ──► portal-lower ──► block-a (level 0)
//	                    │  └──► stairs ──► portal-upper ──► block-b (level 1)
//	                    │  └──► lift ────► portal-upper
//	                    └──► pit-gate ──► pit   (requires: arena)
//	                    └──► stage-door ──► backstage  (crew only)
func testPlan() Plan {
	doors := time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)
	curfew := time.Date(2026, 8, 22, 1, 0, 0, 0, time.UTC)

	return Plan{
		Zones: []Zone{
			{Code: "perimeter", Name: "Festival Ground", Kind: ZonePerimeter, Capacity: 6000},
			{Code: "concourse", Name: "Main Concourse", Kind: ZoneConcourse, Parent: "perimeter"},
			{Code: "arena", Name: "Arena", Kind: ZoneArena, Parent: "perimeter", Restricted: true},
			{Code: "pit", Name: "Front Pit", Kind: ZonePit, Parent: "arena", Capacity: 400, Restricted: true},
			{Code: "backstage", Name: "Backstage", Kind: ZoneBackstage, Parent: "perimeter", Capacity: 60, Restricted: true},
		},
		Sections: []Section{
			{
				Code: "block-a", Name: "Block A", Kind: SectionSeated, Zone: "arena",
				Entrances: []CheckpointCode{"portal-lower"}, Node: "n-portal-lower",
				Rows: []Row{
					{Label: "A", Start: Point{X: 40, Y: 60}, End: Point{X: 90, Y: 60}, Curve: 4, Aisle: "n-aisle-a", Seats: numberedSeats(6)},
					{Label: "B", Start: Point{X: 40, Y: 68}, End: Point{X: 90, Y: 68}, Curve: 4, Aisle: "n-aisle-a", Seats: numberedSeats(6)},
				},
			},
			{
				Code: "block-b", Name: "Block B", Kind: SectionSeated, Zone: "arena",
				Entrances: []CheckpointCode{"portal-upper"}, Node: "n-portal-upper",
				ViewNote: "Upper tier, behind the mix position",
				Rows: []Row{
					{Label: "A", Start: Point{X: 40, Y: 20}, End: Point{X: 90, Y: 20}, Aisle: "n-aisle-b", Seats: []Seat{
						{Number: "1"},
						{Number: "2", Kind: SeatRestricted, Note: "Pillar on the left"},
						{Number: "3", Blocked: true},
						{Number: "4", Kind: SeatAccessible},
					}},
				},
			},
			{Code: "golden-circle", Name: "Golden Circle", Kind: SectionStanding, Zone: "pit", Capacity: 400, Node: "n-pit"},
		},
		Checkpoints: []Checkpoint{
			{
				Code: "gate-north", Name: "North Gate", Zone: "perimeter", Direction: DirectionIn,
				Policy: PolicyOnce, Position: Point{X: 10, Y: 100}, Node: "n-gate-north", Lane: "1",
				OpensAt: doors, ClosesAt: curfew,
			},
			{
				Code: "gate-south", Name: "South Gate", Zone: "perimeter", Direction: DirectionIn,
				Policy: PolicyOnce, Position: Point{X: 120, Y: 100}, Node: "n-gate-south", Lane: "1",
			},
			{
				Code: "portal-lower", Name: "Portal C Lower", Zone: "arena", Direction: DirectionIn,
				Policy: PolicyOnce, Requires: []ZoneCode{"perimeter"}, Sections: []SectionCode{"block-a"},
				Node: "n-portal-lower", Position: Point{X: 65, Y: 80},
			},
			{
				Code: "portal-upper", Name: "Portal C Upper", Zone: "arena", Direction: DirectionIn,
				Policy: PolicyOnce, Requires: []ZoneCode{"perimeter"}, Sections: []SectionCode{"block-b"},
				Node: "n-portal-upper", Position: Point{X: 65, Y: 30},
			},
			{
				Code: "pit-gate", Name: "Pit Wristband Check", Zone: "pit", Direction: DirectionIn,
				Policy: PolicyOnce, Requires: []ZoneCode{"arena"}, Tiers: []TierCode{"vip", "crew"},
				Node: "n-pit", Position: Point{X: 65, Y: 55},
			},
			{
				Code: "stage-door", Name: "Stage Door", Zone: "backstage", Direction: DirectionIn,
				Policy: PolicyOnce, Requires: []ZoneCode{"perimeter"}, Tiers: []TierCode{"crew"},
				Node: "n-backstage",
			},
			{
				Code: "food-court", Name: "Food Court", Zone: "concourse", Direction: DirectionBoth,
				Policy: PolicyReEntry, Requires: []ZoneCode{"perimeter"}, Node: "n-concourse",
			},
			{
				Code: "bar-token", Name: "Bar Token", Zone: "concourse", Direction: DirectionIn,
				Policy: PolicyCounted, CountLimit: 2, Requires: []ZoneCode{"perimeter"}, Node: "n-concourse",
			},
			{Code: "gate-north-out", Name: "North Gate Exit", Zone: "perimeter", Direction: DirectionOut, Policy: PolicyReEntry, Node: "n-gate-north"},
		},
		Tiers: []Tier{
			{Code: "ga", Name: "General Admission", Zones: []ZoneCode{"perimeter", "arena"}, Colour: "#3B82F6", Priority: 10},
			{Code: "vip", Name: "VIP", Zones: []ZoneCode{"perimeter", "arena", "pit"}, Colour: "#A855F7", Priority: 20},
			{Code: "crew", Name: "Crew", Zones: []ZoneCode{"perimeter", "backstage"}, Colour: "#F59E0B", Priority: 90},
		},
		Amenities: []Amenity{
			{ID: "wc-concourse", Kind: AmenityWashroom, Name: "Concourse Toilets", Zone: "concourse", Position: Point{X: 55, Y: 92}, Node: "n-concourse", Accessible: true},
			{ID: "wc-upper", Kind: AmenityWashroom, Name: "Upper Toilets", Zone: "arena", Position: Point{X: 70, Y: 26}, Node: "n-portal-upper"},
			{ID: "wc-backstage", Kind: AmenityWashroom, Name: "Backstage Toilets", Zone: "backstage", Position: Point{X: 130, Y: 20}, Node: "n-backstage"},
			{
				ID: "food-1", Kind: AmenityFood, Name: "Biryani Cart", Zone: "concourse", Position: Point{X: 50, Y: 95}, Node: "n-concourse",
				OpenFrom: doors, OpenTo: time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC),
			},
			{ID: "medical-1", Kind: AmenityMedical, Name: "Medical Tent", Zone: "concourse", Position: Point{X: 20, Y: 95}, Node: "n-concourse", Accessible: true},
			{ID: "water-1", Kind: AmenityWater, Name: "Water Point", Zone: "arena", Position: Point{X: 45, Y: 75}, Node: "n-portal-lower"},
		},
		Map: Map{
			Width: 160, Height: 120, MetresPerUnit: 1.5,
			Stage:   Polygon{{X: 40, Y: 5}, {X: 90, Y: 5}, {X: 90, Y: 14}, {X: 40, Y: 14}},
			Outline: Polygon{{X: 0, Y: 0}, {X: 160, Y: 0}, {X: 160, Y: 120}, {X: 0, Y: 120}},
			Nodes: []Node{
				{ID: "n-gate-north", Kind: NodeGate, Name: "North Gate", Position: Point{X: 10, Y: 100}},
				{ID: "n-gate-south", Kind: NodeGate, Name: "South Gate", Position: Point{X: 120, Y: 100}},
				{ID: "n-concourse", Kind: NodeConcourse, Name: "the concourse", Zone: "concourse", Position: Point{X: 65, Y: 95}},
				{ID: "n-portal-lower", Kind: NodePortal, Name: "Portal C Lower", Zone: "arena", Position: Point{X: 65, Y: 80}},
				{ID: "n-stairs-top", Kind: NodeStair, Name: "the upper landing", Zone: "arena", Position: Point{X: 100, Y: 60}, Level: 1},
				{ID: "n-lift-top", Kind: NodeLift, Name: "the upper landing", Zone: "arena", Position: Point{X: 104, Y: 60}, Level: 1},
				{ID: "n-portal-upper", Kind: NodePortal, Name: "Portal C Upper", Zone: "arena", Position: Point{X: 65, Y: 30}, Level: 1},
				{ID: "n-aisle-a", Kind: NodeAisle, Name: "Block A aisle", Zone: "arena", Position: Point{X: 38, Y: 64}},
				{ID: "n-aisle-b", Kind: NodeAisle, Name: "Block B aisle", Zone: "arena", Position: Point{X: 38, Y: 20}, Level: 1},
				{ID: "n-pit", Kind: NodeSeatBlock, Name: "the pit", Zone: "pit", Position: Point{X: 65, Y: 55}},
				{ID: "n-backstage", Kind: NodeJunction, Name: "backstage", Zone: "backstage", Position: Point{X: 130, Y: 20}},
			},
			Edges: []Edge{
				{From: "n-gate-north", To: "n-concourse", Kind: EdgeWalk},
				{From: "n-gate-south", To: "n-concourse", Kind: EdgeWalk},
				{From: "n-concourse", To: "n-portal-lower", Kind: EdgeDoor, Note: "through the double doors"},
				{From: "n-concourse", To: "n-stairs-top", Kind: EdgeStair},
				{From: "n-concourse", To: "n-lift-top", Kind: EdgeLift},
				{From: "n-stairs-top", To: "n-portal-upper", Kind: EdgeWalk},
				{From: "n-lift-top", To: "n-portal-upper", Kind: EdgeWalk},
				{From: "n-portal-lower", To: "n-aisle-a", Kind: EdgeWalk},
				{From: "n-portal-upper", To: "n-aisle-b", Kind: EdgeWalk},
				{From: "n-portal-lower", To: "n-pit", Kind: EdgeWalk},
				{From: "n-concourse", To: "n-backstage", Kind: EdgeWalk},
			},
		},
	}
}

// numberedSeats builds a straightforward run of standard seats.
func numberedSeats(n int) []Seat {
	seats := make([]Seat, 0, n)
	for i := 1; i <= n; i++ {
		seats = append(seats, Seat{Number: itoa(i)})
	}
	return seats
}

// itoa avoids pulling strconv into a fixture for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
