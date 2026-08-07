package venue

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func compileTestVenue(t *testing.T) *Venue {
	t.Helper()
	v, err := Compile(testPlan())
	if err != nil {
		t.Fatalf("the test plan does not compile: %v", err)
	}
	return v
}

func TestCompileAcceptsTheReferencePlan(t *testing.T) {
	v := compileTestVenue(t)
	if len(v.Zones()) != 5 || len(v.Sections()) != 3 || len(v.Tiers()) != 3 {
		t.Fatalf("compiled %d zones, %d sections, %d tiers", len(v.Zones()), len(v.Sections()), len(v.Tiers()))
	}
	if !v.HasMap() || !v.HasWalkGraph() {
		t.Fatal("the reference plan should carry both a map and a walk graph")
	}
}

func TestCompileNormalizesCodes(t *testing.T) {
	plan := testPlan()
	plan.Zones[0].Code = "  PERIMETER  "
	for i := range plan.Checkpoints {
		if plan.Checkpoints[i].Zone == "perimeter" {
			plan.Checkpoints[i].Zone = "Perimeter"
		}
	}
	for i := range plan.Tiers {
		for j := range plan.Tiers[i].Zones {
			if plan.Tiers[i].Zones[j] == "perimeter" {
				plan.Tiers[i].Zones[j] = "PERIMETER "
			}
		}
	}
	for i := range plan.Zones {
		if plan.Zones[i].Parent == "perimeter" {
			plan.Zones[i].Parent = "PERIMETER"
		}
	}

	v, err := Compile(plan)
	if err != nil {
		t.Fatalf("normalisation should have made this plan valid: %v", err)
	}
	if _, ok := v.Zone("perimeter"); !ok {
		t.Fatal("zone code was not normalised to lowercase")
	}
}

// TestCompileRejectsBrokenPlans is the bulk of this package's value. A venue
// plan is authored days before doors by somebody who will not be reading logs
// during the event, so every one of these has to fail loudly at compile time
// rather than quietly at a gate at 8pm.
func TestCompileRejectsBrokenPlans(t *testing.T) {
	for name, break_ := range map[string]func(*Plan){
		"no zones":      func(p *Plan) { p.Zones = nil },
		"no tiers":      func(p *Plan) { p.Tiers = nil },
		"no gates":      func(p *Plan) { p.Checkpoints = nil },
		"bad zone code": func(p *Plan) { p.Zones[0].Code = "Main Arena!" },
		"duplicate zone": func(p *Plan) {
			p.Zones = append(p.Zones, Zone{Code: "arena", Name: "Arena Again"})
		},
		"missing parent":     func(p *Plan) { p.Zones[1].Parent = "nowhere" },
		"self parent":        func(p *Plan) { p.Zones[1].Parent = p.Zones[1].Code },
		"negative capacity":  func(p *Plan) { p.Zones[0].Capacity = -1 },
		"two point shape":    func(p *Plan) { p.Zones[0].Shape = Polygon{{}, {}} },
		"checkpoint no zone": func(p *Plan) { p.Checkpoints[0].Zone = "nowhere" },
		"duplicate checkpoint": func(p *Plan) {
			p.Checkpoints = append(p.Checkpoints, Checkpoint{Code: "gate-north", Zone: "perimeter"})
		},
		"requires missing zone": func(p *Plan) { p.Checkpoints[2].Requires = []ZoneCode{"nowhere"} },
		"requires own zone": func(p *Plan) {
			p.Checkpoints[2].Requires = []ZoneCode{p.Checkpoints[2].Zone}
		},
		"unknown direction": func(p *Plan) { p.Checkpoints[0].Direction = "sideways" },
		"unknown policy":    func(p *Plan) { p.Checkpoints[0].Policy = "sometimes" },
		"once with a limit": func(p *Plan) { p.Checkpoints[0].CountLimit = 3 },
		"counted with no limit": func(p *Plan) {
			p.Checkpoints[0].Policy = PolicyCounted
		},
		"re-entry one way": func(p *Plan) {
			p.Checkpoints[0].Policy = PolicyReEntry
		},
		"closes before it opens": func(p *Plan) {
			p.Checkpoints[0].ClosesAt = p.Checkpoints[0].OpensAt.Add(-time.Hour)
		},
		"checkpoint unknown tier":    func(p *Plan) { p.Checkpoints[4].Tiers = []TierCode{"ghost"} },
		"checkpoint unknown section": func(p *Plan) { p.Checkpoints[2].Sections = []SectionCode{"ghost"} },
		"checkpoint unknown node":    func(p *Plan) { p.Checkpoints[0].Node = "ghost" },
		"tier with no zones":         func(p *Plan) { p.Tiers[0].Zones = nil },
		"tier unknown zone":          func(p *Plan) { p.Tiers[0].Zones = []ZoneCode{"nowhere"} },
		"duplicate tier": func(p *Plan) {
			p.Tiers = append(p.Tiers, Tier{Code: "ga", Zones: []ZoneCode{"perimeter"}})
		},
		"section unknown zone": func(p *Plan) { p.Sections[0].Zone = "nowhere" },
		"seated with no rows": func(p *Plan) {
			p.Sections[0].Rows = nil
		},
		"standing with no capacity": func(p *Plan) { p.Sections[2].Capacity = 0 },
		"unknown section kind":      func(p *Plan) { p.Sections[0].Kind = "hammock" },
		"row with no label":         func(p *Plan) { p.Sections[0].Rows[0].Label = "" },
		"row with no seats":         func(p *Plan) { p.Sections[0].Rows[0].Seats = nil },
		"duplicate row": func(p *Plan) {
			p.Sections[0].Rows[1].Label = p.Sections[0].Rows[0].Label
		},
		"duplicate seat": func(p *Plan) {
			p.Sections[0].Rows[0].Seats[1].Number = p.Sections[0].Rows[0].Seats[0].Number
		},
		"seat with no number":  func(p *Plan) { p.Sections[0].Rows[0].Seats[0].Number = "" },
		"row unknown aisle":    func(p *Plan) { p.Sections[0].Rows[0].Aisle = "ghost" },
		"section unknown node": func(p *Plan) { p.Sections[0].Node = "ghost" },
		"entrance does not exist": func(p *Plan) {
			p.Sections[0].Entrances = []CheckpointCode{"ghost"}
		},
		"entrance is an exit": func(p *Plan) {
			p.Sections[0].Entrances = []CheckpointCode{"gate-north-out"}
		},
		"amenity unknown zone": func(p *Plan) { p.Amenities[0].Zone = "nowhere" },
		"amenity no kind":      func(p *Plan) { p.Amenities[0].Kind = "" },
		"duplicate amenity": func(p *Plan) {
			p.Amenities = append(p.Amenities, Amenity{ID: "wc-concourse", Kind: AmenityWashroom, Zone: "concourse"})
		},
		"amenity closes before it opens": func(p *Plan) {
			p.Amenities[3].OpenTo = p.Amenities[3].OpenFrom.Add(-time.Hour)
		},
		"amenity unknown node": func(p *Plan) { p.Amenities[0].Node = "ghost" },
		"duplicate node":       func(p *Plan) { p.Map.Nodes[1].ID = p.Map.Nodes[0].ID },
		"node unknown zone":    func(p *Plan) { p.Map.Nodes[2].Zone = "nowhere" },
		"edge unknown from":    func(p *Plan) { p.Map.Edges[0].From = "ghost" },
		"edge unknown to":      func(p *Plan) { p.Map.Edges[0].To = "ghost" },
		"edge to itself":       func(p *Plan) { p.Map.Edges[0].To = p.Map.Edges[0].From },
	} {
		plan := testPlan()
		break_(&plan)
		if _, err := Compile(plan); err == nil {
			t.Errorf("%s: Compile accepted a broken plan", name)
		}
	}
}

func TestCompileDetectsAZoneCycle(t *testing.T) {
	plan := testPlan()
	// perimeter -> arena -> perimeter
	plan.Zones[0].Parent = "arena"
	_, err := Compile(plan)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("got %v, want a parent cycle error", err)
	}
}

// TestTierGrantsCascadeIntoUnrestrictedZonesOnly pins the entitlement rule that
// matters most. Cascading grants are a convenience, and the first version of
// this package cascaded unconditionally: because the fixture nests the backstage
// inside the perimeter, every general-admission ticket inherited backstage
// access. Restricted zones exist so that the dangerous direction fails closed.
func TestTierGrantsCascadeIntoUnrestrictedZonesOnly(t *testing.T) {
	v := compileTestVenue(t)

	// The concourse is unrestricted and nested inside the perimeter, so a grant
	// on the perimeter reaches it. This is the convenience the cascade is for:
	// the organizer adds a concourse and nobody has to edit three tiers.
	if !v.TierAdmits("ga", "concourse") {
		t.Error("a grant on the perimeter should cascade into the unrestricted concourse")
	}
	if !v.TierAdmits("crew", "concourse") {
		t.Error("crew should reach the concourse through the perimeter grant")
	}

	// The pit and the backstage are restricted, so no ancestor grant reaches
	// them. Only a grant by name does.
	if v.TierAdmits("ga", "pit") {
		t.Error("general admission inherited the restricted pit")
	}
	if v.TierAdmits("ga", "backstage") {
		t.Error("general admission inherited the restricted backstage")
	}
	if !v.TierAdmits("vip", "pit") {
		t.Error("VIP is granted the pit by name and should have it")
	}
	if !v.TierAdmits("crew", "backstage") {
		t.Error("crew is granted the backstage by name and should have it")
	}

	// The arena is restricted too, which is what makes a ticket mean something:
	// the perimeter is the field, the arena is the thing you paid for.
	if v.TierAdmits("crew", "arena") {
		t.Error("crew inherited the ticketed arena from the perimeter grant")
	}
	if !v.TierAdmits("ga", "arena") {
		t.Error("general admission is granted the arena by name and should have it")
	}

	// Entitlement and routing are separate checks, so the pit is protected
	// twice: by entitlement above, and by the checkpoint's own tier list.
	if v.CheckpointServes("pit-gate", "ga", SeatRef{}) {
		t.Error("the pit checkpoint should not serve general admission")
	}
	if !v.CheckpointServes("pit-gate", "vip", SeatRef{}) {
		t.Error("the pit checkpoint should serve VIP")
	}
}

func TestSatisfiesZoneWalksUpTheTree(t *testing.T) {
	v := compileTestVenue(t)

	// Being in the pit means being in the arena, which means being inside the
	// perimeter. Being in the arena does not mean being in the pit.
	if !v.SatisfiesZone("pit", "arena") || !v.SatisfiesZone("pit", "perimeter") {
		t.Error("an admission into the pit should satisfy the arena and the perimeter")
	}
	if v.SatisfiesZone("arena", "pit") {
		t.Error("an admission into the arena should not satisfy the pit")
	}
	if !v.SatisfiesZone("arena", "arena") {
		t.Error("a zone should satisfy itself")
	}
}

func TestSeatsAreLaidOutAlongTheRowGeometry(t *testing.T) {
	v := compileTestVenue(t)
	section, ok := v.Section("block-a")
	if !ok {
		t.Fatal("block-a is missing")
	}
	row := section.Rows[0]

	if row.Seats[0].Position != (Point{X: 40, Y: 60}) {
		t.Errorf("first seat sits at %+v, want the row start", row.Seats[0].Position)
	}
	last := row.Seats[len(row.Seats)-1].Position
	if last != (Point{X: 90, Y: 60}) {
		t.Errorf("last seat sits at %+v, want the row end", last)
	}
	// Curve bows the row towards the stage, which is at the top of this map, so
	// the middle seats have a smaller Y than the ends.
	middle := row.Seats[len(row.Seats)/2].Position
	if middle.Y >= row.Seats[0].Position.Y {
		t.Errorf("row did not curve: middle seat Y %.2f is not above the ends at %.2f", middle.Y, row.Seats[0].Position.Y)
	}
	// Seats must stay in order along the row, or the drawn map interleaves them.
	for i := 1; i < len(row.Seats); i++ {
		if row.Seats[i].Position.X <= row.Seats[i-1].Position.X {
			t.Fatalf("seat %d is not to the right of seat %d", i, i-1)
		}
	}
}

func TestExplicitSeatPositionsSurviveLayout(t *testing.T) {
	plan := testPlan()
	plan.Sections[0].Rows[0].Seats[2].Position = Point{X: 999, Y: 999}
	v, err := Compile(plan)
	if err != nil {
		t.Fatal(err)
	}
	seat, ok := v.Seat(SeatRef{Section: "block-a", Row: "A", Seat: "3"})
	if !ok {
		t.Fatal("seat missing")
	}
	if seat.Position != (Point{X: 999, Y: 999}) {
		t.Fatalf("hand-placed seat was overwritten: %+v", seat.Position)
	}
}

func TestSectionCapacityExcludesBlockedSeats(t *testing.T) {
	v := compileTestVenue(t)

	// Block B has four seats, one of them blocked.
	if got := v.SectionCapacity("block-b"); got != 3 {
		t.Errorf("block-b capacity is %d, want 3 with the blocked seat excluded", got)
	}
	if got := v.SectionCapacity("block-a"); got != 12 {
		t.Errorf("block-a capacity is %d, want 12", got)
	}
	if got := v.SectionCapacity("golden-circle"); got != 400 {
		t.Errorf("standing capacity is %d, want the declared 400", got)
	}
}

func TestZoneCapacityIsDerivedFromSectionsWhenUnstated(t *testing.T) {
	v := compileTestVenue(t)
	arena, _ := v.Zone("arena")
	// The arena declares no capacity, so it should have picked up block-a plus
	// block-b, and nothing from the pit, which declares its own.
	if arena.Capacity != 15 {
		t.Errorf("derived arena capacity is %d, want 15", arena.Capacity)
	}
	pit, _ := v.Zone("pit")
	if pit.Capacity != 400 {
		t.Errorf("declared pit capacity was overwritten: %d", pit.Capacity)
	}
}

func TestValidateSeat(t *testing.T) {
	v := compileTestVenue(t)

	for name, tc := range map[string]struct {
		tier    TierCode
		ref     SeatRef
		wantErr bool
	}{
		"general admission has no seat": {tier: "ga", ref: SeatRef{}},
		"real seat":                     {tier: "ga", ref: SeatRef{Section: "block-a", Row: "A", Seat: "1"}},
		"standing section":              {tier: "vip", ref: SeatRef{Section: "golden-circle"}},
		"missing section":               {tier: "ga", ref: SeatRef{Section: "ghost", Row: "A", Seat: "1"}, wantErr: true},
		"missing row":                   {tier: "ga", ref: SeatRef{Section: "block-a", Row: "Z", Seat: "1"}, wantErr: true},
		"missing seat":                  {tier: "ga", ref: SeatRef{Section: "block-a", Row: "A", Seat: "99"}, wantErr: true},
		"blocked seat":                  {tier: "ga", ref: SeatRef{Section: "block-b", Row: "A", Seat: "3"}, wantErr: true},
		"seated section needs a row":    {tier: "ga", ref: SeatRef{Section: "block-a"}, wantErr: true},
		"seated section needs a seat":   {tier: "ga", ref: SeatRef{Section: "block-a", Row: "A"}, wantErr: true},
		"row on a standing section":     {tier: "vip", ref: SeatRef{Section: "golden-circle", Row: "A"}, wantErr: true},
		"tier not entitled":             {tier: "crew", ref: SeatRef{Section: "block-a", Row: "A", Seat: "1"}, wantErr: true},
	} {
		err := v.ValidateSeat(tc.tier, tc.ref)
		if tc.wantErr != (err != nil) {
			t.Errorf("%s: got %v, wantErr=%v", name, err, tc.wantErr)
		}
	}
}

func TestSeatRefString(t *testing.T) {
	for _, tc := range []struct {
		ref  SeatRef
		want string
	}{
		{SeatRef{}, ""},
		{SeatRef{Section: "golden-circle"}, "golden-circle"},
		{SeatRef{Section: "block-a", Row: "A"}, "block-a row A"},
		{SeatRef{Section: "block-a", Row: "A", Seat: "12"}, "block-a row A seat 12"},
	} {
		if got := tc.ref.String(); got != tc.want {
			t.Errorf("SeatRef%+v renders %q, want %q", tc.ref, got, tc.want)
		}
	}
}

func TestSectionEntrancesFallBackToTheZonesInboundGates(t *testing.T) {
	v := compileTestVenue(t)
	// golden-circle names no entrances, so it should inherit the pit's inbound
	// checkpoints and not the exit.
	got := v.SectionEntrances("golden-circle")
	if len(got) != 1 || got[0] != "pit-gate" {
		t.Fatalf("inferred entrances %v, want [pit-gate]", got)
	}
	// block-a names one explicitly and should keep it.
	if got := v.SectionEntrances("block-a"); len(got) != 1 || got[0] != "portal-lower" {
		t.Fatalf("explicit entrances %v, want [portal-lower]", got)
	}
}

func TestCheckpointOpeningHours(t *testing.T) {
	v := compileTestVenue(t)
	doors := time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)

	if v.CheckpointOpen("gate-north", doors.Add(-time.Minute)) {
		t.Error("north gate accepted a scan before doors")
	}
	if !v.CheckpointOpen("gate-north", doors.Add(time.Hour)) {
		t.Error("north gate refused a scan during the event")
	}
	if v.CheckpointOpen("gate-north", doors.Add(20*time.Hour)) {
		t.Error("north gate accepted a scan after curfew")
	}
	// An unbounded checkpoint is always open.
	if !v.CheckpointOpen("gate-south", doors.Add(-100*time.Hour)) {
		t.Error("an unbounded checkpoint should always be open")
	}
}

func TestCheckpointServesFiltersOnSectionAndTier(t *testing.T) {
	v := compileTestVenue(t)

	blockA := SeatRef{Section: "block-a", Row: "A", Seat: "1"}
	blockB := SeatRef{Section: "block-b", Row: "A", Seat: "1"}

	if !v.CheckpointServes("portal-lower", "ga", blockA) {
		t.Error("portal-lower should serve a block-a holder")
	}
	if v.CheckpointServes("portal-lower", "ga", blockB) {
		t.Error("portal-lower should not serve a block-b holder")
	}
	// A section-restricted portal cannot serve a ticket with no seat at all.
	if v.CheckpointServes("portal-lower", "ga", SeatRef{}) {
		t.Error("a section-restricted portal served a seatless ticket")
	}
	// An unrestricted gate serves everyone entitled.
	if !v.CheckpointServes("gate-north", "ga", SeatRef{}) {
		t.Error("an unrestricted gate should serve any tier")
	}
}

func TestRouteFindsTheShortestPath(t *testing.T) {
	v := compileTestVenue(t)

	route, err := v.Route("n-gate-north", "n-aisle-a", RouteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := []NodeID{"n-gate-north", "n-concourse", "n-portal-lower", "n-aisle-a"}
	if len(route.Nodes) != len(want) {
		t.Fatalf("route is %v, want %v", route.Nodes, want)
	}
	for i, node := range want {
		if route.Nodes[i] != node {
			t.Fatalf("route is %v, want %v", route.Nodes, want)
		}
	}
	if len(route.Legs) != 3 {
		t.Fatalf("got %d legs for a 4 node route, want 3", len(route.Legs))
	}
	if route.Distance <= 0 || route.Metres <= 0 || route.Seconds <= 0 {
		t.Fatalf("route has no measured length: %+v", route)
	}
	if !route.StepFree {
		t.Error("a route with no stairs reported itself as not step-free")
	}
	// The scale is declared, so metres must be the distance times the scale.
	if got, want := route.Metres, route.Distance*1.5; got < want-0.001 || got > want+0.001 {
		t.Errorf("metres %.3f does not match distance %.3f at the declared scale", got, want)
	}
}

func TestRouteToTheSameNodeIsEmptyRatherThanAnError(t *testing.T) {
	v := compileTestVenue(t)
	route, err := v.Route("n-concourse", "n-concourse", RouteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(route.Legs) != 0 || route.Distance != 0 || !route.StepFree {
		t.Fatalf("a zero-length route should be empty and step-free, got %+v", route)
	}
}

func TestStepFreeRoutingTakesTheLiftInsteadOfTheStairs(t *testing.T) {
	v := compileTestVenue(t)

	// Stairs are the shorter hop, so the default route uses them.
	normal, err := v.Route("n-concourse", "n-portal-upper", RouteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !containsNode(normal.Nodes, "n-stairs-top") {
		t.Fatalf("default route %v was expected to use the stairs", normal.Nodes)
	}
	if normal.StepFree {
		t.Error("a route over stairs reported itself as step-free")
	}

	stepFree, err := v.Route("n-concourse", "n-portal-upper", RouteOptions{StepFree: true})
	if err != nil {
		t.Fatal(err)
	}
	if containsNode(stepFree.Nodes, "n-stairs-top") {
		t.Fatalf("step-free route %v still used the stairs", stepFree.Nodes)
	}
	if !containsNode(stepFree.Nodes, "n-lift-top") {
		t.Fatalf("step-free route %v did not use the lift", stepFree.Nodes)
	}
	if !stepFree.StepFree {
		t.Error("the step-free route did not report itself as step-free")
	}
}

func TestStepFreeRoutingFailsLoudlyWhenThereIsNoLift(t *testing.T) {
	plan := testPlan()
	// Delete the lift. Silently routing this person up the stairs would be the
	// worst failure this package could produce, so it must be an error.
	var kept []Edge
	for _, edge := range plan.Map.Edges {
		if edge.Kind != EdgeLift {
			kept = append(kept, edge)
		}
	}
	plan.Map.Edges = kept

	v, err := Compile(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Route("n-concourse", "n-portal-upper", RouteOptions{StepFree: true}); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("got %v, want ErrNoRoute", err)
	}
	// And the ordinary route still works, so we failed for the right reason.
	if _, err := v.Route("n-concourse", "n-portal-upper", RouteOptions{}); err != nil {
		t.Fatalf("the stairs route broke too: %v", err)
	}
}

func TestRoutingRefusesToCrossAZoneTheHolderCannotEnter(t *testing.T) {
	v := compileTestVenue(t)

	allowed := make(map[ZoneCode]bool)
	for _, zone := range v.TierZones("ga") {
		allowed[zone] = true
	}
	if allowed["backstage"] {
		t.Fatal("fixture assumption broken: GA should not be entitled to backstage")
	}

	if _, err := v.Route("n-concourse", "n-backstage", RouteOptions{AllowedZones: allowed}); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("routed a general-admission holder to backstage: %v", err)
	}
	// Crew has the perimeter but the backstage node sits in the backstage zone,
	// so crew cannot route there either under a strict entitlement filter. With
	// no filter it is reachable, which proves the graph itself is fine.
	if _, err := v.Route("n-concourse", "n-backstage", RouteOptions{}); err != nil {
		t.Fatalf("the unfiltered route to backstage broke: %v", err)
	}
}

func TestRouteRejectsUnknownEndpoints(t *testing.T) {
	v := compileTestVenue(t)
	if _, err := v.Route("ghost", "n-concourse", RouteOptions{}); err == nil {
		t.Error("routed from a node that does not exist")
	}
	if _, err := v.Route("n-concourse", "ghost", RouteOptions{}); err == nil {
		t.Error("routed to a node that does not exist")
	}
}

func TestRouteIsDeterministic(t *testing.T) {
	// A route that changes between page loads reads as a bug even when both
	// answers are correct, and it makes the attendee app's cached directions
	// disagree with the ones the steward is reading.
	v := compileTestVenue(t)
	first, err := v.Route("n-gate-south", "n-aisle-b", RouteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		again, err := v.Route("n-gate-south", "n-aisle-b", RouteOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(again.Nodes) != len(first.Nodes) {
			t.Fatalf("iteration %d produced a different route: %v vs %v", i, again.Nodes, first.Nodes)
		}
		for j := range first.Nodes {
			if again.Nodes[j] != first.Nodes[j] {
				t.Fatalf("iteration %d produced a different route: %v vs %v", i, again.Nodes, first.Nodes)
			}
		}
	}
}

func TestLegInstructionsAreHumanReadable(t *testing.T) {
	v := compileTestVenue(t)
	route, err := v.Route("n-gate-north", "n-portal-upper", RouteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i, leg := range route.Legs {
		if leg.Instruction == "" {
			t.Fatalf("leg %d has no instruction", i)
		}
		if strings.Contains(leg.Instruction, "n-") {
			t.Errorf("leg %d leaks a node id into the instruction: %q", i, leg.Instruction)
		}
	}
	// The stair leg has to say stairs, and it has to say which way.
	var sawStairs bool
	for _, leg := range route.Legs {
		if leg.Kind == EdgeStair {
			sawStairs = true
			if !strings.Contains(strings.ToLower(leg.Instruction), "stairs up") {
				t.Errorf("stair instruction %q does not say which way", leg.Instruction)
			}
			if leg.LevelChange != 1 {
				t.Errorf("stair leg reports a level change of %d, want 1", leg.LevelChange)
			}
		}
	}
	if !sawStairs {
		t.Error("expected this route to include the stairs")
	}
}

func TestTurnClassification(t *testing.T) {
	// Y grows downward, matching SVG, so a turn that looks clockwise on screen
	// is a right turn. Getting this backwards sends every attendee the wrong way
	// at every junction, which is why it has its own test.
	origin := Point{X: 0, Y: 0}
	via := Point{X: 10, Y: 0} // heading east

	for name, tc := range map[string]struct {
		to   Point
		want turn
	}{
		"straight on":   {Point{X: 20, Y: 0}, turnStraight},
		"right is down": {Point{X: 10, Y: 10}, turnRight},
		"left is up":    {Point{X: 10, Y: -10}, turnLeft},
		"doubling back": {Point{X: 0, Y: 0}, turnBack},
		"slight drift":  {Point{X: 20, Y: 2}, turnStraight},
	} {
		if got := turnOf(origin, via, tc.to); got != tc.want {
			t.Errorf("%s: got turn %d, want %d", name, got, tc.want)
		}
	}
}

func TestGuidanceWalksAMultiStageVenue(t *testing.T) {
	v := compileTestVenue(t)
	during := time.Date(2026, 8, 21, 19, 0, 0, 0, time.UTC)
	seat := SeatRef{Section: "block-a", Row: "A", Seat: "4"}

	// Before the first scan the only ready step is the outer gate; everything
	// else is waiting on the perimeter.
	first, err := v.Guidance(GuidanceRequest{Tier: "ga", Seat: seat, At: during})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Next) == 0 {
		t.Fatal("no ready steps before entering")
	}
	for _, step := range first.Next {
		if step.Zone != "perimeter" {
			t.Errorf("step %q is ready before the attendee is inside the perimeter", step.Checkpoint)
		}
	}
	if !hasStep(first.Later, "portal-lower") {
		t.Error("portal-lower should be listed as a later step with a missing prerequisite")
	}
	for _, step := range first.Later {
		if step.Checkpoint == "portal-lower" && (len(step.Missing) != 1 || step.Missing[0] != "perimeter") {
			t.Errorf("portal-lower reports missing %v, want [perimeter]", step.Missing)
		}
	}
	if first.Destination == nil || first.Destination.SeatLabel != seat.String() {
		t.Fatalf("destination is %+v, want the seated destination", first.Destination)
	}
	if first.Arrived {
		t.Error("reported as arrived before entering the venue")
	}

	// After being admitted to the perimeter, the portal for this section opens
	// up and the outer gate drops off the list.
	second, err := v.Guidance(GuidanceRequest{
		Tier: "ga", Seat: seat, Admitted: []ZoneCode{"perimeter"},
		From: "n-gate-north", At: during,
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasStep(second.Next, "gate-north") || hasStep(second.Later, "gate-north") {
		t.Error("a once-only gate already used is still being offered")
	}
	if !hasStep(second.Next, "portal-lower") {
		t.Errorf("portal-lower is not ready after entering the perimeter: next=%v later=%v", stepCodes(second.Next), stepCodes(second.Later))
	}
	if hasStep(second.Next, "portal-upper") || hasStep(second.Later, "portal-upper") {
		t.Error("portal-upper serves block-b and should not be offered to a block-a holder")
	}
	// Routes should be attached now that we know where they are standing.
	for _, step := range second.Next {
		if step.Node != "" && step.Route == nil {
			t.Errorf("step %q has a graph node but no route", step.Checkpoint)
		}
	}
	if second.Destination.Route == nil {
		t.Error("no route to the seat once the attendee's position is known")
	}

	// Once inside the arena there is nothing left for a GA ticket to do.
	third, err := v.Guidance(GuidanceRequest{
		Tier: "ga", Seat: seat, Admitted: []ZoneCode{"perimeter", "arena"},
		From: "n-portal-lower", At: during,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The pit is entitled by cascade but not served for GA, the food court is
	// re-entry so it stays available, and the bar token is counted.
	for _, step := range append(third.Next, third.Later...) {
		if step.Checkpoint == "pit-gate" {
			t.Error("the pit was offered to general admission")
		}
	}
	if !hasStep(third.Next, "food-court") {
		t.Error("a re-entry checkpoint should stay available after entering")
	}
}

func TestGuidanceOffersThePitToVIPOnly(t *testing.T) {
	v := compileTestVenue(t)
	inside := []ZoneCode{"perimeter", "arena"}

	vip, err := v.Guidance(GuidanceRequest{Tier: "vip", Admitted: inside, From: "n-portal-lower"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasStep(vip.Next, "pit-gate") {
		t.Fatalf("the pit is not ready for a VIP inside the arena: %v", stepCodes(vip.Next))
	}

	ga, err := v.Guidance(GuidanceRequest{Tier: "ga", Admitted: inside, From: "n-portal-lower"})
	if err != nil {
		t.Fatal(err)
	}
	if hasStep(ga.Next, "pit-gate") || hasStep(ga.Later, "pit-gate") {
		t.Fatal("the pit was offered to general admission")
	}
}

func TestGuidanceFlagsAClosedCheckpointRatherThanHidingIt(t *testing.T) {
	v := compileTestVenue(t)
	beforeDoors := time.Date(2026, 8, 21, 17, 0, 0, 0, time.UTC)

	out, err := v.Guidance(GuidanceRequest{Tier: "ga", At: beforeDoors})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, step := range out.Later {
		if step.Checkpoint == "gate-north" {
			found = true
			if !step.Closed {
				t.Error("north gate is not marked closed before doors")
			}
			if step.OpensAt.IsZero() {
				t.Error("a closed step should say when it opens")
			}
			if step.Ready {
				t.Error("a closed step should not be ready")
			}
		}
	}
	if !found {
		t.Fatalf("north gate is missing from the later list: %v", stepCodes(out.Later))
	}
}

func TestGuidanceSortsReadyStepsByWalkingDistance(t *testing.T) {
	v := compileTestVenue(t)
	// Standing at the south gate, the south gate is nearer than the north gate.
	out, err := v.Guidance(GuidanceRequest{Tier: "ga", From: "n-gate-south"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Next) < 2 {
		t.Fatalf("expected at least two ready steps, got %v", stepCodes(out.Next))
	}
	for i := 1; i < len(out.Next); i++ {
		previous, current := out.Next[i-1].Route, out.Next[i].Route
		if previous == nil || current == nil {
			continue
		}
		if current.Distance < previous.Distance {
			t.Fatalf("ready steps are not sorted by distance: %v", stepCodes(out.Next))
		}
	}
}

func TestGuidanceRejectsAnUnknownTier(t *testing.T) {
	v := compileTestVenue(t)
	if _, err := v.Guidance(GuidanceRequest{Tier: "ghost"}); err == nil {
		t.Fatal("built guidance for a tier that does not exist")
	}
}

func TestNearestAmenitiesSortsByWalkingDistanceAndHidesTheUnreachable(t *testing.T) {
	v := compileTestVenue(t)
	during := time.Date(2026, 8, 21, 20, 0, 0, 0, time.UTC)

	found, err := v.NearestAmenities(NearestAmenitiesRequest{
		Kinds: []AmenityKind{AmenityWashroom}, From: "n-portal-lower", Tier: "ga", At: during,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("no toilets found")
	}
	for _, entry := range found {
		if entry.Amenity.ID == "wc-backstage" {
			t.Error("a general-admission holder was shown the backstage toilets")
		}
	}
	for i := 1; i < len(found); i++ {
		if found[i].Route.Distance < found[i-1].Route.Distance {
			t.Fatal("results are not sorted by walking distance")
		}
	}
}

func TestNearestAmenitiesPutsOpenOnesFirst(t *testing.T) {
	v := compileTestVenue(t)
	afterClose := time.Date(2026, 8, 22, 0, 30, 0, 0, time.UTC)

	found, err := v.NearestAmenities(NearestAmenitiesRequest{From: "n-concourse", Tier: "ga", At: afterClose, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	var sawClosed bool
	for _, entry := range found {
		if !entry.Open {
			sawClosed = true
			continue
		}
		if sawClosed {
			t.Fatal("an open amenity is listed after a closed one")
		}
	}
	// The biryani cart shuts at midnight, so at 00:30 it must be present and
	// marked closed rather than silently dropped.
	var foundCart bool
	for _, entry := range found {
		if entry.Amenity.ID == "food-1" {
			foundCart = true
			if entry.Open {
				t.Error("the food cart is reported open half an hour after it closed")
			}
		}
	}
	if !foundCart {
		t.Error("a closed amenity was hidden instead of greyed out")
	}
}

func TestNearestAmenitiesRespectsAccessibleOnly(t *testing.T) {
	v := compileTestVenue(t)
	found, err := v.NearestAmenities(NearestAmenitiesRequest{
		Kinds: []AmenityKind{AmenityWashroom}, From: "n-concourse", Tier: "ga", AccessibleOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("no accessible toilets found, but the fixture has one")
	}
	for _, entry := range found {
		if !entry.Amenity.Accessible {
			t.Errorf("%q is not accessible but was returned under AccessibleOnly", entry.Amenity.ID)
		}
	}
}

func TestNearestAmenitiesNeedsAStartingPoint(t *testing.T) {
	v := compileTestVenue(t)
	if _, err := v.NearestAmenities(NearestAmenitiesRequest{Kinds: []AmenityKind{AmenityWashroom}}); err == nil {
		t.Fatal(`"nearest" with no starting point should be an error`)
	}
}

func TestPlanRoundTripsThroughCompile(t *testing.T) {
	// The box re-exports its venue in the post-event manifest, so compiling the
	// export has to give the same venue back. A drift here means the record of
	// what happened disagrees with the venue it happened in.
	first := compileTestVenue(t)
	second, err := Compile(first.Plan())
	if err != nil {
		t.Fatalf("the exported plan does not recompile: %v", err)
	}
	if len(second.Zones()) != len(first.Zones()) ||
		len(second.Sections()) != len(first.Sections()) ||
		len(second.Checkpoints()) != len(first.Checkpoints()) ||
		len(second.Tiers()) != len(first.Tiers()) ||
		len(second.Amenities()) != len(first.Amenities()) {
		t.Fatal("the round trip changed the venue's shape")
	}
	if second.SectionCapacity("block-b") != first.SectionCapacity("block-b") {
		t.Fatal("the round trip changed a capacity")
	}
}

func containsNode(nodes []NodeID, want NodeID) bool {
	for _, node := range nodes {
		if node == want {
			return true
		}
	}
	return false
}

func hasStep(steps []Step, want CheckpointCode) bool {
	for _, step := range steps {
		if step.Checkpoint == want {
			return true
		}
	}
	return false
}

func stepCodes(steps []Step) []CheckpointCode {
	out := make([]CheckpointCode, 0, len(steps))
	for _, step := range steps {
		out = append(out, step.Checkpoint)
	}
	return out
}

func BenchmarkGuidance(b *testing.B) {
	v, err := Compile(testPlan())
	if err != nil {
		b.Fatal(err)
	}
	req := GuidanceRequest{
		Tier: "vip", Seat: SeatRef{Section: "block-a", Row: "A", Seat: "1"},
		Admitted: []ZoneCode{"perimeter", "arena"}, From: "n-concourse",
		At: time.Date(2026, 8, 21, 20, 0, 0, 0, time.UTC),
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := v.Guidance(req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoute(b *testing.B) {
	v, err := Compile(testPlan())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := v.Route("n-gate-south", "n-aisle-b", RouteOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}
