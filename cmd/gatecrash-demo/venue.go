package main

import (
	"strconv"
	"time"

	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/manifest"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// manifestBody builds the demo event and issues its tickets.
//
// The venue is a small stadium rather than a single door, because every
// interesting thing in this system is about the relationships between doors: a
// perimeter you enter first, an arena that requires it, a pit that requires the
// arena and only admits VIPs, a food court you can leave and come back to, and a
// bar that gives you exactly two drinks.
func (d *demo) manifestBody() manifest.Body {
	plan := venue.Plan{
		Zones: []venue.Zone{
			{Code: "perimeter", Name: "Festival Ground", Kind: venue.ZonePerimeter, Capacity: 3000,
				Shape: venue.Polygon{{X: 2, Y: 2}, {X: 118, Y: 2}, {X: 118, Y: 108}, {X: 2, Y: 108}}},
			{Code: "concourse", Name: "Concourse", Kind: venue.ZoneConcourse, Parent: "perimeter",
				Shape: venue.Polygon{{X: 4, Y: 84}, {X: 116, Y: 84}, {X: 116, Y: 106}, {X: 4, Y: 106}}},
			// Restricted, so a grant on the perimeter does not silently include
			// the thing people paid for.
			{Code: "arena", Name: "Arena", Kind: venue.ZoneArena, Parent: "perimeter", Restricted: true,
				Shape: venue.Polygon{{X: 26, Y: 20}, {X: 94, Y: 20}, {X: 94, Y: 82}, {X: 26, Y: 82}}},
			{Code: "pit", Name: "Front Pit", Kind: venue.ZonePit, Parent: "arena", Capacity: 150, Restricted: true,
				Shape: venue.Polygon{{X: 42, Y: 21}, {X: 78, Y: 21}, {X: 78, Y: 26}, {X: 42, Y: 26}}},
			{Code: "backstage", Name: "Backstage", Kind: venue.ZoneBackstage, Parent: "perimeter", Capacity: 40, Restricted: true,
				Shape: venue.Polygon{{X: 84, Y: 4}, {X: 116, Y: 4}, {X: 116, Y: 18}, {X: 84, Y: 18}}},
		},
		Sections: []venue.Section{
			{
				Code: "block-a", Name: "Block A", Kind: venue.SectionSeated, Zone: "arena",
				Entrances: []venue.CheckpointCode{"portal-a"}, Node: "n-portal-a",
				Shape: venue.Polygon{{X: 28, Y: 50}, {X: 92, Y: 50}, {X: 92, Y: 68}, {X: 28, Y: 68}},
				Rows: []venue.Row{
					{Label: "A", Start: venue.Point{X: 30, Y: 55}, End: venue.Point{X: 90, Y: 55}, Curve: 4, Aisle: "n-aisle-a", Seats: numbered(12)},
					{Label: "B", Start: venue.Point{X: 30, Y: 62}, End: venue.Point{X: 90, Y: 62}, Curve: 4, Aisle: "n-aisle-a", Seats: numbered(12)},
				},
			},
			{
				Code: "block-b", Name: "Block B", Kind: venue.SectionSeated, Zone: "arena",
				Entrances: []venue.CheckpointCode{"portal-b"}, Node: "n-portal-b",
				// Further from the stage than Block A, because that is what "upper
				// tier, behind the mix position" means on the ground.
				Shape:    venue.Polygon{{X: 28, Y: 70}, {X: 92, Y: 70}, {X: 92, Y: 80}, {X: 28, Y: 80}},
				ViewNote: "Upper tier, behind the mix position",
				Rows: []venue.Row{
					{Label: "A", Start: venue.Point{X: 30, Y: 75}, End: venue.Point{X: 90, Y: 75}, Curve: 3, Aisle: "n-aisle-b", Seats: numbered(12)},
				},
			},
			{Code: "golden-circle", Name: "Golden Circle", Kind: venue.SectionStanding, Zone: "pit", Capacity: 150, Node: "n-pit",
				Shape: venue.Polygon{{X: 43, Y: 21}, {X: 77, Y: 21}, {X: 77, Y: 25}, {X: 43, Y: 25}}},
		},
		Checkpoints: []venue.Checkpoint{
			{Code: "gate-north", Name: "North Gate", Zone: "perimeter", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Lane: "1", Node: "n-gate-north", OpensAt: doors, ClosesAt: doors.Add(7 * time.Hour)},
			{Code: "gate-south", Name: "South Gate", Zone: "perimeter", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Lane: "1", Node: "n-gate-south", OpensAt: doors, ClosesAt: doors.Add(7 * time.Hour)},
			{Code: "gate-exit", Name: "Exit", Zone: "perimeter", Direction: venue.DirectionOut, Policy: venue.PolicyReEntry, Node: "n-gate-north"},
			{Code: "portal-a", Name: "Portal A", Zone: "arena", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"perimeter"}, Sections: []venue.SectionCode{"block-a"}, Node: "n-portal-a"},
			{Code: "portal-b", Name: "Portal B", Zone: "arena", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"perimeter"}, Sections: []venue.SectionCode{"block-b"}, Node: "n-portal-b"},
			// The general entrance, for tickets with no seat. Without one, every
			// arena door is section-restricted and a standing ticket has no way in.
			{Code: "arena-general", Name: "Arena Entrance", Zone: "arena", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"perimeter"}, Node: "n-portal-a"},
			{Code: "pit-gate", Name: "Pit Wristband", Zone: "pit", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"arena"}, Tiers: []venue.TierCode{"vip", "crew"}, Node: "n-pit"},
			{Code: "stage-door", Name: "Stage Door", Zone: "backstage", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"perimeter"}, Tiers: []venue.TierCode{"crew"}, Node: "n-concourse"},
			{Code: "food-court", Name: "Food Court", Zone: "concourse", Direction: venue.DirectionBoth, Policy: venue.PolicyReEntry, Requires: []venue.ZoneCode{"perimeter"}, Node: "n-concourse"},
			{Code: "bar-token", Name: "Bar", Zone: "concourse", Direction: venue.DirectionIn, Policy: venue.PolicyCounted, CountLimit: 2, Requires: []venue.ZoneCode{"perimeter"}, Node: "n-concourse"},
		},
		Tiers: []venue.Tier{
			{Code: "ga", Name: "General Admission", Zones: []venue.ZoneCode{"perimeter", "arena"}, Colour: "#3B82F6", Priority: 10},
			{Code: "vip", Name: "VIP", Zones: []venue.ZoneCode{"perimeter", "arena", "pit"}, Colour: "#A855F7", Priority: 20},
			{Code: "crew", Name: "Crew", Zones: []venue.ZoneCode{"perimeter", "concourse", "arena", "pit", "backstage"}, Colour: "#F59E0B", Priority: 90},
		},
		Amenities: []venue.Amenity{
			{ID: "wc-concourse", Kind: venue.AmenityWashroom, Name: "Concourse Toilets", Zone: "concourse", Position: venue.Point{X: 45, Y: 92}, Node: "n-concourse", Accessible: true},
			{ID: "wc-arena", Kind: venue.AmenityWashroom, Name: "Arena Toilets", Zone: "arena", Position: venue.Point{X: 88, Y: 70}, Node: "n-portal-a"},
			{ID: "food-1", Kind: venue.AmenityFood, Name: "Biryani Cart", Zone: "concourse", Position: venue.Point{X: 38, Y: 95}, Node: "n-concourse"},
			{ID: "water-1", Kind: venue.AmenityWater, Name: "Water Point", Zone: "concourse", Position: venue.Point{X: 52, Y: 95}, Node: "n-concourse"},
			{ID: "medical-1", Kind: venue.AmenityMedical, Name: "Medical Tent", Zone: "concourse", Position: venue.Point{X: 20, Y: 95}, Node: "n-concourse", Accessible: true},
		},
		Map: venue.Map{
			Width: 120, Height: 110, MetresPerUnit: 1.5,
			Stage:   venue.Polygon{{X: 40, Y: 8}, {X: 80, Y: 8}, {X: 80, Y: 18}, {X: 40, Y: 18}},
			Outline: venue.Polygon{{X: 0, Y: 0}, {X: 120, Y: 0}, {X: 120, Y: 110}, {X: 0, Y: 110}},
			Nodes: []venue.Node{
				{ID: "n-gate-north", Kind: venue.NodeGate, Name: "the North Gate", Position: venue.Point{X: 15, Y: 100}},
				{ID: "n-gate-south", Kind: venue.NodeGate, Name: "the South Gate", Position: venue.Point{X: 105, Y: 100}},
				{ID: "n-concourse", Kind: venue.NodeConcourse, Name: "the concourse", Zone: "concourse", Position: venue.Point{X: 60, Y: 92}},
				{ID: "n-portal-a", Kind: venue.NodePortal, Name: "Portal A", Zone: "arena", Position: venue.Point{X: 45, Y: 75}},
				{ID: "n-stairs", Kind: venue.NodeStair, Name: "the upper landing", Zone: "arena", Position: venue.Point{X: 95, Y: 70}, Level: 1},
				{ID: "n-lift", Kind: venue.NodeLift, Name: "the upper landing", Zone: "arena", Position: venue.Point{X: 100, Y: 70}, Level: 1},
				{ID: "n-portal-b", Kind: venue.NodePortal, Name: "Portal B", Zone: "arena", Position: venue.Point{X: 60, Y: 42}, Level: 1},
				{ID: "n-aisle-a", Kind: venue.NodeAisle, Name: "the Block A aisle", Zone: "arena", Position: venue.Point{X: 28, Y: 58}},
				{ID: "n-aisle-b", Kind: venue.NodeAisle, Name: "the Block B aisle", Zone: "arena", Position: venue.Point{X: 28, Y: 76}, Level: 1},
				{ID: "n-pit", Kind: venue.NodeSeatBlock, Name: "the pit", Zone: "pit", Position: venue.Point{X: 60, Y: 25}},
			},
			Edges: []venue.Edge{
				{From: "n-gate-north", To: "n-concourse"},
				{From: "n-gate-south", To: "n-concourse"},
				{From: "n-concourse", To: "n-portal-a", Kind: venue.EdgeDoor, Note: "through the double doors"},
				{From: "n-concourse", To: "n-stairs", Kind: venue.EdgeStair},
				{From: "n-concourse", To: "n-lift", Kind: venue.EdgeLift},
				{From: "n-stairs", To: "n-portal-b"},
				{From: "n-lift", To: "n-portal-b"},
				{From: "n-portal-a", To: "n-aisle-a"},
				{From: "n-portal-b", To: "n-aisle-b"},
				{From: "n-portal-a", To: "n-pit"},
			},
		},
	}

	body := manifest.Body{
		Event: manifest.Event{
			ID: d.keys.eventID, Name: "Sundown Sessions", Venue: "Kingdom of Dreams",
			Timezone: "Asia/Kolkata", Doors: doors, Curfew: doors.Add(7 * time.Hour),
			Mode: engine.ModeStrict, Support: "WhatsApp +91 90000 00000",
		},
		Venue:     plan,
		Verifying: d.keys.verifying,
		Master:    d.keys.master.String(),
		IssuedAt:  doors.Add(-48 * time.Hour),
		Sequence:  1,
	}

	// The cast. Named rather than numbered, because the narration reads better and
	// because each one exists to exercise a different path.
	for _, spec := range []struct {
		name   string
		tier   venue.TierCode
		seat   venue.SeatRef
		format engine.Format
	}{
		{"asha", "ga", venue.SeatRef{Section: "block-a", Row: "A", Seat: "1"}, engine.FormatStatic},
		{"bilal", "ga", venue.SeatRef{Section: "block-a", Row: "A", Seat: "2"}, engine.FormatStatic},
		{"chetan", "ga", venue.SeatRef{Section: "block-b", Row: "A", Seat: "1"}, engine.FormatStatic},
		{"divya", "ga", venue.SeatRef{}, engine.FormatStatic},
		{"esha", "vip", venue.SeatRef{Section: "golden-circle"}, engine.FormatRotating},
		{"farhan", "crew", venue.SeatRef{}, engine.FormatStatic},
		{"ghost", "ga", venue.SeatRef{}, engine.FormatStatic},
	} {
		record, payload := d.issue(spec.tier, spec.seat, spec.format)
		d.tickets[spec.name] = issued{record: record, payload: payload}
		body.Tickets = append(body.Tickets, record)
	}
	// The revoked one, so the demo can show what a cancelled ticket looks like.
	revoked := d.tickets["ghost"]
	revoked.record.Revoked = true
	d.tickets["ghost"] = revoked
	for i := range body.Tickets {
		if body.Tickets[i].ID == revoked.record.ID {
			body.Tickets[i].Revoked = true
		}
	}
	return body
}

// issue mints one ticket exactly as the organizer's CLI does.
func (d *demo) issue(tier venue.TierCode, seat venue.SeatRef, format engine.Format) (engine.Ticket, string) {
	id := ticket.MustNewID()
	claims := ticket.Claims{
		EventID: d.keys.eventID, TicketID: id, Tier: string(tier),
		IssuedAt: doors.Add(-48 * time.Hour).UnixMilli(),
	}
	payload, err := ticket.SignGC1(d.keys.signing, claims)
	if err != nil {
		panic(err)
	}
	parsed, err := ticket.ParseGC1(payload)
	if err != nil {
		panic(err)
	}
	record := engine.Ticket{
		ID: id, EventID: d.keys.eventID, Tier: tier, Seat: seat,
		IssuedAt: claims.IssuedAt, Signature: parsed.Signature, Format: format,
	}
	// A rotating ticket has no static payload to hand out; presenting one would
	// undo the whole anti-screenshot property.
	if format == engine.FormatRotating {
		return record, ""
	}
	return record, payload
}

func numbered(n int) []venue.Seat {
	out := make([]venue.Seat, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, venue.Seat{Number: strconv.Itoa(i)})
	}
	return out
}
