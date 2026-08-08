// Package enginetest is the conformance harness for redemption engine stores.
//
// There are three implementations of engine.Store — SQLite on the box, an
// in-memory store for the simulator, and a fault-injecting wrapper — and they
// all have to agree about the one thing that matters: the compare-and-set. A
// store that returns "inserted" twice for the same tuple breaks the only
// guarantee Gatecrash makes, and it would break it silently.
//
// So the assertions live here rather than in any one store's test file, and every
// store runs them. This is the same shape as the sink conformance harness in
// walcast, and for the same reason: a contract nobody can check is a contract
// nobody keeps.
//
// It lives in its own package so that importing the box's storage layer does not
// drag the testing package into the shipped binary.
package enginetest

import (
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// Doors is the instant every fixture event opens. Fixed rather than relative to
// now, so a test that fails at 3am fails the same way at noon.
var Doors = time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)

// Curfew is when the fixture event's gates close.
var Curfew = time.Date(2026, 8, 22, 1, 0, 0, 0, time.UTC)

// Fixture is a complete event: keys, venue, tickets and enrolled scanners,
// everything a test needs to drive real scans through a real engine.
type Fixture struct {
	EventID   ticket.ID
	Signing   ticket.SigningKey
	Verifying ticket.VerifyingKey
	Master    ticket.MasterKey
	Venue     *venue.Venue

	// Tickets is every issued ticket, keyed by a readable name so a failing
	// assertion says "vip-pit" instead of a base32 blob.
	Tickets map[string]engine.Ticket

	// Payloads is the GC1 payload for each static ticket.
	Payloads map[string]string
}

// VenuePlan is the fixture venue, and it is a small stadium rather than a single
// door because every interesting property of the engine is about the
// relationships between doors.
//
//	perimeter (open ground)
//	├── concourse            food court (re-entry), bar tokens (counted x2)
//	├── arena  [restricted]  requires perimeter
//	│   ├── block-a          via portal-lower
//	│   ├── block-b          via portal-upper
//	│   └── pit [restricted] requires arena, vip and crew only
//	└── backstage [restricted] requires perimeter, crew only
func VenuePlan() venue.Plan {
	return venue.Plan{
		Zones: []venue.Zone{
			{Code: "perimeter", Name: "Festival Ground", Kind: venue.ZonePerimeter, Capacity: 6000},
			{Code: "concourse", Name: "Concourse", Kind: venue.ZoneConcourse, Parent: "perimeter"},
			{Code: "arena", Name: "Arena", Kind: venue.ZoneArena, Parent: "perimeter", Restricted: true},
			{Code: "pit", Name: "Front Pit", Kind: venue.ZonePit, Parent: "arena", Capacity: 400, Restricted: true},
			{Code: "backstage", Name: "Backstage", Kind: venue.ZoneBackstage, Parent: "perimeter", Capacity: 60, Restricted: true},
		},
		Sections: []venue.Section{
			{
				Code: "block-a", Name: "Block A", Kind: venue.SectionSeated, Zone: "arena",
				Entrances: []venue.CheckpointCode{"portal-lower"},
				Rows: []venue.Row{
					{Label: "A", Start: venue.Point{X: 40, Y: 60}, End: venue.Point{X: 90, Y: 60}, Seats: seats(10)},
					{Label: "B", Start: venue.Point{X: 40, Y: 68}, End: venue.Point{X: 90, Y: 68}, Seats: seats(10)},
				},
			},
			{
				Code: "block-b", Name: "Block B", Kind: venue.SectionSeated, Zone: "arena",
				Entrances: []venue.CheckpointCode{"portal-upper"},
				Rows: []venue.Row{
					{Label: "A", Start: venue.Point{X: 40, Y: 20}, End: venue.Point{X: 90, Y: 20}, Seats: seats(10)},
				},
			},
			{Code: "golden-circle", Name: "Golden Circle", Kind: venue.SectionStanding, Zone: "pit", Capacity: 400},
		},
		Checkpoints: []venue.Checkpoint{
			{Code: "gate-north", Name: "North Gate", Zone: "perimeter", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Lane: "1", OpensAt: Doors, ClosesAt: Curfew},
			{Code: "gate-south", Name: "South Gate", Zone: "perimeter", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Lane: "1", OpensAt: Doors, ClosesAt: Curfew},
			{Code: "gate-exit", Name: "Exit", Zone: "perimeter", Direction: venue.DirectionOut, Policy: venue.PolicyReEntry},
			{
				Code: "portal-lower", Name: "Portal C Lower", Zone: "arena", Direction: venue.DirectionIn,
				Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"perimeter"}, Sections: []venue.SectionCode{"block-a"},
			},
			{
				Code: "portal-upper", Name: "Portal C Upper", Zone: "arena", Direction: venue.DirectionIn,
				Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"perimeter"}, Sections: []venue.SectionCode{"block-b"},
			},
			{
				Code: "arena-general", Name: "Arena General", Zone: "arena", Direction: venue.DirectionIn,
				Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"perimeter"},
			},
			{
				Code: "pit-gate", Name: "Pit Wristband Check", Zone: "pit", Direction: venue.DirectionIn,
				Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"arena"}, Tiers: []venue.TierCode{"vip", "crew"},
			},
			{
				Code: "stage-door", Name: "Stage Door", Zone: "backstage", Direction: venue.DirectionIn,
				Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"perimeter"}, Tiers: []venue.TierCode{"crew"},
			},
			{
				Code: "food-court", Name: "Food Court", Zone: "concourse", Direction: venue.DirectionBoth,
				Policy: venue.PolicyReEntry, Requires: []venue.ZoneCode{"perimeter"},
			},
			{
				Code: "bar-token", Name: "Bar Token", Zone: "concourse", Direction: venue.DirectionIn,
				Policy: venue.PolicyCounted, CountLimit: 2, Requires: []venue.ZoneCode{"perimeter"},
			},
		},
		Tiers: []venue.Tier{
			{Code: "ga", Name: "General Admission", Zones: []venue.ZoneCode{"perimeter", "arena"}, Colour: "#3B82F6", Priority: 10},
			{Code: "vip", Name: "VIP", Zones: []venue.ZoneCode{"perimeter", "arena", "pit"}, Colour: "#A855F7", Priority: 20},
			{Code: "crew", Name: "Crew", Zones: []venue.ZoneCode{"perimeter", "arena", "pit", "backstage"}, Colour: "#F59E0B", Priority: 90},
		},
		Map: venue.Map{Width: 160, Height: 120, MetresPerUnit: 1.5},
	}
}

func seats(n int) []venue.Seat {
	out := make([]venue.Seat, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, venue.Seat{Number: itoa(i)})
	}
	return out
}

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

// ticketSpec describes one ticket the fixture issues.
type ticketSpec struct {
	name   string
	tier   venue.TierCode
	seat   venue.SeatRef
	format engine.Format
}

// specs is the fixture's ticket roster. One per interesting shape, because a
// hundred identical general-admission tickets prove nothing that one does not.
var specs = []ticketSpec{
	{name: "ga-block-a", tier: "ga", seat: venue.SeatRef{Section: "block-a", Row: "A", Seat: "1"}, format: engine.FormatStatic},
	{name: "ga-block-a-2", tier: "ga", seat: venue.SeatRef{Section: "block-a", Row: "A", Seat: "2"}, format: engine.FormatStatic},
	{name: "ga-block-b", tier: "ga", seat: venue.SeatRef{Section: "block-b", Row: "A", Seat: "1"}, format: engine.FormatStatic},
	{name: "ga-standing", tier: "ga", format: engine.FormatStatic},
	{name: "vip-pit", tier: "vip", seat: venue.SeatRef{Section: "golden-circle"}, format: engine.FormatStatic},
	{name: "crew", tier: "crew", format: engine.FormatStatic},
	{name: "rotating", tier: "ga", format: engine.FormatRotating},
	{name: "either", tier: "ga", format: engine.FormatEither},
	{name: "revoked", tier: "ga", format: engine.FormatStatic},
}

// NewFixture builds a fixture with fresh keys and a full ticket roster.
func NewFixture(t *testing.T) *Fixture {
	t.Helper()

	signing, verifying, err := ticket.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	root, err := ticket.NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	eventID := ticket.MustNewID()
	master, err := ticket.DeriveEventMaster(root, eventID)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := venue.Compile(VenuePlan())
	if err != nil {
		t.Fatalf("the fixture venue does not compile: %v", err)
	}

	f := &Fixture{
		EventID:   eventID,
		Signing:   signing,
		Verifying: verifying,
		Master:    master,
		Venue:     compiled,
		Tickets:   make(map[string]engine.Ticket, len(specs)),
		Payloads:  make(map[string]string, len(specs)),
	}

	for _, spec := range specs {
		id := ticket.MustNewID()
		claims := ticket.Claims{
			EventID:  eventID,
			TicketID: id,
			Tier:     string(spec.tier),
			IssuedAt: Doors.Add(-72 * time.Hour).UnixMilli(),
		}
		payload, err := ticket.SignGC1(signing, claims)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ticket.ParseGC1(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := compiled.ValidateSeat(spec.tier, spec.seat); err != nil {
			t.Fatalf("fixture ticket %q has an invalid seat: %v", spec.name, err)
		}
		f.Tickets[spec.name] = engine.Ticket{
			ID:        id,
			EventID:   eventID,
			Tier:      spec.tier,
			Seat:      spec.seat,
			IssuedAt:  claims.IssuedAt,
			Revoked:   spec.name == "revoked",
			Signature: parsed.Signature,
			Format:    spec.format,
		}
		f.Payloads[spec.name] = payload
	}
	return f
}

// Issued is a ticket together with its static payload, which is what a test
// driving scans actually needs in hand.
type Issued struct {
	Ticket  engine.Ticket
	Payload string
}

// Issue mints one additional ticket. Used by load-shaped tests that need
// thousands of holders rather than the nine named ones.
func (f *Fixture) Issue(t *testing.T, tier venue.TierCode, seat venue.SeatRef, format engine.Format) Issued {
	t.Helper()

	id := ticket.MustNewID()
	claims := ticket.Claims{
		EventID:  f.EventID,
		TicketID: id,
		Tier:     string(tier),
		IssuedAt: Doors.Add(-72 * time.Hour).UnixMilli(),
	}
	payload, err := ticket.SignGC1(f.Signing, claims)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ticket.ParseGC1(payload)
	if err != nil {
		t.Fatal(err)
	}
	return Issued{
		Ticket: engine.Ticket{
			ID: id, EventID: f.EventID, Tier: tier, Seat: seat,
			IssuedAt: claims.IssuedAt, Signature: parsed.Signature, Format: format,
		},
		Payload: payload,
	}
}

// IssueMany mints n general-admission standing tickets.
func (f *Fixture) IssueMany(t *testing.T, n int) []Issued {
	t.Helper()
	out := make([]Issued, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, f.Issue(t, "ga", venue.SeatRef{}, engine.FormatStatic))
	}
	return out
}

// Load seeds a store with the fixture's tickets and devices.
func (f *Fixture) Load(store interface {
	PutTicket(engine.Ticket)
	PutDevice(engine.Device)
}) {
	for _, record := range f.Tickets {
		store.PutTicket(record)
	}
	for _, device := range f.Devices() {
		store.PutDevice(device)
	}
}

// Devices is the fixture's enrolled scanner roster: one per checkpoint plus a
// couple of deliberate misconfigurations to scan against.
func (f *Fixture) Devices() []engine.Device {
	all := make([]venue.CheckpointCode, 0)
	for _, cp := range f.Venue.Checkpoints() {
		all = append(all, cp.Code)
	}
	return []engine.Device{
		{ID: "scanner-north", Name: "North 1", Checkpoints: []venue.CheckpointCode{"gate-north"}},
		{ID: "scanner-north-2", Name: "North 2", Checkpoints: []venue.CheckpointCode{"gate-north"}},
		{ID: "scanner-south", Name: "South 1", Checkpoints: []venue.CheckpointCode{"gate-south"}},
		{ID: "scanner-exit", Name: "Exit 1", Checkpoints: []venue.CheckpointCode{"gate-exit"}},
		{ID: "scanner-portal-lower", Name: "Portal C Lower", Checkpoints: []venue.CheckpointCode{"portal-lower"}},
		{ID: "scanner-portal-upper", Name: "Portal C Upper", Checkpoints: []venue.CheckpointCode{"portal-upper"}},
		{ID: "scanner-arena", Name: "Arena General", Checkpoints: []venue.CheckpointCode{"arena-general"}},
		{ID: "scanner-pit", Name: "Pit", Checkpoints: []venue.CheckpointCode{"pit-gate"}},
		{ID: "scanner-stage", Name: "Stage Door", Checkpoints: []venue.CheckpointCode{"stage-door"}},
		{ID: "scanner-food", Name: "Food Court", Checkpoints: []venue.CheckpointCode{"food-court"}},
		{ID: "scanner-bar", Name: "Bar", Checkpoints: []venue.CheckpointCode{"bar-token"}},
		// A roaming supervisor device, allowed everywhere.
		{ID: "scanner-roam", Name: "Supervisor", Checkpoints: all},
		// Enrolled but unassigned. An unassigned device must scan nothing:
		// "no checkpoints" is not the same as "every checkpoint".
		{ID: "scanner-unassigned", Name: "Spare"},
		// Enrolled, assigned, and revoked because it was stolen.
		{ID: "scanner-stolen", Name: "Stolen", Checkpoints: []venue.CheckpointCode{"gate-north"}, Revoked: true},
	}
}

// Config returns an engine config for this fixture with a clock the caller
// controls.
func (f *Fixture) Config(mode engine.Mode, now func() time.Time) engine.Config {
	return engine.Config{
		EventID:   f.EventID,
		Venue:     f.Venue,
		Verifying: f.Verifying,
		Master:    f.Master,
		Mode:      mode,
		Now:       now,
	}
}

// ID returns a named ticket's id.
func (f *Fixture) ID(name string) ticket.ID { return f.Tickets[name].ID }

// Rotating returns a valid GC2 payload for a named ticket at an instant.
func (f *Fixture) Rotating(t *testing.T, name string, at time.Time) string {
	t.Helper()
	id := f.ID(name)
	secret, err := ticket.DeriveSecret(f.Master, id)
	if err != nil {
		t.Fatal(err)
	}
	return ticket.GenerateGC2At(secret, f.EventID, id, at)
}
