package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/manifest"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// Keys is the organizer's key file.
//
// One file holding both the signing key and the root master key, because they are
// used together and splitting them would mean two things to lose. The file is
// written 0600 and the docs are blunt about what it is: whoever holds this can
// mint tickets for every event you will ever run.
type Keys struct {
	// Signing is the Ed25519 private key that signs tickets and manifests.
	Signing string `json:"signing_key"`

	// Verifying is the public half, published so anybody can check a ticket.
	Verifying string `json:"verifying_key"`

	// Fingerprint identifies the key pair. This is the value provisioned onto each
	// box, and it is what makes a manifest verifiable rather than merely
	// self-consistent.
	Fingerprint string `json:"fingerprint"`

	// Root is the organization-wide master key. Per-event master keys are derived
	// from it, so a box seized after one event cannot mint codes for any other.
	Root string `json:"root_master_key"`

	CreatedAt time.Time `json:"created_at"`
}

// keygen writes a new organizer key file.
func keygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := flags.String("out", "gatecrash-keys.json", "where to write the key file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	signing, verifying, err := ticket.GenerateSigningKey()
	if err != nil {
		return err
	}
	root, err := ticket.NewMasterKey()
	if err != nil {
		return err
	}

	keys := Keys{
		Signing:     signing.String(),
		Verifying:   verifying.String(),
		Fingerprint: verifying.Fingerprint(),
		Root:        root.String(),
		CreatedAt:   time.Now().UTC(),
	}
	if err := writeJSONFile(*out, 0o600, keys); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, `wrote %s (mode 0600)

  fingerprint  %s

Provision that fingerprint onto every box:

  GATECRASH_ORGANIZER_FINGERPRINT=%s

Keep this file. Whoever holds it can mint tickets for every event you run, and
there is no revocation for it — losing it means re-keying and re-provisioning
every box.
`, *out, keys.Fingerprint, keys.Fingerprint)
	return nil
}

// load reads and parses a key file.
func (k Keys) signingKey() (ticket.SigningKey, error) { return ticket.ParseSigningKey(k.Signing) }
func (k Keys) rootKey() (ticket.MasterKey, error)     { return ticket.ParseMasterKey(k.Root) }

// starterVenue writes a plan an organizer can edit.
//
// A worked example rather than an empty skeleton, because the interesting part of
// a venue plan is the relationships — which zone is nested in which, which
// checkpoint requires which zone — and an empty file teaches none of that.
func starterVenue(args []string) error {
	flags := flag.NewFlagSet("venue", flag.ContinueOnError)
	out := flags.String("out", "venue.json", "where to write the plan")
	if err := flags.Parse(args); err != nil {
		return err
	}

	plan := venue.Plan{
		// Every zone carries a footprint. Shape is optional in the schema — a plan
		// with no geometry still runs an event — but a starter plan without it
		// renders as an empty box with labels floating in it, which teaches the
		// wrong lesson about what the map is for. These are laid out in the same
		// 120x110 grid as Map below: stage at the top, arena in front of it, pit
		// against the barrier, concourse along the bottom where the gates are.
		Zones: []venue.Zone{
			{Code: "perimeter", Name: "Festival Ground", Kind: venue.ZonePerimeter, Capacity: 2000,
				Shape: venue.Polygon{{X: 2, Y: 2}, {X: 118, Y: 2}, {X: 118, Y: 108}, {X: 2, Y: 108}}},
			{Code: "concourse", Name: "Concourse", Kind: venue.ZoneConcourse, Parent: "perimeter",
				Shape: venue.Polygon{{X: 4, Y: 84}, {X: 116, Y: 84}, {X: 116, Y: 106}, {X: 4, Y: 106}}},
			// Restricted, so a grant on the perimeter does not quietly include it.
			// This is the flag that stops nesting from becoming a security hole.
			{Code: "arena", Name: "Arena", Kind: venue.ZoneArena, Parent: "perimeter", Restricted: true,
				Shape: venue.Polygon{{X: 26, Y: 20}, {X: 94, Y: 20}, {X: 94, Y: 82}, {X: 26, Y: 82}}},
			{Code: "pit", Name: "Front Pit", Kind: venue.ZonePit, Parent: "arena", Capacity: 200, Restricted: true,
				Shape: venue.Polygon{{X: 42, Y: 21}, {X: 78, Y: 21}, {X: 78, Y: 42}, {X: 42, Y: 42}}},
		},
		Sections: []venue.Section{
			{
				Code: "block-a", Name: "Block A", Kind: venue.SectionSeated, Zone: "arena",
				Entrances: []venue.CheckpointCode{"portal-a"}, Node: "n-portal-a",
				// The block's own outline, wide enough to contain the two curved
				// rows below. Drawn behind the seats so a block reads as a block
				// from across the concourse rather than as a scatter of dots.
				Shape: venue.Polygon{{X: 28, Y: 50}, {X: 92, Y: 50}, {X: 92, Y: 68}, {X: 28, Y: 68}},
				Rows: []venue.Row{
					// Authored with geometry rather than per-seat coordinates: a
					// start, an end, a curve and a seat count is how a real stand
					// is described, and the compiler lays the seats out.
					{Label: "A", Start: venue.Point{X: 30, Y: 55}, End: venue.Point{X: 90, Y: 55}, Curve: 4, Aisle: "n-aisle-a", Seats: seats(12)},
					{Label: "B", Start: venue.Point{X: 30, Y: 62}, End: venue.Point{X: 90, Y: 62}, Curve: 4, Aisle: "n-aisle-a", Seats: seats(12)},
				},
			},
			// Standing, so it has a footprint and no seats. A standing section with
			// no shape is invisible on the map, which is the one part of the plan an
			// attendee in the pit most needs to recognise.
			{Code: "golden-circle", Name: "Golden Circle", Kind: venue.SectionStanding, Zone: "pit", Capacity: 200, Node: "n-pit",
				Shape: venue.Polygon{{X: 44, Y: 23}, {X: 76, Y: 23}, {X: 76, Y: 40}, {X: 44, Y: 40}}},
		},
		Checkpoints: []venue.Checkpoint{
			{Code: "gate-north", Name: "North Gate", Zone: "perimeter", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Lane: "1", Node: "n-gate-north", Position: venue.Point{X: 15, Y: 100}},
			{Code: "gate-south", Name: "South Gate", Zone: "perimeter", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Lane: "1", Node: "n-gate-south", Position: venue.Point{X: 105, Y: 100}},
			{Code: "gate-exit", Name: "Exit", Zone: "perimeter", Direction: venue.DirectionOut, Policy: venue.PolicyReEntry, Node: "n-gate-north", Position: venue.Point{X: 35, Y: 100}},
			// Section-restricted: this portal serves Block A and nothing else, which
			// is what a stadium vomitory is.
			{Code: "portal-a", Name: "Portal A", Zone: "arena", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"perimeter"}, Sections: []venue.SectionCode{"block-a"}, Node: "n-portal-a", Position: venue.Point{X: 60, Y: 75}},
			// A general arena entrance for tickets with no seat. Without one, every
			// arena door is section-restricted and a standing or VIP ticket has no
			// way in at all — which is a mistake worth having the starter plan not
			// make, because it only shows up when somebody is standing at a gate.
			{Code: "arena-general", Name: "Arena Entrance", Zone: "arena", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"perimeter"}, Node: "n-portal-a", Position: venue.Point{X: 40, Y: 75}},
			{Code: "pit-gate", Name: "Pit Wristband", Zone: "pit", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"arena"}, Tiers: []venue.TierCode{"vip"}, Node: "n-pit", Position: venue.Point{X: 60, Y: 40}},
			{Code: "food-court", Name: "Food Court", Zone: "concourse", Direction: venue.DirectionBoth, Policy: venue.PolicyReEntry, Requires: []venue.ZoneCode{"perimeter"}, Node: "n-concourse", Position: venue.Point{X: 70, Y: 88}},
			{Code: "bar-token", Name: "Bar Token", Zone: "concourse", Direction: venue.DirectionIn, Policy: venue.PolicyCounted, CountLimit: 2, Requires: []venue.ZoneCode{"perimeter"}, Node: "n-concourse", Position: venue.Point{X: 95, Y: 88}},
		},
		Tiers: []venue.Tier{
			{Code: "ga", Name: "General Admission", Zones: []venue.ZoneCode{"perimeter", "arena"}, Colour: "#3B82F6", Priority: 10},
			{Code: "vip", Name: "VIP", Zones: []venue.ZoneCode{"perimeter", "arena", "pit"}, Colour: "#A855F7", Priority: 20},
			{Code: "crew", Name: "Crew", Zones: []venue.ZoneCode{"perimeter", "concourse", "arena", "pit"}, Colour: "#F59E0B", Priority: 90},
		},
		Amenities: []venue.Amenity{
			{ID: "wc-concourse", Kind: venue.AmenityWashroom, Name: "Concourse Toilets", Zone: "concourse", Position: venue.Point{X: 45, Y: 92}, Node: "n-concourse", Accessible: true},
			{ID: "wc-arena", Kind: venue.AmenityWashroom, Name: "Arena Toilets", Zone: "arena", Position: venue.Point{X: 88, Y: 70}, Node: "n-portal-a"},
			{ID: "food-1", Kind: venue.AmenityFood, Name: "Biryani Cart", Zone: "concourse", Position: venue.Point{X: 38, Y: 95}, Node: "n-concourse"},
			{ID: "water-1", Kind: venue.AmenityWater, Name: "Water Point", Zone: "concourse", Position: venue.Point{X: 52, Y: 95}, Node: "n-concourse"},
			{ID: "medical-1", Kind: venue.AmenityMedical, Name: "Medical Tent", Zone: "concourse", Position: venue.Point{X: 20, Y: 95}, Node: "n-concourse", Accessible: true},
			{ID: "exit-1", Kind: venue.AmenityExit, Name: "Emergency Exit", Zone: "perimeter", Position: venue.Point{X: 5, Y: 60}, Node: "n-gate-north"},
		},
		Map: venue.Map{
			Width: 120, Height: 110, MetresPerUnit: 1.5,
			Stage:   venue.Polygon{{X: 40, Y: 8}, {X: 80, Y: 8}, {X: 80, Y: 18}, {X: 40, Y: 18}},
			Outline: venue.Polygon{{X: 0, Y: 0}, {X: 120, Y: 0}, {X: 120, Y: 110}, {X: 0, Y: 110}},
			Nodes: []venue.Node{
				{ID: "n-gate-north", Kind: venue.NodeGate, Name: "the North Gate", Position: venue.Point{X: 15, Y: 100}},
				{ID: "n-gate-south", Kind: venue.NodeGate, Name: "the South Gate", Position: venue.Point{X: 105, Y: 100}},
				{ID: "n-concourse", Kind: venue.NodeConcourse, Name: "the concourse", Zone: "concourse", Position: venue.Point{X: 60, Y: 92}},
				{ID: "n-portal-a", Kind: venue.NodePortal, Name: "Portal A", Zone: "arena", Position: venue.Point{X: 60, Y: 75}},
				{ID: "n-aisle-a", Kind: venue.NodeAisle, Name: "the Block A aisle", Zone: "arena", Position: venue.Point{X: 28, Y: 58}},
				{ID: "n-pit", Kind: venue.NodeSeatBlock, Name: "the pit", Zone: "pit", Position: venue.Point{X: 60, Y: 40}},
			},
			Edges: []venue.Edge{
				{From: "n-gate-north", To: "n-concourse"},
				{From: "n-gate-south", To: "n-concourse"},
				{From: "n-concourse", To: "n-portal-a", Kind: venue.EdgeDoor, Note: "through the double doors"},
				{From: "n-portal-a", To: "n-aisle-a"},
				{From: "n-portal-a", To: "n-pit"},
			},
		},
	}

	// Compiled before it is written, so the starter plan is known to be valid and
	// an organizer editing it has a working baseline to diff against.
	if _, err := venue.Compile(plan); err != nil {
		return fmt.Errorf("the starter plan does not compile, which is a bug: %w", err)
	}
	if err := writeJSONFile(*out, 0o644, plan); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s — edit it, then run `gatecrash-keys issue`\n", *out)
	return nil
}

func seats(n int) []venue.Seat {
	out := make([]venue.Seat, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, venue.Seat{Number: fmt.Sprint(i)})
	}
	return out
}

// TicketFile is the issued ticket list.
type TicketFile struct {
	EventID string          `json:"event_id"`
	Tickets []engine.Ticket `json:"tickets"`

	// Holders maps a ticket id to the URL an attendee opens. Written for the
	// organizer's mail merge and deliberately not sent to the box: the box holds
	// pseudonymous ids and nothing that would make it worth stealing.
	Holders []Holder `json:"holders"`
}

// Holder is one issued ticket in the form the organizer's mail merge wants.
type Holder struct {
	TicketID string `json:"ticket_id"`
	Tier     string `json:"tier"`
	Seat     string `json:"seat,omitempty"`

	// Payload is the static QR string, for print or email.
	Payload string `json:"payload,omitempty"`

	// URL is the attendee's ticket page, for the in-app path.
	URL string `json:"url"`
}

// issue mints tickets against a venue plan.
func issue(args []string) error {
	flags := flag.NewFlagSet("issue", flag.ContinueOnError)
	keysPath := flags.String("keys", "gatecrash-keys.json", "the organizer key file")
	venuePath := flags.String("venue", "venue.json", "the venue plan")
	out := flags.String("out", "tickets.json", "where to write the ticket list")
	eventIDHex := flags.String("event", "", "an existing event id; a new one is generated when empty")
	count := flags.Int("n", 100, "how many tickets to issue")
	tier := flags.String("tier", "ga", "the tier to issue")
	section := flags.String("section", "", "seat tickets into this section, filling rows in order")
	rotating := flags.Bool("rotating", false, "issue rotating in-app codes instead of printed ones")
	base := flags.String("base-url", "http://go.gate", "the base URL for attendee ticket links")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *count <= 0 {
		return errors.New("issue at least one ticket")
	}

	var keys Keys
	if err := readJSONFile(*keysPath, &keys); err != nil {
		return err
	}
	signing, err := keys.signingKey()
	if err != nil {
		return err
	}

	var plan venue.Plan
	if err := readJSONFile(*venuePath, &plan); err != nil {
		return err
	}
	compiled, err := venue.Compile(plan)
	if err != nil {
		return fmt.Errorf("the venue plan does not compile: %w", err)
	}
	if _, ok := compiled.Tier(venue.TierCode(*tier)); !ok {
		return fmt.Errorf("the plan defines no tier %q", *tier)
	}

	eventID := ticket.MustNewID()
	if *eventIDHex != "" {
		if eventID, err = ticket.ParseID(*eventIDHex); err != nil {
			return err
		}
	}

	format := engine.FormatStatic
	if *rotating {
		format = engine.FormatRotating
	}

	// Seats are allocated in row order, which is what a promoter selling a block
	// expects: consecutive buyers sit together.
	var allocations []venue.SeatRef
	if *section != "" {
		if allocations, err = allocateSeats(compiled, venue.SectionCode(*section), *count); err != nil {
			return err
		}
	}

	issuedAt := time.Now().UTC().UnixMilli()
	file := TicketFile{EventID: eventID.Hex()}

	for i := 0; i < *count; i++ {
		id := ticket.MustNewID()
		var seat venue.SeatRef
		if allocations != nil {
			seat = allocations[i]
		}
		if err := compiled.ValidateSeat(venue.TierCode(*tier), seat); err != nil {
			return err
		}

		claims := ticket.Claims{
			EventID: eventID, TicketID: id, Tier: *tier, IssuedAt: issuedAt,
		}
		payload, err := ticket.SignGC1(signing, claims)
		if err != nil {
			return err
		}
		parsed, err := ticket.ParseGC1(payload)
		if err != nil {
			return err
		}

		file.Tickets = append(file.Tickets, engine.Ticket{
			ID: id, EventID: eventID, Tier: venue.TierCode(*tier), Seat: seat,
			IssuedAt: issuedAt, Signature: parsed.Signature, Format: format,
		})
		holder := Holder{
			TicketID: id.String(), Tier: *tier, Seat: seat.String(),
			URL: fmt.Sprintf("%s/attendee/#/t/%s", *base, id.String()),
		}
		// The static payload only for tickets that may actually be presented that
		// way. Printing a GC1 code for a rotating ticket would undo the whole
		// anti-screenshot property before the event even starts.
		if format != engine.FormatRotating {
			holder.Payload = payload
		}
		file.Holders = append(file.Holders, holder)
	}

	if err := writeJSONFile(*out, 0o600, file); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "issued %d %s tickets for event %s\n  wrote %s\n",
		*count, *tier, eventID.Hex(), *out)
	if *rotating {
		fmt.Fprintln(os.Stderr, "  these are rotating in-app codes: attendees must open the link to claim them")
	}
	return nil
}

// allocateSeats hands out consecutive seats from a section.
func allocateSeats(compiled *venue.Venue, section venue.SectionCode, count int) ([]venue.SeatRef, error) {
	found, ok := compiled.Section(section)
	if !ok {
		return nil, fmt.Errorf("the plan defines no section %q", section)
	}
	if !found.Kind.Seated() {
		return nil, fmt.Errorf("section %q is standing, so it has no seats to allocate", section)
	}

	var out []venue.SeatRef
	for _, row := range found.Rows {
		for _, seat := range row.Seats {
			if seat.Blocked {
				continue
			}
			out = append(out, venue.SeatRef{Section: section, Row: row.Label, Seat: seat.Number})
			if len(out) == count {
				return out, nil
			}
		}
	}
	return nil, fmt.Errorf("section %q holds %d seats, which is fewer than the %d requested",
		section, len(out), count)
}

// signManifest builds and signs the manifest the box ingests.
func signManifest(args []string) error {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	keysPath := flags.String("keys", "gatecrash-keys.json", "the organizer key file")
	venuePath := flags.String("venue", "venue.json", "the venue plan")
	ticketPaths := flags.String("tickets", "tickets.json", "comma-separated ticket files")
	out := flags.String("out", "manifest.json", "where to write the manifest")
	eventName := flags.String("event", "", "the event name")
	venueName := flags.String("venue-name", "", "the venue's human name")
	timezone := flags.String("tz", "Asia/Kolkata", "IANA timezone, for display only")
	doors := flags.String("doors", "", "when doors open, RFC 3339")
	curfew := flags.String("curfew", "", "when gates close, RFC 3339")
	mode := flags.String("mode", string(engine.ModeStrict), "consistency mode: strict or degraded")
	support := flags.String("support", "", "what an attendee should do when something goes wrong")
	sequence := flags.Int("sequence", 1, "manifest sequence; raise it for every re-issue")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *eventName == "" {
		return errors.New("an event needs a name (-event)")
	}

	var keys Keys
	if err := readJSONFile(*keysPath, &keys); err != nil {
		return err
	}
	signing, err := keys.signingKey()
	if err != nil {
		return err
	}
	root, err := keys.rootKey()
	if err != nil {
		return err
	}

	var plan venue.Plan
	if err := readJSONFile(*venuePath, &plan); err != nil {
		return err
	}

	var (
		tickets  []engine.Ticket
		eventID  ticket.ID
		rotating bool
	)
	for _, path := range splitList(*ticketPaths) {
		var file TicketFile
		if err := readJSONFile(path, &file); err != nil {
			return err
		}
		parsed, err := ticket.ParseID(file.EventID)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if eventID.IsZero() {
			eventID = parsed
		} else if eventID != parsed {
			// Two ticket files for two different events in one manifest would
			// produce a box that rejects half its own tickets as WRONG_EVENT.
			return fmt.Errorf("%s is for event %s but the others are for %s", path, parsed, eventID)
		}
		for _, issued := range file.Tickets {
			if issued.Format != engine.FormatStatic {
				rotating = true
			}
		}
		tickets = append(tickets, file.Tickets...)
	}
	if eventID.IsZero() {
		return errors.New("no tickets found; run `gatecrash-keys issue` first")
	}

	body := manifest.Body{
		Event: manifest.Event{
			ID: eventID, Name: *eventName, Venue: *venueName, Timezone: *timezone,
			Mode: engine.Mode(*mode), Support: *support,
		},
		Venue:     plan,
		Tickets:   tickets,
		Verifying: signing.Public(),
		IssuedAt:  time.Now().UTC(),
		Sequence:  uint64(*sequence),
	}
	if *doors != "" {
		if body.Event.Doors, err = time.Parse(time.RFC3339, *doors); err != nil {
			return fmt.Errorf("parsing -doors: %w", err)
		}
	}
	if *curfew != "" {
		if body.Event.Curfew, err = time.Parse(time.RFC3339, *curfew); err != nil {
			return fmt.Errorf("parsing -curfew: %w", err)
		}
	}
	// The event master key is only included when something in the manifest needs
	// it. A print-only event ships without the most sensitive field in the file,
	// which is the correct default.
	if rotating {
		eventMaster, err := ticket.DeriveEventMaster(root, eventID)
		if err != nil {
			return err
		}
		body.Master = eventMaster.String()
	}

	envelope, err := manifest.Sign(signing, body)
	if err != nil {
		return err
	}
	raw, err := envelope.Marshal()
	if err != nil {
		return err
	}
	if *out == "-" {
		_, err := os.Stdout.Write(raw)
		return err
	}
	if err := os.WriteFile(*out, raw, 0o600); err != nil {
		return err
	}

	summary := body.Summarise()
	fmt.Fprintf(os.Stderr, `wrote %s

  event        %s
  event id     %s
  organizer    %s
  digest       %s
  tickets      %d (%d rotating)
  checkpoints  %d
  mode         %s

`, *out, summary.Event, summary.EventID, summary.Fingerprint, envelope.Digest(),
		summary.Tickets, summary.Rotating, summary.Checkpoints, summary.Mode)

	if rotating {
		fmt.Fprintf(os.Stderr, `This manifest carries the event master key, which can mint a rotating code for
every ticket in it. Seal it before it travels:

  gatecrash-keys seal -in %s -out %s.sealed

`, *out, *out)
	}
	return nil
}

// seal encrypts a manifest under a passphrase for transport.
func seal(args []string) error {
	flags := flag.NewFlagSet("seal", flag.ContinueOnError)
	in := flags.String("in", "manifest.json", "the manifest to seal")
	out := flags.String("out", "manifest.sealed.json", "where to write the sealed file")
	passphrase := flags.String("passphrase", "", "the passphrase; read from GATECRASH_MANIFEST_PASSPHRASE when empty")
	if err := flags.Parse(args); err != nil {
		return err
	}

	phrase := *passphrase
	if phrase == "" {
		phrase = os.Getenv("GATECRASH_MANIFEST_PASSPHRASE")
	}
	if phrase == "" {
		return errors.New("a passphrase is required; pass -passphrase or set GATECRASH_MANIFEST_PASSPHRASE")
	}

	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	envelope, err := manifest.Unmarshal(raw)
	if err != nil {
		return err
	}
	sealed, err := manifest.Seal(envelope, phrase)
	if err != nil {
		return err
	}
	if err := writeJSONFile(*out, 0o600, sealed); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "sealed %s into %s\n  the box needs GATECRASH_MANIFEST_PASSPHRASE to open it\n", *in, *out)
	return nil
}

// inspect describes a manifest.
//
// Explicitly without trusting it: this prints what the file claims, so somebody
// handed a manifest can see what they have before a box ingests it.
func inspect(args []string) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fingerprint := flags.String("fingerprint", "", "require this organizer fingerprint")
	passphrase := flags.String("passphrase", "", "passphrase for a sealed manifest")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: gatecrash-keys inspect <manifest.json>")
	}

	raw, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		return err
	}
	envelope, err := manifest.Unmarshal(raw)
	if err != nil {
		var sealed manifest.Sealed
		if jsonErr := jsonUnmarshalStrict(raw, &sealed); jsonErr != nil || sealed.Format != manifest.SealFormat {
			return err
		}
		fmt.Printf("sealed manifest\n  signed by  %s\n", sealed.Fingerprint)
		if *passphrase == "" {
			fmt.Println("  pass -passphrase to look inside")
			return nil
		}
		if envelope, err = manifest.Open(sealed, *passphrase); err != nil {
			return err
		}
	}

	body, err := manifest.Verify(envelope, ticket.VerifyingKey{}, *fingerprint)
	if err != nil {
		return err
	}
	summary := body.Summarise()
	summary.Digest = envelope.Digest()

	encoded, err := jsonIndent(summary)
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	if *fingerprint == "" {
		fmt.Fprintln(os.Stderr,
			"\nnote: checked for self-consistency only. Pass -fingerprint to verify it is really yours.")
	}
	return nil
}

// splitList splits a comma-separated flag value.
func splitList(value string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(value); i++ {
		if i == len(value) || value[i] == ',' {
			if part := trim(value[start:i]); part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
