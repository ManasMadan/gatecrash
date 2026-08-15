package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/httpapi"
	"github.com/ManasMadan/gatecrash/internal/incident"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

func (d *demo) actSetup() error {
	var meta httpapi.Meta
	if err := d.request(http.MethodGet, "/v1/meta", "", nil, &meta); err != nil {
		return err
	}
	d.note("event          %s at %s", meta.Event, meta.VenueName)
	d.note("mode           %s (gates stop admitting during a partition)", meta.Mode)
	d.note("tickets        %d issued", len(d.tickets))
	d.note("rotating       %v (in-app codes rotate every %ds)", meta.Rotating, ticket.WindowSeconds)

	var venueResponse httpapi.VenueResponse
	if err := d.request(http.MethodGet, "/v1/venue", "", nil, &venueResponse); err != nil {
		return err
	}
	seats := 0
	for _, section := range venueResponse.Plan.Sections {
		for _, row := range section.Rows {
			seats += len(row.Seats)
		}
	}
	d.note("venue          %d zones, %d checkpoints, %d sections, %d seats, %d amenities",
		len(venueResponse.Plan.Zones), len(venueResponse.Plan.Checkpoints),
		len(venueResponse.Plan.Sections), seats, len(venueResponse.Plan.Amenities))
	d.note("walk graph     %d nodes, %d edges (routing, with a step-free variant)",
		len(venueResponse.Plan.Map.Nodes), len(venueResponse.Plan.Map.Edges))
	return nil
}

func (d *demo) actEnroll() error {
	d.note("the organizer prints a QR per gate; each one is single-use and expires in ten minutes")
	for _, gate := range []struct {
		name        string
		checkpoints []venue.CheckpointCode
	}{
		{"north", []venue.CheckpointCode{"gate-north"}},
		{"south", []venue.CheckpointCode{"gate-south"}},
		{"exit", []venue.CheckpointCode{"gate-exit"}},
		{"portal-a", []venue.CheckpointCode{"portal-a"}},
		{"portal-b", []venue.CheckpointCode{"portal-b"}},
		{"arena", []venue.CheckpointCode{"arena-general"}},
		{"pit", []venue.CheckpointCode{"pit-gate"}},
		{"stage", []venue.CheckpointCode{"stage-door"}},
		{"food", []venue.CheckpointCode{"food-court"}},
		{"bar", []venue.CheckpointCode{"bar-token"}},
	} {
		if err := d.enrollGate(gate.name, gate.checkpoints...); err != nil {
			return err
		}
	}

	// The sync a scanner performs on connect: one request and it can reject
	// unknown QR codes with no network at all.
	var sync httpapi.ManifestResponse
	if err := d.request(http.MethodGet, "/v1/manifest", d.tokens["north"], nil, &sync); err != nil {
		return err
	}
	d.note("")
	d.note("north's offline mirror: bloom over %d ticket ids (%d bits, %d hashes), %d already redeemed, seq %d",
		sync.Tickets, sync.BloomBits, sync.BloomHashes, len(sync.Redeemed), sync.Seq)
	d.note("it can now reject a random QR code in microseconds with no network at all")
	return nil
}

func (d *demo) actHappyPath() error {
	asha := d.tickets["asha"].payload

	result, err := d.scan("north", asha, "gate-north")
	if err != nil {
		return err
	}
	d.verdict("north gate", result)

	d.advance(4 * time.Minute)
	result, err = d.scan("portal-a", asha, "portal-a")
	if err != nil {
		return err
	}
	d.verdict("portal A", result)

	// What the attendee's own app shows, computed on the box so the usher and the
	// person they are directing cannot be told different things.
	var view httpapi.TicketResponse
	if err := d.request(http.MethodGet, "/v1/ticket/"+d.tickets["asha"].record.ID.String()+"?from=n-portal-a", "", nil, &view); err != nil {
		return err
	}
	d.note("")
	d.note("asha's phone says: %s, %s", view.TierName, view.SeatLabel)
	if view.Guidance != nil && view.Guidance.Destination != nil {
		destination := view.Guidance.Destination
		d.note("  destination  %s", destination.SeatLabel)
		if destination.Route != nil {
			d.note("  route        %d m, about %ds", int(destination.Route.Metres), destination.Route.Seconds)
			for _, leg := range destination.Route.Legs {
				d.note("               %s", leg.Instruction)
			}
		}
	}
	for _, admission := range view.History {
		d.note("  been through %s into %s", admission.CheckpointName, admission.ZoneName)
	}
	return nil
}

func (d *demo) actDoubleScan() error {
	d.note("somebody photographs asha's ticket and tries it at the other gate")
	result, err := d.scan("south", d.tickets["asha"].payload, "gate-south")
	if err != nil {
		return err
	}
	// A different gate is a different tuple, so this legitimately admits: the
	// guarantee is one admission per (ticket, checkpoint), and the north gate is
	// not the south gate. Saying so out loud is more useful than pretending.
	d.verdict("south gate", result)
	d.note("  the south gate is a different checkpoint, so this is a second, legitimate pass")
	d.note("  the guarantee is one admission per (ticket, checkpoint) — not one per ticket")

	d.note("")
	d.note("at the gate they already used, though:")
	result, err = d.scan("north", d.tickets["asha"].payload, "gate-north")
	if err != nil {
		return err
	}
	d.verdict("north gate", result)
	return nil
}

func (d *demo) actIdempotency() error {
	d.note("bilal's scan is sent, the Wi-Fi drops, and the scanner retries the same request")
	request := httpapi.ScanRequest{
		ScanID: ticket.MustNewID().Hex(), Payload: d.tickets["bilal"].payload, Checkpoint: "gate-north",
	}

	first, err := d.scanWith("north", request)
	if err != nil {
		return err
	}
	d.verdict("north gate", first)

	for i := 0; i < 2; i++ {
		replay, err := d.scanWith("north", request)
		if err != nil {
			return err
		}
		d.verdict("retry", replay)
	}
	d.note("")
	d.note("  the retries carry the same scan id, so the box replays the original verdict")
	d.note("  most systems report this to staff as ticket reuse; it is a duplicated packet")
	return nil
}

func (d *demo) actWrongDoor() error {
	d.note("chetan holds Block B but joins the Block A queue")
	if _, err := d.scan("north", d.tickets["chetan"].payload, "gate-north"); err != nil {
		return err
	}

	result, err := d.scan("portal-a", d.tickets["chetan"].payload, "portal-a")
	if err != nil {
		return err
	}
	d.verdict("portal A", result)
	d.note("  amber, not red: the ticket is perfect and the person is in the wrong place")
	d.note("  a red screen here is how gate staff end up arguing with paying customers")

	result, err = d.scan("portal-b", d.tickets["chetan"].payload, "portal-b")
	if err != nil {
		return err
	}
	d.verdict("portal B", result)

	// The step-free route exists because the upper tier is up a flight of stairs,
	// and silently routing somebody who cannot use them would be the worst failure
	// this system could produce.
	var view httpapi.TicketResponse
	if err := d.request(http.MethodGet,
		"/v1/ticket/"+d.tickets["chetan"].record.ID.String()+"?from=n-concourse&step_free=1", "", nil, &view); err != nil {
		return err
	}
	if view.Guidance != nil && view.Guidance.Destination != nil && view.Guidance.Destination.Route != nil {
		d.note("")
		d.note("chetan asks for a step-free route to Block B:")
		for _, leg := range view.Guidance.Destination.Route.Legs {
			d.note("  %s", leg.Instruction)
		}
		d.note("  step free: %v", view.Guidance.Destination.Route.StepFree)
	}
	return nil
}

func (d *demo) actPrerequisite() error {
	d.note("divya has a standing ticket and walks straight to the pit")
	if _, err := d.scan("north", d.tickets["divya"].payload, "gate-north"); err != nil {
		return err
	}

	result, err := d.scan("pit", d.tickets["divya"].payload, "pit-gate")
	if err != nil {
		return err
	}
	d.verdict("pit", result)
	d.note("  general admission is not entitled to the pit at all — that is a red screen")

	d.note("")
	d.note("she goes to the arena instead:")
	result, err = d.scan("arena", d.tickets["divya"].payload, "arena-general")
	if err != nil {
		return err
	}
	d.verdict("arena", result)
	return nil
}

func (d *demo) actRotating() error {
	esha := d.tickets["esha"].record

	var view httpapi.TicketResponse
	if err := d.request(http.MethodGet, "/v1/ticket/"+esha.ID.String(), "", nil, &view); err != nil {
		return err
	}
	d.note("esha's ticket is a rotating in-app code")
	d.note("  format  %s", view.Format)
	d.note("  static payload handed out: %q — there isn't one, by design", view.Payload)

	// The claim is the only time the secret crosses the network. After this the
	// phone generates codes with no network at all.
	var claim httpapi.ClaimResponse
	if err := d.request(http.MethodPost, "/v1/ticket/"+esha.ID.String()+"/claim", "",
		httpapi.ClaimRequest{Device: "esha-pixel"}, &claim); err != nil {
		return err
	}
	secret, err := ticket.ParseSecret(claim.Secret)
	if err != nil {
		return err
	}
	d.note("  claimed once over TLS; from here the phone generates codes offline")

	window := ticket.Window(claim.Window)
	fresh := ticket.GenerateGC2(secret, d.keys.eventID, esha.ID, window)
	d.note("")
	d.note("the code her phone draws right now (%d characters, a version 3 QR):", len(fresh))
	d.note("  %s", fresh)

	result, err := d.scan("north", fresh, "gate-north")
	if err != nil {
		return err
	}
	d.verdict("north gate", result)

	// The pit, which is what she paid for.
	if _, err := d.scan("arena", ticket.GenerateGC2(secret, d.keys.eventID, esha.ID, window), "arena-general"); err != nil {
		return err
	}
	result, err = d.scan("pit", ticket.GenerateGC2(secret, d.keys.eventID, esha.ID, window), "pit-gate")
	if err != nil {
		return err
	}
	d.verdict("pit", result)

	d.note("")
	d.note("her friend screenshots the code and turns up ninety seconds later:")
	stale := ticket.GenerateGC2(secret, d.keys.eventID, esha.ID, window-3)
	result, err = d.scan("south", stale, "gate-south")
	if err != nil {
		return err
	}
	d.verdict("south gate", result)
	d.note("  amber, because the usual cause is a phone that was in a pocket")
	d.note("  a screenshot is dead in at most %ds; the compare-and-set catches the rest", 2*ticket.WindowSeconds)
	return nil
}

func (d *demo) actGarbage() error {
	for label, payload := range map[string]string{
		"a supermarket barcode": "4006381333931",
		"a URL":                 "https://example.com/tickets",
		"last year's ticket":    d.foreignTicket(),
		"a cancelled ticket":    d.tickets["ghost"].payload,
	} {
		result, err := d.scan("north", payload, "gate-north")
		if err != nil {
			return err
		}
		d.verdict(label, result)
	}
	d.note("")
	d.note("  each one is a different verdict, because each needs a different sentence")
	d.note("  most systems collapse all of these into \"invalid\"")
	return nil
}

// foreignTicket mints a well-formed ticket signed by somebody else's key, which is
// what a forgery actually looks like.
func (d *demo) foreignTicket() string {
	signing, _, err := ticket.GenerateSigningKey()
	if err != nil {
		panic(err)
	}
	payload, err := ticket.SignGC1(signing, ticket.Claims{
		EventID: d.keys.eventID, TicketID: d.tickets["asha"].record.ID,
		Tier: "ga", IssuedAt: doors.UnixMilli(),
	})
	if err != nil {
		panic(err)
	}
	return payload
}

func (d *demo) actPolicies() error {
	farhan := d.tickets["farhan"].payload
	if _, err := d.scan("north", farhan, "gate-north"); err != nil {
		return err
	}

	d.note("farhan is crew. the food court is a re-entry door:")
	for round := 0; round < 2; round++ {
		in, err := d.scanWith("food", httpapi.ScanRequest{
			ScanID: ticket.MustNewID().Hex(), Payload: farhan,
			Checkpoint: "food-court", Direction: venue.DirectionIn,
		})
		if err != nil {
			return err
		}
		d.verdict("food court in", in)
		d.advance(11 * time.Minute)

		out, err := d.scanWith("food", httpapi.ScanRequest{
			ScanID: ticket.MustNewID().Hex(), Payload: farhan,
			Checkpoint: "food-court", Direction: venue.DirectionOut,
		})
		if err != nil {
			return err
		}
		d.verdict("food court out", out)
	}

	d.note("")
	d.note("the bar gives him exactly two:")
	for i := 0; i < 3; i++ {
		result, err := d.scan("bar", farhan, "bar-token")
		if err != nil {
			return err
		}
		d.verdict(fmt.Sprintf("drink %d", i+1), result)
	}

	d.note("")
	d.note("he leaves the site, then tries the arena on the way past:")
	out, err := d.scan("exit", farhan, "gate-exit")
	if err != nil {
		return err
	}
	d.verdict("exit", out)
	result, err := d.scan("arena", farhan, "arena-general")
	if err != nil {
		return err
	}
	d.verdict("arena", result)
	d.note("  walking out undoes the perimeter, so the arena's prerequisite fails")
	return nil
}

func (d *demo) actIncidents() error {
	d.note("the pit is filling up. the bouncer presses two buttons.")

	var staffing incident.Incident
	if err := d.request(http.MethodPost, "/v1/incidents", d.tokens["pit"], httpapi.IncidentRequest{
		Kind: incident.NeedStaff, HeadCount: 3, Reporter: "Aditi", Note: "queue is 200 deep",
	}, &staffing); err != nil {
		return err
	}
	d.note("")
	d.note("  %s  %s  %s", staffing.ID, staffing.Kind, staffing.Severity)
	d.note("    at %s (%s), raised by %s on %s",
		staffing.CheckpointName, staffing.ZoneName, staffing.Reporter, staffing.Device)
	d.note("    asking for %d people; the box attached the gate's own scan rate of %.0f/min",
		staffing.HeadCount, staffing.QueueRate)

	var alarm incident.Incident
	if err := d.request(http.MethodPost, "/v1/incidents", d.tokens["pit"], httpapi.IncidentRequest{
		Kind: incident.Crush, Reporter: "Aditi", Note: "front barrier is buckling",
	}, &alarm); err != nil {
		return err
	}
	d.note("")
	d.note("  %s  %s  %s  ← takes over the control room's screen", alarm.ID, alarm.Kind, alarm.Severity)

	// The lifecycle is the point: an alert nobody acknowledged is worse than no
	// alert, because everybody assumes somebody else has it.
	d.advance(35 * time.Second)
	if err := d.request(http.MethodPost, "/v1/admin/incidents/"+string(alarm.ID), d.admin,
		httpapi.TransitionRequest{Status: incident.Acknowledged, Actor: "control"}, nil); err != nil {
		return err
	}
	d.advance(20 * time.Second)
	var assigned incident.Incident
	if err := d.request(http.MethodPost, "/v1/admin/incidents/"+string(alarm.ID), d.admin,
		httpapi.TransitionRequest{Status: incident.Assigned, Actor: "control", AssignedTo: "security-2"}, &assigned); err != nil {
		return err
	}
	d.advance(3 * time.Minute)
	var resolved incident.Incident
	if err := d.request(http.MethodPost, "/v1/admin/incidents/"+string(alarm.ID), d.admin,
		httpapi.TransitionRequest{Status: incident.Resolved, Actor: "security-2", Note: "barrier reset, pit thinned out"}, &resolved); err != nil {
		return err
	}

	acked, _ := resolved.AcknowledgedAfter()
	fixed, _ := resolved.ResolvedAfter()
	d.note("")
	d.note("  acknowledged after %s, resolved after %s", acked, fixed)
	for _, event := range resolved.History {
		d.note("    %-14s %-12s %s", event.Status, event.Actor, event.Note)
	}
	d.note("")
	d.note("  every transition is attributed and hash-chained into the same log as the admissions")
	d.note("  \"we called for medical at 23:41 and nobody came\" is provable or it is hearsay")

	// A gate sees its own zone plus emergencies, and nothing else.
	var atNorth []incident.Incident
	if err := d.request(http.MethodGet, "/v1/incidents", d.tokens["north"], nil, &atNorth); err != nil {
		return err
	}
	d.note("")
	d.note("  the north gate's own list: %d items (the pit's staffing request is not its business)", len(atNorth))

	// And an announcement, which also goes out over the mesh at organizer priority.
	var announcement httpapi.Announcement
	if err := d.request(http.MethodPost, "/v1/admin/announce", d.admin,
		httpapi.AnnounceRequest{Text: "Pit is at capacity. Head to the arena floor.", Priority: true}, &announcement); err != nil {
		return err
	}
	d.note("  announcement sent: %q", announcement.Text)
	return nil
}

func (d *demo) actDashboard() error {
	var board httpapi.DashboardStats
	if err := d.request(http.MethodGet, "/v1/admin/stats", d.admin, nil, &board); err != nil {
		return err
	}
	live := board.Live

	d.note("inside     %d  ·  scans %d  ·  denied %d  ·  admissions %d",
		live.Inside, live.Scans, live.Denied, live.Scans-live.Denied)

	verdicts := make([]string, 0, len(live.Verdicts))
	for verdict, count := range live.Verdicts {
		verdicts = append(verdicts, fmt.Sprintf("%s×%d", verdict, count))
	}
	d.note("verdicts   %s", strings.Join(verdicts, "  "))

	d.note("")
	for _, zone := range live.Zones {
		if zone.Occupied == 0 {
			continue
		}
		capacity := "no stated capacity"
		if zone.Capacity > 0 {
			capacity = fmt.Sprintf("of %d (%.0f%% full)", zone.Capacity, zone.Fill*100)
		}
		d.note("zone       %-18s %3d %s", zone.Name, zone.Occupied, capacity)
	}
	d.note("")
	for _, gate := range live.Gates {
		if gate.Admitted == 0 && gate.Denied == 0 {
			continue
		}
		// The throughput rate is omitted here: the demo drives its clock forwards
		// in minutes, so the one-minute window has always rolled past and the
		// number would read as zero for reasons that have nothing to do with the
		// gate.
		d.note("gate       %-18s %d in, %d refused", gate.Name, gate.Admitted, gate.Denied)
	}
	d.note("")
	for _, section := range live.Sections {
		if section.Admitted == 0 {
			continue
		}
		d.note("section    %-18s %3d of %d seats taken", section.Name, section.Admitted, section.Capacity)
	}
	d.note("")
	d.note("incidents  %+v", board.Counts)
	d.note("response   median ack %.0fs, worst %.0fs, never acknowledged %d",
		board.Response.MedianAckSeconds, board.Response.WorstAckSeconds, board.Response.NeverAcked)
	d.note("chain      %d rows, head %s…", board.ChainRows, board.ChainHead[:16])
	d.note("scanners   %d enrolled", len(board.Devices))
	return nil
}

func (d *demo) actSettlement() error {
	rows, err := d.verifyChain()
	if err != nil {
		return err
	}
	d.note("the audit log holds %d rows — every decision, not just the admissions", rows)
	d.note("replaying the hash chain: ok")

	var verified httpapi.VerifyResponse
	if err := d.request(http.MethodGet, "/v1/admin/verify", d.admin, nil, &verified); err != nil {
		return err
	}
	d.note("the box agrees: ok=%v, %d rows", verified.OK, verified.Rows)

	sealed, err := d.store.Seal(context.Background(), 0)
	if err != nil {
		return err
	}
	d.note("")
	d.note("sealed checkpoint")
	d.note("  rows  %d", sealed.Rows)
	d.note("  root  %s", sealed.Root)
	d.note("  head  %s", sealed.Head)
	d.note("  the organizer publishes that root. it is 32 bytes.")

	// One admission, proved against the published root by somebody holding nothing
	// else. This is the settlement workflow.
	proof, found, err := d.store.Attendance(context.Background(), d.tickets["asha"].record.ID)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("asha was admitted but has no attendance proof")
	}
	if err := audit.VerifyAttendance(proof); err != nil {
		return err
	}
	d.note("")
	d.note("asha's admission, proved against that root:")
	d.note("  %s at %s by %s", proof.Record.Verdict, proof.Record.Checkpoint, proof.Record.Device)
	d.note("  %d sibling hashes, %d bytes", len(proof.Proof.Siblings), len(proof.Proof.Siblings)*32)
	d.note("  verified with the root alone — no log, no database, no trust in the box")

	// And tampering is caught.
	tampered := proof
	tampered.Record.Device = "scanner-that-never-existed"
	if err := audit.VerifyAttendance(tampered); err == nil {
		return errors.New("a forged attendance record verified, which is a bug")
	}
	d.note("")
	d.note("changing one field of that record: proof fails. tampering is mathematically evident.")

	// The whole event, signed.
	var report map[string]any
	if err := d.request(http.MethodGet, "/v1/admin/export", d.admin, nil, &report); err != nil {
		return err
	}
	d.note("")
	d.note("the signed attendance report is %d fields of settlement evidence,", len(report))
	d.note("signed by the box's own key so a promoter cannot edit it on the way to the artist.")
	return nil
}
