package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/enginetest"
	"github.com/ManasMadan/gatecrash/internal/memstore"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// harness is one event, wired up and ready to scan.
type harness struct {
	t     *testing.T
	f     *enginetest.Fixture
	store *memstore.Store
	e     *engine.Engine
	now   time.Time
}

func newHarness(t *testing.T, mode engine.Mode) *harness {
	t.Helper()
	h := &harness{t: t, store: memstore.New(), now: enginetest.Doors.Add(90 * time.Minute)}
	h.f = enginetest.NewFixture(t)
	h.f.Load(h.store)

	e, err := engine.New(h.f.Config(mode, func() time.Time { return h.now }))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(context.Background(), h.store); err != nil {
		t.Fatal(err)
	}
	h.e = e
	return h
}

// scan drives one scan with a fresh idempotency key.
func (h *harness) scan(name string, checkpoint venue.CheckpointCode, device string) engine.Result {
	h.t.Helper()
	return h.scanPayload(h.f.Payloads[name], checkpoint, device)
}

func (h *harness) scanPayload(payload string, checkpoint venue.CheckpointCode, device string) engine.Result {
	h.t.Helper()
	result, err := h.e.Scan(context.Background(), h.store, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: payload, Checkpoint: checkpoint, Device: device,
	})
	if err != nil {
		h.t.Fatalf("scan at %s on %s: %v", checkpoint, device, err)
	}
	return result
}

// scanFull drives a scan with every field under the caller's control.
func (h *harness) scanFull(s engine.Scan) engine.Result {
	h.t.Helper()
	if s.ScanID.IsZero() {
		s.ScanID = ticket.MustNewID()
	}
	result, err := h.e.Scan(context.Background(), h.store, s)
	if err != nil {
		h.t.Fatalf("scan: %v", err)
	}
	return result
}

// want asserts a verdict, reporting the reason on failure because the reason is
// what a human debugging a gate would read.
func want(t *testing.T, got engine.Result, verdict engine.Verdict) {
	t.Helper()
	if got.Verdict != verdict {
		t.Fatalf("got %s (%s), want %s", got.Verdict, got.Reason, verdict)
	}
}

func TestAdmitCarriesEverythingTheGateNeedsToShow(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	result := h.scan("ga-block-a", "gate-north", "scanner-north")

	want(t, result, engine.Admit)
	if result.Severity != engine.SeverityAdmit {
		t.Errorf("severity is %s, want admit", result.Severity)
	}
	// These are the fields the verdict screen draws large: the tier colour band
	// the guard matches against a wristband, and the seat an usher points at.
	if result.TierName != "General Admission" || result.TierColour == "" {
		t.Errorf("tier presentation is %q / %q", result.TierName, result.TierColour)
	}
	// The section's name, not its code. An usher points at Block A; "block-a" is a
	// database row.
	if result.SeatLabel != "Block A row A seat 1" {
		t.Errorf("seat label is %q", result.SeatLabel)
	}
	if result.SectionName != "Block A" {
		t.Errorf("section name is %q", result.SectionName)
	}
	if result.ZoneName != "Festival Ground" {
		t.Errorf("zone name is %q", result.ZoneName)
	}
	if result.CheckpointName != "North Gate" {
		t.Errorf("checkpoint name is %q", result.CheckpointName)
	}
	if result.Seq == 0 || result.HLC == 0 {
		t.Errorf("admission has seq %d and hlc %s", result.Seq, result.HLC)
	}
	if result.Reason == "" {
		t.Error("no reason for staff")
	}
}

func TestEveryDenialHasItsOwnVerdict(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)

	t.Run("malformed payload", func(t *testing.T) {
		for _, payload := range []string{"", "hello", "https://example.com", "4006381333931", "GC1.short"} {
			want(t, h.scanPayload(payload, "gate-north", "scanner-north"), engine.Malformed)
		}
	})

	t.Run("unknown ticket", func(t *testing.T) {
		// A well-formed payload for an id that is not in the manifest.
		other := enginetest.NewFixture(t)
		want(t, h.scanPayload(other.Payloads["ga-standing"], "gate-north", "scanner-north"), engine.UnknownTicket)
	})

	t.Run("revoked ticket", func(t *testing.T) {
		want(t, h.scan("revoked", "gate-north", "scanner-north"), engine.Revoked)
	})

	t.Run("forged signature", func(t *testing.T) {
		// A real ticket id with a signature minted by somebody else's key: the
		// id is in the manifest, so this gets past the Bloom filter and the
		// lookup, and only the signature check stops it.
		attacker := enginetest.NewFixture(t)
		real := h.f.Tickets["ga-standing"]
		forged, err := ticket.SignGC1(attacker.Signing, ticket.Claims{
			EventID: h.f.EventID, TicketID: real.ID, Tier: string(real.Tier), IssuedAt: real.IssuedAt,
		})
		if err != nil {
			t.Fatal(err)
		}
		want(t, h.scanPayload(forged, "gate-north", "scanner-north"), engine.InvalidSig)
	})

	t.Run("tier upgrade attempt", func(t *testing.T) {
		// The classic forgery: take a real general-admission ticket and re-sign
		// it claiming to be crew. Without the organizer's key the signature does
		// not verify, and the manifest's own tier is what the box trusts anyway.
		real := h.f.Tickets["ga-standing"]
		upgraded, err := ticket.SignGC1(h.f.Signing, ticket.Claims{
			EventID: h.f.EventID, TicketID: real.ID, Tier: "crew", IssuedAt: real.IssuedAt,
		})
		if err != nil {
			t.Fatal(err)
		}
		// It fails because the stored signature does not match the presented one.
		want(t, h.scanPayload(upgraded, "gate-north", "scanner-north"), engine.InvalidSig)
	})

	t.Run("wrong event", func(t *testing.T) {
		// A genuinely signed ticket, by this organizer, for a different show.
		// This is the multi-room venue and the multi-day festival case, and it
		// must not look like a broken manifest.
		otherEvent := ticket.MustNewID()
		id := ticket.MustNewID()
		claims := ticket.Claims{EventID: otherEvent, TicketID: id, Tier: "ga", IssuedAt: enginetest.Doors.UnixMilli()}
		payload, err := ticket.SignGC1(h.f.Signing, claims)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ticket.ParseGC1(payload)
		if err != nil {
			t.Fatal(err)
		}
		h.store.PutTicket(engine.Ticket{
			ID: id, EventID: otherEvent, Tier: "ga", IssuedAt: claims.IssuedAt,
			Signature: parsed.Signature, Format: engine.FormatStatic,
		})
		want(t, h.scanPayload(payload, "gate-north", "scanner-north"), engine.WrongEvent)
	})
}

// TestScannerAllowlist is the stolen-scanner story. A device is enrolled to a
// checkpoint, not to the event, and an unassigned device scans nothing.
func TestScannerAllowlist(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)

	t.Run("unenrolled device", func(t *testing.T) {
		want(t, h.scan("ga-standing", "gate-north", "scanner-nobody"), engine.ScannerNotAuthorized)
	})
	t.Run("revoked device", func(t *testing.T) {
		want(t, h.scan("ga-standing", "gate-north", "scanner-stolen"), engine.ScannerNotAuthorized)
	})
	t.Run("unassigned device scans nothing", func(t *testing.T) {
		// "No checkpoints" must not mean "every checkpoint". A spare phone
		// somebody picks up should not be able to admit to the pit.
		want(t, h.scan("ga-standing", "gate-north", "scanner-unassigned"), engine.ScannerNotAuthorized)
	})
	t.Run("device at the wrong checkpoint", func(t *testing.T) {
		want(t, h.scan("ga-standing", "gate-south", "scanner-north"), engine.ScannerNotAuthorized)
	})
	t.Run("roaming supervisor device", func(t *testing.T) {
		want(t, h.scan("ga-standing", "gate-south", "scanner-roam"), engine.Admit)
	})

	t.Run("an unauthorized scanner learns nothing about a ticket", func(t *testing.T) {
		// Attribution is checked before the ticket lookup, so a rogue device
		// cannot use the gate as an oracle for which ids exist.
		other := enginetest.NewFixture(t)
		real := h.scan("ga-block-a-2", "gate-north", "scanner-nobody")
		fake := h.scanPayload(other.Payloads["ga-standing"], "gate-north", "scanner-nobody")
		if real.Verdict != fake.Verdict {
			t.Fatalf("a rogue device can distinguish a real ticket (%s) from a fake one (%s)", real.Verdict, fake.Verdict)
		}
	})

	t.Run("revoking a device mid-event stops it immediately", func(t *testing.T) {
		want(t, h.scan("ga-block-a", "gate-north", "scanner-north-2"), engine.Admit)
		h.store.RevokeDevice("scanner-north-2")
		want(t, h.scan("crew", "gate-north", "scanner-north-2"), engine.ScannerNotAuthorized)
		// The same ticket on a device that is still enrolled goes through, so the
		// revocation stopped the device rather than the event.
		want(t, h.scan("crew", "gate-north", "scanner-north"), engine.Admit)
	})
}

// TestZoneEntitlementAndTheDoorTheyShouldBeAt separates the two questions that
// most systems collapse: may this person be in there at all, and is this their
// door. The second is amber with directions, not red.
func TestZoneEntitlementAndTheDoorTheyShouldBeAt(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)

	// Get everyone inside the perimeter first.
	want(t, h.scan("ga-block-a", "gate-north", "scanner-north"), engine.Admit)
	want(t, h.scan("ga-block-b", "gate-north", "scanner-north"), engine.Admit)
	want(t, h.scan("vip-pit", "gate-north", "scanner-north"), engine.Admit)
	want(t, h.scan("crew", "gate-north", "scanner-north"), engine.Admit)

	t.Run("not entitled to the zone at all", func(t *testing.T) {
		result := h.scan("ga-block-a", "stage-door", "scanner-stage")
		want(t, result, engine.WrongZone)
		if result.Severity != engine.SeverityDeny {
			t.Errorf("severity is %s, want deny", result.Severity)
		}
	})

	t.Run("entitled but at the wrong portal", func(t *testing.T) {
		// A Block B holder at the Block A portal. Their ticket is perfect.
		result := h.scan("ga-block-b", "portal-lower", "scanner-portal-lower")
		want(t, result, engine.WrongDoor)
		if result.Severity != engine.SeverityRedirect {
			t.Errorf("severity is %s, want redirect: a misrouted paying customer is not a forgery", result.Severity)
		}
		if len(result.Redirect) == 0 {
			t.Fatal("WRONG_DOOR carries no directions, so the guard has nothing to point at")
		}
		if result.Redirect[0].Checkpoint != "portal-upper" {
			t.Errorf("directed to %s, want portal-upper", result.Redirect[0].Checkpoint)
		}
		if result.Redirect[0].Name == "" {
			t.Error("the direction has no human name")
		}
	})

	t.Run("the right portal admits", func(t *testing.T) {
		want(t, h.scan("ga-block-b", "portal-upper", "scanner-portal-upper"), engine.Admit)
		want(t, h.scan("ga-block-a", "portal-lower", "scanner-portal-lower"), engine.Admit)
	})

	t.Run("a tier-restricted door refuses an entitled holder of another tier", func(t *testing.T) {
		// GA is not entitled to the pit at all, so this is WRONG_ZONE rather
		// than WRONG_DOOR.
		want(t, h.scan("ga-block-a", "pit-gate", "scanner-pit"), engine.WrongZone)
	})
}

// TestPrerequisiteSequencing is the multi-stage venue: the pit cannot be entered
// from the street, and the denial says where to go instead.
func TestPrerequisiteSequencing(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)

	t.Run("the pit refuses somebody who is not in the arena", func(t *testing.T) {
		want(t, h.scan("vip-pit", "gate-north", "scanner-north"), engine.Admit)
		result := h.scan("vip-pit", "pit-gate", "scanner-pit")
		want(t, result, engine.PrerequisiteMissing)
		if result.Severity != engine.SeverityRedirect {
			t.Errorf("severity is %s, want redirect", result.Severity)
		}
		if len(result.Missing) != 1 || result.Missing[0] != "arena" {
			t.Fatalf("missing prerequisites are %v, want [arena]", result.Missing)
		}
		if len(result.Redirect) == 0 {
			t.Fatal("a prerequisite denial carries no directions")
		}
		// The directions must point at doors into the arena, not at the pit.
		for _, redirect := range result.Redirect {
			if redirect.Zone != "arena" {
				t.Errorf("directed to %s in zone %s, want an arena door", redirect.Checkpoint, redirect.Zone)
			}
		}
	})

	t.Run("satisfying the prerequisite opens the pit", func(t *testing.T) {
		want(t, h.scan("vip-pit", "arena-general", "scanner-arena"), engine.Admit)
		want(t, h.scan("vip-pit", "pit-gate", "scanner-pit"), engine.Admit)
	})

	t.Run("a nested admission satisfies an ancestor requirement", func(t *testing.T) {
		// Crew enters the arena through the portal, which is inside the arena
		// zone; the pit requires "arena" and must accept that.
		want(t, h.scan("crew", "gate-north", "scanner-north"), engine.Admit)
		want(t, h.scan("crew", "arena-general", "scanner-arena"), engine.Admit)
		want(t, h.scan("crew", "pit-gate", "scanner-pit"), engine.Admit)
	})

	t.Run("leaving undoes a prerequisite", func(t *testing.T) {
		// Somebody who has walked out of the perimeter is not inside it, and
		// should not be able to walk straight into the arena on the strength of
		// a scan from an hour ago.
		holder := h.f.Issue(t, "ga", venue.SeatRef{}, engine.FormatStatic)
		h.store.PutTicket(holder.Ticket)

		want(t, h.scanPayload(holder.Payload, "gate-north", "scanner-north"), engine.Admit)
		want(t, h.scanPayload(holder.Payload, "gate-exit", "scanner-exit"), engine.Admit)
		want(t, h.scanPayload(holder.Payload, "arena-general", "scanner-arena"), engine.PrerequisiteMissing)
	})
}

func TestCheckpointPolicies(t *testing.T) {
	t.Run("once admits exactly one time", func(t *testing.T) {
		h := newHarness(t, engine.ModeStrict)
		want(t, h.scan("ga-standing", "gate-north", "scanner-north"), engine.Admit)
		want(t, h.scan("ga-standing", "gate-north", "scanner-north-2"), engine.AlreadyUsed)
		want(t, h.scan("ga-standing", "gate-north", "scanner-roam"), engine.AlreadyUsed)
	})

	t.Run("once at one gate does not block another gate", func(t *testing.T) {
		// Two different once-only checkpoints are two different tuples, so an
		// admission at the north gate says nothing about the arena portal.
		h := newHarness(t, engine.ModeStrict)
		want(t, h.scan("ga-standing", "gate-north", "scanner-north"), engine.Admit)
		want(t, h.scan("ga-standing", "arena-general", "scanner-arena"), engine.Admit)
	})

	t.Run("re-entry alternates in and out", func(t *testing.T) {
		h := newHarness(t, engine.ModeStrict)
		want(t, h.scan("ga-standing", "gate-north", "scanner-north"), engine.Admit)

		for round := 0; round < 4; round++ {
			in := h.scanFull(engine.Scan{
				Payload: h.f.Payloads["ga-standing"], Checkpoint: "food-court",
				Device: "scanner-food", Direction: venue.DirectionIn,
			})
			want(t, in, engine.Admit)
			if in.Occurrence != uint32(round*2) {
				t.Errorf("round %d entry has occurrence %d, want %d", round, in.Occurrence, round*2)
			}
			out := h.scanFull(engine.Scan{
				Payload: h.f.Payloads["ga-standing"], Checkpoint: "food-court",
				Device: "scanner-food", Direction: venue.DirectionOut,
			})
			want(t, out, engine.Admit)
		}
	})

	t.Run("re-entry refuses an exit from somebody who is not inside", func(t *testing.T) {
		h := newHarness(t, engine.ModeStrict)
		want(t, h.scan("ga-standing", "gate-north", "scanner-north"), engine.Admit)

		result := h.scanFull(engine.Scan{
			Payload: h.f.Payloads["ga-standing"], Checkpoint: "food-court",
			Device: "scanner-food", Direction: venue.DirectionOut,
		})
		// Almost always the guard has the toggle the wrong way round, so this is
		// amber and says so rather than red.
		want(t, result, engine.WrongDirection)
		if result.Severity != engine.SeverityRedirect {
			t.Errorf("severity is %s, want redirect", result.Severity)
		}
	})

	t.Run("re-entry notices somebody already inside", func(t *testing.T) {
		h := newHarness(t, engine.ModeStrict)
		want(t, h.scan("ga-standing", "gate-north", "scanner-north"), engine.Admit)
		want(t, h.scanFull(engine.Scan{
			Payload: h.f.Payloads["ga-standing"], Checkpoint: "food-court",
			Device: "scanner-food", Direction: venue.DirectionIn,
		}), engine.Admit)
		want(t, h.scanFull(engine.Scan{
			Payload: h.f.Payloads["ga-standing"], Checkpoint: "food-court",
			Device: "scanner-food", Direction: venue.DirectionIn,
		}), engine.AlreadyUsed)
	})

	t.Run("counted spends its passes and then stops", func(t *testing.T) {
		h := newHarness(t, engine.ModeStrict)
		want(t, h.scan("ga-standing", "gate-north", "scanner-north"), engine.Admit)

		first := h.scan("ga-standing", "bar-token", "scanner-bar")
		want(t, first, engine.Admit)
		if first.PassesLeft == nil || *first.PassesLeft != 1 {
			t.Fatalf("after the first token, passes left is %v, want 1", first.PassesLeft)
		}
		second := h.scan("ga-standing", "bar-token", "scanner-bar")
		want(t, second, engine.Admit)
		if second.PassesLeft == nil || *second.PassesLeft != 0 {
			t.Fatalf("after the second token, passes left is %v, want 0", second.PassesLeft)
		}
		third := h.scan("ga-standing", "bar-token", "scanner-bar")
		want(t, third, engine.PassLimitReached)
		if third.PassesLeft == nil || *third.PassesLeft != 0 {
			t.Fatalf("a refused token reports passes left %v, want 0", third.PassesLeft)
		}
	})
}

func TestOpeningHours(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)

	h.now = enginetest.Doors.Add(-time.Minute)
	early := h.scan("ga-standing", "gate-north", "scanner-north")
	want(t, early, engine.DoorsClosed)
	if early.Severity != engine.SeverityRedirect {
		t.Errorf("severity is %s, want redirect: arriving early is not an offence", early.Severity)
	}

	h.now = enginetest.Doors.Add(time.Minute)
	want(t, h.scan("ga-standing", "gate-north", "scanner-north"), engine.Admit)

	h.now = enginetest.Curfew.Add(time.Minute)
	want(t, h.scan("crew", "gate-north", "scanner-north"), engine.DoorsClosed)
}

func TestRotatingCodes(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)

	t.Run("a fresh code admits", func(t *testing.T) {
		want(t, h.scanPayload(h.f.Rotating(t, "rotating", h.now), "gate-north", "scanner-north"), engine.Admit)
	})

	t.Run("a screenshot from two minutes ago does not", func(t *testing.T) {
		screenshot := h.f.Rotating(t, "either", h.now.Add(-2*time.Minute))
		result := h.scanPayload(screenshot, "gate-north", "scanner-north")
		want(t, result, engine.ExpiredWindow)
		// Amber, because the usual cause is a phone that has been in a pocket
		// and the fix is to reopen the app.
		if result.Severity != engine.SeverityRedirect {
			t.Errorf("severity is %s, want redirect", result.Severity)
		}
	})

	t.Run("a rotating ticket refuses a static payload", func(t *testing.T) {
		// This is what makes the anti-screenshot property real rather than
		// advisory: a ticket sold as an in-app code must not be admissible from
		// a printout of its static form.
		want(t, h.scanPayload(h.f.Payloads["rotating"], "gate-south", "scanner-south"), engine.InvalidSig)
	})

	t.Run("an either ticket takes both forms", func(t *testing.T) {
		h2 := newHarness(t, engine.ModeStrict)
		want(t, h2.scanPayload(h2.f.Payloads["either"], "gate-north", "scanner-north"), engine.Admit)
		// The rotating form of the same ticket at the same door: a different
		// payload for the same identity, so the compare-and-set still catches it.
		want(t, h2.scanPayload(h2.f.Rotating(t, "either", h2.now), "gate-north", "scanner-north-2"), engine.AlreadyUsed)
	})

	t.Run("a forged rotating code fails", func(t *testing.T) {
		attacker := enginetest.NewFixture(t)
		id := h.f.ID("rotating")
		secret, err := ticket.DeriveSecret(attacker.Master, id)
		if err != nil {
			t.Fatal(err)
		}
		forged := ticket.GenerateGC2At(secret, h.f.EventID, id, h.now)
		want(t, h.scanPayload(forged, "gate-south", "scanner-south"), engine.InvalidSig)
	})
}

// TestDegradedModeFlagsADoubleUseInsteadOfPreventingIt is the CAP position,
// asserted. Under a partition prevention is impossible; detection is not, and
// this is where it happens.
func TestDegradedModeFlagsADoubleUseInsteadOfPreventingIt(t *testing.T) {
	h := newHarness(t, engine.ModeDegraded)

	// Gate one is online and admits normally.
	first := h.scan("ga-standing", "gate-north", "scanner-north")
	want(t, first, engine.Admit)

	// Gate two was partitioned, let the same ticket through on its local mirror,
	// and is now draining its queue.
	late := h.scanFull(engine.Scan{
		Payload: h.f.Payloads["ga-standing"], Checkpoint: "gate-north",
		Device: "scanner-north-2", OfflineAdmitted: true,
	})
	want(t, late, engine.AlreadyUsed)
	if !late.Flagged {
		t.Fatal("a reconciled offline double use was not flagged")
	}
	if late.Previous == nil {
		t.Fatal("the flag carries no evidence of the winning admission")
	}

	flags := h.store.Flags()
	if len(flags) != 1 {
		t.Fatalf("%d double-use flags recorded, want 1", len(flags))
	}
	flag := flags[0]
	if flag.TicketID != h.f.ID("ga-standing") {
		t.Error("the flag names the wrong ticket")
	}
	// Both records have to be present, because a supervisor deciding what
	// actually happened needs to know which gate and which device each was.
	if flag.Winner.Device != "scanner-north" || flag.Loser.Device != "scanner-north-2" {
		t.Errorf("flag records winner=%s loser=%s", flag.Winner.Device, flag.Loser.Device)
	}
	if !flag.Loser.Offline {
		t.Error("the losing record is not marked offline, so nobody can tell a person actually walked through")
	}

	// Exactly one row exists in the redemption table, which is what keeps the
	// headcount honest even though two people got in.
	enginetest.AssertNoDoubleAdmit(t, h.f.Venue, h.store.Admissions())
}

func TestAnOnlineDoubleUseIsNotFlaggedAsAnIncident(t *testing.T) {
	// Somebody trying a ticket twice at a working gate is an ordinary denial, not
	// a security incident. Flagging it would bury the real ones.
	h := newHarness(t, engine.ModeDegraded)
	want(t, h.scan("ga-standing", "gate-north", "scanner-north"), engine.Admit)
	second := h.scan("ga-standing", "gate-north", "scanner-north-2")
	want(t, second, engine.AlreadyUsed)
	if second.Flagged {
		t.Error("an ordinary repeat scan was flagged as a double use")
	}
	if len(h.store.Flags()) != 0 {
		t.Error("an ordinary repeat scan produced a security flag")
	}
}

func TestEveryScanIsChainedIncludingDenials(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)

	// A log that records only successes cannot prove a gate was working, and
	// "we never saw that ticket" is exactly the claim a dispute turns on.
	h.scan("ga-standing", "gate-north", "scanner-north")
	h.scan("revoked", "gate-north", "scanner-north")
	h.scanPayload("not a ticket", "gate-north", "scanner-north")
	h.scan("ga-standing", "gate-north", "scanner-north-2")

	rows := h.store.Records()
	if len(rows) != 4 {
		t.Fatalf("%d audit rows for 4 scans, want 4", len(rows))
	}
	enginetest.AssertChainVerifies(t, rows)

	verdicts := make([]string, 0, len(rows))
	for _, row := range rows {
		verdicts = append(verdicts, row.Verdict)
	}
	expected := []string{"ADMIT", "REVOKED", "MALFORMED", "ALREADY_USED"}
	for i := range expected {
		if verdicts[i] != expected[i] {
			t.Errorf("row %d records %q, want %q", i, verdicts[i], expected[i])
		}
	}
}

func TestSubscribersSeeOnlyCommittedAdmissions(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)

	var seen []engine.Redemption
	unsubscribe := h.e.Subscribe(func(r engine.Redemption) { seen = append(seen, r) })

	want(t, h.scan("ga-standing", "gate-north", "scanner-north"), engine.Admit)
	want(t, h.scan("revoked", "gate-north", "scanner-north"), engine.Revoked)
	want(t, h.scan("ga-standing", "gate-north", "scanner-north-2"), engine.AlreadyUsed)

	if len(seen) != 1 {
		t.Fatalf("the delta stream saw %d events, want only the one committed admission", len(seen))
	}
	if seen[0].TicketID != h.f.ID("ga-standing") {
		t.Error("the delta names the wrong ticket")
	}

	unsubscribe()
	want(t, h.scan("crew", "gate-north", "scanner-north"), engine.Admit)
	if len(seen) != 1 {
		t.Fatal("an unsubscribed listener still received events")
	}
}

func TestScanRequiresRecoverFirst(t *testing.T) {
	store := memstore.New()
	f := enginetest.NewFixture(t)
	f.Load(store)

	e, err := engine.New(f.Config(engine.ModeStrict, func() time.Time { return enginetest.Doors }))
	if err != nil {
		t.Fatal(err)
	}
	// Scanning before recovery would start a second chain from genesis and make
	// the whole log unverifiable, so it is refused rather than tolerated.
	if _, err := e.Scan(context.Background(), store, engine.Scan{
		ScanID: ticket.MustNewID(), Payload: f.Payloads["ga-standing"],
		Checkpoint: "gate-north", Device: "scanner-north",
	}); err == nil {
		t.Fatal("a scan before Recover succeeded")
	}
}

func TestScanRequiresAnIdempotencyKey(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	if _, err := h.e.Scan(context.Background(), h.store, engine.Scan{
		Payload: h.f.Payloads["ga-standing"], Checkpoint: "gate-north", Device: "scanner-north",
	}); err == nil {
		t.Fatal("a scan with no idempotency key was accepted")
	}
}

func TestNewRejectsAnIncompleteConfig(t *testing.T) {
	f := enginetest.NewFixture(t)
	base := f.Config(engine.ModeStrict, time.Now)

	for name, mutate := range map[string]func(engine.Config) engine.Config{
		"no event": func(c engine.Config) engine.Config { c.EventID = ticket.ID{}; return c },
		"no venue": func(c engine.Config) engine.Config { c.Venue = nil; return c },
		"no key":   func(c engine.Config) engine.Config { c.Verifying = ticket.VerifyingKey{}; return c },
		"bad mode": func(c engine.Config) engine.Config { c.Mode = "eventually"; return c },
	} {
		if _, err := engine.New(mutate(base)); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
	// A missing master key is legal: print-only events do not use rotating codes.
	noMaster := base
	noMaster.Master = ticket.MasterKey{}
	if _, err := engine.New(noMaster); err != nil {
		t.Errorf("New rejected a print-only event: %v", err)
	}
}

func TestInsideZonesReplaysHistory(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	want(t, h.scan("vip-pit", "gate-north", "scanner-north"), engine.Admit)
	want(t, h.scan("vip-pit", "arena-general", "scanner-arena"), engine.Admit)
	want(t, h.scan("vip-pit", "pit-gate", "scanner-pit"), engine.Admit)

	var history []engine.Redemption
	if err := h.store.Read(context.Background(), func(tx engine.Tx) error {
		var err error
		history, err = tx.Redemptions(h.f.ID("vip-pit"))
		return err
	}); err != nil {
		t.Fatal(err)
	}

	inside := h.e.InsideZones(history)
	got := make(map[venue.ZoneCode]bool, len(inside))
	for _, zone := range inside {
		got[zone] = true
	}
	for _, expected := range []venue.ZoneCode{"perimeter", "arena", "pit"} {
		if !got[expected] {
			t.Errorf("not reported as inside %s, from %v", expected, inside)
		}
	}
}

func BenchmarkScanAdmit(b *testing.B) {
	store := memstore.New()
	f := enginetest.NewFixture(&testing.T{})
	f.Load(store)

	e, err := engine.New(f.Config(engine.ModeStrict, func() time.Time { return enginetest.Doors.Add(time.Hour) }))
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	if err := e.Recover(ctx, store); err != nil {
		b.Fatal(err)
	}

	holders := make([]enginetest.Issued, 0, b.N)
	for i := 0; i < b.N; i++ {
		issued := f.Issue(&testing.T{}, "ga", venue.SeatRef{}, engine.FormatStatic)
		store.PutTicket(issued.Ticket)
		holders = append(holders, issued)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := e.Scan(ctx, store, engine.Scan{
			ScanID: ticket.MustNewID(), Payload: holders[i].Payload,
			Checkpoint: "gate-north", Device: "scanner-north",
		})
		if err != nil {
			b.Fatal(err)
		}
		if result.Verdict != engine.Admit {
			b.Fatalf("got %s", result.Verdict)
		}
	}
}
