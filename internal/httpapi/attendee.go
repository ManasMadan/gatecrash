package httpapi

import (
	"net/http"
	"time"

	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// TicketResponse is the attendee's whole view of their own ticket.
//
// One request returns the ticket, where they are entitled to go, where they
// currently are, where to go next, and how to walk there. That is deliberate: the
// attendee app has to work on a phone with no bars inside a crowd, and every
// round trip is a chance to fail.
type TicketResponse struct {
	ID       string         `json:"id"`
	Tier     venue.TierCode `json:"tier"`
	TierName string         `json:"tier_name"`
	Colour   string         `json:"colour,omitempty"`

	Seat      venue.SeatRef `json:"seat,omitzero"`
	SeatLabel string        `json:"seat_label,omitempty"`

	Event   string `json:"event"`
	EventID string `json:"event_id"`
	Venue   string `json:"venue,omitempty"`
	Support string `json:"support,omitempty"`

	Doors  time.Time `json:"doors,omitzero"`
	Curfew time.Time `json:"curfew,omitzero"`

	Revoked bool `json:"revoked,omitempty"`

	// Format says which QR the app should render. A rotating ticket draws a code
	// that changes every thirty seconds; a static one draws the payload it was
	// issued with.
	Format engine.Format `json:"format"`

	// Payload is the static GC1 string, present only for tickets that may be
	// presented statically.
	Payload string `json:"payload,omitempty"`

	// Guidance is where to go next, computed on the box so that the attendee and
	// the usher directing them cannot be told different things.
	Guidance *venue.Guidance `json:"guidance,omitempty"`

	// History is where this ticket has already been admitted, so the app can show
	// "you are inside the arena" rather than making somebody guess.
	History []Admission `json:"history,omitempty"`

	// Now and Window anchor the app's clock to the box's, which is what makes
	// offline rotating-code generation work on a phone whose clock is wrong.
	Now    time.Time `json:"now"`
	Window int64     `json:"gc2_window"`

	// InstallURLs point at the native apps. The mesh chat cannot be a web app —
	// Web Bluetooth does not exist on iOS Safari and cannot advertise as a
	// peripheral anywhere — so the PWA's job is to get people to the native build
	// if they want chat, while remaining fully usable if they do not.
	Install *InstallLinks `json:"install,omitempty"`
}

// Admission is one past pass through a checkpoint, in the attendee's view.
type Admission struct {
	Checkpoint     venue.CheckpointCode `json:"checkpoint"`
	CheckpointName string               `json:"checkpoint_name"`
	Zone           venue.ZoneCode       `json:"zone"`
	ZoneName       string               `json:"zone_name"`
	Direction      venue.Direction      `json:"direction"`
	At             time.Time            `json:"at"`
}

// InstallLinks point at the native apps.
type InstallLinks struct {
	Android string `json:"android,omitempty"`
	IOS     string `json:"ios,omitempty"`

	// Why explains, in the attendee's own language, what installing buys them.
	// Shown next to the links because "install our app" with no reason is ignored,
	// and this one has a genuine reason.
	Why string `json:"why"`
}

// attendeeTicket serves an attendee's own ticket.
//
// Authenticated by knowing the ticket id, which is 128 bits of random and the only
// credential an attendee has. Stated plainly in the docs: somebody who shares
// their ticket id shares their ticket, exactly as somebody who forwards their
// emailed PDF does.
func (a *API) attendeeTicket(w http.ResponseWriter, r *http.Request) {
	id, err := ticket.ParseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_ticket", "That is not a ticket id.")
		return
	}

	var (
		found   engine.Ticket
		present bool
		history []engine.Redemption
	)
	if err := a.deps.Store.Read(r.Context(), func(tx engine.Tx) error {
		var err error
		if found, present, err = tx.Ticket(id); err != nil || !present {
			return err
		}
		history, err = tx.Redemptions(id)
		return err
	}); err != nil {
		a.log.Error("ticket: reading", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not look that up.")
		return
	}
	if !present {
		// The same answer as a ticket for another event, deliberately: an
		// attendee-facing endpoint that distinguishes "does not exist" from
		// "exists but is not yours" is an oracle for enumerating ticket ids.
		writeError(w, http.StatusNotFound, "unknown_ticket", "That ticket is not for this event.")
		return
	}
	if found.EventID != a.deps.Event.ID {
		writeError(w, http.StatusNotFound, "unknown_ticket", "That ticket is not for this event.")
		return
	}

	now := a.deps.Now()
	out := TicketResponse{
		ID:        id.String(),
		Tier:      found.Tier,
		Seat:      found.Seat,
		SeatLabel: a.deps.Venue.SeatLabel(found.Seat),
		Event:     a.deps.Event.Name,
		EventID:   a.deps.Event.ID.Hex(),
		Venue:     a.deps.Event.Venue,
		Support:   a.deps.Event.Support,
		Doors:     a.deps.Event.Doors,
		Curfew:    a.deps.Event.Curfew,
		Revoked:   found.Revoked,
		Format:    found.Format,
		Now:       now,
		Window:    int64(ticket.WindowAt(now)),
		Install:   a.installLinks(),
	}
	if tier, ok := a.deps.Venue.Tier(found.Tier); ok {
		out.TierName = tier.Name
		out.Colour = tier.Colour
	}
	for _, pass := range history {
		entry := Admission{
			Checkpoint: pass.Checkpoint, Zone: pass.Zone,
			Direction: pass.Direction, At: pass.At,
		}
		if cp, ok := a.deps.Venue.Checkpoint(pass.Checkpoint); ok {
			entry.CheckpointName = cp.Name
		}
		if zone, ok := a.deps.Venue.Zone(pass.Zone); ok {
			entry.ZoneName = zone.Name
		}
		out.History = append(out.History, entry)
	}

	guidance, err := a.deps.Venue.Guidance(venue.GuidanceRequest{
		Tier:     found.Tier,
		Seat:     found.Seat,
		Admitted: a.deps.Engine.InsideZones(history),
		From:     venue.NodeID(r.URL.Query().Get("from")),
		StepFree: r.URL.Query().Get("step_free") == "1",
		At:       now,
	})
	if err == nil {
		out.Guidance = &guidance
	} else {
		// A venue with no walk graph produces no guidance, and that is a
		// degradation rather than a failure: the ticket still renders and the map
		// still draws.
		a.log.Debug("ticket: no guidance available", "error", err)
	}

	// The static payload only when the ticket may actually be presented that way.
	// Handing out a GC1 string for a rotating ticket would undo the whole
	// anti-screenshot property.
	if found.Format != engine.FormatRotating {
		out.Payload = a.staticPayload(found)
	}

	// Never cached. A ticket response carries the current window and the
	// admission history, both of which change.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// installLinks describes the native apps, when the box is serving them.
func (a *API) installLinks() *InstallLinks {
	// Served from the box itself, because an attendee inside a venue with no
	// signal cannot reach an app store. The APK is a sideload and the docs are
	// honest about what that means; iOS cannot be sideloaded at all, so that link
	// goes to TestFlight and only works for somebody with signal.
	return &InstallLinks{
		Android: "/install/gatecrash-backstage.apk",
		IOS:     "https://testflight.apple.com/join/gatecrash",
		Why:     "Backstage adds crowd chat and a friend finder that work with no signal at all. Your ticket works without it.",
	}
}

// staticPayload rebuilds the GC1 string from the stored signature.
//
// Rebuilt rather than stored, because the payload is entirely derivable from the
// ticket id and the signature the manifest already carries, and storing both would
// be two things that can disagree.
func (a *API) staticPayload(found engine.Ticket) string {
	if len(found.Signature) == 0 {
		return ""
	}
	return ticket.EncodeGC1(found.ID, found.Signature)
}

// ClaimRequest claims a rotating ticket for a device.
type ClaimRequest struct {
	// Device is an opaque identifier the app generates and keeps, so the box can
	// tell a re-claim on the same phone from a claim on a different one.
	Device string `json:"device"`
}

// ClaimResponse hands over the per-ticket secret.
type ClaimResponse struct {
	// Secret is the HKDF-derived per-ticket secret, base64. This is the only time
	// it crosses the network, and after this the phone generates rotating codes
	// entirely offline — which is the whole point.
	Secret string `json:"secret"`

	TicketID string `json:"ticket_id"`
	EventID  string `json:"event_id"`

	// Window and Now anchor the phone's clock, so a phone whose clock is four
	// minutes fast still generates a code the gate accepts.
	Window int64     `json:"gc2_window"`
	Now    time.Time `json:"now"`

	// Seconds is the rotation period, so the app does not hardcode it.
	Seconds int `json:"window_seconds"`
}

// claimTicket hands an attendee their own ticket secret.
//
// This is the one endpoint that gives out key material, and it is deliberately
// simple: the secret is derived from the event master key and the ticket id, so
// there is nothing to store and nothing to revoke. Claiming twice returns the same
// secret, because it is a derivation rather than an issuance — which means a
// reinstalled app just works, and there is no "you have already claimed this
// ticket" dead end at a gate.
//
// What this does not do is authenticate the claimer beyond knowing the ticket id.
// That is the honest limit of a system with no accounts: the ticket id is the
// credential, exactly as the emailed PDF is, and the anti-screenshot property
// comes from the code rotating rather than from the secret being unshareable.
func (a *API) claimTicket(w http.ResponseWriter, r *http.Request) {
	id, err := ticket.ParseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_ticket", "That is not a ticket id.")
		return
	}
	var req ClaimRequest
	if r.ContentLength > 0 {
		if err := readJSON(w, r, limitScan, &req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
	}

	if a.deps.Master.IsZero() {
		writeError(w, http.StatusConflict, "no_rotating",
			"This event uses printed tickets, so there is nothing to claim.")
		return
	}

	var (
		found   engine.Ticket
		present bool
	)
	if err := a.deps.Store.Read(r.Context(), func(tx engine.Tx) error {
		var err error
		found, present, err = tx.Ticket(id)
		return err
	}); err != nil {
		a.log.Error("claim: reading ticket", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not look that up.")
		return
	}
	if !present || found.EventID != a.deps.Event.ID {
		writeError(w, http.StatusNotFound, "unknown_ticket", "That ticket is not for this event.")
		return
	}
	if found.Revoked {
		writeError(w, http.StatusForbidden, "revoked", "That ticket has been cancelled.")
		return
	}
	if found.Format == engine.FormatStatic {
		writeError(w, http.StatusConflict, "static_ticket",
			"This is a printed ticket. Show the code you were sent.")
		return
	}

	secret, err := ticket.DeriveSecret(a.deps.Master, id)
	if err != nil {
		a.log.Error("claim: deriving secret", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not prepare that ticket.")
		return
	}

	now := a.deps.Now()
	a.log.Info("ticket claimed", "ticket", id.Hex(), "device", req.Device)

	// Never cached, never logged. The response body is key material.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, ClaimResponse{
		Secret:   secret.String(),
		TicketID: id.String(),
		EventID:  a.deps.Event.ID.Hex(),
		Window:   int64(ticket.WindowAt(now)),
		Now:      now,
		Seconds:  ticket.WindowSeconds,
	})
}

// attendeeNearby answers "where is the nearest toilet", routed and offline.
//
// The least glamorous endpoint in the system and the one attendees use most. It
// takes the ticket id so it can hide what the holder cannot reach: showing a
// general-admission holder the backstage toilets is a small cruelty.
func (a *API) attendeeNearby(w http.ResponseWriter, r *http.Request) {
	id, err := ticket.ParseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_ticket", "That is not a ticket id.")
		return
	}
	from := r.URL.Query().Get("from")
	if from == "" {
		writeError(w, http.StatusBadRequest, "no_position",
			`"Nearest" needs to know where you are.`)
		return
	}

	var (
		found   engine.Ticket
		present bool
	)
	if err := a.deps.Store.Read(r.Context(), func(tx engine.Tx) error {
		var err error
		found, present, err = tx.Ticket(id)
		return err
	}); err != nil {
		a.log.Error("nearby: reading ticket", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not look that up.")
		return
	}
	if !present || found.EventID != a.deps.Event.ID {
		writeError(w, http.StatusNotFound, "unknown_ticket", "That ticket is not for this event.")
		return
	}

	var kinds []venue.AmenityKind
	for _, kind := range r.URL.Query()["kind"] {
		kinds = append(kinds, venue.AmenityKind(kind))
	}

	nearby, err := a.deps.Venue.NearestAmenities(venue.NearestAmenitiesRequest{
		Kinds:          kinds,
		From:           venue.NodeID(from),
		Tier:           found.Tier,
		AccessibleOnly: r.URL.Query().Get("accessible") == "1",
		StepFree:       r.URL.Query().Get("step_free") == "1",
		Limit:          parseInt(r.URL.Query().Get("limit"), 5, 25),
		At:             a.deps.Now(),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nearby)
}

// Announcement is an organizer message.
type Announcement struct {
	ID   string    `json:"id"`
	Text string    `json:"text"`
	At   time.Time `json:"at"`

	// Zone scopes an announcement, so "Gate 4 is now open" does not interrupt
	// somebody in the campsite.
	Zone venue.ZoneCode `json:"zone,omitempty"`

	// Priority marks the ones that override do-not-disturb. Used sparingly and on
	// purpose: an app that buzzes for everything is an app people mute.
	Priority bool `json:"priority,omitempty"`
}

// announcements serves the organizer's message feed.
//
// Public, because the alternative is an attendee who cannot read "the last train
// is in twenty minutes" because they have not claimed their ticket.
func (a *API) announcements(w http.ResponseWriter, r *http.Request) {
	a.announceMu.RLock()
	defer a.announceMu.RUnlock()

	out := a.announced
	if since := parseUint(r.URL.Query().Get("since"), 0); since > 0 && int(since) < len(out) {
		out = out[since:]
	}
	if out == nil {
		out = []Announcement{}
	}
	writeJSON(w, http.StatusOK, out)
}
