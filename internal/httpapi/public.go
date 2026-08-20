package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ManasMadan/gatecrash/internal/store"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
	"github.com/ManasMadan/gatecrash/internal/version"
)

// health is the liveness endpoint.
//
// Deliberately cheap and deliberately unauthenticated: a watchdog, a load
// balancer and an operator with curl all need it, and making it prove anything
// about the database would make it fail for reasons unrelated to whether the
// process is alive.
func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"version": version.Version,
		"api":     version.APIVersion,
	})
}

// Meta is the public description of the box, which every client fetches first.
type Meta struct {
	API     string `json:"api"`
	Version string `json:"version"`

	Event     string `json:"event"`
	EventID   string `json:"event_id"`
	VenueName string `json:"venue,omitempty"`
	Timezone  string `json:"timezone,omitempty"`
	Support   string `json:"support,omitempty"`

	Doors  time.Time `json:"doors,omitzero"`
	Curfew time.Time `json:"curfew,omitzero"`

	// Mode is the consistency posture. Published so a scanner knows before it
	// enrolls whether it will be allowed to admit during a partition, rather than
	// finding out when the network drops.
	Mode string `json:"mode"`

	// CAFingerprint lets a client confirm it is pinned to the right box.
	CAFingerprint string `json:"ca_fingerprint,omitempty"`

	// OrganizerFingerprint lets a scanner refuse a box belonging to somebody
	// else's event.
	OrganizerFingerprint string `json:"organizer_fingerprint,omitempty"`

	// Seq is the current redemption sequence, so a reconnecting client can see how
	// far behind its mirror is before asking for anything.
	Seq uint64 `json:"seq"`

	// Now is the box's clock. The authority for GC2 rotating codes: the box's
	// absolute wall time may be wrong, and everything is relative to this.
	Now time.Time `json:"now"`

	// Window is the current GC2 rotation window, so a phone can generate a valid
	// code without trusting its own clock at all.
	Window int64 `json:"gc2_window"`

	// Rotating says whether this event issues rotating codes.
	Rotating bool `json:"rotating"`
}

// meta serves the public box description.
func (a *API) meta(w http.ResponseWriter, r *http.Request) {
	seq, err := a.deps.Store.LatestSeq(r.Context())
	if err != nil {
		a.log.Error("meta: reading sequence", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not read the box state.")
		return
	}

	now := a.deps.Now()
	out := Meta{
		API:       version.APIVersion,
		Version:   version.Version,
		Event:     a.deps.Event.Name,
		EventID:   a.deps.Event.ID.Hex(),
		VenueName: a.deps.Event.Venue,
		Timezone:  a.deps.Event.Timezone,
		Support:   a.deps.Event.Support,
		Doors:     a.deps.Event.Doors,
		Curfew:    a.deps.Event.Curfew,
		Mode:      string(a.deps.Engine.Mode()),
		Seq:       seq,
		Now:       now,
		Window:    int64(ticket.WindowAt(now)),
		Rotating:  !a.deps.Master.IsZero(),
	}
	if a.deps.CA != nil {
		out.CAFingerprint = a.deps.CA.Fingerprint()
	}
	if fingerprint, found, err := a.deps.Store.Meta(r.Context(), store.MetaOrganizerKey); err == nil && found {
		out.OrganizerFingerprint = fingerprint
	}
	writeJSON(w, http.StatusOK, out)
}

// BoxTime is the clock synchronisation response.
type BoxTime struct {
	Now    time.Time `json:"now"`
	Unix   int64     `json:"unix_ms"`
	Window int64     `json:"gc2_window"`

	// Skew is how far off the caller's clock is, when it told us what it thought
	// the time was. The attendee app shows this when a rotating code is rejected,
	// because "your phone's clock is four minutes fast" is an answer somebody can
	// act on and "invalid code" is not.
	SkewMillis int64 `json:"skew_ms,omitempty"`
}

// boxTime serves the box's clock.
//
// This is the anchor for the whole GC2 mechanism. A Raspberry Pi has no
// battery-backed clock and there is no NTP on an air-gapped LAN, so the box's
// absolute wall time is very likely wrong — and that is fine, because every party
// takes its time from here. What matters is that everybody agrees, not that
// anybody is right.
func (a *API) boxTime(w http.ResponseWriter, r *http.Request) {
	now := a.deps.Now()
	out := BoxTime{
		Now:    now,
		Unix:   now.UnixMilli(),
		Window: int64(ticket.WindowAt(now)),
	}
	if theirs := r.URL.Query().Get("t"); theirs != "" {
		var millis int64
		if _, err := sscanInt64(theirs, &millis); err == nil && millis > 0 {
			out.SkewMillis = millis - now.UnixMilli()
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// caCertificate serves the box's CA for installation.
//
// Content-Disposition matters more than it looks: Android and iOS both decide
// whether to offer "install this certificate" based on the content type, and
// getting it wrong means the file lands in Downloads and the attendee gives up.
func (a *API) caCertificate(w http.ResponseWriter, _ *http.Request) {
	if a.deps.CA == nil {
		writeError(w, http.StatusNotFound, "no_ca", "This box is not serving TLS.")
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="gatecrash-ca.crt"`)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(a.deps.CA.CAPEM())
}

// VenueResponse is the map, the seating and the amenities.
type VenueResponse struct {
	Plan venue.Plan `json:"plan"`

	// Fingerprint identifies this exact venue plan, so an app can cache the map
	// and re-fetch only when it changes. The map is the largest payload the
	// attendee app downloads and it does not change during an event.
	Fingerprint string `json:"fingerprint"`
}

// venuePlan serves the compiled venue for the attendee and dashboard maps.
//
// Unauthenticated: the map is public information, printed on signage and handed
// out at the gate. Requiring a credential would mean an attendee who has not
// claimed their ticket cannot find the toilets.
func (a *API) venuePlan(w http.ResponseWriter, r *http.Request) {
	digest, _, err := a.deps.Store.Meta(r.Context(), store.MetaManifestDigest)
	if err != nil {
		a.log.Error("venue: reading digest", "error", err)
	}

	body, err := json.Marshal(VenueResponse{Plan: a.deps.Venue.Plan(), Fingerprint: digest})
	if err != nil {
		a.log.Error("venue: encoding the plan", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not render the venue plan.")
		return
	}

	// The ETag is a hash of the bytes actually being sent, not the manifest digest.
	//
	// It used to be the digest, which was wrong in the one case that matters: the
	// plan the box runs comes from the manifest file beside it, and the digest comes
	// from what was last ingested. Move a gate on the morning of the event and the
	// two disagree — every phone then held a five-minute-stale plan and got a 304
	// forever, so the map kept pointing at a door that was not there. Hashing the
	// response cannot drift from the response.
	//
	// Revalidate rather than cache blind. A plan can change during an event, and
	// the round trip this costs is one conditional request on a LAN answered by an
	// empty 304 — while the thing it protects against is an attendee being sent to
	// the wrong gate.
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		a.log.Debug("venue: client went away mid-write", "error", err)
	}
}

// root redirects to the attendee app, which is what somebody who typed the box's
// address is looking for.
func (a *API) root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not_found", "No such page.")
		return
	}
	http.Redirect(w, r, "/attendee/", http.StatusFound)
}
