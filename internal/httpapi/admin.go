package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/enroll"
	"github.com/ManasMadan/gatecrash/internal/incident"
	"github.com/ManasMadan/gatecrash/internal/manifest"
	"github.com/ManasMadan/gatecrash/internal/ssehub"
	"github.com/ManasMadan/gatecrash/internal/stats"
	"github.com/ManasMadan/gatecrash/internal/store"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// DashboardStats is the control room's whole picture in one object.
type DashboardStats struct {
	Live stats.Live `json:"live"`

	// Incidents is the live board plus the response summary, because an operator
	// looking at throughput also needs to see that a medical alarm has been open
	// for four minutes.
	Incidents []incident.Incident `json:"incidents"`
	Counts    incident.Counts     `json:"incident_counts"`
	Response  incident.Response   `json:"incident_response"`

	// Chain is the audit log's position, so the organizer can see the log is
	// growing and read out the head if somebody asks.
	ChainHead string `json:"chain_head"`
	ChainRows uint64 `json:"chain_rows"`

	// Flags is how many double uses have been detected. The number that decides
	// whether DEGRADED mode was a good idea at this event.
	Flags int `json:"flags"`

	// Streams and Dropped describe the SSE fan-out. A climbing Dropped is the
	// signal that a device or the network is in trouble.
	Streams int    `json:"streams"`
	Dropped uint64 `json:"dropped_streams"`

	// Devices is the enrolled roster with liveness, which is how the control room
	// notices a dead battery before the queue does.
	Devices []enroll.Device `json:"devices"`

	// PendingCodes is how many enrollment codes are live.
	PendingCodes int `json:"pending_codes"`

	// CertificateExpires warns before a certificate quietly expires and a gate
	// quietly stops working.
	CertificateExpires time.Time `json:"certificate_expires,omitzero"`

	Mode string    `json:"mode"`
	Now  time.Time `json:"now"`
}

// adminStats serves the dashboard's poll.
func (a *API) adminStats(w http.ResponseWriter, r *http.Request) {
	head, rows := a.deps.Engine.AuditHead()

	out := DashboardStats{
		Live:         a.deps.Stats.Snapshot(),
		ChainHead:    head.String(),
		ChainRows:    rows,
		Streams:      a.deps.Hub.Subscribers(),
		Dropped:      a.deps.Hub.Dropped(),
		Devices:      a.deps.Registry.Devices(),
		PendingCodes: a.deps.Registry.PendingCodes(),
		Mode:         string(a.deps.Engine.Mode()),
		Now:          a.deps.Now(),
	}
	if a.deps.Board != nil {
		out.Incidents = a.deps.Board.List(incident.Filter{})
		out.Counts = a.deps.Board.Counts()
		out.Response = a.deps.Board.Response()
	}
	if a.deps.CA != nil {
		out.CertificateExpires = a.deps.CA.LeafExpiry()
	}
	if flags, err := a.deps.Store.Flags(r.Context()); err == nil {
		out.Flags = len(flags)
	}
	writeJSON(w, http.StatusOK, out)
}

// adminStream serves the control room's SSE feed: everything, unfiltered.
func (a *API) adminStream(w http.ResponseWriter, r *http.Request) {
	a.deps.Hub.Handler(ssehub.HandlerOptions{Replay: a.replayRedemptions}).ServeHTTP(w, r)
}

// adminIncidents lists incidents with the dashboard's filters.
func (a *API) adminIncidents(w http.ResponseWriter, r *http.Request) {
	if a.deps.Board == nil {
		writeJSON(w, http.StatusOK, []incident.Incident{})
		return
	}
	filter := incident.Filter{
		LiveOnly:    r.URL.Query().Get("live") == "1",
		Zone:        venue.ZoneCode(r.URL.Query().Get("zone")),
		MinSeverity: incident.Severity(r.URL.Query().Get("min_severity")),
		Since:       parseUint(r.URL.Query().Get("since"), 0),
	}
	for _, kind := range r.URL.Query()["kind"] {
		filter.Kinds = append(filter.Kinds, incident.Kind(kind))
	}
	writeJSON(w, http.StatusOK, a.deps.Board.List(filter))
}

// TransitionRequest moves an incident along its lifecycle.
type TransitionRequest struct {
	Status incident.Status `json:"status"`

	// Actor is who is doing it. Required by the board: an unattributed transition
	// is an accountability hole, and the whole package exists to close it.
	Actor string `json:"actor"`

	Note       string `json:"note,omitempty"`
	AssignedTo string `json:"assigned_to,omitempty"`
}

// adminTransitionIncident acknowledges, assigns, resolves or cancels.
func (a *API) adminTransitionIncident(w http.ResponseWriter, r *http.Request) {
	if a.deps.Board == nil {
		writeError(w, http.StatusServiceUnavailable, "no_board", "This box is not tracking incidents.")
		return
	}
	var req TransitionRequest
	if err := readJSON(w, r, limitIncident, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	updated, err := a.deps.Board.Transition(incident.ID(r.PathValue("id")), incident.Transition{
		Status: req.Status, Actor: req.Actor, Note: req.Note, AssignedTo: req.AssignedTo,
	})
	if err != nil {
		// The board's errors are all caller mistakes: unknown id, already closed,
		// no actor, cancelling with no reason. A 409 rather than a 400 for the
		// closed case would be more precise, and is not worth the branch: the
		// message says which it was.
		writeError(w, http.StatusBadRequest, "bad_transition", err.Error())
		return
	}
	a.deps.Hub.Publish(ssehub.Event{Kind: "incident", Seq: updated.Seq, Data: updated})
	writeJSON(w, http.StatusOK, updated)
}

// InviteRequest issues an enrollment code.
type InviteRequest struct {
	Checkpoints []venue.CheckpointCode `json:"checkpoints"`
	Name        string                 `json:"name,omitempty"`

	// TTLSeconds overrides the code lifetime.
	TTLSeconds int `json:"ttl_seconds,omitempty"`

	// Uses is how many phones one printed sheet may enroll.
	Uses int `json:"uses,omitempty"`
}

// InviteResponse carries the code and the QR payload to render.
type InviteResponse struct {
	Invite enroll.Invite `json:"invite"`

	// QR is the encoded payload, so the dashboard renders it without knowing the
	// format. Keeping the format on the box means a scanner and a dashboard can
	// never disagree about it.
	QR string `json:"qr"`
}

// adminInvite issues an enrollment code.
func (a *API) adminInvite(w http.ResponseWriter, r *http.Request) {
	var req InviteRequest
	if err := readJSON(w, r, limitAdmin, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	// Validate the checkpoints against the venue here rather than letting a typo
	// produce a code that enrolls a device to a door that does not exist.
	for _, code := range req.Checkpoints {
		if _, ok := a.deps.Venue.Checkpoint(code); !ok {
			writeError(w, http.StatusBadRequest, "unknown_checkpoint",
				fmt.Sprintf("There is no checkpoint called %q.", code))
			return
		}
	}

	fingerprint := ""
	if a.deps.CA != nil {
		fingerprint = a.deps.CA.Fingerprint()
	}
	invite, err := a.deps.Registry.Issue(enroll.InviteRequest{
		Checkpoints: req.Checkpoints,
		Name:        req.Name,
		TTL:         time.Duration(req.TTLSeconds) * time.Second,
		Uses:        req.Uses,
	}, a.deps.BoxURL, fingerprint, a.deps.Event.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	payload, err := invite.Encode()
	if err != nil {
		a.log.Error("invite: encoding", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not build the code.")
		return
	}
	// Never cached and never logged: the response body is a credential.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, InviteResponse{Invite: invite, QR: payload})
}

// adminDevices lists the enrolled scanner roster.
func (a *API) adminDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := a.deps.Store.Devices(r.Context())
	if err != nil {
		a.log.Error("devices: listing", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not read the roster.")
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

// adminRevokeDevice disables a stolen scanner. One tap, effective on the next
// scan, because the engine reads the device row inside every scan's transaction
// rather than caching it.
func (a *API) adminRevokeDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.deps.Store.RevokeDeviceContext(r.Context(), id, true); err != nil {
		writeError(w, http.StatusNotFound, "unknown_device", err.Error())
		return
	}
	// Both the registry and the store, because the registry holds the token and
	// the store is what the scan path reads. Revoking one and not the other would
	// leave a half-revoked device.
	if err := a.deps.Registry.Revoke(id); err != nil {
		a.log.Debug("revoke: device not in the registry", "device", id, "error", err)
	}

	a.log.Warn("device revoked", "device", id)
	a.raiseAutomatic(incident.Report{
		Kind: incident.EquipmentFault,
		Note: "Scanner " + id + " was revoked from the dashboard.",
	})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": id})
}

// adminRevokeTicket cancels a ticket.
func (a *API) adminRevokeTicket(w http.ResponseWriter, r *http.Request) {
	id, err := ticket.ParseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_ticket", "That is not a ticket id.")
		return
	}
	if err := a.deps.Store.RevokeTicket(r.Context(), id.Hex(), true); err != nil {
		writeError(w, http.StatusNotFound, "unknown_ticket", err.Error())
		return
	}
	a.log.Warn("ticket revoked", "ticket", id.Hex())
	writeJSON(w, http.StatusOK, map[string]any{"revoked": id.String()})
}

// AnnounceRequest publishes an organizer message.
type AnnounceRequest struct {
	Text     string         `json:"text"`
	Zone     venue.ZoneCode `json:"zone,omitempty"`
	Priority bool           `json:"priority,omitempty"`
}

// adminAnnounce publishes an organizer message to every connected client.
//
// The same message also goes out over the BLE mesh at organizer priority, which
// is how "gate 4 is now open" reaches a phone with no bars. That relay lives in
// the mesh package; this endpoint is where the message enters the system.
func (a *API) adminAnnounce(w http.ResponseWriter, r *http.Request) {
	var req AnnounceRequest
	if err := readJSON(w, r, limitAdmin, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if req.Text == "" {
		writeError(w, http.StatusBadRequest, "empty", "An announcement needs some text.")
		return
	}
	if len(req.Text) > 280 {
		// A cap, because an announcement is read on a lock screen in a crowd. The
		// number is Twitter's for the same reason Twitter picked it.
		writeError(w, http.StatusBadRequest, "too_long", "Keep it under 280 characters.")
		return
	}
	if req.Zone != "" {
		if _, ok := a.deps.Venue.Zone(req.Zone); !ok {
			writeError(w, http.StatusBadRequest, "unknown_zone", "There is no zone called "+string(req.Zone)+".")
			return
		}
	}

	id, err := randomID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Could not send that.")
		return
	}
	announcement := Announcement{ID: id, Text: req.Text, At: a.deps.Now(), Zone: req.Zone, Priority: req.Priority}

	a.announceMu.Lock()
	a.announced = append(a.announced, announcement)
	// Bounded, because this is in memory for the life of the process and an
	// operator with a stuck key should not be able to grow it without limit.
	if len(a.announced) > 500 {
		a.announced = a.announced[len(a.announced)-500:]
	}
	a.announceMu.Unlock()

	a.deps.Hub.Publish(ssehub.Event{Kind: "announcement", Data: announcement})
	a.log.Info("announcement", "text", req.Text, "zone", req.Zone, "priority", req.Priority)
	writeJSON(w, http.StatusOK, announcement)
}

// adminSeal seals a Merkle checkpoint and returns the root to publish.
func (a *API) adminSeal(w http.ResponseWriter, r *http.Request) {
	sealed, err := a.deps.Store.Seal(r.Context(), a.deps.Engine.Clock().Now())
	if err != nil {
		a.log.Error("seal", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not seal the log.")
		return
	}
	a.log.Info("audit log sealed", "rows", sealed.Rows, "root", sealed.Root.String())
	writeJSON(w, http.StatusOK, sealed)
}

// VerifyResponse reports on the audit chain.
type VerifyResponse struct {
	OK   bool   `json:"ok"`
	Rows uint64 `json:"rows"`
	Head string `json:"head"`

	// Error is the first inconsistency, when there is one. A broken link is
	// evidence of tampering; a sequence gap is usually evidence of a bad export.
	Error string `json:"error,omitempty"`
}

// adminVerify replays the chain and reports the first inconsistency.
func (a *API) adminVerify(w http.ResponseWriter, r *http.Request) {
	head, rows := a.deps.Engine.AuditHead()
	out := VerifyResponse{OK: true, Rows: rows, Head: head.String()}

	if err := a.deps.Store.Verify(r.Context()); err != nil {
		out.OK = false
		out.Error = err.Error()
		a.log.Error("audit chain does not verify", "error", err)
	}
	writeJSON(w, http.StatusOK, out)
}

// adminAttendance produces a provable statement that one ticket was admitted.
func (a *API) adminAttendance(w http.ResponseWriter, r *http.Request) {
	id, err := ticket.ParseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_ticket", "That is not a ticket id.")
		return
	}
	proof, found, err := a.deps.Store.Attendance(r.Context(), id)
	if err != nil {
		a.log.Error("attendance", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not build the proof.")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not_admitted", "That ticket was never admitted.")
		return
	}
	writeJSON(w, http.StatusOK, proof)
}

// adminFlags lists detected double uses.
//
// Published rather than buried. This is the honest half of DEGRADED mode: the
// number of people who got in on a ticket that was already used, with both records
// attached, rather than a rounded-away discrepancy.
func (a *API) adminFlags(w http.ResponseWriter, r *http.Request) {
	flags, err := a.deps.Store.Flags(r.Context())
	if err != nil {
		a.log.Error("flags", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not read the flags.")
		return
	}
	if flags == nil {
		flags = []engine.DoubleUse{}
	}
	writeJSON(w, http.StatusOK, flags)
}

// adminLog serves a window of the audit log.
func (a *API) adminLog(w http.ResponseWriter, r *http.Request) {
	from := parseUint(r.URL.Query().Get("from"), 1)
	limit := uint64(parseInt(r.URL.Query().Get("limit"), 200, 2000))

	rows, err := a.deps.Store.AuditRows(r.Context(), from, from+limit-1)
	if err != nil {
		a.log.Error("log", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not read the log.")
		return
	}
	if rows == nil {
		rows = []audit.Record{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// adminExport produces the signed post-event attendance report.
//
// This is the artifact that settles a door split. It is signed by the box's own
// key so a promoter cannot edit the numbers on the way to the artist's manager,
// and it carries the Merkle root so any individual admission in it can be proved
// later with about twenty hashes.
func (a *API) adminExport(w http.ResponseWriter, r *http.Request) {
	sealed, err := a.deps.Store.Seal(r.Context(), a.deps.Engine.Clock().Now())
	if err != nil {
		a.log.Error("export: sealing", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not seal the log.")
		return
	}
	opened, closed, err := a.deps.Store.SessionWindow(r.Context())
	if err != nil {
		a.log.Error("export: session window", "error", err)
	}
	digest, _, err := a.deps.Store.Meta(r.Context(), store.MetaManifestDigest)
	if err != nil {
		a.log.Error("export: manifest digest", "error", err)
	}

	report := manifest.Attendance{
		EventID:        a.deps.Event.ID,
		Event:          a.deps.Event.Name,
		ManifestDigest: digest,
		OpenedAt:       opened,
		ClosedAt:       closed,
		Checkpoint:     sealed,
		Totals:         a.deps.Stats.Snapshot(),
	}
	if a.deps.Board != nil {
		report.Incidents = a.deps.Board.List(incident.Filter{})
		report.IncidentResponse = a.deps.Board.Response()
	}
	if flags, err := a.deps.Store.Flags(r.Context()); err == nil {
		for _, flag := range flags {
			report.Flags = append(report.Flags, manifest.Flag{
				TicketID:     flag.TicketID,
				Winner:       flag.Winner.Device,
				WinnerAt:     flag.Winner.At,
				Loser:        flag.Loser.Device,
				LoserAt:      flag.Loser.At,
				LoserOffline: flag.Loser.Offline,
			})
		}
	}

	// Unsigned when the box has no key of its own, which is a valid configuration
	// for a box that is not being asked to settle anything. The response says so
	// rather than pretending.
	if a.deps.BoxKey.IsZero() {
		w.Header().Set("Content-Disposition", `attachment; filename="attendance-unsigned.json"`)
		writeJSON(w, http.StatusOK, report)
		return
	}

	signed, err := manifest.SignAttendance(a.deps.BoxKey, report)
	if err != nil {
		a.log.Error("export: signing", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not sign the report.")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="attendance.json"`)
	if err := json.NewEncoder(w).Encode(signed); err != nil {
		a.log.Error("export: writing", "error", err)
	}
}

// raiseAutomatic records one of the box's own signals, ignoring failures.
//
// Failures are ignored because an automatic signal is a courtesy: the box noticing
// something and telling the control room. If the board refuses it, the thing it
// was reporting has already happened and there is nothing useful to do with the
// error.
func (a *API) raiseAutomatic(report incident.Report) {
	if a.deps.Board == nil {
		return
	}
	raised, err := a.deps.Board.Raise(report)
	if err != nil {
		a.log.Debug("automatic incident refused", "kind", report.Kind, "error", err)
		return
	}
	a.deps.Hub.Publish(ssehub.Event{Kind: "incident", Seq: raised.Seq, Data: raised})
}

// portalPage serves the captive-portal landing page when no built assets are
// mounted, which is the case in tests and on a box whose web build is missing.
func (a *API) portalPage(w http.ResponseWriter, r *http.Request) {
	if a.deps.Assets != nil {
		http.Redirect(w, r, "/attendee/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html><meta charset="utf-8">`+
		`<meta name="viewport" content="width=device-width,initial-scale=1">`+
		`<title>%s</title><h1>%s</h1><p>Connected. Open your ticket to get in.`,
		htmlEscape(a.deps.Event.Name), htmlEscape(a.deps.Event.Name))
}

// randomID returns a short opaque identifier for an announcement.
func randomID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
