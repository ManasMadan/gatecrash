package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/ManasMadan/gatecrash/internal/enroll"
	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/incident"
	"github.com/ManasMadan/gatecrash/internal/ssehub"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// Body size limits. Each is the smallest thing that fits the request, because an
// unbounded body is how any device on the venue Wi-Fi makes the box allocate.
const (
	limitEnroll   = 4 << 10
	limitScan     = 4 << 10
	limitIncident = 8 << 10
	limitAdmin    = 64 << 10
)

// EnrollRequest redeems an enrollment code.
type EnrollRequest struct {
	// Code is the single-use code from the printed QR. It is the authentication:
	// possession of the sheet is the authorisation, and the sheet is something the
	// organizer physically controls.
	Code string `json:"code"`

	// Name is what staff typed, shown on the dashboard so six identical phones can
	// be told apart.
	Name string `json:"name"`

	// PublicKey is an optional base64 DER public key. When present the box issues a
	// client certificate as well as a token, which is the strong path: a
	// certificate's private key never leaves the device, whereas a bearer token can
	// be read off a screen.
	PublicKey string `json:"public_key,omitempty"`
}

// EnrollResponse is what a newly enrolled scanner receives.
type EnrollResponse struct {
	DeviceID    string                 `json:"device_id"`
	Token       string                 `json:"token"`
	Name        string                 `json:"name"`
	Checkpoints []venue.CheckpointCode `json:"checkpoints"`

	// ClientCertificate is a PEM certificate, present only when the device sent a
	// public key.
	ClientCertificate string `json:"client_certificate,omitempty"`

	// The event context, so the scanner can render its home screen without a
	// second round trip on a network that may not give it one.
	Event         string `json:"event"`
	Mode          string `json:"mode"`
	CAFingerprint string `json:"ca_fingerprint,omitempty"`

	// Checkpoint detail for the gate the device is assigned to: the name, the
	// lane and the zone go on the scanner's home screen so staff can confirm the
	// device in their hand belongs to the door they are standing at.
	Assignments []Assignment `json:"assignments"`
}

// Assignment describes one checkpoint a device may scan at.
type Assignment struct {
	Checkpoint venue.CheckpointCode `json:"checkpoint"`
	Name       string               `json:"name"`
	Lane       string               `json:"lane,omitempty"`
	Zone       venue.ZoneCode       `json:"zone"`
	ZoneName   string               `json:"zone_name"`
	Direction  venue.Direction      `json:"direction"`
	Policy     venue.Policy         `json:"policy"`
	OpensAt    time.Time            `json:"opens_at,omitzero"`
	ClosesAt   time.Time            `json:"closes_at,omitzero"`
}

// enrollDevice redeems an enrollment code for a device token.
func (a *API) enrollDevice(w http.ResponseWriter, r *http.Request) {
	var req EnrollRequest
	if err := readJSON(w, r, limitEnroll, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	enrolled, err := a.deps.Registry.Redeem(req.Code, req.Name)
	switch {
	case err == nil:
	case errors.Is(err, enroll.ErrNoDeviceName):
		writeError(w, http.StatusBadRequest, "no_name", "Give this scanner a name.")
		return
	default:
		// Unknown, expired and already-spent codes are deliberately
		// indistinguishable here, matching the registry: telling a caller a code
		// exists but is expired confirms a guess.
		writeError(w, http.StatusForbidden, "bad_code", "That code is not valid. Ask for a new one.")
		return
	}

	// Mirror the device into the store, so the engine's own allowlist check sees
	// it. The registry is the credential authority; the store is what the scan
	// path reads inside its transaction.
	if err := a.deps.Store.PutDeviceContext(r.Context(), engineDevice(enrolled)); err != nil {
		a.log.Error("enroll: persisting device", "device", enrolled.DeviceID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not save this scanner.")
		return
	}
	a.deps.Stats.NameDevice(enrolled.DeviceID, enrolled.Name)

	out := EnrollResponse{
		DeviceID:    enrolled.DeviceID,
		Token:       enrolled.Token,
		Name:        enrolled.Name,
		Checkpoints: enrolled.Checkpoints,
		Event:       a.deps.Event.Name,
		Mode:        string(a.deps.Engine.Mode()),
		Assignments: a.assignmentsFor(enrolled.Checkpoints),
	}
	if a.deps.CA != nil {
		out.CAFingerprint = a.deps.CA.Fingerprint()
	}
	if req.PublicKey != "" && a.deps.CA != nil {
		if certificate, err := a.issueClientCert(enrolled.DeviceID, req.PublicKey); err != nil {
			// A failed certificate is not a failed enrollment: the token works and
			// the device can run on it. Logging and continuing beats refusing to
			// enroll a phone at a gate.
			a.log.Warn("enroll: could not issue a client certificate", "device", enrolled.DeviceID, "error", err)
		} else {
			out.ClientCertificate = certificate
		}
	}

	a.log.Info("enroll: device enrolled", "device", enrolled.DeviceID, "name", enrolled.Name,
		"checkpoints", enrolled.Checkpoints)
	writeJSON(w, http.StatusOK, out)
}

// assignmentsFor describes the checkpoints a device may scan at.
func (a *API) assignmentsFor(codes []venue.CheckpointCode) []Assignment {
	out := make([]Assignment, 0, len(codes))
	for _, code := range codes {
		cp, ok := a.deps.Venue.Checkpoint(code)
		if !ok {
			continue
		}
		assignment := Assignment{
			Checkpoint: code, Name: cp.Name, Lane: cp.Lane, Zone: cp.Zone,
			Direction: cp.Direction, Policy: cp.Policy,
			OpensAt: cp.OpensAt, ClosesAt: cp.ClosesAt,
		}
		if zone, ok := a.deps.Venue.Zone(cp.Zone); ok {
			assignment.ZoneName = zone.Name
		}
		out = append(out, assignment)
	}
	return out
}

// ManifestResponse is the scanner's two-step sync payload.
//
// One request, everything the device needs to work offline: the Bloom filter to
// reject unknown ids with no network at all, the redeemed snapshot to warn about
// reuse before the server answers, and the sequence to resume the delta stream
// from.
type ManifestResponse struct {
	Event   string `json:"event"`
	EventID string `json:"event_id"`
	Mode    string `json:"mode"`

	// Bloom is the base64 filter over every valid ticket id. About 175 KB for
	// fifty thousand tickets, and after this the scanner rejects a random QR code
	// off the internet in microseconds with zero network traffic.
	Bloom string `json:"bloom"`

	// BloomBits and BloomHashes let a client verify the filter it received matches
	// the header it parsed, which is cheaper than trusting a truncated download.
	BloomBits   uint64 `json:"bloom_bits"`
	BloomHashes uint64 `json:"bloom_hashes"`
	Tickets     int    `json:"tickets"`

	// Redeemed is the ticket ids already admitted at this device's checkpoint, so
	// the mirror can warn about reuse before the server verdict lands. Scoped to
	// the checkpoint: a portal scanner does not need to know who came through the
	// north gate, and sending it anyway costs a megabyte over venue Wi-Fi.
	Redeemed []string `json:"redeemed"`

	// Seq is where the delta stream starts.
	Seq uint64 `json:"seq"`

	// Venue is the compiled plan, so the scanner can render the next-step
	// directions it shows after an admit without another round trip.
	Venue venue.Plan `json:"venue"`

	// Assignments is this device's own checkpoints.
	Assignments []Assignment `json:"assignments"`

	// IncidentKinds is what the alarm and staffing buttons should offer, sent by
	// the box so a scanner never draws a button the box will reject.
	IncidentKinds []IncidentKind `json:"incident_kinds"`

	// Now and Window anchor the scanner's clock to the box's.
	Now    time.Time `json:"now"`
	Window int64     `json:"gc2_window"`
}

// IncidentKind describes one reportable kind for the scanner's UI.
type IncidentKind struct {
	Kind     incident.Kind     `json:"kind"`
	Severity incident.Severity `json:"severity"`
	Alarm    bool              `json:"alarm"`
}

// scannerManifest serves the sync payload.
func (a *API) scannerManifest(w http.ResponseWriter, r *http.Request, device enroll.Device) {
	checkpoint := venue.CheckpointCode(r.URL.Query().Get("checkpoint"))
	if checkpoint == "" && len(device.Checkpoints) > 0 {
		checkpoint = device.Checkpoints[0]
	}
	if checkpoint != "" && !authorizedFor(device, checkpoint) {
		writeError(w, http.StatusForbidden, "not_assigned", "This scanner is not assigned to that gate.")
		return
	}

	body, err := a.manifestBody(r, device, checkpoint)
	if err != nil {
		a.log.Error("manifest: building", "device", device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not build the manifest.")
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// manifestBody assembles the sync payload.
func (a *API) manifestBody(r *http.Request, device enroll.Device, checkpoint venue.CheckpointCode) (ManifestResponse, error) {
	filter, err := a.buildBloom(r)
	if err != nil {
		return ManifestResponse{}, err
	}
	encoded, err := filter.MarshalBinary()
	if err != nil {
		return ManifestResponse{}, err
	}

	redeemed, seq, err := a.deps.Store.RedeemedIDs(r.Context(), string(checkpoint))
	if err != nil {
		return ManifestResponse{}, err
	}
	if redeemed == nil {
		// An empty list rather than null. A JSON null forces every client to
		// special-case it, and the one that forgets crashes at a gate on the first
		// scan of the evening.
		redeemed = []string{}
	}
	now := a.deps.Now()

	kinds := make([]IncidentKind, 0, len(incident.Kinds()))
	for _, kind := range incident.Kinds() {
		if incident.IsAutomatic(kind) {
			// The box raises these itself; a scanner drawing a button for
			// "gate offline" would be reporting on its own absence.
			continue
		}
		kinds = append(kinds, IncidentKind{
			Kind: kind, Severity: incident.DefaultSeverity(kind), Alarm: incident.IsAlarm(kind),
		})
	}

	return ManifestResponse{
		Event:         a.deps.Event.Name,
		EventID:       a.deps.Event.ID.Hex(),
		Mode:          string(a.deps.Engine.Mode()),
		Bloom:         base64.StdEncoding.EncodeToString(encoded),
		BloomBits:     filter.Bits(),
		BloomHashes:   filter.Hashes(),
		Tickets:       filter.Len(),
		Redeemed:      redeemed,
		Seq:           seq,
		Venue:         a.deps.Venue.Plan(),
		Assignments:   a.assignmentsFor(device.Checkpoints),
		IncidentKinds: kinds,
		Now:           now,
		Window:        int64(ticket.WindowAt(now)),
	}, nil
}

// scannerStream serves the redemption delta stream.
func (a *API) scannerStream(w http.ResponseWriter, r *http.Request, device enroll.Device) {
	// A gate scanner receives redemptions and the announcements it needs to show
	// staff, and nothing else. The incident feed for the whole venue is the
	// control room's business.
	filter := func(event ssehub.Event) bool {
		switch event.Kind {
		case "redemption", "announcement", "config":
			return true
		case "incident":
			// Only emergencies reach a gate, because an evacuation is everybody's
			// business and a request for a tea break is not.
			return isEmergency(event.Data)
		default:
			return false
		}
	}

	a.deps.Hub.Handler(ssehub.HandlerOptions{
		Filter: filter,
		Replay: a.replayRedemptions,
	}).ServeHTTP(w, r)
	_ = device
}

// isEmergency reports whether an incident payload is loud enough to reach a gate.
func isEmergency(data any) bool {
	found, ok := data.(incident.Incident)
	if !ok {
		return false
	}
	return found.Severity == incident.Emergency
}

// replayRedemptions supplies the deltas a reconnecting scanner missed.
func (a *API) replayRedemptions(ctx context.Context, since uint64) ([]ssehub.Event, error) {
	deltas, err := a.deps.Store.Deltas(ctx, since, 0)
	if err != nil {
		return nil, err
	}
	out := make([]ssehub.Event, 0, len(deltas))
	for _, delta := range deltas {
		out = append(out, ssehub.Event{Kind: "redemption", Seq: delta.Seq, Data: delta})
	}
	return out, nil
}

// ScanRequest is one presentation of a QR code at a gate.
type ScanRequest struct {
	// ScanID is the client-generated idempotency key, a UUIDv7-shaped value the
	// scanner mints before it sends. A retry after a Wi-Fi blip resends the same
	// id and gets the original verdict back, which is what stops "the network
	// duplicated my request" from being reported to staff as "someone is reusing a
	// ticket".
	ScanID string `json:"scan_id"`

	// Payload is the raw decoded string from the camera or the barcode gun.
	Payload string `json:"payload"`

	// Checkpoint is the gate. Optional when the device has exactly one.
	Checkpoint venue.CheckpointCode `json:"checkpoint,omitempty"`

	// Direction is which way the holder is moving, for bidirectional doors.
	Direction venue.Direction `json:"direction,omitempty"`

	// HLC is the scanner's hybrid logical clock reading, merged into the box's so
	// causality across devices survives every clock being wrong.
	HLC string `json:"hlc,omitempty"`

	// OfflineAdmitted means the scanner already let this person through on its
	// local mirror during a partition. The box records the admission as offline
	// and flags a double use if it loses the compare-and-set.
	OfflineAdmitted bool `json:"offline_admitted,omitempty"`

	// ObservedAt is when the scanner scanned. Advisory: shown in the audit trail,
	// never used to decide anything.
	ObservedAt time.Time `json:"observed_at,omitzero"`
}

// scan is the gate's endpoint.
func (a *API) scan(w http.ResponseWriter, r *http.Request, device enroll.Device) {
	var req ScanRequest
	if err := readJSON(w, r, limitScan, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	scanID, err := ticket.ParseID(req.ScanID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_scan_id", "The scan id must be a 128-bit value.")
		return
	}

	checkpoint := req.Checkpoint
	if checkpoint == "" {
		if len(device.Checkpoints) != 1 {
			writeError(w, http.StatusBadRequest, "no_checkpoint",
				"This scanner covers several gates, so the scan has to say which one.")
			return
		}
		checkpoint = device.Checkpoints[0]
	}
	// Rejected at the edge as well as in the engine. The engine's check inside the
	// transaction is the authority, but a clear 403 here beats a verdict, and it
	// keeps the audit log free of rows from a device that should not have been
	// talking to this endpoint.
	if !authorizedFor(device, checkpoint) {
		writeError(w, http.StatusForbidden, "not_assigned", "This scanner is not assigned to that gate.")
		return
	}

	var deviceHLC hlc.Timestamp
	if req.HLC != "" {
		if parsed, err := hlc.Parse(req.HLC); err == nil {
			deviceHLC = parsed
		}
		// A malformed clock reading is ignored rather than rejected. The box's own
		// clock still orders the scan correctly, and refusing a scan because a
		// scanner's clock string was odd would be trading an admission for
		// nothing.
	}

	result, err := a.deps.Engine.Scan(r.Context(), a.deps.Store, engineScan(scanID, req, checkpoint, device, deviceHLC))
	if err != nil {
		// This is the amber case in STRICT mode: the box could not decide, so the
		// scanner must not admit. A 503 rather than a 500 because it is a
		// transient condition and the scanner should retry.
		a.log.Error("scan: engine", "device", device.ID, "checkpoint", checkpoint, "error", err)
		writeError(w, http.StatusServiceUnavailable, "undecided",
			"The box could not decide. Do not admit; try again.")
		return
	}

	a.deps.Stats.Observe(result)
	a.publishScan(result)
	writeJSON(w, http.StatusOK, result)
}

// GuidanceResponse tells a gate where to send somebody next.
type GuidanceResponse struct {
	Guidance venue.Guidance `json:"guidance"`
}

// guidanceForTicket answers "where does this person go now" for gate staff.
//
// Separate from the scan so an usher can ask without recording an admission. A
// staff member holding a printed ticket that will not scan needs to be able to
// look it up and point, and doing that through the scan endpoint would put a row
// in the audit log for something that did not happen.
func (a *API) guidanceForTicket(w http.ResponseWriter, r *http.Request, device enroll.Device) {
	id, err := ticket.ParseID(r.URL.Query().Get("ticket"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_ticket", "That is not a ticket id.")
		return
	}
	guidance, ok, err := a.guidanceFor(r, id, r.URL.Query().Get("from"), r.URL.Query().Get("step_free") == "1")
	if err != nil {
		a.log.Error("guidance", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "Could not work that out.")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "unknown_ticket", "That ticket is not on the list.")
		return
	}
	writeJSON(w, http.StatusOK, GuidanceResponse{Guidance: guidance})
	_ = device
}

// IncidentRequest raises a staff signal.
type IncidentRequest struct {
	Kind     incident.Kind     `json:"kind"`
	Severity incident.Severity `json:"severity,omitempty"`

	Checkpoint venue.CheckpointCode `json:"checkpoint,omitempty"`
	Note       string               `json:"note,omitempty"`

	// HeadCount is how many extra staff a request is asking for.
	HeadCount int `json:"head_count,omitempty"`

	// Reporter is the staff member's name, if they signed in with one.
	Reporter string `json:"reporter,omitempty"`

	// ClientID is the idempotency key. A bouncer jabbing the alarm button on a
	// flaky link raises one incident, not four.
	ClientID string `json:"client_id,omitempty"`
}

// raiseIncident records a staff signal from a gate.
func (a *API) raiseIncident(w http.ResponseWriter, r *http.Request, device enroll.Device) {
	var req IncidentRequest
	if err := readJSON(w, r, limitIncident, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if a.deps.Board == nil {
		writeError(w, http.StatusServiceUnavailable, "no_board", "This box is not tracking incidents.")
		return
	}

	checkpoint := req.Checkpoint
	if checkpoint == "" && len(device.Checkpoints) > 0 {
		checkpoint = device.Checkpoints[0]
	}
	if checkpoint != "" && !authorizedFor(device, checkpoint) {
		writeError(w, http.StatusForbidden, "not_assigned", "This scanner is not assigned to that gate.")
		return
	}

	raised, err := a.deps.Board.Raise(incident.Report{
		Kind:       req.Kind,
		Severity:   req.Severity,
		Checkpoint: checkpoint,
		Device:     device.ID,
		Reporter:   req.Reporter,
		Note:       req.Note,
		HeadCount:  req.HeadCount,
		// Attached automatically, because somebody pressing the crush button is
		// not going to stop and fill in a form. It is the difference between "send
		// help" and "send help, this gate has dropped from 40 scans a minute to 6".
		QueueRate: a.deps.Stats.GateRate(checkpoint),
		ClientID:  req.ClientID,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_incident", err.Error())
		return
	}

	a.log.Warn("incident raised", "id", raised.ID, "kind", raised.Kind,
		"severity", raised.Severity, "checkpoint", raised.Checkpoint, "device", device.ID)
	writeJSON(w, http.StatusOK, raised)
}

// listIncidentsForGate returns the live incidents relevant to a gate.
func (a *API) listIncidentsForGate(w http.ResponseWriter, r *http.Request, device enroll.Device) {
	if a.deps.Board == nil {
		writeJSON(w, http.StatusOK, []incident.Incident{})
		return
	}
	// A gate sees exactly its own zone, plus emergencies anywhere.
	//
	// Exactly its own zone, not everything nested inside it: the pit's crush is the
	// pit staff's problem and the control room's, and putting it on the north
	// gate's list is how a bouncer ends up scrolling a feed instead of watching the
	// queue. Emergencies are the exception, because an evacuation is everybody's
	// business.
	var zone venue.ZoneCode
	if len(device.Checkpoints) > 0 {
		if cp, ok := a.deps.Venue.Checkpoint(device.Checkpoints[0]); ok {
			zone = cp.Zone
		}
	}

	mine := a.deps.Board.List(incident.Filter{LiveOnly: true, Zone: zone, ExactZone: true})
	seen := make(map[incident.ID]bool, len(mine))
	for _, found := range mine {
		seen[found.ID] = true
	}
	for _, found := range a.deps.Board.List(incident.Filter{LiveOnly: true, MinSeverity: incident.Emergency}) {
		if !seen[found.ID] {
			mine = append(mine, found)
		}
	}
	if mine == nil {
		mine = []incident.Incident{}
	}
	writeJSON(w, http.StatusOK, mine)
}
