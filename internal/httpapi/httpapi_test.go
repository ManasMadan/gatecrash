package httpapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/bloom"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/enginetest"
	"github.com/ManasMadan/gatecrash/internal/enroll"
	"github.com/ManasMadan/gatecrash/internal/httpapi"
	"github.com/ManasMadan/gatecrash/internal/incident"
	"github.com/ManasMadan/gatecrash/internal/manifest"
	"github.com/ManasMadan/gatecrash/internal/ssehub"
	"github.com/ManasMadan/gatecrash/internal/stats"
	"github.com/ManasMadan/gatecrash/internal/store"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// harness is a whole box behind a real HTTP server.
//
// Everything is real except the clock and the certificate: the same engine, the
// same SQLite store, the same router. An integration test that stubs the engine
// proves that the handlers call something, which is not the interesting question.
type harness struct {
	t     *testing.T
	f     *enginetest.Fixture
	store *store.Store
	board *incident.Board
	reg   *enroll.Registry
	hub   *ssehub.Hub
	stats *stats.Tracker

	server *httptest.Server
	admin  string

	mu  sync.Mutex
	now time.Time
}

const adminToken = "test-admin-token"

func newHarness(t *testing.T, mode engine.Mode) *harness {
	t.Helper()

	h := &harness{t: t, admin: adminToken, now: enginetest.Doors.Add(90 * time.Minute)}
	clock := func() time.Time {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.now
	}

	s, err := store.Open(context.Background(), store.Options{
		Path: filepath.Join(t.TempDir(), "box.db"), Now: clock, Synchronous: "NORMAL",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	h.store = s

	h.f = enginetest.NewFixture(t)
	h.f.Load(s)

	e, err := engine.New(h.f.Config(mode, clock))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(context.Background(), s); err != nil {
		t.Fatal(err)
	}

	h.hub = ssehub.New(nil)
	t.Cleanup(h.hub.Close)
	h.stats = stats.New(stats.Config{Venue: h.f.Venue, Now: clock})
	h.board = incident.NewBoard(incident.BoardConfig{Venue: h.f.Venue, Now: clock})

	h.reg, err = enroll.New(enroll.Config{
		Secret: []byte("a-test-secret-of-sufficient-len"), Now: clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	boxSigning, _, err := ticket.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	api, err := httpapi.New(httpapi.Deps{
		Engine: e, Store: s, Venue: h.f.Venue, Stats: h.stats, Board: h.board,
		Registry: h.reg, Hub: h.hub,
		Event: manifest.Event{
			ID: h.f.EventID, Name: "Sundown Sessions", Venue: "Kingdom of Dreams",
			Mode: mode, Doors: enginetest.Doors, Curfew: enginetest.Curfew,
			Support: "+91 90000 00000",
		},
		Master:     h.f.Master,
		BoxKey:     boxSigning,
		AdminToken: adminToken,
		BoxURL:     "https://10.11.0.1:8443",
		Now:        clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	h.server = httptest.NewServer(api.Handler())
	t.Cleanup(h.server.Close)
	return h
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = h.now.Add(d)
}

// do issues a request and decodes the response.
func (h *harness) do(method, path, token string, body any, into any) int {
	h.t.Helper()

	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()

	if into != nil {
		if err := json.NewDecoder(resp.Body).Decode(into); err != nil && resp.StatusCode < 400 {
			h.t.Fatalf("%s %s: decoding response: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

// enrollScanner runs the whole ceremony and returns a device token.
func (h *harness) enrollScanner(name string, checkpoints ...venue.CheckpointCode) httpapi.EnrollResponse {
	h.t.Helper()

	var invite httpapi.InviteResponse
	if status := h.do(http.MethodPost, "/v1/admin/invite", h.admin,
		httpapi.InviteRequest{Checkpoints: checkpoints, Name: name}, &invite); status != http.StatusOK {
		h.t.Fatalf("issuing an invite: status %d", status)
	}

	// The dashboard renders invite.QR; a scanner decodes it and finds the URL, the
	// fingerprint and the code without being told anything.
	decoded, err := enroll.DecodeInvite(invite.QR)
	if err != nil {
		h.t.Fatalf("the QR the dashboard rendered does not decode: %v", err)
	}

	var enrolled httpapi.EnrollResponse
	if status := h.do(http.MethodPost, "/v1/enroll", "",
		httpapi.EnrollRequest{Code: decoded.Code, Name: name}, &enrolled); status != http.StatusOK {
		h.t.Fatalf("redeeming a code: status %d", status)
	}
	return enrolled
}

// scan posts one scan.
func (h *harness) scan(token, payload string, checkpoint venue.CheckpointCode) (engine.Result, int) {
	h.t.Helper()
	var result engine.Result
	status := h.do(http.MethodPost, "/v1/scan", token, httpapi.ScanRequest{
		ScanID: ticket.MustNewID().Hex(), Payload: payload, Checkpoint: checkpoint,
	}, &result)
	return result, status
}

func TestMetaTellsAClientEverythingItNeedsFirst(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)

	var meta httpapi.Meta
	if status := h.do(http.MethodGet, "/v1/meta", "", nil, &meta); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if meta.Event != "Sundown Sessions" || meta.EventID != h.f.EventID.Hex() {
		t.Errorf("meta describes %q / %q", meta.Event, meta.EventID)
	}
	if meta.Mode != string(engine.ModeStrict) {
		t.Errorf("mode is %q", meta.Mode)
	}
	// The window is the anchor for rotating codes on a phone whose clock is wrong.
	if meta.Window == 0 || meta.Now.IsZero() {
		t.Error("meta carries no clock anchor")
	}
	if !meta.Rotating {
		t.Error("the fixture has a master key, so rotating codes should be advertised")
	}
	if meta.API == "" {
		t.Error("no api version, so a scanner cannot refuse an incompatible box")
	}
}

func TestHealthIsCheapAndUnauthenticated(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	var body map[string]any
	if status := h.do(http.MethodGet, "/healthz", "", nil, &body); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if body["ok"] != true {
		t.Fatalf("health body is %+v", body)
	}
}

// TestFullEnrollmentCeremony walks the whole thing: the organizer issues a code,
// a phone decodes the QR, redeems it, and comes back with a token bound to
// specific checkpoints.
func TestFullEnrollmentCeremony(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North 1", "gate-north")

	if enrolled.Token == "" || enrolled.DeviceID == "" {
		t.Fatalf("enrollment returned %+v", enrolled)
	}
	if len(enrolled.Checkpoints) != 1 || enrolled.Checkpoints[0] != "gate-north" {
		t.Errorf("granted %v", enrolled.Checkpoints)
	}
	// The scanner's home screen needs the door's name and lane so staff can confirm
	// the phone in their hand belongs to the door they are standing at.
	if len(enrolled.Assignments) != 1 {
		t.Fatalf("%d assignments", len(enrolled.Assignments))
	}
	if enrolled.Assignments[0].Name != "North Gate" || enrolled.Assignments[0].ZoneName == "" {
		t.Errorf("assignment is %+v", enrolled.Assignments[0])
	}
	if enrolled.Event != "Sundown Sessions" || enrolled.Mode == "" {
		t.Error("the enrollment response does not carry the event context")
	}
}

func TestEnrollmentCodesAreSingleUseOverTheAPI(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)

	var invite httpapi.InviteResponse
	h.do(http.MethodPost, "/v1/admin/invite", h.admin,
		httpapi.InviteRequest{Checkpoints: []venue.CheckpointCode{"gate-north"}}, &invite)

	if status := h.do(http.MethodPost, "/v1/enroll", "",
		httpapi.EnrollRequest{Code: invite.Invite.Code, Name: "first"}, nil); status != http.StatusOK {
		t.Fatalf("first redemption: status %d", status)
	}
	if status := h.do(http.MethodPost, "/v1/enroll", "",
		httpapi.EnrollRequest{Code: invite.Invite.Code, Name: "second"}, nil); status != http.StatusForbidden {
		t.Fatalf("second redemption: status %d, want 403", status)
	}
}

func TestInviteRefusesAnUnknownCheckpoint(t *testing.T) {
	// A typo here would produce a code that enrolls a device to a door that does
	// not exist, and the failure would surface at the gate.
	h := newHarness(t, engine.ModeStrict)
	if status := h.do(http.MethodPost, "/v1/admin/invite", h.admin,
		httpapi.InviteRequest{Checkpoints: []venue.CheckpointCode{"gate-west"}}, nil); status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", status)
	}
}

func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)

	for _, path := range []string{"/v1/manifest", "/v1/incidents", "/v1/guidance?ticket=x"} {
		if status := h.do(http.MethodGet, path, "", nil, nil); status != http.StatusUnauthorized {
			t.Errorf("GET %s with no token: status %d, want 401", path, status)
		}
		if status := h.do(http.MethodGet, path, "not-a-token", nil, nil); status != http.StatusUnauthorized {
			t.Errorf("GET %s with a bad token: status %d, want 401", path, status)
		}
	}
	for _, path := range []string{"/v1/admin/stats", "/v1/admin/devices", "/v1/admin/export"} {
		if status := h.do(http.MethodGet, path, "", nil, nil); status != http.StatusUnauthorized {
			t.Errorf("GET %s with no token: status %d, want 401", path, status)
		}
		// A device token must not open the dashboard.
		enrolled := h.enrollScanner("phone", "gate-north")
		if status := h.do(http.MethodGet, path, enrolled.Token, nil, nil); status != http.StatusUnauthorized {
			t.Errorf("GET %s with a device token: status %d, want 401", path, status)
		}
	}
}

// TestManifestIsEverythingAScannerNeedsToWorkOffline is the sync contract: one
// request and the device can reject unknown QR codes with no network at all.
func TestManifestIsEverythingAScannerNeedsToWorkOffline(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North 1", "gate-north")

	var body httpapi.ManifestResponse
	if status := h.do(http.MethodGet, "/v1/manifest", enrolled.Token, nil, &body); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}

	raw, err := base64.StdEncoding.DecodeString(body.Bloom)
	if err != nil {
		t.Fatal(err)
	}
	var filter bloom.Filter
	if err := filter.UnmarshalBinary(raw); err != nil {
		t.Fatalf("the filter the box sent does not parse: %v", err)
	}
	// Every real ticket has to be present, or a scanner rejects a paying customer
	// offline with no round trip to catch it.
	for name := range h.f.Tickets {
		id := h.f.ID(name)
		if !filter.Test(id[:]) {
			t.Fatalf("ticket %q is missing from the filter", name)
		}
	}
	// A random id must be rejected, which is what makes a garbage-QR flood free.
	stranger := ticket.MustNewID()
	if filter.Test(stranger[:]) {
		t.Error("the filter matched a random id (possible but should be rare)")
	}
	if body.BloomBits != filter.Bits() || body.BloomHashes != filter.Hashes() {
		t.Error("the advertised filter dimensions do not match the filter")
	}

	// The venue plan rides along so the scanner can render next-step directions
	// after an admit without another round trip.
	if len(body.Venue.Checkpoints) == 0 || len(body.Venue.Zones) == 0 {
		t.Error("the manifest carries no venue plan")
	}
	// And the incident buttons come from the box, so a scanner never draws a button
	// the box will reject.
	if len(body.IncidentKinds) == 0 {
		t.Error("the manifest carries no incident kinds")
	}
	for _, kind := range body.IncidentKinds {
		if incident.IsAutomatic(kind.Kind) {
			t.Errorf("the scanner was offered %q, which the box raises itself", kind.Kind)
		}
	}
	if body.Now.IsZero() || body.Window == 0 {
		t.Error("the manifest carries no clock anchor")
	}
}

func TestManifestRedeemedSnapshotIsScopedToTheCheckpoint(t *testing.T) {
	// A portal scanner does not need to know who came through the north gate, and
	// sending it anyway costs a megabyte over venue Wi-Fi.
	h := newHarness(t, engine.ModeStrict)
	north := h.enrollScanner("North 1", "gate-north")
	portal := h.enrollScanner("Portal", "portal-lower")

	if result, _ := h.scan(north.Token, h.f.Payloads["ga-standing"], "gate-north"); result.Verdict != engine.Admit {
		t.Fatalf("got %s", result.Verdict)
	}

	var northBody, portalBody httpapi.ManifestResponse
	h.do(http.MethodGet, "/v1/manifest", north.Token, nil, &northBody)
	h.do(http.MethodGet, "/v1/manifest", portal.Token, nil, &portalBody)

	if len(northBody.Redeemed) != 1 {
		t.Errorf("the north gate's snapshot has %d ids, want 1", len(northBody.Redeemed))
	}
	if len(portalBody.Redeemed) != 0 {
		t.Errorf("the portal's snapshot carries %d ids from another gate", len(portalBody.Redeemed))
	}
}

func TestManifestRefusesACheckpointTheDeviceIsNotAssignedTo(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North 1", "gate-north")
	if status := h.do(http.MethodGet, "/v1/manifest?checkpoint=pit-gate", enrolled.Token, nil, nil); status != http.StatusForbidden {
		t.Fatalf("status %d, want 403", status)
	}
}

// TestScanEndToEnd walks a ticket through the real HTTP surface: admit, then the
// same ticket again, then a retry of the first request.
func TestScanEndToEnd(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North 1", "gate-north")

	first, status := h.scan(enrolled.Token, h.f.Payloads["ga-block-a"], "gate-north")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if first.Verdict != engine.Admit {
		t.Fatalf("got %s (%s)", first.Verdict, first.Reason)
	}
	// The fields the verdict screen draws large.
	if first.TierName == "" || first.TierColour == "" || first.SeatLabel == "" {
		t.Errorf("the verdict is missing presentation fields: %+v", first)
	}
	if first.Severity != engine.SeverityAdmit {
		t.Errorf("severity is %q", first.Severity)
	}

	second, _ := h.scan(enrolled.Token, h.f.Payloads["ga-block-a"], "gate-north")
	if second.Verdict != engine.AlreadyUsed {
		t.Fatalf("the second scan got %s", second.Verdict)
	}
	if second.Previous == nil {
		t.Fatal("ALREADY_USED carries no evidence")
	}
	if second.Ago == "" {
		t.Error("no human-readable elapsed time, so the gate cannot show the evidence")
	}
}

// TestRetryingTheSameScanIDReplaysTheVerdict is the property that stops a flaky
// link from being reported to staff as ticket reuse.
func TestRetryingTheSameScanIDReplaysTheVerdict(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North 1", "gate-north")

	scanID := ticket.MustNewID().Hex()
	request := httpapi.ScanRequest{
		ScanID: scanID, Payload: h.f.Payloads["ga-standing"], Checkpoint: "gate-north",
	}

	var first engine.Result
	if status := h.do(http.MethodPost, "/v1/scan", enrolled.Token, request, &first); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if first.Verdict != engine.Admit || first.Idempotent {
		t.Fatalf("first scan: %s idempotent=%v", first.Verdict, first.Idempotent)
	}

	for i := 0; i < 4; i++ {
		var replay engine.Result
		h.do(http.MethodPost, "/v1/scan", enrolled.Token, request, &replay)
		if replay.Verdict != engine.Admit {
			t.Fatalf("retry %d got %s, want the original ADMIT", i, replay.Verdict)
		}
		if !replay.Idempotent {
			t.Errorf("retry %d is not marked idempotent", i)
		}
		if replay.Seq != first.Seq {
			t.Errorf("retry %d has seq %d, want %d", i, replay.Seq, first.Seq)
		}
	}
}

func TestScanRejectsBadRequests(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North 1", "gate-north")
	roaming := h.enrollScanner("Roaming", "gate-north", "gate-south")

	t.Run("no scan id", func(t *testing.T) {
		if status := h.do(http.MethodPost, "/v1/scan", enrolled.Token, httpapi.ScanRequest{
			Payload: h.f.Payloads["ga-standing"], Checkpoint: "gate-north",
		}, nil); status != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", status)
		}
	})

	t.Run("a checkpoint the device is not assigned to", func(t *testing.T) {
		if status := h.do(http.MethodPost, "/v1/scan", enrolled.Token, httpapi.ScanRequest{
			ScanID: ticket.MustNewID().Hex(), Payload: h.f.Payloads["ga-standing"], Checkpoint: "pit-gate",
		}, nil); status != http.StatusForbidden {
			t.Fatalf("status %d, want 403", status)
		}
	})

	t.Run("a multi-gate device must say which gate", func(t *testing.T) {
		// Guessing would be worse than refusing: a scan attributed to the wrong
		// door is a wrong audit row and a wrong occupancy count.
		if status := h.do(http.MethodPost, "/v1/scan", roaming.Token, httpapi.ScanRequest{
			ScanID: ticket.MustNewID().Hex(), Payload: h.f.Payloads["ga-standing"],
		}, nil); status != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", status)
		}
	})

	t.Run("unknown json fields are refused", func(t *testing.T) {
		// So a scanner talking a newer protocol finds out immediately instead of
		// having half its request silently dropped.
		req, err := http.NewRequest(http.MethodPost, h.server.URL+"/v1/scan",
			strings.NewReader(`{"scan_id":"`+ticket.MustNewID().Hex()+`","payload":"x","invented_field":1}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+enrolled.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", resp.StatusCode)
		}
	})
}

func TestMalformedPayloadsGetAVerdictNotAnError(t *testing.T) {
	// A supermarket barcode is a scan with an answer, not a protocol error. The
	// gate needs a red screen and a reason, not a 400 it has to interpret.
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North 1", "gate-north")

	for _, payload := range []string{"4006381333931", "https://example.com", "hello"} {
		result, status := h.scan(enrolled.Token, payload, "gate-north")
		if status != http.StatusOK {
			t.Errorf("payload %q: status %d, want 200 with a verdict", payload, status)
		}
		if result.Verdict != engine.Malformed {
			t.Errorf("payload %q: verdict %s", payload, result.Verdict)
		}
		if result.Reason == "" {
			t.Errorf("payload %q: no reason for staff", payload)
		}
	}
}

func TestRateLimitingProtectsTheBox(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North 1", "gate-north")

	// The burst is allowed: a scanner draining an offline queue legitimately
	// bursts, and refusing that would turn a heal into a stall.
	limited := false
	for i := 0; i < 400; i++ {
		status := h.do(http.MethodPost, "/v1/scan", enrolled.Token, httpapi.ScanRequest{
			ScanID: ticket.MustNewID().Hex(), Payload: "garbage", Checkpoint: "gate-north",
		}, nil)
		if status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("a device sending 400 requests instantly was never rate limited")
	}

	// And it recovers, rather than locking a gate out for the evening.
	h.advance(5 * time.Second)
	if status := h.do(http.MethodPost, "/v1/scan", enrolled.Token, httpapi.ScanRequest{
		ScanID: ticket.MustNewID().Hex(), Payload: "garbage", Checkpoint: "gate-north",
	}, nil); status == http.StatusTooManyRequests {
		t.Fatal("the device was still rate limited five seconds later")
	}
}

func TestRateLimitIsPerDevice(t *testing.T) {
	// One misbehaving scanner must not take a gate down for everybody else.
	h := newHarness(t, engine.ModeStrict)
	noisy := h.enrollScanner("Noisy", "gate-north")
	quiet := h.enrollScanner("Quiet", "gate-north")

	for i := 0; i < 400; i++ {
		if h.do(http.MethodPost, "/v1/scan", noisy.Token, httpapi.ScanRequest{
			ScanID: ticket.MustNewID().Hex(), Payload: "garbage", Checkpoint: "gate-north",
		}, nil) == http.StatusTooManyRequests {
			break
		}
	}
	if status := h.do(http.MethodPost, "/v1/scan", quiet.Token, httpapi.ScanRequest{
		ScanID: ticket.MustNewID().Hex(), Payload: "garbage", Checkpoint: "gate-north",
	}, nil); status == http.StatusTooManyRequests {
		t.Fatal("a quiet device was rate limited because another device was noisy")
	}
}

// TestMultiStageVenueOverTheAPI is the product walkthrough: perimeter, then the
// portal for this ticket's block, with a wrong-door redirect in between.
func TestMultiStageVenueOverTheAPI(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	north := h.enrollScanner("North 1", "gate-north")
	lower := h.enrollScanner("Portal C Lower", "portal-lower")
	upper := h.enrollScanner("Portal C Upper", "portal-upper")

	if result, _ := h.scan(north.Token, h.f.Payloads["ga-block-b"], "gate-north"); result.Verdict != engine.Admit {
		t.Fatalf("perimeter: %s", result.Verdict)
	}

	// A Block B holder at the Block A portal: entitled, misrouted, and told where
	// to go rather than turned away.
	wrong, _ := h.scan(lower.Token, h.f.Payloads["ga-block-b"], "portal-lower")
	if wrong.Verdict != engine.WrongDoor {
		t.Fatalf("wrong portal: %s", wrong.Verdict)
	}
	if wrong.Severity != engine.SeverityRedirect {
		t.Errorf("severity is %q, want redirect: a misrouted paying customer is not a forgery", wrong.Severity)
	}
	if len(wrong.Redirect) == 0 || wrong.Redirect[0].Checkpoint != "portal-upper" {
		t.Fatalf("redirect is %+v", wrong.Redirect)
	}
	if wrong.Redirect[0].Name == "" {
		t.Error("the redirect has no human name, so the guard has nothing to say")
	}

	if right, _ := h.scan(upper.Token, h.f.Payloads["ga-block-b"], "portal-upper"); right.Verdict != engine.Admit {
		t.Fatalf("the right portal: %s", right.Verdict)
	}
}

func TestPrerequisitesOverTheAPI(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	north := h.enrollScanner("North", "gate-north")
	pit := h.enrollScanner("Pit", "pit-gate")
	arena := h.enrollScanner("Arena", "arena-general")

	if result, _ := h.scan(north.Token, h.f.Payloads["vip-pit"], "gate-north"); result.Verdict != engine.Admit {
		t.Fatalf("perimeter: %s", result.Verdict)
	}

	blocked, _ := h.scan(pit.Token, h.f.Payloads["vip-pit"], "pit-gate")
	if blocked.Verdict != engine.PrerequisiteMissing {
		t.Fatalf("pit before arena: %s", blocked.Verdict)
	}
	if len(blocked.Missing) != 1 || blocked.Missing[0] != "arena" {
		t.Errorf("missing is %v", blocked.Missing)
	}
	if len(blocked.Redirect) == 0 {
		t.Error("a prerequisite denial carries no directions")
	}

	if result, _ := h.scan(arena.Token, h.f.Payloads["vip-pit"], "arena-general"); result.Verdict != engine.Admit {
		t.Fatalf("arena: %s", result.Verdict)
	}
	if result, _ := h.scan(pit.Token, h.f.Payloads["vip-pit"], "pit-gate"); result.Verdict != engine.Admit {
		t.Fatalf("pit after arena: %s", result.Verdict)
	}
}

// TestAttendeeTicketIsOneRoundTrip is the attendee contract: everything the app
// needs in one response, because the app runs on a phone with no bars in a crowd.
func TestAttendeeTicketIsOneRoundTrip(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	id := h.f.ID("ga-block-a")

	var body httpapi.TicketResponse
	if status := h.do(http.MethodGet, "/v1/ticket/"+id.String(), "", nil, &body); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if body.TierName == "" || body.SeatLabel == "" {
		t.Errorf("the ticket is missing display fields: %+v", body)
	}
	if body.Event != "Sundown Sessions" || body.Support == "" {
		t.Error("the ticket does not carry the event context")
	}
	if body.Payload == "" {
		t.Error("a static ticket carries no payload to render")
	}
	if body.Guidance == nil || len(body.Guidance.Next) == 0 {
		t.Error("the ticket carries no guidance, so the app cannot say where to go")
	}
	if body.Window == 0 || body.Now.IsZero() {
		t.Error("the ticket carries no clock anchor")
	}
	// The install links exist because mesh chat cannot be a web app, and the copy
	// has to say why rather than just demanding an install.
	if body.Install == nil || body.Install.Why == "" {
		t.Error("no install links or no reason given")
	}

	// It also has to be uncacheable: the window and the history both change.
	resp, err := http.Get(h.server.URL + "/v1/ticket/" + id.String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		t.Errorf("Cache-Control is %q", resp.Header.Get("Cache-Control"))
	}
}

func TestAttendeeTicketReflectsAdmissionHistory(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	north := h.enrollScanner("North", "gate-north")
	id := h.f.ID("ga-block-a")

	if result, _ := h.scan(north.Token, h.f.Payloads["ga-block-a"], "gate-north"); result.Verdict != engine.Admit {
		t.Fatalf("%s", result.Verdict)
	}

	var body httpapi.TicketResponse
	h.do(http.MethodGet, "/v1/ticket/"+id.String(), "", nil, &body)

	if len(body.History) != 1 {
		t.Fatalf("history has %d entries", len(body.History))
	}
	if body.History[0].CheckpointName != "North Gate" || body.History[0].ZoneName == "" {
		t.Errorf("history entry is %+v", body.History[0])
	}
	// And the guidance has moved on: the outer gate is behind them.
	if body.Guidance == nil {
		t.Fatal("no guidance")
	}
	for _, step := range body.Guidance.Next {
		if step.Checkpoint == "gate-north" {
			t.Error("a once-only gate already used is still being offered")
		}
	}
}

func TestUnknownTicketsAreIndistinguishableFromForeignOnes(t *testing.T) {
	// An attendee-facing endpoint that distinguishes "does not exist" from "exists
	// but is not yours" is an oracle for enumerating ticket ids.
	h := newHarness(t, engine.ModeStrict)
	other := enginetest.NewFixture(t)

	nonexistent := h.do(http.MethodGet, "/v1/ticket/"+ticket.MustNewID().String(), "", nil, nil)
	foreign := h.do(http.MethodGet, "/v1/ticket/"+other.ID("ga-standing").String(), "", nil, nil)
	if nonexistent != foreign {
		t.Fatalf("a nonexistent ticket gives %d and a foreign one gives %d", nonexistent, foreign)
	}
	if nonexistent != http.StatusNotFound {
		t.Fatalf("status %d, want 404", nonexistent)
	}
}

// TestClaimHandsOverASecretThatGeneratesValidCodes closes the loop on rotating
// tickets: the phone claims once over TLS and then generates codes entirely
// offline.
func TestClaimHandsOverASecretThatGeneratesValidCodes(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North", "gate-north")
	id := h.f.ID("rotating")

	var claim httpapi.ClaimResponse
	if status := h.do(http.MethodPost, "/v1/ticket/"+id.String()+"/claim", "",
		httpapi.ClaimRequest{Device: "phone-1"}, &claim); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if claim.Secret == "" || claim.Seconds != ticket.WindowSeconds {
		t.Fatalf("claim response is %+v", claim)
	}

	// Generate a code from the claimed secret, exactly as the app does, and admit
	// with it.
	secret, err := ticket.ParseSecret(claim.Secret)
	if err != nil {
		t.Fatal(err)
	}
	payload := ticket.GenerateGC2(secret, h.f.EventID, id, ticket.Window(claim.Window))
	result, _ := h.scan(enrolled.Token, payload, "gate-north")
	if result.Verdict != engine.Admit {
		t.Fatalf("a code generated from the claimed secret got %s (%s)", result.Verdict, result.Reason)
	}

	// Claiming twice returns the same secret, because it is a derivation rather
	// than an issuance: a reinstalled app just works, with no dead end at a gate.
	var again httpapi.ClaimResponse
	h.do(http.MethodPost, "/v1/ticket/"+id.String()+"/claim", "", httpapi.ClaimRequest{Device: "phone-2"}, &again)
	if again.Secret != claim.Secret {
		t.Error("claiming twice produced different secrets, so a reinstall would lock somebody out")
	}
}

func TestClaimRefusesAPrintedTicket(t *testing.T) {
	// Handing out a rotating secret for a print-only ticket would be issuing a
	// credential nobody asked for.
	h := newHarness(t, engine.ModeStrict)
	if status := h.do(http.MethodPost, "/v1/ticket/"+h.f.ID("ga-standing").String()+"/claim", "",
		httpapi.ClaimRequest{}, nil); status != http.StatusConflict {
		t.Fatalf("status %d, want 409", status)
	}
}

func TestClaimRefusesARevokedTicket(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	if status := h.do(http.MethodPost, "/v1/ticket/"+h.f.ID("revoked").String()+"/claim", "",
		httpapi.ClaimRequest{}, nil); status == http.StatusOK {
		t.Fatal("a revoked ticket was claimable")
	}
}

func TestStaticPayloadIsNotHandedOutForRotatingTickets(t *testing.T) {
	// Handing out the GC1 string for a rotating ticket would undo the entire
	// anti-screenshot property.
	h := newHarness(t, engine.ModeStrict)
	var body httpapi.TicketResponse
	h.do(http.MethodGet, "/v1/ticket/"+h.f.ID("rotating").String(), "", nil, &body)
	if body.Payload != "" {
		t.Fatalf("a rotating ticket handed out a static payload: %q", body.Payload)
	}
}

func TestVenuePlanIsCacheableWithAnETag(t *testing.T) {
	// The map is the largest payload the attendee app fetches and it does not
	// change during an event.
	h := newHarness(t, engine.ModeStrict)

	resp, err := http.Get(h.server.URL + "/v1/venue")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var body httpapi.VenueResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Plan.Zones) == 0 || len(body.Plan.Sections) == 0 {
		t.Error("the venue response carries no plan")
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "max-age") {
		t.Errorf("Cache-Control is %q", resp.Header.Get("Cache-Control"))
	}
}

func TestNearestAmenitiesNeedsAPosition(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	path := "/v1/ticket/" + h.f.ID("ga-standing").String() + "/nearby"
	if status := h.do(http.MethodGet, path, "", nil, nil); status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 without a position", status)
	}
}

// TestStaffSignalReachesTheControlRoom is the bouncer's button: it lands with the
// gate, the zone and the queue rate already filled in.
func TestStaffSignalReachesTheControlRoom(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("Pit", "pit-gate")

	var raised incident.Incident
	if status := h.do(http.MethodPost, "/v1/incidents", enrolled.Token, httpapi.IncidentRequest{
		Kind: incident.Crush, Reporter: "Aditi", Note: "front barrier is buckling",
	}, &raised); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if raised.Severity != incident.Emergency {
		t.Errorf("a crush report is %s, want emergency", raised.Severity)
	}
	// Filled in from the device's own enrollment, because somebody pressing the
	// crush button is not going to fill in a form.
	if raised.Checkpoint != "pit-gate" || raised.ZoneName == "" {
		t.Errorf("the incident does not know where it came from: %+v", raised)
	}
	if raised.Device != enrolled.DeviceID {
		t.Errorf("the incident is attributed to %q", raised.Device)
	}

	// The control room sees it.
	var listed []incident.Incident
	h.do(http.MethodGet, "/v1/admin/incidents?live=1", h.admin, nil, &listed)
	if len(listed) != 1 || listed[0].ID != raised.ID {
		t.Fatalf("the control room sees %d incidents", len(listed))
	}

	// And acknowledging it is attributed and timed.
	h.advance(40 * time.Second)
	var acked incident.Incident
	if status := h.do(http.MethodPost, "/v1/admin/incidents/"+string(raised.ID), h.admin,
		httpapi.TransitionRequest{Status: incident.Acknowledged, Actor: "control"}, &acked); status != http.StatusOK {
		t.Fatalf("acknowledging: status %d", status)
	}
	elapsed, ok := acked.AcknowledgedAfter()
	if !ok || elapsed != 40*time.Second {
		t.Errorf("acknowledged after %s, want 40s", elapsed)
	}
}

func TestStaffSignalCarriesTheQueueRate(t *testing.T) {
	// The difference between "send help" and "send help, this gate has dropped
	// from 40 scans a minute to 6".
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North", "gate-north")

	holders := h.f.IssueMany(t, 10)
	for _, issued := range holders {
		if err := h.store.PutTicketContext(context.Background(), issued.Ticket); err != nil {
			t.Fatal(err)
		}
		h.scan(enrolled.Token, issued.Payload, "gate-north")
	}

	var raised incident.Incident
	h.do(http.MethodPost, "/v1/incidents", enrolled.Token, httpapi.IncidentRequest{
		Kind: incident.NeedStaff, HeadCount: 2,
	}, &raised)

	if raised.QueueRate <= 0 {
		t.Errorf("the staffing request carries a queue rate of %v", raised.QueueRate)
	}
	if raised.HeadCount != 2 {
		t.Errorf("head count is %d", raised.HeadCount)
	}
}

func TestIncidentIdempotency(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("Pit", "pit-gate")

	request := httpapi.IncidentRequest{Kind: incident.Medical, ClientID: "panic-1"}
	var first, second incident.Incident
	h.do(http.MethodPost, "/v1/incidents", enrolled.Token, request, &first)
	h.do(http.MethodPost, "/v1/incidents", enrolled.Token, request, &second)

	if first.ID != second.ID {
		t.Fatalf("a jabbed button raised two incidents: %s and %s", first.ID, second.ID)
	}
}

// TestGateSeesItsOwnZonePlusEmergencies pins the split. A bouncer scrolling the
// whole venue's incident feed is a bouncer not watching the queue — but an
// evacuation is everybody's business, so emergencies cross zone boundaries and
// nothing else does.
func TestGateSeesItsOwnZonePlusEmergencies(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	pit := h.enrollScanner("Pit", "pit-gate")
	north := h.enrollScanner("North", "gate-north")

	// A staffing request in the pit: the pit's business, nobody else's.
	h.do(http.MethodPost, "/v1/incidents", pit.Token, httpapi.IncidentRequest{Kind: incident.NeedRelief}, nil)

	var atNorth []incident.Incident
	h.do(http.MethodGet, "/v1/incidents", north.Token, nil, &atNorth)
	for _, found := range atNorth {
		if found.Zone == "pit" {
			t.Errorf("the north gate can see the pit's %s", found.Kind)
		}
	}

	var atPit []incident.Incident
	h.do(http.MethodGet, "/v1/incidents", pit.Token, nil, &atPit)
	if len(atPit) != 1 {
		t.Fatalf("the pit sees %d of its own incidents", len(atPit))
	}

	// An emergency in the pit reaches the north gate.
	h.do(http.MethodPost, "/v1/incidents", pit.Token, httpapi.IncidentRequest{Kind: incident.Evacuate}, nil)
	atNorth = nil
	h.do(http.MethodGet, "/v1/incidents", north.Token, nil, &atNorth)

	var sawEvacuation bool
	for _, found := range atNorth {
		if found.Kind == incident.Evacuate {
			sawEvacuation = true
		}
		if found.Kind == incident.NeedRelief {
			t.Error("a non-emergency from another zone crossed to the north gate")
		}
	}
	if !sawEvacuation {
		t.Fatal("an evacuation did not reach the north gate")
	}
}

func TestDashboardStats(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North", "gate-north")

	h.scan(enrolled.Token, h.f.Payloads["ga-standing"], "gate-north")
	h.scan(enrolled.Token, h.f.Payloads["revoked"], "gate-north")

	var body httpapi.DashboardStats
	if status := h.do(http.MethodGet, "/v1/admin/stats", h.admin, nil, &body); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if body.Live.Scans != 2 || body.Live.Denied != 1 {
		t.Errorf("live picture is %d scans, %d denied", body.Live.Scans, body.Live.Denied)
	}
	if body.Live.Admitted != 1 {
		t.Errorf("headline admitted is %d", body.Live.Admitted)
	}
	// A wall of one verdict at one gate is the most useful diagnostic the
	// dashboard shows.
	if body.Live.Verdicts[engine.Revoked] != 1 {
		t.Errorf("verdict breakdown is %v", body.Live.Verdicts)
	}
	if body.ChainRows != 2 || body.ChainHead == "" {
		t.Errorf("chain is at %d rows, head %q", body.ChainRows, body.ChainHead)
	}
	if len(body.Devices) != 1 {
		t.Errorf("%d devices on the roster", len(body.Devices))
	}
	if body.Mode != string(engine.ModeStrict) {
		t.Errorf("mode is %q", body.Mode)
	}
}

func TestRevokingADeviceStopsItImmediately(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("Stolen", "gate-north")

	if result, _ := h.scan(enrolled.Token, h.f.Payloads["ga-standing"], "gate-north"); result.Verdict != engine.Admit {
		t.Fatalf("%s", result.Verdict)
	}
	if status := h.do(http.MethodPost, "/v1/admin/devices/"+enrolled.DeviceID+"/revoke", h.admin, nil, nil); status != http.StatusOK {
		t.Fatalf("revoking: status %d", status)
	}
	// The token is revoked in the registry too, so the request is refused before
	// it reaches the engine.
	if status := h.do(http.MethodPost, "/v1/scan", enrolled.Token, httpapi.ScanRequest{
		ScanID: ticket.MustNewID().Hex(), Payload: h.f.Payloads["crew"], Checkpoint: "gate-north",
	}, nil); status != http.StatusUnauthorized {
		t.Fatalf("a revoked device got status %d, want 401", status)
	}
}

func TestRevokingATicketStopsIt(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North", "gate-north")
	id := h.f.ID("crew")

	if status := h.do(http.MethodPost, "/v1/admin/tickets/"+id.String()+"/revoke", h.admin, nil, nil); status != http.StatusOK {
		t.Fatalf("revoking: status %d", status)
	}
	result, _ := h.scan(enrolled.Token, h.f.Payloads["crew"], "gate-north")
	if result.Verdict != engine.Revoked {
		t.Fatalf("a revoked ticket got %s", result.Verdict)
	}
}

func TestAnnouncements(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)

	var sent httpapi.Announcement
	if status := h.do(http.MethodPost, "/v1/admin/announce", h.admin,
		httpapi.AnnounceRequest{Text: "Gate 4 is now open", Priority: true}, &sent); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if sent.ID == "" || sent.At.IsZero() {
		t.Errorf("the announcement is %+v", sent)
	}

	var feed []httpapi.Announcement
	if status := h.do(http.MethodGet, "/v1/announcements", "", nil, &feed); status != http.StatusOK {
		t.Fatalf("reading the feed: status %d", status)
	}
	if len(feed) != 1 || feed[0].Text != "Gate 4 is now open" {
		t.Fatalf("the feed is %+v", feed)
	}

	t.Run("empty text is refused", func(t *testing.T) {
		if status := h.do(http.MethodPost, "/v1/admin/announce", h.admin,
			httpapi.AnnounceRequest{}, nil); status != http.StatusBadRequest {
			t.Fatalf("status %d", status)
		}
	})
	t.Run("an unknown zone is refused", func(t *testing.T) {
		if status := h.do(http.MethodPost, "/v1/admin/announce", h.admin,
			httpapi.AnnounceRequest{Text: "hello", Zone: "nowhere"}, nil); status != http.StatusBadRequest {
			t.Fatalf("status %d", status)
		}
	})
	t.Run("an essay is refused", func(t *testing.T) {
		// An announcement is read on a lock screen in a crowd.
		if status := h.do(http.MethodPost, "/v1/admin/announce", h.admin,
			httpapi.AnnounceRequest{Text: strings.Repeat("x", 500)}, nil); status != http.StatusBadRequest {
			t.Fatalf("status %d", status)
		}
	})
}

// TestSealAndAttendanceProofOverTheAPI is the settlement workflow end to end.
func TestSealAndAttendanceProofOverTheAPI(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North", "gate-north")

	holders := h.f.IssueMany(t, 20)
	for _, issued := range holders {
		if err := h.store.PutTicketContext(context.Background(), issued.Ticket); err != nil {
			t.Fatal(err)
		}
		if result, _ := h.scan(enrolled.Token, issued.Payload, "gate-north"); result.Verdict != engine.Admit {
			t.Fatalf("%s", result.Verdict)
		}
	}

	var sealed map[string]any
	if status := h.do(http.MethodPost, "/v1/admin/seal", h.admin, nil, &sealed); status != http.StatusOK {
		t.Fatalf("sealing: status %d", status)
	}
	if sealed["root"] == "" {
		t.Fatal("the seal has no root to publish")
	}

	var verify httpapi.VerifyResponse
	if status := h.do(http.MethodGet, "/v1/admin/verify", h.admin, nil, &verify); status != http.StatusOK {
		t.Fatalf("verifying: status %d", status)
	}
	if !verify.OK {
		t.Fatalf("the chain does not verify: %s", verify.Error)
	}
	if verify.Rows != 20 {
		t.Errorf("the chain is at %d rows", verify.Rows)
	}

	// One ticket, proved.
	proofPath := "/v1/admin/attendance/" + holders[7].Ticket.ID.String()
	var raw json.RawMessage
	if status := h.do(http.MethodGet, proofPath, h.admin, nil, &raw); status != http.StatusOK {
		t.Fatalf("attendance: status %d", status)
	}
	if !bytes.Contains(raw, []byte(`"proof"`)) {
		t.Errorf("the attendance response carries no proof: %s", raw)
	}

	// A ticket that never scanned has no proof, rather than a proof of nothing.
	if status := h.do(http.MethodGet, "/v1/admin/attendance/"+ticket.MustNewID().String(), h.admin, nil, nil); status != http.StatusNotFound {
		t.Errorf("status %d for a ticket that never scanned, want 404", status)
	}
}

func TestSignedExport(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North", "gate-north")
	h.scan(enrolled.Token, h.f.Payloads["ga-standing"], "gate-north")

	resp, err := http.Get(h.server.URL + "/v1/admin/export?token=" + adminToken)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	// A filename, because this is a file an operator emails to an artist's
	// manager.
	if !strings.Contains(resp.Header.Get("Content-Disposition"), "attendance") {
		t.Errorf("Content-Disposition is %q", resp.Header.Get("Content-Disposition"))
	}

	var signed manifest.SignedAttendance
	if err := json.NewDecoder(resp.Body).Decode(&signed); err != nil {
		t.Fatal(err)
	}
	if signed.Format != manifest.AttendanceFormat || len(signed.Signature) == 0 {
		t.Fatalf("the export is not signed: %+v", signed.Format)
	}
	// Self-consistency is all a test can check without the published box key,
	// which is exactly the check a recipient without it can make.
	report, err := manifest.VerifyAttendance(signed, ticket.VerifyingKey{})
	if err != nil {
		t.Fatalf("the export does not verify: %v", err)
	}
	if report.Event != "Sundown Sessions" || report.Checkpoint.Rows == 0 {
		t.Errorf("the report is %+v", report.Event)
	}
	if report.Totals.Admitted != 1 {
		t.Errorf("the report says %d admitted", report.Totals.Admitted)
	}
}

// TestDegradedModeFlagIsVisibleOnTheAPI is the honest half of DEGRADED mode: the
// number of people who got in on a ticket that was already used, published rather
// than rounded away.
func TestDegradedModeFlagIsVisibleOnTheAPI(t *testing.T) {
	h := newHarness(t, engine.ModeDegraded)
	first := h.enrollScanner("North 1", "gate-north")
	second := h.enrollScanner("North 2", "gate-north")

	h.scan(first.Token, h.f.Payloads["ga-standing"], "gate-north")

	var late engine.Result
	h.do(http.MethodPost, "/v1/scan", second.Token, httpapi.ScanRequest{
		ScanID: ticket.MustNewID().Hex(), Payload: h.f.Payloads["ga-standing"],
		Checkpoint: "gate-north", OfflineAdmitted: true,
	}, &late)

	if late.Verdict != engine.AlreadyUsed || !late.Flagged {
		t.Fatalf("the reconciled offline scan got %s flagged=%v", late.Verdict, late.Flagged)
	}

	var flags []engine.DoubleUse
	if status := h.do(http.MethodGet, "/v1/admin/flags", h.admin, nil, &flags); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if len(flags) != 1 {
		t.Fatalf("%d flags", len(flags))
	}
	if !flags[0].Loser.Offline {
		t.Error("the flag does not record that a person actually walked through")
	}
}

// TestSSEStreamDeliversAdmissions covers the live delta path a scanner mirror
// depends on.
func TestSSEStreamDeliversAdmissions(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North", "gate-north")

	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/v1/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+enrolled.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	// Let the subscription land before publishing.
	time.Sleep(100 * time.Millisecond)
	if result, _ := h.scan(enrolled.Token, h.f.Payloads["ga-standing"], "gate-north"); result.Verdict != engine.Admit {
		t.Fatalf("%s", result.Verdict)
	}

	found := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		var seen strings.Builder
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				seen.Write(buf[:n])
				if strings.Contains(seen.String(), "event: redemption") {
					found <- seen.String()
					return
				}
			}
			if err != nil {
				found <- seen.String()
				return
			}
		}
	}()

	select {
	case body := <-found:
		if !strings.Contains(body, "event: redemption") {
			t.Fatalf("the stream carried no redemption: %q", body)
		}
		if !strings.Contains(body, "id: ") {
			t.Error("the event carries no id, so a reconnect cannot resume")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event arrived on the stream")
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	h := newHarness(t, engine.ModeStrict)
	resp, err := http.Get(h.server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s is %q, want %q", header, got, want)
		}
	}
}

func TestNewRejectsAnIncompleteConfig(t *testing.T) {
	for name, deps := range map[string]httpapi.Deps{
		"no engine": {},
		"no admin token": {
			Engine: &engine.Engine{},
		},
	} {
		if _, err := httpapi.New(deps); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}

func BenchmarkScanOverHTTP(b *testing.B) {
	t := &testing.T{}
	h := newHarness(t, engine.ModeStrict)
	enrolled := h.enrollScanner("North", "gate-north")

	holders := make([]enginetest.Issued, 0, b.N)
	for i := 0; i < b.N; i++ {
		issued := h.f.Issue(t, "ga", venue.SeatRef{}, engine.FormatStatic)
		if err := h.store.PutTicketContext(context.Background(), issued.Ticket); err != nil {
			b.Fatal(err)
		}
		holders = append(holders, issued)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// The rate limiter is a policy about how fast a human can present tickets,
		// not a statement about how fast the box can decide them. Advancing the
		// clock in step keeps it out of the measurement; without this the benchmark
		// measures the limiter, which is not the interesting number.
		h.advance(time.Second / 20)

		result, status := h.scan(enrolled.Token, holders[i].Payload, "gate-north")
		if status != http.StatusOK || result.Verdict != engine.Admit {
			b.Fatalf("status %d verdict %s", status, result.Verdict)
		}
	}
}
