package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/enroll"
	"github.com/ManasMadan/gatecrash/internal/httpapi"
	"github.com/ManasMadan/gatecrash/internal/incident"
	"github.com/ManasMadan/gatecrash/internal/logx"
	"github.com/ManasMadan/gatecrash/internal/manifest"
	"github.com/ManasMadan/gatecrash/internal/ssehub"
	"github.com/ManasMadan/gatecrash/internal/stats"
	"github.com/ManasMadan/gatecrash/internal/store"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// doors is when the demo event opens. Fixed rather than relative to now, so two
// runs of the demo print the same times and a copy-pasted transcript is stable.
var doors = time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)

// demo holds the running box and the scripted event.
type demo struct {
	quiet bool

	mu  sync.Mutex
	now time.Time

	server *httptest.Server
	store  *store.Store
	admin  string

	keys    organizerKeys
	tickets map[string]issued
	tokens  map[string]string
}

// organizerKeys is the demo's key material. Generated fresh every run: the demo
// never writes a key anybody could mistake for a real one.
type organizerKeys struct {
	signing   ticket.SigningKey
	verifying ticket.VerifyingKey
	master    ticket.MasterKey
	eventID   ticket.ID
}

// issued is one ticket the demo hands out.
type issued struct {
	record  engine.Ticket
	payload string
}

func runDemo(keep string, quiet bool) error {
	d := &demo{
		quiet:   quiet,
		now:     doors.Add(30 * time.Minute),
		tickets: map[string]issued{},
		tokens:  map[string]string{},
	}

	dir := keep
	if dir == "" {
		temp, err := os.MkdirTemp("", "gatecrash-demo-*")
		if err != nil {
			return err
		}
		dir = temp
		defer os.RemoveAll(temp)
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	if err := d.boot(dir); err != nil {
		return err
	}
	defer d.server.Close()
	defer d.store.Close()

	d.banner("Gatecrash demo", "a whole event, in one process, over real HTTP")
	d.note("box            %s", d.server.URL)
	d.note("database       %s", filepath.Join(dir, "gatecrash.db"))
	d.note("organizer key  %s", d.keys.verifying.Fingerprint())
	d.note("clock          %s (driven forwards; an evening fits in a second)", d.now.Format(time.RFC1123))

	for _, act := range []struct {
		title string
		fn    func() error
	}{
		{"Setup: the venue, the tickets, the manifest", d.actSetup},
		{"Doors: enrolling scanners with a printed QR", d.actEnroll},
		{"The happy path: a seated ticket walks in", d.actHappyPath},
		{"The same ticket, twice", d.actDoubleScan},
		{"A retry after a Wi-Fi blip is not a reuse", d.actIdempotency},
		{"The wrong door, and where to send them", d.actWrongDoor},
		{"Out of order: the pit before the arena", d.actPrerequisite},
		{"Rotating codes: a screenshot dies in sixty seconds", d.actRotating},
		{"Things that are not tickets", d.actGarbage},
		{"Re-entry, drink tokens, and walking out", d.actPolicies},
		{"The bouncer's two buttons", d.actIncidents},
		{"The control room", d.actDashboard},
		{"Settlement: proving one admission with twenty hashes", d.actSettlement},
	} {
		d.act(act.title)
		if err := act.fn(); err != nil {
			return fmt.Errorf("%s: %w", act.title, err)
		}
	}

	d.act("Done")
	if keep != "" {
		d.note("the box's data is in %s", keep)
		d.note("inspect it with:  gatecrash verify -db %s", filepath.Join(keep, "gatecrash.db"))
	}
	return nil
}

// boot assembles a real box behind a real HTTP server.
func (d *demo) boot(dir string) error {
	ctx := context.Background()
	clock := d.clock

	signing, verifying, err := ticket.GenerateSigningKey()
	if err != nil {
		return err
	}
	root, err := ticket.NewMasterKey()
	if err != nil {
		return err
	}
	eventID := ticket.MustNewID()
	master, err := ticket.DeriveEventMaster(root, eventID)
	if err != nil {
		return err
	}
	d.keys = organizerKeys{signing: signing, verifying: verifying, master: master, eventID: eventID}

	opened, err := store.Open(ctx, store.Options{
		Path: filepath.Join(dir, "gatecrash.db"), Now: clock,
		// NORMAL rather than FULL: the demo is not fighting an SD card, and FULL
		// makes it several times slower for no signal.
		Synchronous: "NORMAL",
	})
	if err != nil {
		return err
	}
	d.store = opened

	body := d.manifestBody()
	envelope, err := manifest.Sign(signing, body)
	if err != nil {
		return err
	}
	if err := opened.Ingest(ctx, body, envelope.Digest()); err != nil {
		return err
	}
	for _, record := range d.tickets {
		if err := opened.PutTicketContext(ctx, record.record); err != nil {
			return err
		}
	}

	compiled, err := venue.Compile(body.Venue)
	if err != nil {
		return err
	}
	redemption, err := engine.New(engine.Config{
		EventID: eventID, Venue: compiled, Verifying: verifying,
		Master: master, Mode: engine.ModeStrict, Now: clock,
	})
	if err != nil {
		return err
	}
	if err := redemption.Recover(ctx, opened); err != nil {
		return err
	}

	hub := ssehub.New(nil)
	tracker := stats.New(stats.Config{Venue: compiled, Now: clock})
	tracker.SetIssued(len(d.tickets), map[venue.TierCode]int{})
	board := incident.NewBoard(incident.BoardConfig{
		Venue: compiled, Now: clock,
		Persist: func(i incident.Incident) { _ = opened.PutIncident(ctx, i) },
	})
	registry, err := enroll.New(enroll.Config{
		Secret: []byte("gatecrash-demo-registry-secret!!"), Now: clock,
	})
	if err != nil {
		return err
	}
	boxKey, _, err := ticket.GenerateSigningKey()
	if err != nil {
		return err
	}

	d.admin = "demo-admin-token"
	api, err := httpapi.New(httpapi.Deps{
		Engine: redemption, Store: opened, Venue: compiled, Stats: tracker,
		Board: board, Registry: registry, Hub: hub,
		Event: body.Event, Master: master, BoxKey: boxKey,
		AdminToken: d.admin, BoxURL: "https://10.11.0.1:8443",
		Now: clock,
		// Errors only: the demo's own narration is the output, and an info-level
		// log line between every step would bury it.
		Logger: logx.New(logx.Options{Level: "error"}),
	})
	if err != nil {
		return err
	}
	if err := opened.OpenSession(ctx, d.clock()); err != nil {
		return err
	}

	d.server = httptest.NewServer(api.Handler())
	return nil
}

func (d *demo) clock() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.now
}

// advance moves the clock forwards. The demo drives it rather than sleeping,
// which is why an evening fits in a second.
func (d *demo) advance(by time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.now = d.now.Add(by)
}

// Narration.

func (d *demo) banner(title, subtitle string) {
	if d.quiet {
		return
	}
	fmt.Printf("\n\033[1m%s\033[0m — %s\n", title, subtitle)
	fmt.Println(strings.Repeat("─", 78))
}

func (d *demo) act(title string) {
	if d.quiet {
		return
	}
	fmt.Printf("\n\033[1m%s\033[0m\n", title)
}

func (d *demo) note(format string, args ...any) {
	if d.quiet {
		return
	}
	fmt.Printf("  %s\n", fmt.Sprintf(format, args...))
}

// verdict prints one scan the way a gate would show it: the colour first, then the
// sentence, then the evidence.
func (d *demo) verdict(where string, result engine.Result) {
	if d.quiet {
		return
	}
	colour := map[engine.Severity]string{
		engine.SeverityAdmit:    "\033[42;30m ADMIT \033[0m",
		engine.SeverityDeny:     "\033[41;97m DENY  \033[0m",
		engine.SeverityRedirect: "\033[43;30m AMBER \033[0m",
	}[result.Severity]

	line := fmt.Sprintf("  %s  %-14s %-22s %s", colour, where, result.Verdict, result.Reason)
	fmt.Println(line)

	if result.Verdict == engine.Admit {
		detail := []string{}
		if result.TierName != "" {
			detail = append(detail, result.TierName)
		}
		if result.SeatLabel != "" {
			detail = append(detail, result.SeatLabel)
		}
		if result.ZoneName != "" {
			detail = append(detail, "into "+result.ZoneName)
		}
		if result.PassesLeft != nil {
			detail = append(detail, fmt.Sprintf("%d left", *result.PassesLeft))
		}
		if len(detail) > 0 {
			fmt.Printf("                 %s\n", strings.Join(detail, "  ·  "))
		}
		return
	}
	if result.Previous != nil {
		fmt.Printf("                 already in at %s, %s\n", result.Previous.CheckpointName, result.Ago)
	}
	if len(result.Missing) > 0 {
		fmt.Printf("                 needs %v first\n", result.Missing)
	}
	if len(result.Redirect) > 0 {
		names := make([]string, 0, len(result.Redirect))
		for _, redirect := range result.Redirect {
			names = append(names, redirect.Name)
		}
		fmt.Printf("                 send them to %s\n", strings.Join(names, " or "))
	}
	if result.Idempotent {
		fmt.Printf("                 (this was a retry of an earlier scan, not a new one)\n")
	}
	if result.Flagged {
		fmt.Printf("                 flagged as a double use on the security feed\n")
	}
}

// HTTP helpers. Everything the demo does goes through these, against the same
// handlers the box serves in production.

func (d *demo) request(method, path, token string, body, into any) error {
	var reader io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, d.server.URL+path, reader)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(raw)))
	}
	if into == nil {
		return nil
	}
	return json.Unmarshal(raw, into)
}

// scan drives one scan through the real endpoint.
func (d *demo) scan(gate, payload string, checkpoint venue.CheckpointCode) (engine.Result, error) {
	return d.scanWith(gate, httpapi.ScanRequest{
		ScanID: ticket.MustNewID().Hex(), Payload: payload, Checkpoint: checkpoint,
	})
}

func (d *demo) scanWith(gate string, req httpapi.ScanRequest) (engine.Result, error) {
	var result engine.Result
	err := d.request(http.MethodPost, "/v1/scan", d.tokens[gate], req, &result)
	return result, err
}

// enrollGate runs the whole ceremony: the organizer issues a code, the QR is
// decoded as a phone would, and the phone redeems it.
func (d *demo) enrollGate(name string, checkpoints ...venue.CheckpointCode) error {
	var invite httpapi.InviteResponse
	if err := d.request(http.MethodPost, "/v1/admin/invite", d.admin,
		httpapi.InviteRequest{Checkpoints: checkpoints, Name: name}, &invite); err != nil {
		return err
	}

	// Decoded rather than read straight out of the response, because this is the
	// step a phone actually performs and the payload format is part of the
	// contract.
	decoded, err := enroll.DecodeInvite(invite.QR)
	if err != nil {
		return err
	}

	var enrolled httpapi.EnrollResponse
	if err := d.request(http.MethodPost, "/v1/enroll", "",
		httpapi.EnrollRequest{Code: decoded.Code, Name: name}, &enrolled); err != nil {
		return err
	}
	d.tokens[name] = enrolled.Token

	lanes := make([]string, 0, len(enrolled.Assignments))
	for _, assignment := range enrolled.Assignments {
		lanes = append(lanes, fmt.Sprintf("%s → %s", assignment.Name, assignment.ZoneName))
	}
	d.note("%-12s %s  (%s)", name, enrolled.DeviceID, strings.Join(lanes, ", "))
	return nil
}

// verifyChain replays the audit log, which is the thing an auditor does.
func (d *demo) verifyChain() (int, error) {
	rows, err := d.store.AuditRows(context.Background(), 1, 0)
	if err != nil {
		return 0, err
	}
	return len(rows), audit.Verify(rows)
}
