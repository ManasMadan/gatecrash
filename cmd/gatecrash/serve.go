package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ManasMadan/gatecrash/internal/beacon"
	"github.com/ManasMadan/gatecrash/internal/config"
	"github.com/ManasMadan/gatecrash/internal/dhcp"
	"github.com/ManasMadan/gatecrash/internal/dnsd"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/enroll"
	"github.com/ManasMadan/gatecrash/internal/httpapi"
	"github.com/ManasMadan/gatecrash/internal/incident"
	"github.com/ManasMadan/gatecrash/internal/logx"
	"github.com/ManasMadan/gatecrash/internal/manifest"
	"github.com/ManasMadan/gatecrash/internal/mdns"
	"github.com/ManasMadan/gatecrash/internal/pki"
	"github.com/ManasMadan/gatecrash/internal/portal"
	"github.com/ManasMadan/gatecrash/internal/ssehub"
	"github.com/ManasMadan/gatecrash/internal/stats"
	"github.com/ManasMadan/gatecrash/internal/store"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
	"github.com/ManasMadan/gatecrash/internal/version"
	"github.com/ManasMadan/gatecrash/internal/watchdog"
	"github.com/ManasMadan/gatecrash/internal/webassets"
)

// serve runs the box.
func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "path to the configuration file")
	dataDir := flags.String("data", "", "override the data directory")
	listen := flags.String("listen", "", "override the HTTPS listen address")
	mode := flags.String("mode", "", "networking mode: router or ap")
	manifestPath := flags.String("manifest", "", "load this manifest at boot")
	logLevel := flags.String("log", "", "log level: debug, info, warn, error")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	// Flags win over the file and the environment, because a flag is somebody
	// standing in front of the hardware on the day.
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *mode != "" {
		cfg.Mode = config.Mode(*mode)
	}
	if *manifestPath != "" {
		cfg.Manifest = *manifestPath
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	log := logx.New(logx.Options{Level: cfg.LogLevel, JSON: cfg.LogJSON})
	log.Info("gatecrash starting", "build", version.String(), "mode", cfg.Mode, "data", cfg.DataDir)

	ctx, stop := signalContext()
	defer stop()

	box, err := open(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer box.close()

	return box.run(ctx)
}

// defaultConfigPath is where the box looks for its configuration.
func defaultConfigPath() string {
	if value := os.Getenv("GATECRASH_CONFIG"); value != "" {
		return value
	}
	return "/etc/gatecrash/config.json"
}

// box is the assembled runtime.
type box struct {
	cfg config.Config
	log *slog.Logger

	store    *store.Store
	engine   *engine.Engine
	venue    *venue.Venue
	stats    *stats.Tracker
	board    *incident.Board
	registry *enroll.Registry
	hub      *ssehub.Hub
	ca       *pki.Authority
	api      *httpapi.API
	notify   *watchdog.Notifier

	addrs      []netip.Addr
	adminToken string
	event      manifest.Event
}

// open assembles the box.
//
// The order matters and is the reverse of how it reads: storage first because
// everything else needs it, then the manifest because the venue comes out of it,
// then the engine because it needs the venue, then the network because it
// advertises what the engine is serving. A box that came up in a different order
// would advertise a gate that cannot yet decide anything.
func open(ctx context.Context, cfg config.Config, log *slog.Logger) (*box, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", cfg.DataDir, err)
	}

	b := &box{cfg: cfg, log: log}

	opened, err := store.Open(ctx, store.Options{
		Path: cfg.DatabasePath(), Synchronous: cfg.Synchronous,
	})
	if err != nil {
		return nil, err
	}
	b.store = opened

	// The integrity check runs at every boot, not just after a suspected problem.
	// The box lives on media that corrupts on power loss, and the difference
	// between finding out at startup and finding out at 8pm with a queue outside is
	// the difference between swapping in the spare Pi and cancelling the show.
	if err := opened.IntegrityCheck(ctx); err != nil {
		return nil, fmt.Errorf("the database did not pass its integrity check: %w", err)
	}
	log.Info("database ready", "path", cfg.DatabasePath(), "synchronous", cfg.Synchronous)

	b.addrs = resolveAddresses(cfg, log)
	if len(b.addrs) == 0 {
		return nil, errors.New("no usable network address; set advertise in the config")
	}

	body, digest, err := b.loadManifest(ctx)
	if err != nil {
		return nil, err
	}
	b.event = body.Event

	compiled, err := venue.Compile(body.Venue)
	if err != nil {
		return nil, fmt.Errorf("compiling the venue: %w", err)
	}
	b.venue = compiled

	master, err := body.MasterKey()
	if err != nil {
		return nil, err
	}
	if master.IsZero() {
		log.Warn("no event master key: rotating in-app codes are unavailable, printed tickets only")
	} else {
		log.Info("event master key loaded", "fingerprint", master.Redacted())
	}

	b.engine, err = engine.New(engine.Config{
		EventID:   body.Event.ID,
		Venue:     compiled,
		Verifying: body.Verifying,
		Master:    master,
		Mode:      body.Event.Mode,
	})
	if err != nil {
		return nil, err
	}
	if err := b.engine.Recover(ctx, opened); err != nil {
		return nil, err
	}
	head, rows := b.engine.AuditHead()
	log.Info("redemption engine ready", "mode", b.engine.Mode(), "audit_rows", rows, "audit_head", head)

	b.ca, err = pki.Load(pki.Config{
		Dir: cfg.PKIDir(), EventName: body.Event.Name,
		Names: []string{cfg.Hostname + ".local", cfg.Hostname}, Addrs: b.addrs,
	})
	if err != nil {
		return nil, err
	}
	log.Info("certificate authority ready",
		"fingerprint", b.ca.ShortFingerprint(), "expires", b.ca.LeafExpiry().Format(time.RFC3339))

	b.hub = ssehub.New(log)
	b.stats = stats.New(stats.Config{Venue: compiled})

	total, byTier, err := opened.TicketCount(ctx)
	if err != nil {
		return nil, err
	}
	tiers := make(map[venue.TierCode]int, len(byTier))
	for tier, count := range byTier {
		tiers[venue.TierCode(tier)] = count
	}
	b.stats.SetIssued(total, tiers)
	log.Info("manifest loaded", "tickets", total, "digest", digest,
		"zones", len(body.Venue.Zones), "checkpoints", len(body.Venue.Checkpoints))

	// Rebuild the live picture from the log.
	//
	// The tracker is in memory and the box is expected to lose power, so without
	// this a reboot brings the dashboard back reading "Inside 0" with the field
	// full — the redemptions are safe in SQLite, but the occupancy number a safety
	// officer reads off the wall has been silently reset. A wrong number that looks
	// authoritative is worse than a missing one.
	//
	// One indexed pass at boot, before the listeners are up, so no scan can
	// interleave with the replay and be counted twice.
	if history, err := opened.DecisionHistory(ctx); err != nil {
		// Not fatal. A box that refuses to boot because it could not rebuild a
		// display number is a box that has turned a cosmetic problem into a closed
		// gate. The counts start from zero and the log says why.
		log.Error("rebuilding the live picture", "error", err)
	} else {
		for _, result := range history {
			// The zone comes from the venue plan rather than the log, so a replay
			// and a live scan derive it the same way. See DecisionHistory.
			if cp, ok := compiled.Checkpoint(result.Checkpoint); ok {
				result.Zone = cp.Zone
			}
			b.stats.Rehydrate(result)
		}
		if len(history) > 0 {
			log.Info("live picture rebuilt", "decisions", len(history),
				"inside", b.stats.Snapshot().Inside)
		}
	}

	b.board = incident.NewBoard(incident.BoardConfig{
		Venue: compiled,
		Persist: func(i incident.Incident) {
			// Best effort: an incident that fails to persist is still live in
			// memory and still on the dashboard. Failing the raise because the
			// database was busy would lose the alarm entirely, which is worse.
			if err := opened.PutIncident(context.Background(), i); err != nil {
				log.Error("persisting an incident", "id", i.ID, "error", err)
			}
		},
	})
	if restored, err := opened.Incidents(ctx); err != nil {
		log.Error("restoring incidents", "error", err)
	} else if len(restored) > 0 {
		b.board.Restore(restored)
		log.Info("incidents restored", "count", len(restored), "live", len(b.board.Live()))
	}

	secret, err := b.enrollSecret()
	if err != nil {
		return nil, err
	}
	b.registry, err = enroll.New(enroll.Config{Secret: secret})
	if err != nil {
		return nil, err
	}
	if devices, err := opened.Devices(ctx); err != nil {
		log.Error("restoring devices", "error", err)
	} else {
		for _, device := range devices {
			b.stats.NameDevice(device.ID, device.Name)
		}
		log.Info("scanner roster loaded", "devices", len(devices))
	}

	boxKey, err := b.boxKey()
	if err != nil {
		return nil, err
	}

	b.adminToken = cfg.AdminToken
	if b.adminToken == "" {
		if b.adminToken, err = b.persistedAdminToken(); err != nil {
			return nil, err
		}
	}

	portalURL := fmt.Sprintf("http://%s%s/portal", b.addrs[0], portForDisplay(cfg.ListenPlain))
	interceptor := portal.New(portal.Config{
		PortalURL: portalURL,
		VenueName: body.Event.Name,
		// Interception is only correct on a network the box owns. Doing it in
		// router mode would be hijacking somebody else's network.
		Enabled: cfg.Mode == config.AP,
		Logger:  log,
	})

	// systemd's notification socket, if there is one. Absent everywhere except a
	// systemd unit, and a no-op there, so no caller has to check.
	if b.notify, err = watchdog.New(); err != nil {
		// Not fatal. A box that refuses to start because it could not reach a
		// supervision socket is a box that will not open a gate over a monitoring
		// detail.
		log.Warn("could not reach the systemd notification socket", "error", err)
		b.notify = &watchdog.Notifier{}
	}

	b.api, err = httpapi.New(httpapi.Deps{
		Engine: b.engine, Store: opened, Venue: compiled, Stats: b.stats,
		Board: b.board, Registry: b.registry, Hub: b.hub, CA: b.ca, Portal: interceptor,
		Event: body.Event, Master: master, BoxKey: boxKey,
		AdminToken: b.adminToken,
		BoxURL:     fmt.Sprintf("https://%s%s", b.addrs[0], portForDisplay(cfg.Listen)),
		Assets:     webassets.Handler(log),
		Logger:     log,
	})
	if err != nil {
		return nil, err
	}

	if err := opened.OpenSession(ctx, time.Now()); err != nil {
		log.Error("recording the session start", "error", err)
	}
	return b, nil
}

// loadManifest reads the configured manifest, or falls back to whatever the
// database already holds.
//
// The fallback is what makes a reboot mid-event work: the manifest was ingested
// before doors and the box does not need the file again. A box with neither is a
// box waiting to be set up, and it says so rather than refusing to start — an
// operator needs the dashboard to be reachable in order to set it up.
func (b *box) loadManifest(ctx context.Context) (manifest.Body, string, error) {
	if b.cfg.Manifest == "" {
		return b.manifestFromStore(ctx)
	}

	raw, err := os.ReadFile(b.cfg.Manifest)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			b.log.Warn("the configured manifest does not exist, using what is already loaded",
				"path", b.cfg.Manifest)
			return b.manifestFromStore(ctx)
		}
		return manifest.Body{}, "", fmt.Errorf("reading %s: %w", b.cfg.Manifest, err)
	}

	envelope, err := b.openEnvelope(raw)
	if err != nil {
		return manifest.Body{}, "", err
	}
	if b.cfg.OrganizerFingerprint == "" {
		// A manifest verified against a key taken from the same file is not
		// verified, it is merely self-consistent. Fine for a demo, wrong for an
		// event, and the log says so at a level somebody will notice.
		b.log.Warn("no organizer fingerprint configured: the manifest is only checked for self-consistency")
	}

	body, err := manifest.Verify(envelope, ticket.VerifyingKey{}, b.cfg.OrganizerFingerprint)
	if err != nil {
		return manifest.Body{}, "", fmt.Errorf("verifying %s: %w", b.cfg.Manifest, err)
	}

	digest := envelope.Digest()
	if err := b.store.Ingest(ctx, body, digest); err != nil {
		if errors.Is(err, manifest.ErrStale) {
			// A stale file on a USB stick must not roll back a revocation, and it
			// must not stop the box from booting on the manifest it already has.
			b.log.Warn("the manifest on disk is older than the one loaded, keeping the loaded one",
				"path", b.cfg.Manifest)
			return b.manifestFromStore(ctx)
		}
		return manifest.Body{}, "", err
	}
	summary := body.Summarise()
	b.log.Info("manifest ingested", "event", summary.Event, "tickets", summary.Tickets,
		"sequence", summary.Sequence, "digest", digest, "organizer", summary.Fingerprint)
	return body, digest, nil
}

// openEnvelope parses a manifest file, unsealing it when it is sealed.
func (b *box) openEnvelope(raw []byte) (manifest.Envelope, error) {
	if envelope, err := manifest.Unmarshal(raw); err == nil && envelope.Format == manifest.Format {
		return envelope, nil
	}

	var sealed manifest.Sealed
	if err := json.Unmarshal(raw, &sealed); err != nil || sealed.Format != manifest.SealFormat {
		return manifest.Envelope{}, fmt.Errorf("%s is neither a manifest nor a sealed manifest", b.cfg.Manifest)
	}
	if b.cfg.ManifestPassphrase == "" {
		return manifest.Envelope{}, errors.New(
			"the manifest is sealed; set GATECRASH_MANIFEST_PASSPHRASE")
	}
	return manifest.Open(sealed, b.cfg.ManifestPassphrase)
}

// manifestFromStore rebuilds enough of a manifest body from the database to run
// on, for a box that has already been set up.
func (b *box) manifestFromStore(ctx context.Context) (manifest.Body, string, error) {
	digest, _, err := b.store.Meta(ctx, store.MetaManifestDigest)
	if err != nil {
		return manifest.Body{}, "", err
	}
	if digest == "" {
		return manifest.Body{}, "", errors.New(
			"no manifest loaded: run `gatecrash ingest <manifest>` or set manifest in the config")
	}
	// Reconstructing the venue and the keys from the database is not something the
	// store is shaped for, so the box keeps the last verified body beside it. This
	// is the one piece of state that lives in a file rather than in SQLite,
	// because it is the input to everything else and it has to be readable before
	// the schema is trusted.
	raw, err := os.ReadFile(filepath.Join(b.cfg.DataDir, "manifest.json"))
	if err != nil {
		return manifest.Body{}, "", fmt.Errorf(
			"a manifest was ingested but its cached copy is missing: %w", err)
	}
	envelope, err := manifest.Unmarshal(raw)
	if err != nil {
		return manifest.Body{}, "", err
	}
	body, err := manifest.Verify(envelope, ticket.VerifyingKey{}, b.cfg.OrganizerFingerprint)
	if err != nil {
		return manifest.Body{}, "", err
	}
	return body, digest, nil
}

// enrollSecret loads or creates the enrollment registry's HMAC secret.
//
// A file of its own rather than a derivation from the CA key, because the CA can
// legitimately be re-minted after a disaster and doing so must not log every
// enrolled scanner out.
func (b *box) enrollSecret() ([]byte, error) {
	path := b.cfg.SecretPath()
	if raw, err := os.ReadFile(path); err == nil && len(raw) >= 32 {
		return raw, nil
	}

	secret := make([]byte, 32)
	if _, err := randRead(secret); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	b.log.Info("generated a new enrollment secret", "path", path)
	return secret, nil
}

// persistedAdminToken loads the dashboard token from the data directory, minting
// one on first boot.
//
// It has to survive a restart. The box is a Raspberry Pi in a cupboard behind a
// bar, and losing power is a designed-for event rather than an exceptional one — so
// a token regenerated on every boot means a power cut signs out every dashboard on
// the wall and leaves the replacement in a log file nobody at the desk can reach.
// Persisting it makes a reboot invisible to the control room, which is the whole
// point of a box that recovers on its own.
//
// Still never in the repo and never a default: it is minted from the system CSPRNG
// on first boot, kept 0600 in the data directory, and printed at boot so the
// organizer can pick it up. Rotating it is deleting the file, and setting
// GATECRASH_ADMIN_TOKEN overrides all of this.
func (b *box) persistedAdminToken() (string, error) {
	path := filepath.Join(b.cfg.DataDir, "admin-token")
	if raw, err := os.ReadFile(path); err == nil {
		if token := strings.TrimSpace(string(raw)); token != "" {
			return token, nil
		}
		// An empty file is a truncated write from a power cut mid-boot. Mint a new
		// one rather than booting with no usable dashboard.
		b.log.Warn("admin token file was empty, minting a new one", "path", path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	token, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return token, nil
}

// boxKey loads or creates the box's own signing key, used for the attendance
// report.
func (b *box) boxKey() (ticket.SigningKey, error) {
	path := b.cfg.KeyPath()
	if raw, err := os.ReadFile(path); err == nil {
		key, err := ticket.ParseSigningKey(strings.TrimSpace(string(raw)))
		if err != nil {
			return ticket.SigningKey{}, fmt.Errorf("reading %s: %w", path, err)
		}
		return key, nil
	}

	key, public, err := ticket.GenerateSigningKey()
	if err != nil {
		return ticket.SigningKey{}, err
	}
	if err := os.WriteFile(path, []byte(key.String()+"\n"), 0o600); err != nil {
		return ticket.SigningKey{}, fmt.Errorf("writing %s: %w", path, err)
	}
	b.log.Info("generated a box signing key", "fingerprint", public.Fingerprint(),
		"note", "publish this fingerprint so the attendance report can be verified")
	return key, nil
}

// idle reports whether a box with no recent scans is legitimately quiet.
//
// Before doors open, and after curfew, there is nothing to serve and the box is
// perfectly healthy. Between those, silence from every gate at once is far more
// likely to be this process than twelve scanners simultaneously going quiet — so
// outside the session window the box is idle, and inside it a lack of scans is
// allowed to look like a hang.
func (b *box) idle() bool {
	now := time.Now()
	doors, curfew := b.event.Doors, b.event.Curfew
	if doors.IsZero() || curfew.IsZero() {
		// An event with no declared hours never claims to be busy, because there is
		// no window to be inside of.
		return true
	}
	return now.Before(doors) || now.After(curfew)
}

// markProgress tells the watchdog the box is still doing work.
//
// Measured from the committed scan count rather than from the request handler, and
// that is the point: a handler that has been entered proves a goroutine was
// scheduled, while a scan count that advanced proves a decision was made, written
// and chained. If the store's writer deadlocks, requests keep arriving and the count
// stops moving — which is exactly the failure a supervisor needs to see.
func (b *box) markProgress(ctx context.Context) error {
	interval := b.notify.Interval() / 3
	if interval <= 0 {
		<-ctx.Done()
		return nil
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	previous := b.stats.Snapshot().Scans
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if current := b.stats.Snapshot().Scans; current != previous {
				previous = current
				b.notify.Alive()
			}
		}
	}
}

// reportStatus keeps the line shown by `systemctl status` current.
//
// Over SSH this is the only tool available when the thing that has broken is the
// dashboard, so it carries the numbers somebody would otherwise open a browser for.
func (b *box) reportStatus(ctx context.Context) error {
	if !b.notify.Enabled() {
		<-ctx.Done()
		return nil
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			live := b.stats.Snapshot()
			gates := 0
			for _, gate := range live.Gates {
				if gate.Admitted > 0 || gate.Denied > 0 {
					gates++
				}
			}
			if err := b.notify.Status(fmt.Sprintf(
				"%d inside of %d · %d gates scanning · %d refused",
				live.Inside, live.Issued, gates, live.Denied,
			)); err != nil {
				b.log.Debug("status notification failed", "error", err)
			}
		}
	}
}

// run starts every service and blocks until the context is cancelled.
func (b *box) run(ctx context.Context) error {
	var wg sync.WaitGroup

	// Every service is started the same way: a goroutine that logs its own failure
	// and returns. None of them are fatal on their own — a box with no mDNS still
	// runs an event through the rest of the discovery ladder — so a failure here is
	// a warning, not an exit.
	start := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx); err != nil && ctx.Err() == nil {
				b.log.Error("service stopped", "service", name, "error", err)
			}
		}()
	}

	start("https", func(ctx context.Context) error { return b.api.Serve(ctx, b.cfg.Listen) })
	if b.cfg.ListenPlain != "" {
		start("http", func(ctx context.Context) error { return b.api.ServePlain(ctx, b.cfg.ListenPlain) })
	}
	if b.cfg.MDNS {
		start("mdns", b.serveMDNS)
	}
	if b.cfg.Beacon {
		start("beacon", b.serveBeacon)
	}
	if b.cfg.Mode == config.AP {
		start("dns", b.serveDNS)
		start("dhcp", b.serveDHCP)
	}
	start("sealer", b.sealPeriodically)
	start("gates", b.watchGates)

	// The systemd heartbeat. Driven by the scan path rather than by a timer, so a box
	// that is running but no longer answering scans stops pinging and gets restarted
	// — see internal/watchdog. Started before Ready so that no deadline is missed
	// during a slow first manifest load.
	start("heartbeat", func(ctx context.Context) error {
		return b.notify.Run(ctx, b.idle)
	})
	start("liveness", b.markProgress)
	start("status", b.reportStatus)

	b.announceReady()

	// READY=1 goes out here and not at the top of main: with Type=notify, systemd
	// holds dependent units until it arrives, so sending it earlier would mean
	// "ready" described a process that could not yet answer a scan.
	if err := b.notify.Ready(); err != nil {
		b.log.Warn("could not notify systemd", "error", err)
	}

	<-ctx.Done()
	b.log.Info("shutting down")

	// Told deliberately, so that a planned stop and a crash are distinguishable in
	// the journal afterwards. Somebody will be asking which one happened at 23:14.
	if err := b.notify.Stopping(); err != nil {
		b.log.Warn("could not notify systemd of shutdown", "error", err)
	}
	b.hub.Close()

	// Flush the WAL into the database before the process exits, so a naive file
	// copy of the database afterwards is complete. This is the single most common
	// way people lose data with SQLite.
	if err := b.store.Checkpoint(context.Background()); err != nil {
		b.log.Error("checkpointing the wal", "error", err)
	}
	if err := b.store.CloseSession(context.Background(), time.Now()); err != nil {
		b.log.Error("recording the session end", "error", err)
	}

	wg.Wait()
	b.log.Info("stopped")
	return nil
}

// announceReady prints the operator's cheat sheet.
//
// Printed rather than logged at debug, because this is the one moment somebody is
// definitely looking at the console: they have just plugged the box in and they
// need the dashboard URL and the token.
func (b *box) announceReady() {
	fmt.Fprintf(os.Stderr, "\n  %s is live\n\n", b.event.Name)
	for _, addr := range b.addrs {
		fmt.Fprintf(os.Stderr, "    scanner    https://%s%s/scanner/\n", addr, portForDisplay(b.cfg.Listen))
	}
	fmt.Fprintf(os.Stderr, "    attendee   https://%s%s/attendee/\n", b.addrs[0], portForDisplay(b.cfg.Listen))
	fmt.Fprintf(os.Stderr, "    dashboard  https://%s%s/dashboard/?token=%s\n",
		b.addrs[0], portForDisplay(b.cfg.Listen), b.adminToken)
	fmt.Fprintf(os.Stderr, "    friendly   http://%s.local%s  ·  http://go.gate\n",
		b.cfg.Hostname, portForDisplay(b.cfg.Listen))
	fmt.Fprintf(os.Stderr, "\n    certificate fingerprint  %s\n", b.ca.Fingerprint())
	fmt.Fprintf(os.Stderr, "    install it from          http://%s%s/ca.crt\n\n",
		b.addrs[0], portForDisplay(b.cfg.ListenPlain))
}

// close releases the box's resources.
func (b *box) close() {
	if b.store != nil {
		if err := b.store.Close(); err != nil {
			b.log.Error("closing the database", "error", err)
		}
	}
}

// serveMDNS runs the multicast responder.
func (b *box) serveMDNS(ctx context.Context) error {
	var v4, v6 []netip.Addr
	for _, addr := range b.addrs {
		if addr.Is4() {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}

	responder, err := mdns.New(mdns.Config{
		Service: mdns.Service{
			Instance: b.event.Name,
			Host:     b.cfg.Hostname,
			Port:     portNumber(b.cfg.Listen, 8443),
			IPv4:     v4,
			IPv6:     v6,
			// The TXT record is what lets a scanner pin the box's certificate
			// without a separate round trip, and refuse a box belonging to
			// somebody else's event.
			TXT: []string{
				"api=" + version.APIVersion,
				"event=" + b.event.Name,
				"fp=" + b.ca.ShortFingerprint(),
				"mode=" + string(b.engine.Mode()),
			},
		},
		Logger: b.log,
	})
	if err != nil {
		return err
	}
	return responder.Run(ctx)
}

// serveBeacon runs the UDP broadcast.
func (b *box) serveBeacon(ctx context.Context) error {
	broadcaster := &beacon.Broadcaster{
		Logger: b.log,
		Announce: func() beacon.Announcement {
			// Built per broadcast rather than stored, because the sequence changes
			// while the box runs and a beacon carrying a stale one tells a scanner
			// its mirror is fresh when it is not.
			seq, err := b.store.LatestSeq(context.Background())
			if err != nil {
				b.log.Debug("beacon: reading sequence", "error", err)
			}
			return beacon.Announcement{
				Event:                b.event.Name,
				EventID:              b.event.ID.Hex(),
				Address:              b.addrs[0].String(),
				Port:                 portNumber(b.cfg.Listen, 8443),
				CAFingerprint:        b.ca.ShortFingerprint(),
				OrganizerFingerprint: b.cfg.OrganizerFingerprint,
				API:                  version.APIVersion,
				Mode:                 string(b.engine.Mode()),
				Seq:                  seq,
			}
		},
	}
	return broadcaster.Run(ctx)
}

// serveDNS runs the wildcard resolver, AP mode only.
func (b *box) serveDNS(ctx context.Context) error {
	server, err := dnsd.New(dnsd.Config{
		Box:      b.cfg.BoxIP,
		Names:    []string{b.cfg.Hostname, b.cfg.Hostname + ".local"},
		Wildcard: true,
		Upstream: b.cfg.Upstream,
		Logger:   b.log,
	})
	if err != nil {
		return err
	}
	return server.ListenAndServe(ctx, fmt.Sprintf(":%d", b.cfg.DNSPort))
}

// serveDHCP runs the lease server, AP mode only.
func (b *box) serveDHCP(ctx context.Context) error {
	server, err := dhcp.New(dhcp.Config{
		Box:        b.cfg.BoxIP,
		Subnet:     b.cfg.Subnet,
		DomainName: b.cfg.Hostname,
		// RFC 8910. A client that reads this goes straight to the portal and none
		// of the probe-interception guesswork is needed.
		PortalURL: fmt.Sprintf("http://%s%s/portal", b.cfg.BoxIP, portForDisplay(b.cfg.ListenPlain)),
		Logger:    b.log,
	})
	if err != nil {
		return err
	}
	return server.ListenAndServe(ctx, b.cfg.Iface)
}

// sealPeriodically seals a Merkle checkpoint on a timer.
//
// On a timer as well as at close, so a box that loses power mid-event still has a
// recent published root. Sealing costs a few milliseconds of hashing and happens
// between scans.
func (b *box) sealPeriodically(ctx context.Context) error {
	ticker := time.NewTicker(b.cfg.SealEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// One last seal on the way out, so the published root covers the whole
			// event rather than up to the last tick.
			if sealed, err := b.store.Seal(context.Background(), b.engine.Clock().Now()); err != nil {
				b.log.Error("final seal", "error", err)
			} else {
				b.log.Info("audit log sealed", "rows", sealed.Rows, "root", sealed.Root)
			}
			return nil
		case <-ticker.C:
			sealed, err := b.store.Seal(ctx, b.engine.Clock().Now())
			if err != nil {
				b.log.Error("periodic seal", "error", err)
				continue
			}
			b.log.Debug("audit log sealed", "rows", sealed.Rows, "root", sealed.Root)
		}
	}
}

// watchGates raises the box's own alarms.
//
// The point of this loop is that the control room finds out about a problem
// without anybody having to notice it first: a gate that has gone quiet, a zone
// over capacity. Both are conditions an operator watching a wall display would
// eventually spot, and "eventually" is the failure.
func (b *box) watchGates(ctx context.Context) error {
	const interval = 30 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Raised-once tracking, so a zone that stays over capacity produces one alarm
	// rather than one every thirty seconds. An alarm that repeats is an alarm
	// people mute.
	reported := make(map[string]bool)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			snapshot := b.stats.Snapshot()

			for _, zone := range snapshot.Zones {
				key := "capacity:" + string(zone.Code)
				if !zone.Over {
					delete(reported, key)
					continue
				}
				if reported[key] {
					continue
				}
				reported[key] = true
				b.raise(incident.Report{
					Kind: incident.OverCapacity,
					Note: fmt.Sprintf("%s is at %d of %d.", zone.Name, zone.Occupied, zone.Capacity),
				})
			}

			for _, gate := range snapshot.Gates {
				key := "quiet:" + string(gate.Code)
				if !gate.Quiet {
					delete(reported, key)
					continue
				}
				if reported[key] {
					continue
				}
				reported[key] = true
				b.raise(incident.Report{
					Kind:       incident.GateOffline,
					Checkpoint: gate.Code,
					Note:       gate.Name + " was working and has not scanned anything for a while.",
				})
			}
		}
	}
}

// raise records one of the box's own signals.
func (b *box) raise(report incident.Report) {
	raised, err := b.board.Raise(report)
	if err != nil {
		b.log.Debug("automatic incident refused", "kind", report.Kind, "error", err)
		return
	}
	b.log.Warn("box raised an incident", "id", raised.ID, "kind", raised.Kind, "note", raised.Note)
	b.hub.Publish(ssehub.Event{Kind: "incident", Seq: raised.Seq, Data: raised})
}

// resolveAddresses works out what to advertise.
//
// Loopback and link-local are skipped: a scanner told to connect to 127.0.0.1 will
// connect to itself, which is a memorably confusing failure. An explicitly
// configured list wins, because a venue with several networks has to be told which
// one the scanners are on.
func resolveAddresses(cfg config.Config, log *slog.Logger) []netip.Addr {
	if len(cfg.Advertise) > 0 {
		return cfg.Advertise
	}
	if cfg.Mode == config.AP {
		return []netip.Addr{cfg.BoxIP}
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Error("listing interfaces", "error", err)
		return nil
	}

	var out []netip.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			parsed, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			parsed = parsed.Unmap()
			if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsMulticast() {
				continue
			}
			out = append(out, parsed)
		}
	}
	// IPv4 first: every device on a venue network speaks it, and a scanner handed
	// an IPv6 address on a link with no IPv6 routing fails in a way nobody can
	// diagnose from the gate.
	sortIPv4First(out)
	return out
}

func sortIPv4First(addrs []netip.Addr) {
	for i := 1; i < len(addrs); i++ {
		for j := i; j > 0 && addrs[j].Is4() && !addrs[j-1].Is4(); j-- {
			addrs[j], addrs[j-1] = addrs[j-1], addrs[j]
		}
	}
}

// portForDisplay renders a listen address's port for a URL, omitting the default.
func portForDisplay(listen string) string {
	_, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" || port == "443" || port == "80" {
		return ""
	}
	return ":" + port
}

// portNumber extracts a listen address's port.
func portNumber(listen string, fallback uint16) uint16 {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fallback
	}
	var value uint16
	for _, r := range port {
		if r < '0' || r > '9' {
			return fallback
		}
		value = value*10 + uint16(r-'0')
	}
	if value == 0 {
		return fallback
	}
	return value
}
