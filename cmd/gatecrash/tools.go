package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/config"
	"github.com/ManasMadan/gatecrash/internal/logx"
	"github.com/ManasMadan/gatecrash/internal/manifest"
	"github.com/ManasMadan/gatecrash/internal/pki"
	"github.com/ManasMadan/gatecrash/internal/store"
	"github.com/ManasMadan/gatecrash/internal/ticket"
)

// ingest loads a manifest into the box's database and exits.
//
// A separate command from serve because setting an event up and running it are
// different jobs, done at different times, often by different people. Doing it
// offline also means the manifest can be verified and the errors read before
// anybody is standing at a gate.
func ingest(args []string) error {
	flags := flag.NewFlagSet("ingest", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "path to the configuration file")
	passphrase := flags.String("passphrase", "", "passphrase for a sealed manifest")
	fingerprint := flags.String("fingerprint", "", "the organizer key fingerprint to require")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: gatecrash ingest [flags] <manifest.json>")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *fingerprint != "" {
		cfg.OrganizerFingerprint = *fingerprint
	}
	if *passphrase != "" {
		cfg.ManifestPassphrase = *passphrase
	}
	log := logx.New(logx.Options{Level: cfg.LogLevel})

	raw, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		return fmt.Errorf("reading %s: %w", flags.Arg(0), err)
	}

	envelope, err := parseManifestFile(raw, cfg.ManifestPassphrase)
	if err != nil {
		return err
	}
	if cfg.OrganizerFingerprint == "" {
		fmt.Fprintln(os.Stderr,
			"warning: no organizer fingerprint, so the manifest is only checked for self-consistency")
	}

	body, err := manifest.Verify(envelope, ticket.VerifyingKey{}, cfg.OrganizerFingerprint)
	if err != nil {
		return err
	}
	summary := body.Summarise()
	// Summarise describes the body; the digest identifies the exact bytes, which
	// only the envelope knows.
	summary.Digest = envelope.Digest()

	ctx := context.Background()
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", cfg.DataDir, err)
	}
	opened, err := store.Open(ctx, store.Options{Path: cfg.DatabasePath(), Synchronous: cfg.Synchronous})
	if err != nil {
		return err
	}
	defer opened.Close()

	if err := opened.Ingest(ctx, body, envelope.Digest()); err != nil {
		return err
	}
	// Cached beside the database so a reboot does not need the original file. The
	// venue graph and the keys live in the manifest, not in the schema, so this is
	// the one piece of state that has to be a file.
	cached, err := envelope.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "manifest.json"), cached, 0o600); err != nil {
		return fmt.Errorf("caching the manifest: %w", err)
	}
	log.Info("manifest ingested", "digest", envelope.Digest())

	out := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(out, "event\t%s\n", summary.Event)
	fmt.Fprintf(out, "organizer\t%s\n", summary.Fingerprint)
	fmt.Fprintf(out, "mode\t%s\n", summary.Mode)
	fmt.Fprintf(out, "sequence\t%d\n", summary.Sequence)
	fmt.Fprintf(out, "digest\t%s\n", summary.Digest)
	fmt.Fprintf(out, "tickets\t%d (%d rotating)\n", summary.Tickets, summary.Rotating)
	fmt.Fprintf(out, "zones\t%d\n", summary.Zones)
	fmt.Fprintf(out, "checkpoints\t%d\n", summary.Checkpoints)
	fmt.Fprintf(out, "sections\t%d (%d seats)\n", summary.Sections, summary.Seats)
	fmt.Fprintf(out, "devices\t%d\n", summary.Devices)
	return out.Flush()
}

// parseManifestFile reads a manifest file, unsealing it when necessary.
func parseManifestFile(raw []byte, passphrase string) (manifest.Envelope, error) {
	if envelope, err := manifest.Unmarshal(raw); err == nil && envelope.Format == manifest.Format {
		return envelope, nil
	}
	var sealed manifest.Sealed
	if err := json.Unmarshal(raw, &sealed); err != nil || sealed.Format != manifest.SealFormat {
		return manifest.Envelope{}, errors.New("that file is neither a manifest nor a sealed manifest")
	}
	if passphrase == "" {
		return manifest.Envelope{}, errors.New(
			"the manifest is sealed; pass -passphrase or set GATECRASH_MANIFEST_PASSPHRASE")
	}
	return manifest.Open(sealed, passphrase)
}

// verify replays the audit chain and reports.
//
// This is the command an auditor runs against a database handed to them by
// somebody they have no reason to trust. It needs no keys, no network and no
// cooperation from the box.
func verify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "path to the configuration file")
	dbPath := flags.String("db", "", "verify this database file directly")
	if err := flags.Parse(args); err != nil {
		return err
	}

	path := *dbPath
	if path == "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		path = cfg.DatabasePath()
	}

	ctx := context.Background()
	opened, err := store.Open(ctx, store.Options{Path: path, Synchronous: "NORMAL"})
	if err != nil {
		return err
	}
	defer opened.Close()

	if err := opened.IntegrityCheck(ctx); err != nil {
		return err
	}
	fmt.Println("database integrity: ok")

	rows, err := opened.AuditRows(ctx, 1, 0)
	if err != nil {
		return err
	}
	if err := audit.Verify(rows); err != nil {
		// A non-zero exit, because this is the answer to a question somebody asked
		// and a script needs to be able to act on it.
		return fmt.Errorf("audit chain: %w", err)
	}
	fmt.Printf("audit chain: ok (%d rows)\n", len(rows))

	sealed, found, err := opened.LatestSeal(ctx)
	if err != nil {
		return err
	}
	if !found {
		fmt.Println("no sealed checkpoint yet")
		return nil
	}
	if err := audit.VerifyCheckpoint(sealed, rows); err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	fmt.Printf("checkpoint: ok\n  rows %d\n  root %s\n  head %s\n", sealed.Rows, sealed.Root, sealed.Head)

	admits := 0
	for _, row := range rows {
		if row.Verdict == "ADMIT" {
			admits++
		}
	}
	fmt.Printf("\nadmissions %d of %d recorded decisions\n", admits, len(rows))
	return nil
}

// export writes the signed attendance report.
func export(args []string) error {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "path to the configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	opened, err := store.Open(ctx, store.Options{Path: cfg.DatabasePath(), Synchronous: cfg.Synchronous})
	if err != nil {
		return err
	}
	defer opened.Close()

	raw, err := os.ReadFile(filepath.Join(cfg.DataDir, "manifest.json"))
	if err != nil {
		return fmt.Errorf("reading the cached manifest: %w", err)
	}
	envelope, err := manifest.Unmarshal(raw)
	if err != nil {
		return err
	}
	body, err := manifest.Verify(envelope, ticket.VerifyingKey{}, cfg.OrganizerFingerprint)
	if err != nil {
		return err
	}

	sealed, err := opened.Seal(ctx, 0)
	if err != nil {
		return err
	}
	opened_, closed, err := opened.SessionWindow(ctx)
	if err != nil {
		return err
	}
	incidents, err := opened.Incidents(ctx)
	if err != nil {
		return err
	}

	report := manifest.Attendance{
		EventID:        body.Event.ID,
		Event:          body.Event.Name,
		ManifestDigest: envelope.Digest(),
		OpenedAt:       opened_,
		ClosedAt:       closed,
		Checkpoint:     sealed,
		Incidents:      incidents,
	}
	if flags2, err := opened.Flags(ctx); err == nil {
		for _, flag := range flags2 {
			report.Flags = append(report.Flags, manifest.Flag{
				TicketID: flag.TicketID,
				Winner:   flag.Winner.Device, WinnerAt: flag.Winner.At,
				Loser: flag.Loser.Device, LoserAt: flag.Loser.At,
				LoserOffline: flag.Loser.Offline,
			})
		}
	}

	keyBytes, err := os.ReadFile(cfg.KeyPath())
	if err != nil {
		return fmt.Errorf("reading the box key: %w", err)
	}
	boxKey, err := ticket.ParseSigningKey(trimSpace(string(keyBytes)))
	if err != nil {
		return err
	}
	signed, err := manifest.SignAttendance(boxKey, report)
	if err != nil {
		return err
	}

	out := os.Stdout
	if flags.NArg() == 1 {
		file, err := os.Create(flags.Arg(0))
		if err != nil {
			return err
		}
		defer file.Close()
		out = file
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(signed); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "signed by %s\n  publish this fingerprint so the report can be verified\n",
		boxKey.Public().Fingerprint())
	return nil
}

// doctor reports on the box's own state.
//
// Written for the person standing next to the hardware twenty minutes before doors
// with a queue forming outside. Everything it prints is something that would
// otherwise be found out the hard way.
func doctor(args []string) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "path to the configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	out := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	defer out.Flush()

	fmt.Fprintf(out, "build\t%s\n", "ok  "+configSummary(cfg))

	opened, err := store.Open(ctx, store.Options{Path: cfg.DatabasePath(), Synchronous: cfg.Synchronous})
	if err != nil {
		fmt.Fprintf(out, "database\tFAIL  %v\n", err)
		return nil
	}
	defer opened.Close()

	if err := opened.IntegrityCheck(ctx); err != nil {
		fmt.Fprintf(out, "database\tFAIL  %v\n", err)
	} else {
		fmt.Fprintf(out, "database\tok  %s\n", cfg.DatabasePath())
	}

	total, byTier, err := opened.TicketCount(ctx)
	if err != nil {
		fmt.Fprintf(out, "manifest\tFAIL  %v\n", err)
	} else if total == 0 {
		fmt.Fprintf(out, "manifest\tEMPTY  no tickets loaded; run `gatecrash ingest`\n")
	} else {
		fmt.Fprintf(out, "manifest\tok  %d tickets across %d tiers\n", total, len(byTier))
	}

	rows, err := opened.AuditRows(ctx, 1, 0)
	if err != nil {
		fmt.Fprintf(out, "audit chain\tFAIL  %v\n", err)
	} else if err := audit.Verify(rows); err != nil {
		fmt.Fprintf(out, "audit chain\tFAIL  %v\n", err)
	} else {
		fmt.Fprintf(out, "audit chain\tok  %d rows\n", len(rows))
	}

	devices, err := opened.Devices(ctx)
	if err != nil {
		fmt.Fprintf(out, "scanners\tFAIL  %v\n", err)
	} else {
		live, revoked := 0, 0
		for _, device := range devices {
			if device.Revoked {
				revoked++
			} else {
				live++
			}
		}
		fmt.Fprintf(out, "scanners\tok  %d enrolled, %d revoked\n", live, revoked)
	}

	authority, err := pki.Load(pki.Config{Dir: cfg.PKIDir(), Addrs: cfg.Advertise})
	if err != nil {
		fmt.Fprintf(out, "certificate\tFAIL  %v\n", err)
	} else {
		remaining := time.Until(authority.LeafExpiry())
		state := "ok"
		if remaining < 7*24*time.Hour {
			// A certificate quietly expiring is a gate that quietly stops working.
			state = "WARN"
		}
		fmt.Fprintf(out, "certificate\t%s  expires in %d days, fingerprint %s\n",
			state, int(remaining.Hours()/24), authority.ShortFingerprint())
	}

	if flagged, err := opened.Flags(ctx); err != nil {
		fmt.Fprintf(out, "double uses\tFAIL  %v\n", err)
	} else if len(flagged) > 0 {
		fmt.Fprintf(out, "double uses\tWARN  %d detected\n", len(flagged))
	} else {
		fmt.Fprintf(out, "double uses\tok  none\n")
	}

	if incidents, err := opened.Incidents(ctx); err == nil {
		open := 0
		for _, found := range incidents {
			if found.Status.Live() {
				open++
			}
		}
		if open > 0 {
			fmt.Fprintf(out, "incidents\tWARN  %d still open\n", open)
		} else {
			fmt.Fprintf(out, "incidents\tok  nothing open\n")
		}
	}

	fmt.Fprintf(out, "free space\t%s\n", diskReport(cfg.DataDir))
	return nil
}

// configSummary is a one-line description of how the box is configured.
func configSummary(cfg config.Config) string {
	return fmt.Sprintf("%s mode, listening on %s, data in %s", cfg.Mode, cfg.Listen, cfg.DataDir)
}

// diskReport describes the free space on the data partition.
//
// Worth a line of its own because a full SD card is the single most common way a
// box fails mid-event, and it fails by refusing to write admissions.
func diskReport(dir string) string {
	free, total, err := diskFree(dir)
	if err != nil {
		return "unknown  " + err.Error()
	}
	if free < 64<<20 {
		return fmt.Sprintf("LOW  %d MiB free of %d MiB", free>>20, total>>20)
	}
	return fmt.Sprintf("ok  %d MiB free of %d MiB", free>>20, total>>20)
}

// trimSpace avoids importing strings for one call.
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// randRead is a seam for the box's key generation, so a test can make it fail.
var randRead = rand.Read
