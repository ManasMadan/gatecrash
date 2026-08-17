package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ManasMadan/gatecrash/internal/config"
)

// TestAdminTokenSurvivesARestart is the whole reason the token is on disk.
//
// The box is a Raspberry Pi behind a bar and losing power is a designed-for event.
// A token minted fresh on every boot would sign out every dashboard on the wall and
// leave its replacement in a log file nobody at the desk can reach.
func TestAdminTokenSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	b := &box{cfg: config.Config{DataDir: dir}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	first, err := b.persistedAdminToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 24 {
		t.Fatalf("token %q is too short to be worth anything", first)
	}

	second, err := b.persistedAdminToken()
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Errorf("token changed across a restart: %q then %q", first, second)
	}

	// 0600. The data directory holds the event master key; the token is no less
	// sensitive, and anybody who can read it can watch the whole event.
	info, err := os.Stat(filepath.Join(dir, "admin-token"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("token file mode is %o, want 600", mode)
	}
}

// TestAdminTokenRecoversFromATruncatedWrite covers the power cut landing between
// the file being created and the bytes reaching the card. Booting with an empty
// token would mean no reachable dashboard at all, which is worse than rotating.
func TestAdminTokenRecoversFromATruncatedWrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "admin-token"), []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	b := &box{cfg: config.Config{DataDir: dir}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	token, err := b.persistedAdminToken()
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("booted with an empty admin token, so the dashboard is unreachable")
	}
}
