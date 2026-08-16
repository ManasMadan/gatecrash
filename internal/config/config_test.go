package config

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultsBootWithNoConfigurationAtAll(t *testing.T) {
	// The promise on the tin is "flash the card, plug it in", and a configuration
	// file is not something you can edit before the first boot.
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("a missing config file should not be an error: %v", err)
	}
	if cfg.Mode != Router {
		t.Errorf("default mode is %q, want router: intercepting probes on somebody else's network is hijacking", cfg.Mode)
	}
	if cfg.Listen == "" || cfg.Hostname != "gate" {
		t.Errorf("defaults are %+v", cfg)
	}
	if cfg.Synchronous != "FULL" {
		t.Errorf("default synchronous is %q, want FULL: the SD card lies about fsync", cfg.Synchronous)
	}
	if !cfg.MDNS || !cfg.Beacon {
		t.Error("discovery is off by default, so a phone would have nothing to find")
	}
}

func TestFileOverridesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
		"mode": "ap",
		"data_dir": "/srv/gatecrash",
		"listen": ":443",
		"hostname": "doors",
		"subnet": "10.20.0.0/24",
		"box_ip": "10.20.0.1",
		"log_level": "debug"
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != AP || cfg.DataDir != "/srv/gatecrash" || cfg.Listen != ":443" {
		t.Fatalf("config is %+v", cfg)
	}
	if cfg.Hostname != "doors" {
		t.Errorf("hostname is %q", cfg.Hostname)
	}
	if cfg.BoxIP != netip.MustParseAddr("10.20.0.1") {
		t.Errorf("box ip is %s", cfg.BoxIP)
	}
}

func TestEnvironmentOverridesFile(t *testing.T) {
	// The environment is how a systemd unit and a container configure the box, and
	// it is the only sensible channel for the two secrets.
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"listen": ":8443", "log_level": "info"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GATECRASH_LISTEN", ":9443")
	t.Setenv("GATECRASH_LOG_LEVEL", "debug")
	t.Setenv("GATECRASH_ADMIN_TOKEN", "from-the-environment")
	t.Setenv("GATECRASH_MANIFEST_PASSPHRASE", "correct horse")
	t.Setenv("GATECRASH_ADVERTISE", "10.11.0.1, 192.168.1.50")
	t.Setenv("GATECRASH_MDNS", "no")
	t.Setenv("GATECRASH_SEAL_EVERY", "60")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9443" || cfg.LogLevel != "debug" {
		t.Fatalf("config is %+v", cfg)
	}
	if cfg.AdminToken != "from-the-environment" || cfg.ManifestPassphrase != "correct horse" {
		t.Error("the secrets did not come through the environment")
	}
	if len(cfg.Advertise) != 2 || cfg.Advertise[1] != netip.MustParseAddr("192.168.1.50") {
		t.Errorf("advertise is %v", cfg.Advertise)
	}
	if cfg.MDNS {
		t.Error(`GATECRASH_MDNS="no" did not turn mDNS off`)
	}
	if cfg.SealEvery != time.Minute {
		t.Errorf("seal interval is %s", cfg.SealEvery)
	}
}

// TestSecretsAreNotSerialised matters because a config file gets committed, copied
// onto a USB stick and pasted into a support ticket.
func TestSecretsAreNotSerialised(t *testing.T) {
	cfg := Default()
	cfg.AdminToken = "super-secret-token"
	cfg.ManifestPassphrase = "correct horse battery staple"

	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"super-secret-token", "correct horse battery staple"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("a secret was serialised into the config JSON: %q", secret)
		}
	}
}

func TestValidateRejectsBadConfigurations(t *testing.T) {
	for name, mutate := range map[string]func(Config) Config{
		"unknown mode":          func(c Config) Config { c.Mode = "magic"; return c },
		"no data dir":           func(c Config) Config { c.DataDir = ""; return c },
		"no listen":             func(c Config) Config { c.Listen = ""; return c },
		"hostname with a dot":   func(c Config) Config { c.Hostname = "gate.local"; return c },
		"hostname with a space": func(c Config) Config { c.Hostname = "my gate"; return c },
		"unknown synchronous":   func(c Config) Config { c.Synchronous = "SOMETIMES"; return c },
		"unknown log level":     func(c Config) Config { c.LogLevel = "chatty"; return c },
		"ap with no subnet": func(c Config) Config {
			c.Mode = AP
			c.Subnet = netip.Prefix{}
			return c
		},
		"ap with no box address": func(c Config) Config {
			c.Mode = AP
			c.BoxIP = netip.Addr{}
			return c
		},
		"ap with the box outside the subnet": func(c Config) Config {
			c.Mode = AP
			c.BoxIP = netip.MustParseAddr("192.168.9.9")
			return c
		},
	} {
		cfg := mutate(Default())
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: Validate accepted it", name)
		}
	}
}

func TestHostnameWithADotIsRefusedForAGoodReason(t *testing.T) {
	// "gate.local" would produce "gate.local.local", which resolves to nothing and
	// is very hard to notice from a gate.
	cfg := Default()
	cfg.Hostname = "gate.local"
	if err := cfg.Validate(); err == nil {
		t.Fatal("a multi-label hostname was accepted")
	}
}

func TestValidateNormalises(t *testing.T) {
	cfg := Default()
	cfg.Hostname = "  DOORS  "
	cfg.Synchronous = "normal"
	cfg.LogLevel = ""
	cfg.SealEvery = 0

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "doors" {
		t.Errorf("hostname is %q", cfg.Hostname)
	}
	if cfg.Synchronous != "NORMAL" {
		t.Errorf("synchronous is %q", cfg.Synchronous)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("log level is %q", cfg.LogLevel)
	}
	if cfg.SealEvery <= 0 {
		t.Error("a zero seal interval was not given a default")
	}
}

func TestPaths(t *testing.T) {
	cfg := Default()
	cfg.DataDir = "/srv/gc"

	for got, want := range map[string]string{
		cfg.DatabasePath(): "/srv/gc/gatecrash.db",
		cfg.PKIDir():       "/srv/gc/pki",
		cfg.KeyPath():      "/srv/gc/box.key",
		cfg.SecretPath():   "/srv/gc/enroll.secret",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestLoadReportsAMalformedFile(t *testing.T) {
	// A missing file is a first boot. A file that exists and is broken is a
	// mistake somebody made, and silently ignoring it would run the event on
	// defaults nobody chose.
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted a malformed config file")
	}
}

func TestTruthy(t *testing.T) {
	// The values people actually write in environment variables.
	for _, yes := range []string{"1", "true", "TRUE", "yes", "on", "y", " True "} {
		if !truthy(yes) {
			t.Errorf("truthy(%q) = false", yes)
		}
	}
	for _, no := range []string{"", "0", "false", "no", "off", "maybe"} {
		if truthy(no) {
			t.Errorf("truthy(%q) = true", no)
		}
	}
}
