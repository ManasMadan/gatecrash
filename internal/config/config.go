// Package config loads the box's configuration.
//
// Three sources, in increasing precedence: a JSON file, environment variables,
// and command-line flags. The file is what an operator edits once; the
// environment is what a systemd unit or a container sets; the flags are what
// somebody debugging on the day reaches for.
//
// Everything has a working default. A box with no configuration file at all boots,
// mints its own CA, serves on the conventional ports and waits for a manifest,
// because the promise on the tin is "flash the card, plug it in" and a
// configuration file is not something you can edit before the first boot.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Mode is the box's networking posture.
type Mode string

// The two networking modes.
const (
	// Router mode joins the venue's existing network. The box takes a DHCP lease
	// or a static address, serves mDNS and its friendly names, and does not touch
	// DNS or DHCP for anybody else. This is the polite default: intercepting
	// probes or handing out addresses on somebody else's network is hijacking.
	Router Mode = "router"

	// AP mode makes the box the network. hostapd brings up the radio and the box
	// runs DHCP, DNS with a wildcard, and the captive portal. Zero venue
	// infrastructure required, which is the whole flex.
	AP Mode = "ap"
)

// Config is the box's configuration.
type Config struct {
	// Mode is the networking posture.
	Mode Mode `json:"mode"`

	// DataDir holds the database, the minted CA and the box's own keys.
	DataDir string `json:"data_dir"`

	// Listen is the HTTPS address. Port 8443 rather than 443 by default so the box
	// does not need to run as root; the deployment docs cover the capability grant
	// or the port redirect for venues that want the bare name to work.
	Listen string `json:"listen"`

	// ListenPlain is the HTTP address, serving the portal, the CA download and the
	// probe responses. A device that has not installed the CA cannot open an
	// https:// URL without a warning, and a certificate warning at the moment
	// somebody joins the Wi-Fi reads as an attack.
	ListenPlain string `json:"listen_plain"`

	// Advertise is the address the box tells clients to reach it on. Empty means
	// "work it out from the interfaces", which is right in every case except a
	// venue with several networks where the box has to be told which one the
	// scanners are on.
	Advertise []netip.Addr `json:"advertise,omitempty"`

	// Hostname is the single label the box claims: "gate" becomes gate.local.
	Hostname string `json:"hostname"`

	// Manifest is a path to load at boot, so a flashed card with a manifest beside
	// it comes up ready.
	Manifest string `json:"manifest,omitempty"`

	// ManifestPassphrase opens a sealed manifest. Deliberately not in the file by
	// default: a passphrase stored next to the thing it encrypts is not a
	// passphrase. The environment or a prompt is the intended path.
	ManifestPassphrase string `json:"-"`

	// OrganizerFingerprint is the key the box will accept a manifest from. Set
	// once at provisioning. Without it the box accepts any self-consistent
	// manifest, which is fine for a demo and wrong for an event, so the boot log
	// says so loudly.
	OrganizerFingerprint string `json:"organizer_fingerprint,omitempty"`

	// AdminToken authenticates the dashboard. Empty means generate one at boot and
	// print it, which is the right default: a box with a hardcoded token is a box
	// with no token.
	AdminToken string `json:"-"`

	// Discovery toggles.
	MDNS   bool `json:"mdns"`
	Beacon bool `json:"beacon"`

	// AP mode settings, ignored in router mode.
	Subnet   netip.Prefix     `json:"subnet,omitempty"`
	BoxIP    netip.Addr       `json:"box_ip,omitempty"`
	SSID     string           `json:"ssid,omitempty"`
	Iface    string           `json:"iface,omitempty"`
	DNSPort  int              `json:"dns_port,omitempty"`
	Upstream []netip.AddrPort `json:"upstream_dns,omitempty"`

	// Synchronous is the SQLite durability setting. FULL is the default and what a
	// real box runs: the SD card lies about fsync and FULL is the closest SQLite
	// can get to insisting.
	Synchronous string `json:"synchronous"`

	// SealEvery is how often to seal a Merkle checkpoint.
	SealEvery time.Duration `json:"seal_every"`

	// LogLevel is debug, info, warn or error.
	LogLevel string `json:"log_level"`

	// LogJSON switches to structured output, which is what the systemd unit uses.
	LogJSON bool `json:"log_json"`
}

// Default returns a configuration that boots and works.
func Default() Config {
	return Config{
		Mode:        Router,
		DataDir:     "/var/lib/gatecrash",
		Listen:      ":8443",
		ListenPlain: ":8080",
		Hostname:    "gate",
		MDNS:        true,
		Beacon:      true,
		Subnet:      netip.MustParsePrefix("10.11.0.0/24"),
		BoxIP:       netip.MustParseAddr("10.11.0.1"),
		SSID:        "GATECRASH",
		DNSPort:     53,
		Synchronous: "FULL",
		SealEvery:   5 * time.Minute,
		LogLevel:    "info",
	}
}

// Load reads a configuration file, applies environment overrides, and validates.
//
// A missing file is not an error: the defaults boot, which is what "flash the
// card, plug it in" requires.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		raw, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := json.Unmarshal(raw, &cfg); err != nil {
				return Config{}, fmt.Errorf("config: parsing %s: %w", path, err)
			}
		case errors.Is(err, os.ErrNotExist):
			// Only an error when the operator named a file explicitly. The default
			// path not existing is the normal first boot.
		default:
			return Config{}, fmt.Errorf("config: reading %s: %w", path, err)
		}
	}

	applyEnvironment(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// applyEnvironment overlays GATECRASH_* variables.
//
// The environment is how a systemd unit and a container configure the box, and it
// is the only sensible channel for the two secrets — the admin token and the
// manifest passphrase — because a secret in a JSON file next to the database is
// not a secret.
func applyEnvironment(cfg *Config) {
	if value := os.Getenv("GATECRASH_MODE"); value != "" {
		cfg.Mode = Mode(strings.ToLower(value))
	}
	if value := os.Getenv("GATECRASH_DATA_DIR"); value != "" {
		cfg.DataDir = value
	}
	if value := os.Getenv("GATECRASH_LISTEN"); value != "" {
		cfg.Listen = value
	}
	if value := os.Getenv("GATECRASH_LISTEN_PLAIN"); value != "" {
		cfg.ListenPlain = value
	}
	if value := os.Getenv("GATECRASH_HOSTNAME"); value != "" {
		cfg.Hostname = value
	}
	if value := os.Getenv("GATECRASH_MANIFEST"); value != "" {
		cfg.Manifest = value
	}
	if value := os.Getenv("GATECRASH_MANIFEST_PASSPHRASE"); value != "" {
		cfg.ManifestPassphrase = value
	}
	if value := os.Getenv("GATECRASH_ORGANIZER_FINGERPRINT"); value != "" {
		cfg.OrganizerFingerprint = value
	}
	if value := os.Getenv("GATECRASH_ADMIN_TOKEN"); value != "" {
		cfg.AdminToken = value
	}
	if value := os.Getenv("GATECRASH_LOG_LEVEL"); value != "" {
		cfg.LogLevel = strings.ToLower(value)
	}
	if value := os.Getenv("GATECRASH_LOG_JSON"); value != "" {
		cfg.LogJSON = truthy(value)
	}
	if value := os.Getenv("GATECRASH_SSID"); value != "" {
		cfg.SSID = value
	}
	if value := os.Getenv("GATECRASH_IFACE"); value != "" {
		cfg.Iface = value
	}
	if value := os.Getenv("GATECRASH_MDNS"); value != "" {
		cfg.MDNS = truthy(value)
	}
	if value := os.Getenv("GATECRASH_BEACON"); value != "" {
		cfg.Beacon = truthy(value)
	}
	if value := os.Getenv("GATECRASH_SYNCHRONOUS"); value != "" {
		cfg.Synchronous = strings.ToUpper(value)
	}
	if value := os.Getenv("GATECRASH_ADVERTISE"); value != "" {
		var addrs []netip.Addr
		for _, part := range strings.Split(value, ",") {
			if addr, err := netip.ParseAddr(strings.TrimSpace(part)); err == nil {
				addrs = append(addrs, addr)
			}
		}
		if len(addrs) > 0 {
			cfg.Advertise = addrs
		}
	}
	if value := os.Getenv("GATECRASH_SEAL_EVERY"); value != "" {
		if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
			cfg.SealEvery = time.Duration(seconds) * time.Second
		}
	}
}

// truthy reads the values people actually write in environment variables.
func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "y":
		return true
	default:
		return false
	}
}

// Validate checks a configuration and normalises it.
func (c *Config) Validate() error {
	switch c.Mode {
	case Router, AP:
	default:
		return fmt.Errorf("config: mode must be %q or %q, got %q", Router, AP, c.Mode)
	}
	if c.DataDir == "" {
		return errors.New("config: no data directory")
	}
	if c.Listen == "" {
		return errors.New("config: no listen address")
	}
	c.Hostname = strings.ToLower(strings.TrimSpace(c.Hostname))
	if c.Hostname == "" {
		c.Hostname = "gate"
	}
	if strings.ContainsAny(c.Hostname, ". ") {
		// A hostname with a dot would produce "gate.local.local", which resolves
		// to nothing and is very hard to notice.
		return fmt.Errorf("config: hostname %q must be a single label with no dots", c.Hostname)
	}
	switch strings.ToUpper(c.Synchronous) {
	case "FULL", "NORMAL", "OFF":
		c.Synchronous = strings.ToUpper(c.Synchronous)
	case "":
		c.Synchronous = "FULL"
	default:
		return fmt.Errorf("config: synchronous must be FULL, NORMAL or OFF, got %q", c.Synchronous)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	case "":
		c.LogLevel = "info"
	default:
		return fmt.Errorf("config: unknown log level %q", c.LogLevel)
	}
	if c.SealEvery <= 0 {
		c.SealEvery = 5 * time.Minute
	}

	if c.Mode == AP {
		if !c.Subnet.IsValid() {
			return errors.New("config: ap mode needs a subnet")
		}
		if !c.BoxIP.IsValid() {
			return errors.New("config: ap mode needs a box address")
		}
		if !c.Subnet.Contains(c.BoxIP) {
			return fmt.Errorf("config: box address %s is outside subnet %s", c.BoxIP, c.Subnet)
		}
		if c.DNSPort <= 0 {
			c.DNSPort = 53
		}
	}
	return nil
}

// DatabasePath is where the SQLite file lives.
func (c Config) DatabasePath() string { return filepath.Join(c.DataDir, "gatecrash.db") }

// PKIDir is where the minted CA lives.
func (c Config) PKIDir() string { return filepath.Join(c.DataDir, "pki") }

// KeyPath is where the box's own signing key lives.
func (c Config) KeyPath() string { return filepath.Join(c.DataDir, "box.key") }

// SecretPath is where the enrollment registry's HMAC secret lives.
//
// A file rather than a derivation from the CA key: the CA can legitimately be
// re-minted after a disaster, and doing so must not log every enrolled scanner
// out.
func (c Config) SecretPath() string { return filepath.Join(c.DataDir, "enroll.secret") }
