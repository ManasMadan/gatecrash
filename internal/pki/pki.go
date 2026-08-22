// Package pki mints and holds the box's own certificate authority.
//
// TLS on an air-gapped LAN is its own problem. There is no Let's Encrypt without
// internet, no public DNS name to prove control of, and no CA on earth that will
// issue for "gate.local" or 10.11.0.1. But TLS is not optional: getUserMedia —
// the camera API the scanner PWA needs to read a QR code — only works in a secure
// context, so a scanner served over plain HTTP has no camera.
//
// So the box is its own CA. At first boot it mints a CA key, a CA certificate and
// a leaf certificate covering every name and address it might be reached by, and
// keeps them for the life of the installation. Trust is established out of band:
// the enrollment QR code carries the CA's SHA-256 fingerprint, so a device that
// scanned a code printed by the organizer can pin the exact certificate it is
// about to talk to. That is a stronger property than the public CA system gives
// you, and it holds without any internet at all.
//
// Two deliberate choices worth stating.
//
// ECDSA P-256, not Ed25519. Ed25519 is the better primitive and it is what signs
// tickets; browsers do not accept Ed25519 certificates. This is the one place in
// the codebase where a worse algorithm is the correct choice, and the reason is
// that a certificate no browser will load is not a certificate.
//
// The CA is a real CA with a real key, kept on the box. That key can mint a
// certificate for any name, so a stolen box is a machine-in-the-middle device for
// anyone who installed its CA. This is why the CA is constrained by name
// (`gate.local`, `go.gate` and the box's addresses), why the leaf is short-lived,
// and why the docs tell operators to install it as a pinned exception rather than
// a system-wide trusted root.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Lifetimes.
const (
	// CALifetime is how long the minted CA is valid. Ten years: the CA is
	// installed on staff devices by hand and re-doing that ceremony is the
	// expensive part, so it should not expire during the life of the hardware.
	CALifetime = 10 * 365 * 24 * time.Hour

	// LeafLifetime is how long the box's serving certificate is valid. Ninety
	// days, renewed automatically at half life. Short because the leaf is cheap
	// to replace and a compromised leaf is bounded, long enough that a box that
	// sat in a cupboard for a month still serves when it is plugged in.
	LeafLifetime = 90 * 24 * time.Hour

	// ClientLifetime is how long an enrolled scanner's client certificate lasts.
	// One week: a scanner is enrolled for an event, and a certificate that
	// outlives the event is a credential nobody is tracking.
	ClientLifetime = 7 * 24 * time.Hour

	// clockSkewAllowance backdates NotBefore. A Raspberry Pi with no RTC boots
	// believing it is whenever its filesystem was last written, and a certificate
	// that is not valid yet is indistinguishable from a broken one to every
	// client on earth.
	clockSkewAllowance = 24 * time.Hour
)

// DefaultNames are the DNS names the box's certificate always covers.
var DefaultNames = []string{"gate.local", "gate", "go.gate", "localhost", "gatecrash.local"}

// Authority is the box's certificate authority and its serving certificate.
type Authority struct {
	// CACert and caKey are the authority.
	CACert *x509.Certificate
	caKey  *ecdsa.PrivateKey

	// caPEM is the CA certificate in PEM form, which is what a device downloads
	// and installs.
	caPEM []byte

	// leaf is the box's serving certificate.
	leaf    tls.Certificate
	leafPEM []byte
	keyPEM  []byte

	dir   string
	names []string
	addrs []netip.Addr
	now   func() time.Time
}

// Config configures the authority.
type Config struct {
	// Dir is where the key material lives. Files are written 0600 inside a 0700
	// directory.
	Dir string

	// EventName goes into the certificate subject so a human looking at a
	// certificate warning can see which event's box they are talking to.
	EventName string

	// Names are extra DNS names to cover, in addition to DefaultNames.
	Names []string

	// Addrs are the IP addresses to cover. The raw-IP URL is what the printed QR
	// code at the gate points at, so it has to be in the certificate or that path
	// produces a name mismatch.
	Addrs []netip.Addr

	// Now is injected so tests can drive expiry and renewal.
	Now func() time.Time
}

// File names inside the directory.
const (
	caCertFile   = "ca.crt"
	caKeyFile    = "ca.key"
	leafCertFile = "box.crt"
	leafKeyFile  = "box.key"
)

// Load opens an existing authority or mints a new one.
//
// Minting happens exactly once per installation, at first boot. Everything after
// that reuses the same CA, because the CA's fingerprint is what devices pinned
// and re-minting it silently would lock every enrolled scanner out.
func Load(cfg Config) (*Authority, error) {
	if cfg.Dir == "" {
		return nil, errors.New("pki: no directory")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("pki: creating %s: %w", cfg.Dir, err)
	}

	a := &Authority{
		dir:   cfg.Dir,
		names: mergeNames(cfg.Names),
		addrs: cfg.Addrs,
		now:   cfg.Now,
	}

	if err := a.loadCA(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := a.mintCA(cfg.EventName); err != nil {
			return nil, err
		}
	}
	if err := a.ensureLeaf(cfg.EventName); err != nil {
		return nil, err
	}
	return a, nil
}

// mergeNames combines the defaults with any extras, deduplicated.
func mergeNames(extra []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(DefaultNames)+len(extra))
	for _, name := range append(append([]string{}, DefaultNames...), extra...) {
		normalised := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if normalised == "" || seen[normalised] {
			continue
		}
		seen[normalised] = true
		out = append(out, normalised)
	}
	return out
}

// loadCA reads an existing CA from disk.
func (a *Authority) loadCA() error {
	certPEM, err := os.ReadFile(filepath.Join(a.dir, caCertFile))
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(a.dir, caKeyFile))
	if err != nil {
		return err
	}

	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return fmt.Errorf("pki: reading ca certificate: %w", err)
	}
	key, err := parseECKeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("pki: reading ca key: %w", err)
	}
	// A cert and key that do not match is a directory somebody has half-restored
	// from a backup. Failing loudly beats serving a certificate nobody can verify.
	if !key.PublicKey.Equal(cert.PublicKey) {
		return errors.New("pki: the ca key does not match the ca certificate")
	}

	a.CACert, a.caKey, a.caPEM = cert, key, certPEM
	return nil
}

// mintCA creates a new authority.
func (a *Authority) mintCA(eventName string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("pki: generating ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}

	now := a.now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   caCommonName(eventName),
			Organization: []string{"Gatecrash"},
			// The event name in the OU is what lets a human staring at a
			// certificate warning tell which box they are talking to.
			OrganizationalUnit: []string{organisationalUnit(eventName)},
		},
		NotBefore:             now.Add(-clockSkewAllowance),
		NotAfter:              now.Add(CALifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// A CA that can only sign leaves, not other CAs. Nothing here needs an
		// intermediate, and a path length of zero means a stolen box cannot mint
		// a sub-CA to hand to somebody else.
		MaxPathLen:     0,
		MaxPathLenZero: true,
		// Name constraints: this CA is only trusted for the box's own names and
		// addresses. Without them, installing it as a system root would let the
		// box impersonate any site on the internet, which is a wildly larger
		// grant than an attendee is agreeing to.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permittedDomains(a.names),
		PermittedIPRanges:           permittedRanges(a.addrs),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("pki: creating ca certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("pki: parsing minted ca certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("pki: encoding ca key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeSecret(filepath.Join(a.dir, caKeyFile), keyPEM); err != nil {
		return err
	}
	// The certificate is public: it is downloaded and installed by every device.
	if err := os.WriteFile(filepath.Join(a.dir, caCertFile), certPEM, 0o644); err != nil {
		return fmt.Errorf("pki: writing ca certificate: %w", err)
	}

	a.CACert, a.caKey, a.caPEM = cert, key, certPEM
	return nil
}

// permittedDomains turns the covered names into name constraints.
//
// A leading dot in a constraint permits the domain and its subdomains; a bare
// name permits exactly it. "localhost" is included because a developer reaching
// the box over an SSH tunnel needs it, and excluding it would make the constraint
// reject the box's own certificate.
func permittedDomains(names []string) []string {
	out := make([]string, 0, len(names)+2)
	seen := make(map[string]bool)
	for _, name := range names {
		for _, constraint := range []string{name, "." + name} {
			if !seen[constraint] {
				seen[constraint] = true
				out = append(out, constraint)
			}
		}
	}
	// ".local" so a box renamed after minting still validates without a fresh CA
	// and a fresh enrollment ceremony for every scanner.
	if !seen[".local"] {
		out = append(out, ".local")
	}
	if !seen[".gate"] {
		out = append(out, ".gate")
	}
	return out
}

// permittedRanges turns the covered addresses into IP name constraints.
func permittedRanges(addrs []netip.Addr) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(addrs)+2)
	for _, addr := range addrs {
		bits := 32
		if addr.Is6() && !addr.Is4In6() {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(bits, bits)})
	}
	// Loopback, for the same reason localhost is in the name list.
	out = append(out,
		&net.IPNet{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
	)
	return out
}

// ensureLeaf loads the serving certificate, minting a new one when it is missing,
// expiring, or no longer covers the box's names.
func (a *Authority) ensureLeaf(eventName string) error {
	certPath := filepath.Join(a.dir, leafCertFile)
	keyPath := filepath.Join(a.dir, leafKeyFile)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)

	if certErr == nil && keyErr == nil {
		if pair, err := tls.X509KeyPair(certPEM, keyPEM); err == nil {
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err == nil && a.leafUsable(leaf) {
				pair.Leaf = leaf
				a.leaf, a.leafPEM, a.keyPEM = pair, certPEM, keyPEM
				return nil
			}
		}
	}
	return a.mintLeaf(eventName)
}

// leafUsable reports whether an existing leaf can keep serving.
//
// Renewal happens once less than half a lifetime remains, rather than at expiry.
// A box switched on the morning of an event and finding its certificate expiring
// that evening should renew before doors, not during them.
//
// The threshold is measured backwards from NotAfter rather than forwards from
// NotBefore, because NotBefore is deliberately backdated a day to survive a Pi
// with no RTC: measuring from it would make "half life" mean something slightly
// different from half the configured lifetime.
func (a *Authority) leafUsable(leaf *x509.Certificate) bool {
	now := a.now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return false
	}
	if leaf.NotAfter.Sub(now) < LeafLifetime/2 {
		return false
	}
	// The addresses change when the venue's DHCP hands the box a different lease,
	// and a certificate that does not cover the address a scanner connects to is
	// a certificate warning at a gate.
	for _, addr := range a.addrs {
		if !coversIP(leaf, addr) {
			return false
		}
	}
	for _, name := range a.names {
		if !coversName(leaf, name) {
			return false
		}
	}
	// It must chain to the CA we actually hold, or a restored backup could leave
	// a leaf signed by a CA that no longer exists.
	return leaf.CheckSignatureFrom(a.CACert) == nil
}

func coversIP(cert *x509.Certificate, addr netip.Addr) bool {
	for _, ip := range cert.IPAddresses {
		if parsed, ok := netip.AddrFromSlice(ip); ok && parsed.Unmap() == addr.Unmap() {
			return true
		}
	}
	return false
}

func coversName(cert *x509.Certificate, name string) bool {
	for _, dns := range cert.DNSNames {
		if strings.EqualFold(dns, name) {
			return true
		}
	}
	return false
}

// mintLeaf issues a fresh serving certificate.
func (a *Authority) mintLeaf(eventName string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("pki: generating leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}

	addresses := make([]net.IP, 0, len(a.addrs)+2)
	for _, addr := range a.addrs {
		addresses = append(addresses, addr.AsSlice())
	}
	addresses = append(addresses, net.IPv4(127, 0, 0, 1).To4(), net.IPv6loopback)

	now := a.now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "gate.local",
			Organization:       []string{"Gatecrash"},
			OrganizationalUnit: []string{organisationalUnit(eventName)},
		},
		NotBefore:   now.Add(-clockSkewAllowance),
		NotAfter:    now.Add(LeafLifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    a.names,
		IPAddresses: addresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, a.CACert, &key.PublicKey, a.caKey)
	if err != nil {
		return fmt.Errorf("pki: creating leaf certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("pki: encoding leaf key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeSecret(filepath.Join(a.dir, leafKeyFile), keyPEM); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.dir, leafCertFile), certPEM, 0o644); err != nil {
		return fmt.Errorf("pki: writing leaf certificate: %w", err)
	}

	// The chain sent to clients is leaf then CA, so a device that has pinned the
	// fingerprint but not installed the root can still build the path.
	pair, err := tls.X509KeyPair(append(certPEM, a.caPEM...), keyPEM)
	if err != nil {
		return fmt.Errorf("pki: loading minted leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("pki: parsing minted leaf: %w", err)
	}
	pair.Leaf = leaf

	a.leaf, a.leafPEM, a.keyPEM = pair, certPEM, keyPEM
	return nil
}

// Fingerprint is the SHA-256 of the CA certificate's DER, in the colon-separated
// hex form every tool prints.
//
// This is the value that travels in the enrollment QR code, the mDNS TXT record
// and the UDP beacon, and it is what a client pins.
func (a *Authority) Fingerprint() string {
	sum := sha256.Sum256(a.CACert.Raw)
	parts := make([]string, 0, len(sum))
	for _, b := range sum {
		parts = append(parts, hex.EncodeToString([]byte{b}))
	}
	return strings.ToUpper(strings.Join(parts, ":"))
}

// ShortFingerprint is a truncated, URL-safe fingerprint for the places a full one
// does not fit: a QR payload, a printed sheet, a TXT record.
//
// Twelve base64 characters is 72 bits. Not collision-resistant against a
// determined adversary, and it is not asked to be: it is compared against the
// full fingerprint after the connection is made, and its job is to let a human
// spot the wrong box.
func (a *Authority) ShortFingerprint() string {
	sum := sha256.Sum256(a.CACert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:9])
}

// CAPEM returns the CA certificate in PEM form, which is what a device downloads
// from /ca.crt and installs.
func (a *Authority) CAPEM() []byte { return append([]byte(nil), a.caPEM...) }

// ServerTLS returns the TLS configuration for the box's HTTPS listener.
func (a *Authority) ServerTLS() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{a.leaf},
		MinVersion:   tls.VersionTLS12,
		// TLS 1.2 as the floor rather than 1.3: the target market includes
		// Android 7 devices that do not speak 1.3, and refusing them would mean
		// refusing the phones this product exists to support.
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// ClientPool returns a pool trusting only this CA, for verifying enrolled
// scanners' client certificates.
func (a *Authority) ClientPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.CACert)
	return pool
}

// IssueClient mints a client certificate for an enrolled scanner.
//
// mTLS is the strong half of device enrollment: a bearer token can be read off a
// screen or out of a log, whereas a client certificate's private key never leaves
// the device that generated it. The box supports both because the PWA cannot hold
// a client certificate and the native scanner can.
func (a *Authority) IssueClient(deviceID string, publicKey any) ([]byte, error) {
	if deviceID == "" {
		return nil, errors.New("pki: client certificate needs a device id")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := a.now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			// The device id is the certificate's common name, so every scan the
			// box records can be attributed from the TLS layer alone.
			CommonName:   deviceID,
			Organization: []string{"Gatecrash Scanner"},
		},
		NotBefore:   now.Add(-clockSkewAllowance),
		NotAfter:    now.Add(ClientLifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, a.CACert, publicKey, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("pki: creating client certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// LeafExpiry returns when the serving certificate expires, for the dashboard's
// diagnostics panel.
func (a *Authority) LeafExpiry() time.Time {
	if a.leaf.Leaf == nil {
		return time.Time{}
	}
	return a.leaf.Leaf.NotAfter
}

// Names returns the DNS names the serving certificate covers.
func (a *Authority) Names() []string { return append([]string(nil), a.names...) }

// Addrs returns the IP addresses it covers.
func (a *Authority) Addrs() []netip.Addr { return append([]netip.Addr(nil), a.addrs...) }

// randomSerial returns a 128-bit certificate serial.
func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("pki: generating serial: %w", err)
	}
	// Zero is not a legal serial number, and a serial that collides with an
	// earlier one makes revocation ambiguous.
	return serial.Add(serial, big.NewInt(1)), nil
}

// writeSecret writes a private key with restrictive permissions.
//
// Written to a temporary file and renamed, so a power cut during a first boot
// cannot leave a truncated key that the box then refuses to start with.
func writeSecret(path string, contents []byte) error {
	temp := path + ".tmp"
	if err := os.WriteFile(temp, contents, 0o600); err != nil {
		return fmt.Errorf("pki: writing %s: %w", temp, err)
	}
	if err := os.Rename(temp, path); err != nil {
		return fmt.Errorf("pki: renaming %s: %w", temp, err)
	}
	return nil
}

func parseCertPEM(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseECKeyPEM(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("not a pem block")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// caCommonName builds the CA subject's common name.
func caCommonName(eventName string) string {
	if eventName == "" {
		return "Gatecrash Box CA"
	}
	return "Gatecrash CA: " + truncate(eventName, 48)
}

func organisationalUnit(eventName string) string {
	if eventName == "" {
		return "Venue Box"
	}
	return truncate(eventName, 64)
}

// truncate shortens a string for a certificate field. X.509 string fields have
// length limits and an organizer's event name is arbitrary text.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}
