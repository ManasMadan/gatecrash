package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func load(t *testing.T, dir string, c *clock, addrs ...netip.Addr) *Authority {
	t.Helper()
	if len(addrs) == 0 {
		addrs = []netip.Addr{netip.MustParseAddr("10.11.0.1")}
	}
	a, err := Load(Config{
		Dir: dir, EventName: "Sundown Sessions", Addrs: addrs, Now: c.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func newClock() *clock {
	return &clock{at: time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)}
}

func TestMintsOnFirstBoot(t *testing.T) {
	dir := t.TempDir()
	c := newClock()
	a := load(t, dir, c)

	if !a.CACert.IsCA {
		t.Error("the minted CA certificate is not marked as a CA")
	}
	// A path length of zero means a stolen box cannot mint a sub-CA to hand to
	// somebody else.
	if !a.CACert.MaxPathLenZero {
		t.Error("the CA can sign intermediate CAs")
	}
	if a.CACert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("the CA cannot sign certificates")
	}
	if !strings.Contains(a.CACert.Subject.CommonName, "Sundown Sessions") {
		t.Errorf("the CA subject is %q, which does not name the event", a.CACert.Subject.CommonName)
	}

	// ECDSA, not Ed25519: browsers do not accept Ed25519 certificates, and a
	// certificate no browser will load is not a certificate.
	if _, ok := a.CACert.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("the CA key is %T, want an ECDSA key that browsers accept", a.CACert.PublicKey)
	}

	for _, name := range []string{caCertFile, caKeyFile, leafCertFile, leafKeyFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s was not written: %v", name, err)
		}
		if strings.HasSuffix(name, ".key") && info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v, want 0600", name, info.Mode().Perm())
		}
	}
}

// TestReloadKeepsTheSameCA is the property enrollment depends on. The CA's
// fingerprint is what devices pinned; re-minting it silently would lock every
// enrolled scanner out.
func TestReloadKeepsTheSameCA(t *testing.T) {
	dir := t.TempDir()
	c := newClock()

	first := load(t, dir, c)
	fingerprint := first.Fingerprint()

	for i := 0; i < 3; i++ {
		c.advance(time.Hour)
		again := load(t, dir, c)
		if again.Fingerprint() != fingerprint {
			t.Fatalf("reload %d minted a new CA: %s", i, again.Fingerprint())
		}
	}
}

func TestLoadRefusesAMismatchedKeyAndCertificate(t *testing.T) {
	// A directory somebody has half-restored from a backup. Failing loudly beats
	// serving a certificate nobody can verify.
	dir := t.TempDir()
	c := newClock()
	load(t, dir, c)

	other := t.TempDir()
	load(t, other, c)

	// Swap in the other box's CA key.
	key, err := os.ReadFile(filepath.Join(other, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), key, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(Config{Dir: dir, Addrs: []netip.Addr{netip.MustParseAddr("10.11.0.1")}, Now: c.now}); err == nil {
		t.Fatal("Load accepted a CA key that does not match its certificate")
	}
}

func TestLeafCoversEveryNameAndAddress(t *testing.T) {
	c := newClock()
	addrs := []netip.Addr{
		netip.MustParseAddr("10.11.0.1"),
		netip.MustParseAddr("192.168.1.50"),
	}
	a, err := Load(Config{
		Dir: t.TempDir(), EventName: "Sundown", Names: []string{"sundown.local"}, Addrs: addrs, Now: c.now,
	})
	if err != nil {
		t.Fatal(err)
	}

	leaf := a.leaf.Leaf
	// The printed QR code at the gate points at the raw-IP URL, so the addresses
	// have to be in the certificate or that path produces a name mismatch.
	for _, addr := range addrs {
		if !coversIP(leaf, addr) {
			t.Errorf("the leaf does not cover %s", addr)
		}
	}
	for _, name := range append(DefaultNames, "sundown.local") {
		if !coversName(leaf, name) {
			t.Errorf("the leaf does not cover %q", name)
		}
	}
	// Loopback, for a developer reaching the box over an SSH tunnel.
	if !coversIP(leaf, netip.MustParseAddr("127.0.0.1")) {
		t.Error("the leaf does not cover loopback")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("the leaf cannot be used for a signature")
	}
	var serverAuth bool
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		t.Error("the leaf is not marked for server authentication")
	}
}

// TestNotBeforeIsBackdated matters because a Raspberry Pi with no RTC boots
// believing it is whenever its filesystem was last written, and a certificate
// that is not valid yet is indistinguishable from a broken one to every client.
func TestNotBeforeIsBackdated(t *testing.T) {
	c := newClock()
	a := load(t, t.TempDir(), c)

	if !a.CACert.NotBefore.Before(c.at) {
		t.Errorf("the CA is valid from %s, which is not before the clock at %s", a.CACert.NotBefore, c.at)
	}
	if a.CACert.NotBefore.After(c.at.Add(-23 * time.Hour)) {
		t.Errorf("the CA is only backdated to %s, which is not enough for a Pi with no RTC", a.CACert.NotBefore)
	}
	if !a.leaf.Leaf.NotBefore.Before(c.at) {
		t.Error("the leaf is not backdated")
	}
}

// TestLeafRenewsAtHalfLife is about doors: a box switched on the morning of an
// event and finding its certificate expiring that evening should renew before
// doors, not during them.
func TestLeafRenewsAtHalfLife(t *testing.T) {
	dir := t.TempDir()
	c := newClock()

	first := load(t, dir, c)
	firstSerial := first.leaf.Leaf.SerialNumber.String()
	caFingerprint := first.Fingerprint()

	// Just before half life: the same leaf.
	c.advance(LeafLifetime/2 - time.Hour)
	same := load(t, dir, c)
	if same.leaf.Leaf.SerialNumber.String() != firstSerial {
		t.Fatal("the leaf was renewed before half life")
	}

	// Past half life: a new leaf, the same CA.
	c.advance(2 * time.Hour)
	renewed := load(t, dir, c)
	if renewed.leaf.Leaf.SerialNumber.String() == firstSerial {
		t.Fatal("the leaf was not renewed past half life")
	}
	if renewed.Fingerprint() != caFingerprint {
		t.Fatal("renewing the leaf re-minted the CA, which would lock out every enrolled scanner")
	}
}

// TestLeafIsReissuedWhenTheAddressChanges covers the venue reality: the box gets
// a different DHCP lease and a certificate that does not cover the address a
// scanner connects to is a certificate warning at a gate.
func TestLeafIsReissuedWhenTheAddressChanges(t *testing.T) {
	dir := t.TempDir()
	c := newClock()

	first := load(t, dir, c, netip.MustParseAddr("10.11.0.1"))
	firstSerial := first.leaf.Leaf.SerialNumber.String()

	moved := load(t, dir, c, netip.MustParseAddr("192.168.4.20"))
	if moved.leaf.Leaf.SerialNumber.String() == firstSerial {
		t.Fatal("the leaf was not reissued after the box's address changed")
	}
	if !coversIP(moved.leaf.Leaf, netip.MustParseAddr("192.168.4.20")) {
		t.Fatal("the reissued leaf does not cover the new address")
	}
	if moved.Fingerprint() != first.Fingerprint() {
		t.Fatal("reissuing the leaf re-minted the CA")
	}
}

// TestNameConstraintsStopTheCAImpersonatingTheInternet is the security property
// that makes installing this CA a defensible thing to ask of an attendee. Without
// constraints, a system-wide install would let the box impersonate any site.
func TestNameConstraintsStopTheCAImpersonatingTheInternet(t *testing.T) {
	c := newClock()
	a := load(t, t.TempDir(), c, netip.MustParseAddr("10.11.0.1"))

	if !a.CACert.PermittedDNSDomainsCritical {
		t.Error("the name constraints are not marked critical, so a client may ignore them")
	}
	if len(a.CACert.PermittedDNSDomains) == 0 {
		t.Fatal("the CA has no name constraints")
	}

	// Build a certificate for a name the CA must not be trusted for, then verify
	// it against a pool containing only this CA. Go's verifier enforces name
	// constraints, so this is a real check rather than an inspection of a field.
	forged := issueFor(t, a, "www.hdfcbank.com")
	pool := a.ClientPool()
	if _, err := forged.Verify(x509.VerifyOptions{
		Roots: pool, DNSName: "www.hdfcbank.com", CurrentTime: c.at,
	}); err == nil {
		t.Fatal("the CA successfully vouched for a bank's domain")
	}

	// And the box's own names still verify, or the constraints are too tight to
	// be useful.
	legitimate := issueFor(t, a, "gate.local")
	if _, err := legitimate.Verify(x509.VerifyOptions{
		Roots: pool, DNSName: "gate.local", CurrentTime: c.at,
	}); err != nil {
		t.Fatalf("the CA cannot vouch for its own name: %v", err)
	}
}

// issueFor mints a server certificate for an arbitrary name using the authority's
// key, to test what the CA is trusted for.
func issueFor(t *testing.T, a *Authority, name string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      a.CACert.Subject,
		NotBefore:    a.CACert.NotBefore,
		NotAfter:     a.CACert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.CACert, &key.PublicKey, a.caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestFingerprintIsStableAndReadable(t *testing.T) {
	c := newClock()
	a := load(t, t.TempDir(), c)

	fingerprint := a.Fingerprint()
	// The colon-separated uppercase hex form every tool prints, so an operator can
	// compare it against what their browser shows.
	if len(fingerprint) != 32*3-1 {
		t.Errorf("fingerprint is %d characters: %q", len(fingerprint), fingerprint)
	}
	if strings.ToUpper(fingerprint) != fingerprint {
		t.Error("the fingerprint is not uppercase")
	}
	if a.Fingerprint() != fingerprint {
		t.Error("the fingerprint is not stable across calls")
	}

	// The short form fits in a QR payload and a printed sheet.
	short := a.ShortFingerprint()
	if len(short) != 12 {
		t.Errorf("short fingerprint is %d characters: %q", len(short), short)
	}
	if strings.ContainsAny(short, "+/=") {
		t.Errorf("short fingerprint %q is not URL safe", short)
	}

	// Two boxes must not share a fingerprint, or pinning means nothing.
	other := load(t, t.TempDir(), c)
	if other.Fingerprint() == fingerprint {
		t.Fatal("two independently minted CAs share a fingerprint")
	}
	if other.ShortFingerprint() == short {
		t.Fatal("two independently minted CAs share a short fingerprint")
	}
}

// TestTLSHandshakeAgainstAPinnedClient is the end-to-end proof: a client holding
// only the CA certificate can complete a handshake with the box, which is what
// makes getUserMedia work in the scanner PWA.
func TestTLSHandshakeAgainstAPinnedClient(t *testing.T) {
	c := newClock()
	a := load(t, t.TempDir(), c, netip.MustParseAddr("127.0.0.1"))

	listener, err := tls.Listen("tcp", "127.0.0.1:0", a.ServerTLS())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "hello")
	}()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(a.CAPEM()) {
		t.Fatal("the CA PEM did not parse")
	}

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", port), &tls.Config{
		RootCAs: pool, ServerName: "gate.local", Time: c.now,
	})
	if err != nil {
		t.Fatalf("a client holding the CA could not complete a handshake: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("read %q", buf)
	}
	// TLS 1.2 is the floor rather than 1.3, because the target market includes
	// Android 7 devices that do not speak 1.3.
	if conn.ConnectionState().Version < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version %#x", conn.ConnectionState().Version)
	}
}

func TestHandshakeFailsWithoutTheCA(t *testing.T) {
	// The other half of pinning: a client that does not hold the CA must not
	// connect, or "install the CA" is theatre.
	c := newClock()
	a := load(t, t.TempDir(), c, netip.MustParseAddr("127.0.0.1"))

	listener, err := tls.Listen("tcp", "127.0.0.1:0", a.ServerTLS())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", port), &tls.Config{
		ServerName: "gate.local", Time: c.now,
	}); err == nil {
		t.Fatal("a client with no trust store completed a handshake")
	}
}

// TestClientCertificateEnablesMutualTLS covers the strong half of device
// enrollment: a bearer token can be read off a screen, whereas a client
// certificate's private key never leaves the device that generated it.
func TestClientCertificateEnablesMutualTLS(t *testing.T) {
	c := newClock()
	a := load(t, t.TempDir(), c, netip.MustParseAddr("127.0.0.1"))

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPEM, err := a.IssueClient("scanner-north", &deviceKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := parseCertPEM(clientPEM)
	if err != nil {
		t.Fatal(err)
	}

	// The device id is the certificate's common name, so every scan can be
	// attributed from the TLS layer alone.
	if clientCert.Subject.CommonName != "scanner-north" {
		t.Errorf("client certificate common name is %q", clientCert.Subject.CommonName)
	}
	var clientAuth bool
	for _, usage := range clientCert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		t.Error("the client certificate is not marked for client authentication")
	}
	// A scanner is enrolled for an event, and a credential that outlives the
	// event is one nobody is tracking.
	if clientCert.NotAfter.Sub(c.at) > 8*24*time.Hour {
		t.Errorf("the client certificate is valid until %s, which outlives the event", clientCert.NotAfter)
	}

	// It has to actually work in a mutual-TLS handshake.
	serverTLS := a.ServerTLS()
	serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
	serverTLS.ClientCAs = a.ClientPool()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	presented := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			presented <- ""
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			presented <- ""
			return
		}
		chain := tlsConn.ConnectionState().PeerCertificates
		if len(chain) == 0 {
			presented <- ""
			return
		}
		presented <- chain[0].Subject.CommonName
	}()

	pool := x509.NewCertPool()
	pool.AddCert(a.CACert)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", port), &tls.Config{
		RootCAs:    pool,
		ServerName: "gate.local",
		Time:       c.now,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{clientCert.Raw},
			PrivateKey:  deviceKey,
		}},
	})
	if err != nil {
		t.Fatalf("mutual TLS handshake failed: %v", err)
	}
	defer conn.Close()

	if got := <-presented; got != "scanner-north" {
		t.Fatalf("the server saw client identity %q", got)
	}
}

func TestMutualTLSRejectsAForeignClientCertificate(t *testing.T) {
	c := newClock()
	box := load(t, t.TempDir(), c, netip.MustParseAddr("127.0.0.1"))
	stranger := load(t, t.TempDir(), c, netip.MustParseAddr("127.0.0.1"))

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A certificate from a different box's CA.
	foreignPEM, err := stranger.IssueClient("scanner-north", &deviceKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := parseCertPEM(foreignPEM)
	if err != nil {
		t.Fatal(err)
	}

	serverTLS := box.ServerTLS()
	serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
	serverTLS.ClientCAs = box.ClientPool()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.(*tls.Conn).Handshake()
	}()

	pool := x509.NewCertPool()
	pool.AddCert(box.CACert)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", port), &tls.Config{
		RootCAs: pool, ServerName: "gate.local", Time: c.now,
		Certificates: []tls.Certificate{{Certificate: [][]byte{foreign.Raw}, PrivateKey: deviceKey}},
	})
	if err != nil {
		// TLS 1.2 fails at the handshake, which is the clean case.
		return
	}
	defer conn.Close()

	// Under TLS 1.3 the client finishes its half of the handshake before the
	// server has verified the client certificate, so Dial succeeds and the
	// rejection arrives on the first read. Either way the connection must not be
	// usable.
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("scan")); err == nil {
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("a client certificate from another box's CA was accepted")
		}
	}
}

func TestIssueClientRequiresADeviceID(t *testing.T) {
	c := newClock()
	a := load(t, t.TempDir(), c)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.IssueClient("", &key.PublicKey); err == nil {
		t.Fatal("issued a client certificate with no device id")
	}
}

func TestLoadRequiresADirectory(t *testing.T) {
	if _, err := Load(Config{}); err == nil {
		t.Fatal("Load accepted an empty directory")
	}
}

func TestLeafExpiryIsReported(t *testing.T) {
	// Shown on the dashboard's diagnostics panel, because a certificate quietly
	// expiring is a gate that quietly stops working.
	c := newClock()
	a := load(t, t.TempDir(), c)
	expiry := a.LeafExpiry()
	if expiry.IsZero() {
		t.Fatal("no leaf expiry reported")
	}
	if expiry.Before(c.at) {
		t.Fatalf("the leaf expires at %s, before the clock at %s", expiry, c.at)
	}
}

func BenchmarkLoadExisting(b *testing.B) {
	dir := b.TempDir()
	c := &clock{at: time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)}
	if _, err := Load(Config{Dir: dir, Addrs: []netip.Addr{netip.MustParseAddr("10.11.0.1")}, Now: c.now}); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Load(Config{Dir: dir, Addrs: []netip.Addr{netip.MustParseAddr("10.11.0.1")}, Now: c.now}); err != nil {
			b.Fatal(err)
		}
	}
}
