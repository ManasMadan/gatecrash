package enroll

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/venue"
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

func newRegistry(t *testing.T) (*Registry, *clock, *[]Device) {
	t.Helper()
	c := &clock{at: time.Date(2026, 8, 21, 17, 0, 0, 0, time.UTC)}
	var persisted []Device
	r, err := New(Config{
		Secret: []byte("a-stable-box-secret-at-least-16"),
		Now:    c.now,
		Persist: func(d Device) {
			persisted = append(persisted, d)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, c, &persisted
}

func issue(t *testing.T, r *Registry, checkpoints ...venue.CheckpointCode) Invite {
	t.Helper()
	if len(checkpoints) == 0 {
		checkpoints = []venue.CheckpointCode{"gate-north"}
	}
	invite, err := r.Issue(
		InviteRequest{Checkpoints: checkpoints, Name: "North Gate"},
		"https://10.11.0.1:8443", "AA:BB:CC:DD", "Sundown Sessions",
	)
	if err != nil {
		t.Fatal(err)
	}
	return invite
}

func TestFullCeremony(t *testing.T) {
	r, _, persisted := newRegistry(t)
	invite := issue(t, r, "gate-north", "gate-south")

	// The QR is doing three jobs: the URL so the phone need not discover anything,
	// the fingerprint so it can pin, and the code so the printed sheet is the
	// authorisation.
	if invite.URL == "" || invite.CAFingerprint == "" || invite.Code == "" {
		t.Fatalf("the invite is missing something: %+v", invite)
	}
	if invite.Event != "Sundown Sessions" {
		t.Errorf("the invite does not name the event: %q", invite.Event)
	}
	// Shown to the person enrolling, so somebody handed the wrong sheet notices
	// before they are standing at a door that will not admit anybody.
	if len(invite.Checkpoints) != 2 {
		t.Errorf("the invite lists %d checkpoints", len(invite.Checkpoints))
	}
	if invite.Expires.IsZero() {
		t.Error("the invite does not say when it expires")
	}

	enrolled, err := r.Redeem(invite.Code, "Pixel 4a")
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.DeviceID == "" || enrolled.Token == "" {
		t.Fatalf("enrollment returned %+v", enrolled)
	}
	if len(enrolled.Checkpoints) != 2 {
		t.Errorf("the device was granted %d checkpoints", len(enrolled.Checkpoints))
	}

	device, ok := r.Authenticate(enrolled.Token)
	if !ok {
		t.Fatal("the token from a successful enrollment does not authenticate")
	}
	if device.ID != enrolled.DeviceID {
		t.Errorf("the token resolves to %q, want %q", device.ID, enrolled.DeviceID)
	}
	if len(*persisted) != 1 {
		t.Errorf("%d devices persisted, want 1", len(*persisted))
	}
}

func TestInviteQRRoundTrip(t *testing.T) {
	r, _, _ := newRegistry(t)
	invite := issue(t, r)

	payload, err := invite.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// The prefix matches the ticket formats so a scanner can tell what it is
	// looking at from three characters.
	if !strings.HasPrefix(payload, QRPrefix+".") {
		t.Fatalf("payload %q does not carry the enrollment prefix", payload[:min(12, len(payload))])
	}

	decoded, err := DecodeInvite(payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Code != invite.Code || decoded.URL != invite.URL || decoded.CAFingerprint != invite.CAFingerprint {
		t.Fatalf("round trip lost data: %+v", decoded)
	}
}

func TestDecodeInviteRejectsGarbage(t *testing.T) {
	for name, payload := range map[string]string{
		"empty":          "",
		"a ticket":       "GC1.AAAAAAAAAAAAAAAAAAAAAAAAAA.BBBB",
		"wrong prefix":   "GCE2.eyJ1cmwiOiJ4In0",
		"not base64":     QRPrefix + ".!!!!",
		"not json":       QRPrefix + ".aGVsbG8",
		"missing fields": QRPrefix + ".e30",
	} {
		if _, err := DecodeInvite(payload); err == nil {
			t.Errorf("%s: DecodeInvite accepted %q", name, payload)
		} else if !errors.Is(err, ErrBadInvite) {
			t.Errorf("%s: got %v, want ErrBadInvite", name, err)
		}
	}
}

func TestCodesAreSingleUse(t *testing.T) {
	r, _, _ := newRegistry(t)
	invite := issue(t, r)

	if _, err := r.Redeem(invite.Code, "first"); err != nil {
		t.Fatal(err)
	}
	// A sheet that enrolls unlimited phones is a sheet somebody photographs.
	if _, err := r.Redeem(invite.Code, "second"); !errors.Is(err, ErrUnknownCode) {
		t.Fatalf("got %v, want ErrUnknownCode on the second use", err)
	}
}

func TestMultiUseCodesEnrollSeveralPhones(t *testing.T) {
	// A supervisor handing out six phones for one gate should not need six printed
	// sheets, and every device still gets its own token and identity.
	r, _, _ := newRegistry(t)
	invite, err := r.Issue(InviteRequest{
		Checkpoints: []venue.CheckpointCode{"gate-north"}, Name: "North Gate", Uses: 3,
	}, "https://10.11.0.1:8443", "AA:BB", "Sundown")
	if err != nil {
		t.Fatal(err)
	}

	tokens := make(map[string]bool)
	ids := make(map[string]bool)
	for i := 0; i < 3; i++ {
		enrolled, err := r.Redeem(invite.Code, "phone-"+string(rune('a'+i)))
		if err != nil {
			t.Fatalf("use %d: %v", i, err)
		}
		if tokens[enrolled.Token] {
			t.Fatal("two devices were issued the same token")
		}
		if ids[enrolled.DeviceID] {
			t.Fatal("two devices were issued the same id")
		}
		tokens[enrolled.Token] = true
		ids[enrolled.DeviceID] = true
		// The dashboard has to be able to tell six identical phones apart.
		if !strings.Contains(enrolled.Name, "North Gate") || !strings.Contains(enrolled.Name, "phone-") {
			t.Errorf("device name is %q, which does not identify both the gate and the phone", enrolled.Name)
		}
	}
	if _, err := r.Redeem(invite.Code, "phone-d"); !errors.Is(err, ErrUnknownCode) {
		t.Fatal("a three-use code enrolled a fourth device")
	}
}

func TestCodesExpire(t *testing.T) {
	// A sheet left on a table overnight is worthless.
	r, c, _ := newRegistry(t)
	invite := issue(t, r)

	c.advance(DefaultCodeTTL + time.Second)
	if _, err := r.Redeem(invite.Code, "late"); !errors.Is(err, ErrUnknownCode) {
		t.Fatalf("got %v, want ErrUnknownCode for an expired code", err)
	}
}

func TestCustomTTL(t *testing.T) {
	r, c, _ := newRegistry(t)
	invite, err := r.Issue(InviteRequest{
		Checkpoints: []venue.CheckpointCode{"gate-north"}, TTL: time.Minute,
	}, "https://10.11.0.1:8443", "AA:BB", "Sundown")
	if err != nil {
		t.Fatal(err)
	}

	c.advance(30 * time.Second)
	if _, err := r.Redeem(invite.Code, "in time"); err != nil {
		t.Fatalf("a code inside its TTL was refused: %v", err)
	}

	second, err := r.Issue(InviteRequest{
		Checkpoints: []venue.CheckpointCode{"gate-north"}, TTL: time.Minute,
	}, "https://10.11.0.1:8443", "AA:BB", "Sundown")
	if err != nil {
		t.Fatal(err)
	}
	c.advance(2 * time.Minute)
	if _, err := r.Redeem(second.Code, "too late"); err == nil {
		t.Fatal("a code past its custom TTL was accepted")
	}
	_ = invite
}

// TestUnknownExpiredAndSpentCodesAreIndistinguishable matters because telling a
// caller that a code exists but is expired confirms a guess, and there is nothing
// useful they can do with the distinction.
func TestUnknownExpiredAndSpentCodesAreIndistinguishable(t *testing.T) {
	r, c, _ := newRegistry(t)

	spent := issue(t, r)
	if _, err := r.Redeem(spent.Code, "first"); err != nil {
		t.Fatal(err)
	}
	expired := issue(t, r)
	c.advance(DefaultCodeTTL + time.Second)

	for name, code := range map[string]string{
		"never existed": "AAAAAAAAAAAAAA",
		"spent":         spent.Code,
		"expired":       expired.Code,
		"empty":         "",
	} {
		_, err := r.Redeem(code, "device")
		if !errors.Is(err, ErrUnknownCode) {
			t.Errorf("%s: got %v, want the same ErrUnknownCode as every other case", name, err)
		}
	}
}

func TestRedeemNeedsADeviceName(t *testing.T) {
	r, _, _ := newRegistry(t)
	invite := issue(t, r)
	for _, name := range []string{"", "   ", "\t\n"} {
		if _, err := r.Redeem(invite.Code, name); !errors.Is(err, ErrNoDeviceName) {
			t.Errorf("name %q: got %v, want ErrNoDeviceName", name, err)
		}
	}
	// And the code must not have been consumed by the failed attempts.
	if _, err := r.Redeem(invite.Code, "real name"); err != nil {
		t.Fatalf("a failed attempt consumed the code: %v", err)
	}
}

func TestIssueRequiresCheckpointsAndAURL(t *testing.T) {
	r, _, _ := newRegistry(t)
	// A device with no checkpoints scans nothing, so issuing one would be a
	// confusing no-op.
	if _, err := r.Issue(InviteRequest{}, "https://10.11.0.1", "AA", "Sundown"); err == nil {
		t.Error("issued a code granting no checkpoints")
	}
	if _, err := r.Issue(InviteRequest{Checkpoints: []venue.CheckpointCode{"gate-north"}}, "", "AA", "Sundown"); err == nil {
		t.Error("issued a code with no box url")
	}
}

func TestTokensAreUniqueAndUnguessable(t *testing.T) {
	r, _, _ := newRegistry(t)
	seen := make(map[string]bool, 200)

	for i := 0; i < 200; i++ {
		invite := issue(t, r)
		enrolled, err := r.Redeem(invite.Code, "device")
		if err != nil {
			t.Fatal(err)
		}
		if seen[enrolled.Token] {
			t.Fatal("a token was issued twice")
		}
		seen[enrolled.Token] = true
		// 32 bytes of base64url is 43 characters.
		if len(enrolled.Token) < 40 {
			t.Fatalf("token is only %d characters", len(enrolled.Token))
		}
	}
}

func TestBadTokensDoNotAuthenticate(t *testing.T) {
	r, _, _ := newRegistry(t)
	invite := issue(t, r)
	enrolled, err := r.Redeem(invite.Code, "device")
	if err != nil {
		t.Fatal(err)
	}

	for name, token := range map[string]string{
		"empty":       "",
		"garbage":     "not-a-token",
		"the code":    invite.Code,
		"truncated":   enrolled.Token[:len(enrolled.Token)-1],
		"one flipped": flipLast(enrolled.Token),
	} {
		if _, ok := r.Authenticate(token); ok {
			t.Errorf("%s authenticated", name)
		}
	}
}

func flipLast(s string) string {
	if s == "" {
		return "x"
	}
	last := s[len(s)-1]
	if last == 'A' {
		last = 'B'
	} else {
		last = 'A'
	}
	return s[:len(s)-1] + string(last)
}

func TestRevocationTakesEffectImmediately(t *testing.T) {
	r, _, persisted := newRegistry(t)
	invite := issue(t, r)
	enrolled, err := r.Redeem(invite.Code, "stolen phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Authenticate(enrolled.Token); !ok {
		t.Fatal("the token does not authenticate before revocation")
	}

	if err := r.Revoke(enrolled.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Authenticate(enrolled.Token); ok {
		t.Fatal("a revoked device still authenticates")
	}
	// The revocation has to be written through, or a reboot un-revokes a stolen
	// phone.
	last := (*persisted)[len(*persisted)-1]
	if !last.Revoked {
		t.Error("the revocation was not persisted")
	}

	if err := r.Revoke("dev-nobody"); err == nil {
		t.Error("revoking a device that does not exist reported success")
	}
}

// TestRestoreSurvivesAReboot is the case that decides whether an event survives a
// box restart: a scanner must not be logged out mid-doors.
func TestRestoreSurvivesAReboot(t *testing.T) {
	r, c, _ := newRegistry(t)
	invite := issue(t, r)
	enrolled, err := r.Redeem(invite.Code, "Pixel 4a")
	if err != nil {
		t.Fatal(err)
	}

	devices := r.Devices()
	hashes := r.TokenHashes()
	if len(hashes) != 1 {
		t.Fatalf("%d token hashes", len(hashes))
	}
	// What is persisted must be a hash, never the token.
	for hash := range hashes {
		if hash == enrolled.Token {
			t.Fatal("the token itself was persisted")
		}
	}

	rebooted, err := New(Config{Secret: []byte("a-stable-box-secret-at-least-16"), Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	rebooted.Restore(devices, hashes)

	device, ok := rebooted.Authenticate(enrolled.Token)
	if !ok {
		t.Fatal("a scanner was logged out by a box reboot")
	}
	if device.ID != enrolled.DeviceID || device.Name != "North Gate" {
		t.Errorf("the restored device is %+v", device)
	}
	// Enrollment codes deliberately do not survive: a code nobody knows exists is
	// a credential nobody is tracking, and regenerating one costs a single tap.
	if rebooted.PendingCodes() != 0 {
		t.Error("enrollment codes survived a reboot")
	}
}

// TestADifferentSecretInvalidatesEveryToken is the flip side: the secret must be
// stable across reboots, and this test documents what happens when it is not.
func TestADifferentSecretInvalidatesEveryToken(t *testing.T) {
	r, c, _ := newRegistry(t)
	invite := issue(t, r)
	enrolled, err := r.Redeem(invite.Code, "device")
	if err != nil {
		t.Fatal(err)
	}

	other, err := New(Config{Secret: []byte("a-completely-different-secret!!"), Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	other.Restore(r.Devices(), r.TokenHashes())
	if _, ok := other.Authenticate(enrolled.Token); ok {
		t.Fatal("a token verified against a registry with a different secret")
	}
}

func TestNewRequiresASecret(t *testing.T) {
	for _, secret := range [][]byte{nil, []byte("short")} {
		if _, err := New(Config{Secret: secret}); err == nil {
			t.Errorf("New accepted a %d byte secret", len(secret))
		}
	}
}

func TestPendingCodesSweepsExpiredOnes(t *testing.T) {
	r, c, _ := newRegistry(t)
	issue(t, r)
	issue(t, r)
	if got := r.PendingCodes(); got != 2 {
		t.Fatalf("%d pending codes, want 2", got)
	}
	c.advance(DefaultCodeTTL + time.Second)
	if got := r.PendingCodes(); got != 0 {
		t.Fatalf("%d pending codes after expiry, want 0", got)
	}
}

func TestRegistryIsSafeForConcurrentUse(t *testing.T) {
	r, _, _ := newRegistry(t)

	var wg sync.WaitGroup
	tokens := make(chan string, 100)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				invite, err := r.Issue(InviteRequest{
					Checkpoints: []venue.CheckpointCode{"gate-north"},
				}, "https://10.11.0.1", "AA", "Sundown")
				if err != nil {
					t.Error(err)
					return
				}
				enrolled, err := r.Redeem(invite.Code, "device")
				if err != nil {
					t.Error(err)
					return
				}
				tokens <- enrolled.Token
			}
		}()
	}
	wg.Wait()
	close(tokens)

	seen := make(map[string]bool)
	for token := range tokens {
		if seen[token] {
			t.Fatal("a token was issued twice under contention")
		}
		seen[token] = true
		if _, ok := r.Authenticate(token); !ok {
			t.Fatal("a token issued under contention does not authenticate")
		}
	}
	if len(seen) != 100 {
		t.Fatalf("%d tokens issued, want 100", len(seen))
	}
}

func BenchmarkAuthenticate(b *testing.B) {
	c := &clock{at: time.Date(2026, 8, 21, 17, 0, 0, 0, time.UTC)}
	r, err := New(Config{Secret: []byte("a-stable-box-secret-at-least-16"), Now: c.now})
	if err != nil {
		b.Fatal(err)
	}
	invite, err := r.Issue(InviteRequest{Checkpoints: []venue.CheckpointCode{"gate-north"}},
		"https://10.11.0.1", "AA", "Sundown")
	if err != nil {
		b.Fatal(err)
	}
	enrolled, err := r.Redeem(invite.Code, "device")
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := r.Authenticate(enrolled.Token); !ok {
			b.Fatal("authentication failed")
		}
	}
}
