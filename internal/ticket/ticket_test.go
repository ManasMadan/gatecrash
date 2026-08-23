package ticket

import (
	"bytes"
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustID(t *testing.T, hexText string) ID {
	t.Helper()
	id, err := ParseID(hexText)
	if err != nil {
		t.Fatalf("ParseID(%q): %v", hexText, err)
	}
	return id
}

func TestIDEncodesToQRAlphanumericCharactersOnly(t *testing.T) {
	// QR alphanumeric mode covers 0-9, A-Z and nine punctuation characters. If
	// an id ever encodes outside that set the encoder silently falls back to
	// byte mode, the symbol grows two versions, and decode reliability on cheap
	// cameras drops. This test is the guard on that promise.
	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	for i := 0; i < 200; i++ {
		encoded := MustNewID().String()
		if len(encoded) != EncodedIDLen {
			t.Fatalf("encoded id is %d characters, want %d", len(encoded), EncodedIDLen)
		}
		if strings.ContainsFunc(encoded, func(r rune) bool { return !strings.ContainsRune(allowed, r) }) {
			t.Fatalf("id %q contains characters outside the base32 alphabet", encoded)
		}
	}
}

func TestParseIDAcceptsBothWireForms(t *testing.T) {
	want := MustNewID()
	for _, form := range []string{want.String(), want.Hex()} {
		got, err := ParseID(form)
		if err != nil {
			t.Fatalf("ParseID(%q): %v", form, err)
		}
		if got != want {
			t.Fatalf("ParseID(%q) = %s, want %s", form, got, want)
		}
	}
}

func TestParseIDBase32RejectsHex(t *testing.T) {
	// Accepting two spellings of one ticket inside a QR payload would mean one
	// ticket has two identities, and two identities is a double admission.
	if _, err := ParseIDBase32(MustNewID().Hex()); err == nil {
		t.Fatal("ParseIDBase32 accepted a hex id")
	}
}

func TestParseIDRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "AAAA", strings.Repeat("A", 25), strings.Repeat("A", 27), strings.Repeat("!", 26)} {
		if _, err := ParseID(in); err == nil {
			t.Errorf("ParseID(%q) accepted garbage", in)
		}
	}
}

func TestDeriveEventMasterIsDeterministicAndEventScoped(t *testing.T) {
	root, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	eventA, eventB := MustNewID(), MustNewID()

	first, err := DeriveEventMaster(root, eventA)
	if err != nil {
		t.Fatal(err)
	}
	again, err := DeriveEventMaster(root, eventA)
	if err != nil {
		t.Fatal(err)
	}
	other, err := DeriveEventMaster(root, eventB)
	if err != nil {
		t.Fatal(err)
	}

	if first != again {
		t.Fatal("derivation is not deterministic")
	}
	if first == other {
		t.Fatal("two events derived the same master key")
	}
	if first == root {
		t.Fatal("derived key equals the root key")
	}
}

func TestDeriveSecretIsDeterministicAndTicketScoped(t *testing.T) {
	master, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	ticketA, ticketB := MustNewID(), MustNewID()

	first, err := DeriveSecret(master, ticketA)
	if err != nil {
		t.Fatal(err)
	}
	again, err := DeriveSecret(master, ticketA)
	if err != nil {
		t.Fatal(err)
	}
	other, err := DeriveSecret(master, ticketB)
	if err != nil {
		t.Fatal(err)
	}

	if first != again {
		t.Fatal("derivation is not deterministic")
	}
	if first == other {
		t.Fatal("two tickets derived the same secret")
	}
}

func TestDeriveSecretRefusesAZeroMaster(t *testing.T) {
	if _, err := DeriveSecret(MasterKey{}, MustNewID()); err == nil {
		t.Fatal("derived a secret from a zero master key")
	}
}

func TestMasterKeyRedactedLeaksNothing(t *testing.T) {
	master, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	redacted := master.Redacted()
	if strings.Contains(redacted, master.String()) {
		t.Fatal("redacted form contains the key")
	}
	if !strings.HasPrefix(redacted, "master:") {
		t.Fatalf("redacted form %q is not recognisable in a log", redacted)
	}
}

func TestMasterKeyRoundTrip(t *testing.T) {
	want, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseMasterKey(want.String())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("master key did not round trip")
	}
	if _, err := ParseMasterKey("short"); err == nil {
		t.Fatal("accepted a short master key")
	}
}

func TestSigningKeyRoundTrip(t *testing.T) {
	signing, verifying, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := ParseSigningKey(signing.String())
	if err != nil {
		t.Fatal(err)
	}
	if !reparsed.Public().Equal(verifying) {
		t.Fatal("reparsed signing key has a different public half")
	}
	if reparsed.Public().Fingerprint() != verifying.Fingerprint() {
		t.Fatal("fingerprints disagree after a round trip")
	}
}

func TestDomainSeparationStopsCrossProtocolSignatureReuse(t *testing.T) {
	signing, verifying, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("same bytes, two domains")
	signature := signing.Sign(domainGC1, message)

	if !verifying.Verify(domainGC1, message, signature) {
		t.Fatal("signature failed in its own domain")
	}
	if verifying.Verify(domainGC2, message, signature) {
		t.Fatal("a GC1 signature verified as GC2")
	}
	if verifying.Verify(domainTicketSecret, message, signature) {
		t.Fatal("a GC1 signature verified in the key-derivation domain")
	}
}

// TestDomainSeparationIsPrefixFree is the reason domainSeparated writes a length
// byte. Without it, domain "ab" + message "c" and domain "a" + message "bc"
// produce identical signed bytes, so a signature minted in one domain is valid
// in the other.
func TestDomainSeparationIsPrefixFree(t *testing.T) {
	first := domainSeparated("ab", []byte("c"))
	second := domainSeparated("a", []byte("bc"))
	if bytes.Equal(first, second) {
		t.Fatalf("ambiguous framing: %q == %q", first, second)
	}
}

func testClaims(t *testing.T) (SigningKey, VerifyingKey, Claims) {
	t.Helper()
	signing, verifying, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return signing, verifying, Claims{
		EventID:  MustNewID(),
		TicketID: MustNewID(),
		Tier:     "VIP",
		IssuedAt: time.Date(2026, 8, 15, 18, 0, 0, 0, time.UTC).UnixMilli(),
	}
}

func TestGC1RoundTripAndLength(t *testing.T) {
	signing, verifying, claims := testClaims(t)

	payload, err := SignGC1(signing, claims)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != GC1Len {
		t.Fatalf("payload is %d characters, want the frozen GC1Len of %d", len(payload), GC1Len)
	}
	if !IsGC1(payload) || IsGC2(payload) {
		t.Fatal("format sniffing misidentified a GC1 payload")
	}

	parsed, err := ParseGC1(payload)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TicketID != claims.TicketID {
		t.Fatal("parsed the wrong ticket id")
	}
	ok, err := parsed.Verify(verifying, claims)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("a freshly signed payload did not verify")
	}
}

// TestGC1SignatureCoversEveryClaim is the test that would catch someone
// "optimising" a field out of signedMessage. Each mutation must break the
// signature, because each field is something a forger would want to change: the
// event (replay a ticket at another show), the tier (upgrade yourself to
// backstage), the issue time (revive a ticket from a cancelled event).
func TestGC1SignatureCoversEveryClaim(t *testing.T) {
	signing, verifying, claims := testClaims(t)
	payload, err := SignGC1(signing, claims)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseGC1(payload)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(Claims) Claims{
		"event id": func(c Claims) Claims { c.EventID = MustNewID(); return c },
		"tier":     func(c Claims) Claims { c.Tier = "GA"; return c },
		"issued at": func(c Claims) Claims {
			c.IssuedAt = c.IssuedAt + 1
			return c
		},
	} {
		mutated := mutate(claims)
		ok, err := parsed.Verify(verifying, mutated)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ok {
			t.Errorf("mutating %s did not break the signature", name)
		}
	}
}

func TestGC1VerifyRefusesClaimsForADifferentTicket(t *testing.T) {
	signing, verifying, claims := testClaims(t)
	payload, err := SignGC1(signing, claims)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseGC1(payload)
	if err != nil {
		t.Fatal(err)
	}

	wrong := claims
	wrong.TicketID = MustNewID()
	// A mismatch means the caller looked up the wrong manifest row and is about
	// to admit the wrong person, which is worth an error rather than a quiet
	// false.
	if _, err := parsed.Verify(verifying, wrong); err == nil {
		t.Fatal("Verify accepted claims for a different ticket without complaint")
	}
}

func TestGC1RejectsAForeignKey(t *testing.T) {
	signing, _, claims := testClaims(t)
	_, attacker, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := SignGC1(signing, claims)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseGC1(payload)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := parsed.Verify(attacker, claims)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("payload verified under an unrelated public key")
	}
}

func TestSignGC1RejectsIncompleteClaims(t *testing.T) {
	signing, _, claims := testClaims(t)
	for name, mutate := range map[string]func(Claims) Claims{
		"no event":  func(c Claims) Claims { c.EventID = ID{}; return c },
		"no ticket": func(c Claims) Claims { c.TicketID = ID{}; return c },
		"no tier":   func(c Claims) Claims { c.Tier = ""; return c },
		"long tier": func(c Claims) Claims { c.Tier = strings.Repeat("x", 256); return c },
		"no time":   func(c Claims) Claims { c.IssuedAt = 0; return c },
	} {
		if _, err := SignGC1(signing, mutate(claims)); err == nil {
			t.Errorf("%s: SignGC1 signed invalid claims", name)
		}
	}
}

func TestParseGC1RejectsMalformedPayloads(t *testing.T) {
	signing, _, claims := testClaims(t)
	valid, err := SignGC1(signing, claims)
	if err != nil {
		t.Fatal(err)
	}

	for name, payload := range map[string]string{
		"empty":            "",
		"wrong prefix":     "GC9" + valid[3:],
		"truncated":        valid[:len(valid)-1],
		"extra character":  valid + "A",
		"missing sections": "GC1." + claims.TicketID.String(),
		"bad base32":       valid[:len(valid)-1] + "!",
		"gc2 payload":      "GC2.AAAAAAAAAAAAAAAAAAAAAAAAAA.1.AAAAAAAAAAAAAAAA",
	} {
		if _, err := ParseGC1(payload); err == nil {
			t.Errorf("%s: ParseGC1 accepted %q", name, payload)
		}
	}
}

func TestGC1FitsInsideQRVersion7Alphanumeric(t *testing.T) {
	// Version 7 at error correction level L holds 154 alphanumeric characters.
	// The README publishes "QR version 7" as a property of the format; if a
	// change pushes the payload past this, the claim is wrong and cheap cameras
	// get measurably slower.
	const version7AlphanumericCapacityL = 154
	if GC1Len > version7AlphanumericCapacityL {
		t.Fatalf("GC1 is %d characters, which no longer fits QR version 7 (%d)", GC1Len, version7AlphanumericCapacityL)
	}
}

func gc2Fixture(t *testing.T) (MasterKey, ID, ID, Secret) {
	t.Helper()
	master, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	eventID, ticketID := MustNewID(), MustNewID()
	secret, err := DeriveSecret(master, ticketID)
	if err != nil {
		t.Fatal(err)
	}
	return master, eventID, ticketID, secret
}

func TestGC2RoundTrip(t *testing.T) {
	master, eventID, ticketID, secret := gc2Fixture(t)
	window := WindowAt(time.Date(2026, 8, 21, 20, 30, 0, 0, time.UTC))

	payload := GenerateGC2(secret, eventID, ticketID, window)
	if !IsGC2(payload) || IsGC1(payload) {
		t.Fatal("format sniffing misidentified a GC2 payload")
	}

	parsed, err := ParseGC2(payload)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TicketID != ticketID || parsed.Window != window {
		t.Fatalf("parsed %s window %d, want %s window %d", parsed.TicketID, parsed.Window, ticketID, window)
	}
	if err := ValidateGC2(master, eventID, parsed, window); err != nil {
		t.Fatalf("a freshly generated code did not validate: %v", err)
	}
}

func TestGC2AcceptsOneWindowOfDriftEitherWay(t *testing.T) {
	master, eventID, ticketID, secret := gc2Fixture(t)
	boxWindow := WindowAt(time.Date(2026, 8, 21, 20, 30, 0, 0, time.UTC))

	for _, drift := range []Window{-1, 0, 1} {
		payload, err := ParseGC2(GenerateGC2(secret, eventID, ticketID, boxWindow+drift))
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateGC2(master, eventID, payload, boxWindow); err != nil {
			t.Errorf("drift %+d rejected: %v", drift, err)
		}
	}
	for _, drift := range []Window{-2, 2, -120, 120} {
		payload, err := ParseGC2(GenerateGC2(secret, eventID, ticketID, boxWindow+drift))
		if err != nil {
			t.Fatal(err)
		}
		err = ValidateGC2(master, eventID, payload, boxWindow)
		if !errors.Is(err, ErrExpiredWindow) {
			t.Errorf("drift %+d gave %v, want ErrExpiredWindow", drift, err)
		}
	}
}

// TestGC2ScreenshotDiesWithinTwoWindows is the anti-screenshot claim from the
// README, asserted rather than asserted-in-prose: a code captured now is
// rejected once the box has moved two windows on, which is at most 60 seconds.
func TestGC2ScreenshotDiesWithinTwoWindows(t *testing.T) {
	master, eventID, ticketID, secret := gc2Fixture(t)
	captured := WindowAt(time.Date(2026, 8, 21, 20, 30, 0, 0, time.UTC))
	screenshot, err := ParseGC2(GenerateGC2(secret, eventID, ticketID, captured))
	if err != nil {
		t.Fatal(err)
	}

	if err := ValidateGC2(master, eventID, screenshot, captured+1); err != nil {
		t.Fatalf("code died too early, at one window: %v", err)
	}
	if err := ValidateGC2(master, eventID, screenshot, captured+2); !errors.Is(err, ErrExpiredWindow) {
		t.Fatalf("code survived two windows: %v", err)
	}
	if elapsed := 2 * WindowSeconds * time.Second; elapsed > 60*time.Second {
		t.Fatalf("two windows is %s, which breaks the published 60 second claim", elapsed)
	}
}

func TestGC2RejectsAForgedMAC(t *testing.T) {
	master, eventID, ticketID, secret := gc2Fixture(t)
	window := WindowAt(time.Now())
	parsed, err := ParseGC2(GenerateGC2(secret, eventID, ticketID, window))
	if err != nil {
		t.Fatal(err)
	}

	forged := parsed
	forged.MAC = bytes.Clone(parsed.MAC)
	forged.MAC[0] ^= 0x01
	if err := ValidateGC2(master, eventID, forged, window); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("flipping one MAC bit gave %v, want ErrBadMAC", err)
	}
}

func TestGC2MACIsBoundToTheEvent(t *testing.T) {
	// Two events that happen to issue the same ticket id must not accept each
	// other's codes, which is why the event id is inside the MAC message even
	// though it is not inside the payload.
	master, eventID, ticketID, secret := gc2Fixture(t)
	window := WindowAt(time.Now())
	parsed, err := ParseGC2(GenerateGC2(secret, eventID, ticketID, window))
	if err != nil {
		t.Fatal(err)
	}

	if err := ValidateGC2(master, MustNewID(), parsed, window); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("a code validated against a different event: %v", err)
	}
}

func TestGC2MACIsBoundToTheWindow(t *testing.T) {
	master, eventID, ticketID, secret := gc2Fixture(t)
	window := WindowAt(time.Now())
	parsed, err := ParseGC2(GenerateGC2(secret, eventID, ticketID, window))
	if err != nil {
		t.Fatal(err)
	}

	// Relabelling a captured code with a fresher window is the obvious attack;
	// the MAC covers the window so the relabel does not verify.
	relabelled := parsed
	relabelled.Window = window + 1
	if err := ValidateGC2(master, eventID, relabelled, window+1); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("relabelling the window gave %v, want ErrBadMAC", err)
	}
}

func TestGC2MACIsBoundToTheTicket(t *testing.T) {
	master, eventID, ticketID, secret := gc2Fixture(t)
	window := WindowAt(time.Now())
	parsed, err := ParseGC2(GenerateGC2(secret, eventID, ticketID, window))
	if err != nil {
		t.Fatal(err)
	}

	// Swapping in someone else's ticket id makes the box derive a different
	// secret, so the MAC cannot verify.
	stolen := parsed
	stolen.TicketID = MustNewID()
	if err := ValidateGC2(master, eventID, stolen, window); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("swapping the ticket id gave %v, want ErrBadMAC", err)
	}
}

func TestParseGC2RejectsMalformedPayloads(t *testing.T) {
	_, eventID, ticketID, secret := gc2Fixture(t)
	valid := GenerateGC2(secret, eventID, ticketID, WindowAt(time.Now()))

	for name, payload := range map[string]string{
		"empty":          "",
		"wrong prefix":   "GC1" + valid[3:],
		"too few parts":  strings.Join(strings.Split(valid, ".")[:3], "."),
		"too many parts": valid + ".EXTRA",
		"bad window":     "GC2." + ticketID.String() + ".!!!." + strings.Repeat("A", encodedMACLen),
		"short mac":      "GC2." + ticketID.String() + ".1.AAAA",
		"bad mac base32": "GC2." + ticketID.String() + ".1." + strings.Repeat("!", encodedMACLen),
	} {
		if _, err := ParseGC2(payload); err == nil {
			t.Errorf("%s: ParseGC2 accepted %q", name, payload)
		}
	}
}

func TestGC2PayloadStaysSmallEnoughForAPhoneScreen(t *testing.T) {
	// Version 3 at error correction level L holds 77 alphanumeric characters.
	// GC2 living inside a version 3 symbol is what makes it readable off a
	// cracked screen at low brightness, and the README says so.
	const version3AlphanumericCapacityL = 77
	_, eventID, ticketID, secret := gc2Fixture(t)
	// A window far in the future is the widest the base36 component ever gets.
	payload := GenerateGC2(secret, eventID, ticketID, WindowAt(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)))
	if len(payload) > version3AlphanumericCapacityL {
		t.Fatalf("GC2 payload is %d characters, past QR version 3 capacity (%d)", len(payload), version3AlphanumericCapacityL)
	}
}

func TestWindowRoundTripsThroughBase36(t *testing.T) {
	for _, want := range []Window{0, 1, 35, 36, 58_000_000, WindowAt(time.Now())} {
		got, err := parseWindow(want.String())
		if err != nil {
			t.Fatalf("parseWindow(%q): %v", want.String(), err)
		}
		if got != want {
			t.Fatalf("window %d round tripped to %d", want, got)
		}
	}
}

func TestWindowStartIsAligned(t *testing.T) {
	at := time.Date(2026, 8, 21, 20, 30, 17, 0, time.UTC)
	start := WindowAt(at).Start()
	if start.After(at) {
		t.Fatalf("window start %s is after the instant %s", start, at)
	}
	if at.Sub(start) >= WindowSeconds*time.Second {
		t.Fatalf("window start %s is more than one window before %s", start, at)
	}
	if start.Unix()%WindowSeconds != 0 {
		t.Fatalf("window start %s is not aligned to the rotation period", start)
	}
}

func TestAcceptanceWindowMatchesValidation(t *testing.T) {
	master, eventID, ticketID, secret := gc2Fixture(t)
	boxWindow := WindowAt(time.Now())
	earliest, latest := AcceptanceWindow(boxWindow)

	for window := earliest - 1; window <= latest+1; window++ {
		parsed, err := ParseGC2(GenerateGC2(secret, eventID, ticketID, window))
		if err != nil {
			t.Fatal(err)
		}
		err = ValidateGC2(master, eventID, parsed, boxWindow)
		inBand := window >= earliest && window <= latest
		if inBand != (err == nil) {
			t.Errorf("window %d: AcceptanceWindow says inBand=%v but validation gave %v", window, inBand, err)
		}
	}
}

func TestEncodedLengthConstantsMatchTheEncoder(t *testing.T) {
	// These constants are used to reject payloads by length before any crypto
	// runs, so they have to agree with the encoder rather than with a comment.
	if got := base32.StdEncoding.WithPadding(base32.NoPadding).EncodedLen(IDLen); got != EncodedIDLen {
		t.Errorf("EncodedIDLen is %d, encoder says %d", EncodedIDLen, got)
	}
	if got := base32.StdEncoding.WithPadding(base32.NoPadding).EncodedLen(64); got != encodedSigLen {
		t.Errorf("encodedSigLen is %d, encoder says %d", encodedSigLen, got)
	}
	if got := base32.StdEncoding.WithPadding(base32.NoPadding).EncodedLen(MACLen); got != encodedMACLen {
		t.Errorf("encodedMACLen is %d, encoder says %d", encodedMACLen, got)
	}
}

func BenchmarkValidateGC2(b *testing.B) {
	master, err := NewMasterKey()
	if err != nil {
		b.Fatal(err)
	}
	eventID, ticketID := MustNewID(), MustNewID()
	secret, err := DeriveSecret(master, ticketID)
	if err != nil {
		b.Fatal(err)
	}
	window := WindowAt(time.Now())
	parsed, err := ParseGC2(GenerateGC2(secret, eventID, ticketID, window))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := ValidateGC2(master, eventID, parsed, window); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyGC1(b *testing.B) {
	signing, verifying, err := GenerateSigningKey()
	if err != nil {
		b.Fatal(err)
	}
	claims := Claims{EventID: MustNewID(), TicketID: MustNewID(), Tier: "GA", IssuedAt: time.Now().UnixMilli()}
	payload, err := SignGC1(signing, claims)
	if err != nil {
		b.Fatal(err)
	}
	parsed, err := ParseGC1(payload)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ok, err := parsed.Verify(verifying, claims)
		if err != nil || !ok {
			b.Fatal("verification failed")
		}
	}
}

// TestGC1LengthMatchesTheClients pins a number that exists in three places.
//
// Go computes it from its parts, which is the right way round — change the prefix or
// the encoding and it follows. TypeScript hardcodes it as GC1_LENGTH because a
// scanner checks the length before it parses anything, and a phone has no business
// recomputing a format. Kotlin and Swift will do the same.
//
// That makes this the one place the three can be tied together, and 134 is also a QR
// version 7 alphanumeric payload — one character more and every printed ticket needs
// a denser code, which is a real change to how well it scans off paper in bad light.
func TestGC1LengthMatchesTheClients(t *testing.T) {
	const clientsExpect = 134 // packages/protocol/src/qr.ts, GC1_LENGTH

	if GC1Len != clientsExpect {
		t.Errorf("GC1Len is %d and every client expects %d — update GC1_LENGTH in "+
			"packages/protocol/src/qr.ts and check the QR version still fits", GC1Len, clientsExpect)
	}
}
