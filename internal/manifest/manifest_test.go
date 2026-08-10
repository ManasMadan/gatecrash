package manifest

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

var doors = time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)

// fixture builds a small but complete signed manifest.
func fixture(t *testing.T) (ticket.SigningKey, ticket.VerifyingKey, Body) {
	t.Helper()

	signing, verifying, err := ticket.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	eventID := ticket.MustNewID()
	root, err := ticket.NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	master, err := ticket.DeriveEventMaster(root, eventID)
	if err != nil {
		t.Fatal(err)
	}

	plan := venue.Plan{
		Zones: []venue.Zone{
			{Code: "perimeter", Name: "Ground", Capacity: 2000},
			{Code: "arena", Name: "Arena", Parent: "perimeter", Restricted: true},
		},
		Sections: []venue.Section{
			{
				Code: "block-a", Name: "Block A", Kind: venue.SectionSeated, Zone: "arena",
				Rows: []venue.Row{{Label: "A", Start: venue.Point{X: 0, Y: 0}, End: venue.Point{X: 10, Y: 0}, Seats: []venue.Seat{{Number: "1"}, {Number: "2"}}}},
			},
		},
		Checkpoints: []venue.Checkpoint{
			{Code: "gate-north", Name: "North Gate", Zone: "perimeter", Direction: venue.DirectionIn, Policy: venue.PolicyOnce},
			{Code: "portal-a", Name: "Portal A", Zone: "arena", Direction: venue.DirectionIn, Policy: venue.PolicyOnce, Requires: []venue.ZoneCode{"perimeter"}},
		},
		Tiers: []venue.Tier{
			{Code: "ga", Name: "General Admission", Zones: []venue.ZoneCode{"perimeter", "arena"}},
		},
		Map: venue.Map{Width: 100, Height: 100},
	}

	var tickets []engine.Ticket
	for i, seat := range []venue.SeatRef{
		{Section: "block-a", Row: "A", Seat: "1"},
		{Section: "block-a", Row: "A", Seat: "2"},
		{},
	} {
		id := ticket.MustNewID()
		claims := ticket.Claims{EventID: eventID, TicketID: id, Tier: "ga", IssuedAt: doors.Add(-48 * time.Hour).UnixMilli()}
		payload, err := ticket.SignGC1(signing, claims)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ticket.ParseGC1(payload)
		if err != nil {
			t.Fatal(err)
		}
		format := engine.FormatStatic
		if i == 2 {
			format = engine.FormatRotating
		}
		tickets = append(tickets, engine.Ticket{
			ID: id, EventID: eventID, Tier: "ga", Seat: seat,
			IssuedAt: claims.IssuedAt, Signature: parsed.Signature, Format: format,
		})
	}

	return signing, verifying, Body{
		Event: Event{
			ID: eventID, Name: "Sundown Sessions", Venue: "Kingdom of Dreams",
			Timezone: "Asia/Kolkata", Doors: doors, Curfew: doors.Add(7 * time.Hour),
			Mode: engine.ModeStrict, Support: "+91 90000 00000",
		},
		Venue:     plan,
		Tickets:   tickets,
		Devices:   []engine.Device{{ID: "scanner-north", Name: "North 1", Checkpoints: []venue.CheckpointCode{"gate-north"}}},
		Verifying: verifying,
		Master:    master.String(),
		IssuedAt:  doors.Add(-24 * time.Hour),
		Sequence:  7,
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	signing, verifying, body := fixture(t)

	env, err := Sign(signing, body)
	if err != nil {
		t.Fatal(err)
	}
	if env.Format != Format {
		t.Errorf("format is %q", env.Format)
	}
	if env.Fingerprint != verifying.Fingerprint() {
		t.Errorf("fingerprint is %q, want %q", env.Fingerprint, verifying.Fingerprint())
	}

	got, err := Verify(env, verifying, verifying.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if got.Event.Name != body.Event.Name || len(got.Tickets) != len(body.Tickets) {
		t.Fatalf("round trip lost data: %q with %d tickets", got.Event.Name, len(got.Tickets))
	}
	if got.Sequence != 7 {
		t.Errorf("sequence is %d, want 7", got.Sequence)
	}
}

func TestEnvelopeSurvivesAFileRoundTrip(t *testing.T) {
	signing, verifying, body := fixture(t)
	env, err := Sign(signing, body)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reparsed.Body, env.Body) {
		t.Fatal("the body changed on the way through a file, so the signature would not verify")
	}
	if _, err := Verify(reparsed, verifying, verifying.Fingerprint()); err != nil {
		t.Fatalf("a manifest written to a file and read back does not verify: %v", err)
	}
}

// TestVerifyRejectsAnyEditToTheBody is the property the whole envelope design
// exists for: the signature covers exact bytes, so nothing inside can be changed
// without detection, and nothing is parsed before it is checked.
func TestVerifyRejectsAnyEditToTheBody(t *testing.T) {
	signing, verifying, body := fixture(t)
	env, err := Sign(signing, body)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a flipped byte", func(t *testing.T) {
		tampered := env
		tampered.Body = bytes.Clone(env.Body)
		tampered.Body[len(tampered.Body)/2] ^= 0x01
		if _, err := Verify(tampered, verifying, verifying.Fingerprint()); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("got %v, want ErrBadSignature", err)
		}
	})

	t.Run("an added ticket", func(t *testing.T) {
		// The attack that matters: somebody with write access to the file adds
		// themselves to the guest list.
		extra := body
		extra.Tickets = append(append([]engine.Ticket(nil), body.Tickets...), engine.Ticket{
			ID: ticket.MustNewID(), EventID: body.Event.ID, Tier: "ga",
			IssuedAt: doors.UnixMilli(), Format: engine.FormatStatic,
		})
		forged, err := Sign(signing, extra)
		if err != nil {
			t.Fatal(err)
		}
		// Re-signed by the real key it verifies, which is correct: the organizer
		// may add tickets. Swapping just the body into the original envelope must
		// not.
		if _, err := Verify(forged, verifying, verifying.Fingerprint()); err != nil {
			t.Fatalf("a legitimately re-signed manifest was rejected: %v", err)
		}
		spliced := env
		spliced.Body = forged.Body
		if _, err := Verify(spliced, verifying, verifying.Fingerprint()); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("a spliced body verified: %v", err)
		}
	})

	t.Run("a mutated signature", func(t *testing.T) {
		tampered := env
		tampered.Signature = bytes.Clone(env.Signature)
		tampered.Signature[0] ^= 0xFF
		if _, err := Verify(tampered, verifying, verifying.Fingerprint()); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("got %v, want ErrBadSignature", err)
		}
	})

	t.Run("a truncated body", func(t *testing.T) {
		tampered := env
		tampered.Body = env.Body[:len(env.Body)-10]
		if _, err := Verify(tampered, verifying, verifying.Fingerprint()); err == nil {
			t.Fatal("a truncated body verified")
		}
	})
}

// TestVerifyRefusesAManifestSignedByAnotherKey is the substitution attack. A
// manifest that carries its own verification key and is trusted on that basis is
// not signed, it is decorated, so the box always passes the fingerprint it was
// provisioned with.
func TestVerifyRefusesAManifestSignedByAnotherKey(t *testing.T) {
	_, verifying, body := fixture(t)
	attackerSigning, attackerVerifying, err := ticket.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	// The attacker builds a whole manifest of their own, including their own key
	// in the body, and signs it consistently.
	forged := body
	forged.Verifying = attackerVerifying
	env, err := Sign(attackerSigning, forged)
	if err != nil {
		t.Fatal(err)
	}

	// Self-consistent, so a naive check passes.
	if _, err := Verify(env, ticket.VerifyingKey{}, ""); err != nil {
		t.Fatalf("the forged manifest is not self-consistent, so this test proves nothing: %v", err)
	}
	// Against the key the box was provisioned with, it fails.
	if _, err := Verify(env, verifying, verifying.Fingerprint()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
	// And a fingerprint mismatch is reported distinctly, so the operator can see
	// they have the wrong file rather than a corrupt one.
	if _, err := Verify(env, attackerVerifying, verifying.Fingerprint()); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("got %v, want ErrWrongKey", err)
	}
}

func TestVerifyRejectsAForeignFormat(t *testing.T) {
	signing, verifying, body := fixture(t)
	env, err := Sign(signing, body)
	if err != nil {
		t.Fatal(err)
	}
	env.Format = "some-other-thing/v1"
	if _, err := Verify(env, verifying, verifying.Fingerprint()); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("got %v, want ErrBadFormat", err)
	}
}

// TestValidateCatchesManifestsThatWouldFailAtAGate is where most of this
// package's value sits. Each of these is a mistake somebody makes at 4pm on
// event day, and each is far cheaper to find here than in a queue at 8pm.
func TestValidateCatchesManifestsThatWouldFailAtAGate(t *testing.T) {
	_, _, base := fixture(t)

	for name, mutate := range map[string]func(Body) Body{
		"no event id":   func(b Body) Body { b.Event.ID = ticket.ID{}; return b },
		"no event name": func(b Body) Body { b.Event.Name = ""; return b },
		"no mode":       func(b Body) Body { b.Event.Mode = ""; return b },
		"unknown mode":  func(b Body) Body { b.Event.Mode = "eventually"; return b },
		"no key":        func(b Body) Body { b.Verifying = ticket.VerifyingKey{}; return b },
		"curfew before doors": func(b Body) Body {
			b.Event.Curfew = b.Event.Doors.Add(-time.Hour)
			return b
		},
		"broken venue": func(b Body) Body {
			b.Venue.Checkpoints[0].Zone = "nowhere"
			return b
		},
		"bad master key": func(b Body) Body { b.Master = "not base64 at all!!"; return b },
		"ticket with no id": func(b Body) Body {
			b.Tickets = append([]engine.Ticket(nil), b.Tickets...)
			b.Tickets[0].ID = ticket.ID{}
			return b
		},
		"duplicate ticket": func(b Body) Body {
			b.Tickets = append(append([]engine.Ticket(nil), b.Tickets...), b.Tickets[0])
			return b
		},
		"ticket for another event": func(b Body) Body {
			b.Tickets = append([]engine.Ticket(nil), b.Tickets...)
			b.Tickets[0].EventID = ticket.MustNewID()
			return b
		},
		"ticket with an undefined tier": func(b Body) Body {
			b.Tickets = append([]engine.Ticket(nil), b.Tickets...)
			b.Tickets[0].Tier = "platinum"
			return b
		},
		"ticket for a seat that does not exist": func(b Body) Body {
			b.Tickets = append([]engine.Ticket(nil), b.Tickets...)
			b.Tickets[0].Seat = venue.SeatRef{Section: "block-a", Row: "Z", Seat: "99"}
			return b
		},
		"ticket with no format": func(b Body) Body {
			b.Tickets = append([]engine.Ticket(nil), b.Tickets...)
			b.Tickets[0].Format = ""
			return b
		},
		"ticket with an unknown format": func(b Body) Body {
			b.Tickets = append([]engine.Ticket(nil), b.Tickets...)
			b.Tickets[0].Format = "hologram"
			return b
		},
		"rotating tickets with no master key": func(b Body) Body {
			b.Master = ""
			return b
		},
		"device with no id": func(b Body) Body {
			b.Devices = append([]engine.Device(nil), b.Devices...)
			b.Devices[0].ID = ""
			return b
		},
		"duplicate device": func(b Body) Body {
			b.Devices = append(append([]engine.Device(nil), b.Devices...), b.Devices[0])
			return b
		},
		"device allowlisted for a checkpoint that does not exist": func(b Body) Body {
			b.Devices = append([]engine.Device(nil), b.Devices...)
			b.Devices[0].Checkpoints = []venue.CheckpointCode{"gate-west"}
			return b
		},
	} {
		if err := mutate(base).Validate(); err == nil {
			t.Errorf("%s: Validate accepted it", name)
		}
	}
}

func TestSignRefusesToSignAnInvalidBody(t *testing.T) {
	signing, _, body := fixture(t)
	body.Event.Name = ""
	if _, err := Sign(signing, body); err == nil {
		t.Fatal("Sign produced a signature over an invalid manifest")
	}
}

func TestPrintOnlyEventsNeedNoMasterKey(t *testing.T) {
	signing, verifying, body := fixture(t)
	body.Master = ""
	// Drop the rotating ticket, since rotating codes need a master key.
	var static []engine.Ticket
	for _, t := range body.Tickets {
		if t.Format == engine.FormatStatic {
			static = append(static, t)
		}
	}
	body.Tickets = static

	env, err := Sign(signing, body)
	if err != nil {
		t.Fatalf("a print-only manifest was refused: %v", err)
	}
	got, err := Verify(env, verifying, verifying.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	master, err := got.MasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if !master.IsZero() {
		t.Fatal("a print-only manifest produced a master key")
	}
}

func TestSummarise(t *testing.T) {
	_, _, body := fixture(t)
	summary := body.Summarise()

	if summary.Tickets != 3 || summary.Rotating != 1 {
		t.Errorf("summary counts %d tickets, %d rotating", summary.Tickets, summary.Rotating)
	}
	if summary.Zones != 2 || summary.Checkpoints != 2 || summary.Tiers != 1 || summary.Sections != 1 {
		t.Errorf("summary shape is %+v", summary)
	}
	if summary.Seats != 2 {
		t.Errorf("summary counts %d seats, want 2", summary.Seats)
	}
	if summary.Mode != engine.ModeStrict {
		t.Errorf("summary mode is %s", summary.Mode)
	}
}

func TestDigestIdentifiesTheExactFile(t *testing.T) {
	signing, _, body := fixture(t)
	first, err := Sign(signing, body)
	if err != nil {
		t.Fatal(err)
	}
	// Re-signing the same body gives the same bytes, so the digest is stable and
	// an operator can compare the box with the office.
	again, err := Sign(signing, body)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() != again.Digest() {
		t.Fatal("two signings of the same body produced different digests")
	}

	changed := body
	changed.Sequence++
	other, err := Sign(signing, changed)
	if err != nil {
		t.Fatal(err)
	}
	if other.Digest() == first.Digest() {
		t.Fatal("a changed manifest produced the same digest")
	}
	if len(first.Digest()) != 16 {
		t.Errorf("digest is %d characters, want something a human can read out", len(first.Digest()))
	}
}

func TestBloomCoversEveryTicket(t *testing.T) {
	_, _, body := fixture(t)
	filter, err := body.Bloom(1e-6)
	if err != nil {
		t.Fatal(err)
	}
	for _, t2 := range body.Tickets {
		if !filter.Test(t2.ID[:]) {
			t.Fatalf("ticket %s is missing from the filter, so a gate would reject it offline", t2.ID)
		}
	}
	if filter.Len() != len(body.Tickets) {
		t.Errorf("filter holds %d, want %d", filter.Len(), len(body.Tickets))
	}
}

func TestBloomHandlesAnEmptyManifest(t *testing.T) {
	// A box set up before any tickets are issued still serves a manifest, and a
	// filter sized for zero elements is undefined.
	_, _, body := fixture(t)
	body.Tickets = nil
	filter, err := body.Bloom(1e-6)
	if err != nil {
		t.Fatal(err)
	}
	stranger := ticket.MustNewID()
	if filter.Test(stranger[:]) {
		t.Error("an empty filter matched a random id")
	}
}

func TestIssuedByTier(t *testing.T) {
	_, _, body := fixture(t)
	counts := body.IssuedByTier()
	if counts["ga"] != 3 {
		t.Fatalf("ga count is %d, want 3", counts["ga"])
	}
}

func TestSealRoundTrip(t *testing.T) {
	signing, verifying, body := fixture(t)
	env, err := Sign(signing, body)
	if err != nil {
		t.Fatal(err)
	}

	const passphrase = "correct horse battery staple"
	sealed, err := Seal(env, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Format != SealFormat {
		t.Errorf("sealed format is %q", sealed.Format)
	}
	// The master key must not be readable in the sealed bytes. This is the whole
	// point: the file travels on a USB stick.
	if bytes.Contains(sealed.Ciphertext, []byte(body.Master)) {
		t.Fatal("the master key is present in plaintext inside the sealed file")
	}
	// The fingerprint stays in the clear so an operator can tell which event a
	// sealed file belongs to without the passphrase.
	if sealed.Fingerprint != verifying.Fingerprint() {
		t.Errorf("sealed fingerprint is %q", sealed.Fingerprint)
	}

	opened, err := Open(sealed, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.Body, env.Body) {
		t.Fatal("unsealing did not return the original envelope bytes")
	}
	// Decryption is confidentiality; the signature is still what establishes
	// authenticity, and it must still check out afterwards.
	if _, err := Verify(opened, verifying, verifying.Fingerprint()); err != nil {
		t.Fatalf("the unsealed manifest does not verify: %v", err)
	}
}

func TestSealIsNondeterministic(t *testing.T) {
	signing, _, body := fixture(t)
	env, err := Sign(signing, body)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Seal(env, "pass")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Seal(env, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Fatal("sealing twice produced identical ciphertext, so the salt or nonce is being reused")
	}
}

func TestOpenRejectsTheWrongPassphraseAndTampering(t *testing.T) {
	signing, _, body := fixture(t)
	env, err := Sign(signing, body)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(env, "the right one")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Open(sealed, "the wrong one"); !errors.Is(err, ErrBadPassphrase) {
		t.Errorf("got %v, want ErrBadPassphrase", err)
	}

	t.Run("mutated ciphertext", func(t *testing.T) {
		bad := sealed
		bad.Ciphertext = bytes.Clone(sealed.Ciphertext)
		bad.Ciphertext[0] ^= 0x01
		if _, err := Open(bad, "the right one"); !errors.Is(err, ErrBadPassphrase) {
			t.Errorf("got %v, want ErrBadPassphrase", err)
		}
	})

	t.Run("downgraded kdf parameters", func(t *testing.T) {
		// Without the parameters being authenticated, an attacker could rewrite
		// them to one cheap pass and brute-force the passphrase offline.
		bad := sealed
		bad.Time = 1
		bad.Memory = 8
		if _, err := Open(bad, "the right one"); err == nil {
			t.Fatal("a downgraded sealed file opened")
		}
	})

	t.Run("absurd memory parameter", func(t *testing.T) {
		bad := sealed
		bad.Memory = 64 * 1024 * 1024 // 64 GiB
		if _, err := Open(bad, "the right one"); !errors.Is(err, ErrBadFormat) {
			t.Fatalf("got %v, want the allocation guard to refuse it", err)
		}
	})

	t.Run("missing parameters", func(t *testing.T) {
		for _, bad := range []Sealed{
			{Format: SealFormat, Salt: sealed.Salt, Time: 0, Memory: argonMemory, Threads: 1},
			{Format: SealFormat, Salt: sealed.Salt, Time: 1, Memory: 0, Threads: 1},
			{Format: SealFormat, Salt: sealed.Salt, Time: 1, Memory: argonMemory, Threads: 0},
			{Format: SealFormat, Salt: []byte("short"), Time: 1, Memory: argonMemory, Threads: 1},
			{Format: "nope", Salt: sealed.Salt, Time: 1, Memory: argonMemory, Threads: 1},
		} {
			if _, err := Open(bad, "x"); !errors.Is(err, ErrBadFormat) {
				t.Errorf("got %v, want ErrBadFormat", err)
			}
		}
	})
}

func TestSealNeedsAPassphrase(t *testing.T) {
	signing, _, body := fixture(t)
	env, err := Sign(signing, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(env, ""); err == nil {
		t.Fatal("sealing with an empty passphrase succeeded")
	}
}

func TestAttendanceRoundTrip(t *testing.T) {
	boxSigning, boxVerifying, err := ticket.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	_, _, body := fixture(t)

	report := Attendance{
		EventID:        body.Event.ID,
		Event:          body.Event.Name,
		ManifestDigest: "abcdef0123456789",
		OpenedAt:       doors,
		ClosedAt:       doors.Add(6 * time.Hour),
	}

	signed, err := SignAttendance(boxSigning, report)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyAttendance(signed, boxVerifying)
	if err != nil {
		t.Fatal(err)
	}
	if got.EventID != report.EventID || got.Event != report.Event {
		t.Fatal("the report changed on the way through")
	}
	if got.BoxKey.Fingerprint() != boxVerifying.Fingerprint() {
		t.Error("the report does not carry the box key")
	}

	// A promoter editing the numbers on the way to the artist's manager is the
	// threat this signature exists for.
	tampered := signed
	tampered.Body = bytes.ReplaceAll(signed.Body, []byte(body.Event.Name), []byte(strings.Repeat("x", len(body.Event.Name))))
	if _, err := VerifyAttendance(tampered, boxVerifying); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}

	// And a report signed by some other box does not pass as this one's.
	otherSigning, _, err := ticket.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := SignAttendance(otherSigning, report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAttendance(other, boxVerifying); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestAttendanceRejectsAForeignFormat(t *testing.T) {
	boxSigning, boxVerifying, err := ticket.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignAttendance(boxSigning, Attendance{EventID: ticket.MustNewID()})
	if err != nil {
		t.Fatal(err)
	}
	signed.Format = "nope/v1"
	if _, err := VerifyAttendance(signed, boxVerifying); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("got %v, want ErrBadFormat", err)
	}
}

func BenchmarkVerifyManifest(b *testing.B) {
	signing, verifying, err := ticket.GenerateSigningKey()
	if err != nil {
		b.Fatal(err)
	}
	eventID := ticket.MustNewID()
	body := Body{
		Event: Event{ID: eventID, Name: "Bench", Mode: engine.ModeStrict},
		Venue: venue.Plan{
			Zones:       []venue.Zone{{Code: "perimeter"}},
			Checkpoints: []venue.Checkpoint{{Code: "gate", Zone: "perimeter"}},
			Tiers:       []venue.Tier{{Code: "ga", Zones: []venue.ZoneCode{"perimeter"}}},
		},
		Verifying: verifying,
		IssuedAt:  doors,
	}
	for i := 0; i < 5000; i++ {
		body.Tickets = append(body.Tickets, engine.Ticket{
			ID: ticket.MustNewID(), EventID: eventID, Tier: "ga",
			IssuedAt: doors.UnixMilli(), Format: engine.FormatStatic,
		})
	}
	env, err := Sign(signing, body)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Verify(env, verifying, verifying.Fingerprint()); err != nil {
			b.Fatal(err)
		}
	}
}
