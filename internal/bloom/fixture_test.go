package bloom

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ManasMadan/gatecrash/internal/ticket"
)

// fixturePath is where the cross-language conformance fixture lands.
//
// It is committed, because the JavaScript side has to be able to run its tests
// without a Go toolchain — a contributor working on the scanner UI should not need
// one.
const fixturePath = "../../packages/protocol/test/testdata/bloom.json"

// bloomFixture is the shape the TypeScript test reads.
type bloomFixture struct {
	// Filter is the serialised Bloom filter, base64.
	Filter string `json:"filter"`

	// Present are ids that were added. Every one must test positive on both sides.
	Present []string `json:"present"`

	// Absent are ids that were not. Almost all must test negative; a handful of
	// false positives is the filter working as designed, and the test asserts a
	// rate rather than zero.
	Absent []string `json:"absent"`

	Bits     uint64 `json:"bits"`
	Hashes   uint64 `json:"hashes"`
	Elements int    `json:"elements"`
}

// TestWriteCrossLanguageFixture regenerates the fixture the TypeScript reader is
// tested against.
//
// The Bloom filter is the one data structure in Gatecrash implemented twice: once
// in Go on the box, once in TypeScript on the scanner. If the two disagree by a
// single bit, the scanner rejects real tickets offline with no round trip to catch
// it — which is the worst failure mode this system has, because it is silent.
//
// So the agreement is not assumed. Go writes a filter and the ids that went into
// it; the TypeScript test parses that exact filter and asserts every id is found.
// Run with -update to regenerate after a format change.
func TestWriteCrossLanguageFixture(t *testing.T) {
	if os.Getenv("GATECRASH_UPDATE_FIXTURES") == "" {
		t.Skip("set GATECRASH_UPDATE_FIXTURES=1 to regenerate the cross-language fixture")
	}

	// A fixed seed, so regenerating the fixture produces the same file and a diff
	// shows a real change rather than fresh randomness.
	present := deterministicIDs("present", 500)
	absent := deterministicIDs("absent", 2000)

	filter, err := New(len(present), 1e-4)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range present {
		filter.Add(id[:])
	}
	encoded, err := filter.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	fixture := bloomFixture{
		Filter:   base64Std(encoded),
		Bits:     filter.Bits(),
		Hashes:   filter.Hashes(),
		Elements: filter.Len(),
	}
	for _, id := range present {
		fixture.Present = append(fixture.Present, id.String())
	}
	for _, id := range absent {
		fixture.Absent = append(fixture.Absent, id.String())
	}

	raw, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s: %d present, %d absent, %d bytes", fixturePath, len(present), len(absent), len(encoded))
}

// TestFixtureStillMatches checks the committed fixture against the current
// implementation, so a change to the hash or the wire format fails here rather
// than silently diverging from the scanner.
func TestFixtureStillMatches(t *testing.T) {
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Skipf("no committed fixture: %v", err)
	}
	var fixture bloomFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}

	decoded, err := decodeBase64Std(fixture.Filter)
	if err != nil {
		t.Fatal(err)
	}
	var filter Filter
	if err := filter.UnmarshalBinary(decoded); err != nil {
		t.Fatalf("the committed fixture no longer parses: %v", err)
	}
	if filter.Bits() != fixture.Bits || filter.Hashes() != fixture.Hashes {
		t.Fatalf("the committed fixture declares %d bits / %d hashes, the filter has %d / %d",
			fixture.Bits, fixture.Hashes, filter.Bits(), filter.Hashes())
	}

	for _, id := range fixture.Present {
		parsed, err := ticket.ParseID(id)
		if err != nil {
			t.Fatal(err)
		}
		if !filter.Test(parsed[:]) {
			t.Fatalf("id %s was in the fixture's filter but no longer tests present; the hash has changed", id)
		}
	}

	// Rebuilding from the same ids must produce the same bytes, which is what lets
	// a scanner detect a stale filter by comparing hashes.
	rebuilt, err := New(len(fixture.Present), 1e-4)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range fixture.Present {
		parsed, err := ticket.ParseID(id)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt.Add(parsed[:])
	}
	fresh, err := rebuilt.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if base64Std(fresh) != fixture.Filter {
		t.Fatal("rebuilding the fixture's filter from its own ids produced different bytes")
	}
}

// deterministicIDs produces reproducible identifiers from a label.
//
// Not random, so regenerating the fixture is a no-op unless something real
// changed. FNV over the label and the index is enough: these only need to be
// distinct, not unpredictable.
func deterministicIDs(label string, count int) []ticket.ID {
	out := make([]ticket.ID, 0, count)
	for i := 0; i < count; i++ {
		var id ticket.ID
		state := uint64(fnvOffset64)
		for _, b := range []byte(label) {
			state = (state ^ uint64(b)) * fnvPrime64
		}
		for j := 0; j < len(id); j++ {
			state = (state ^ uint64(i+j*31)) * fnvPrime64
			id[j] = byte(state >> 32)
		}
		out = append(out, id)
	}
	return out
}

func base64Std(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

func decodeBase64Std(text string) ([]byte, error) { return base64.StdEncoding.DecodeString(text) }
