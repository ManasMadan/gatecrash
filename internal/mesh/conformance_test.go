package mesh

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/ManasMadan/gatecrash/internal/meshcrypto"
)

// conformancePath holds the values the Kotlin and Swift ports are checked against.
//
// The Go implementation is the reference, so the fixture is generated from it rather
// than written by hand. A hand-written fixture is a second implementation of the format
// with no tests, and when it disagrees with the code nobody knows which one is wrong.
const conformancePath = "testdata/conformance.json"

type conformance struct {
	FrameEncoded   string            `json:"frame_encoded"`
	FrameAAD       string            `json:"frame_aad"`
	FrameHoppedAAD string            `json:"frame_hopped_aad"`
	ChannelID      string            `json:"channel_id"`
	Fingerprints   map[string]uint16 `json:"cuckoo_fingerprints"`
	BeaconTokens   map[string]string `json:"beacon_tokens"`
}

// conformanceFrame is the frame the fixture pins: every header field non-zero and
// distinguishable, so a port that transposes two of them fails rather than passes.
func conformanceFrame() Frame {
	return Frame{
		Version: Version,
		Kind:    KindChannel,
		Flags:   FlagPriority,
		TTL:     4,
		ID:      msgID(0x0102030405060708),
		Channel: meshcrypto.ChannelID{9, 10, 11, 12},
		Body:    []byte("hello mesh"),
	}
}

func buildConformance(t *testing.T) conformance {
	t.Helper()

	frame := conformanceFrame()
	raw, err := frame.Encode()
	if err != nil {
		t.Fatal(err)
	}
	hopped, ok := frame.Hop()
	if !ok {
		t.Fatal("the conformance frame will not hop")
	}

	key := meshcrypto.DeriveChannelKey("SUNDOWN", "lost-and-found", "orange lanyard")

	var beacon meshcrypto.BeaconKey
	for i := range beacon {
		beacon[i] = byte(i)
	}
	tokens := map[string]string{}
	for _, window := range []string{"0", "1", "1000000"} {
		var w uint64
		for _, digit := range window {
			w = w*10 + uint64(digit-'0')
		}
		token := beacon.BeaconToken(w)
		tokens[window] = hex.EncodeToString(token[:])
	}

	return conformance{
		FrameEncoded:   hex.EncodeToString(raw),
		FrameAAD:       hex.EncodeToString(frame.AAD()),
		FrameHoppedAAD: hex.EncodeToString(hopped.AAD()),
		ChannelID:      hex.EncodeToString(key.ID[:]),
		BeaconTokens:   tokens,
	}
}

// TestWriteConformanceFixture regenerates the file the ports are checked against.
//
// Behind an environment variable rather than run by default, so a change to the wire
// format shows up as a failing comparison below before it shows up as a changed file.
func TestWriteConformanceFixture(t *testing.T) {
	if os.Getenv("GATECRASH_UPDATE_FIXTURES") == "" {
		t.Skip("set GATECRASH_UPDATE_FIXTURES=1 to regenerate the port conformance fixture")
	}

	body, err := json.MarshalIndent(buildConformance(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conformancePath, append(body, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", conformancePath)
}

// TestConformanceFixtureIsCurrent fails when the wire format changes without the
// fixture being regenerated.
//
// That failure is the point. It means somebody has to look at the Kotlin and Swift
// ports, which is exactly the moment to notice that a header field moved.
func TestConformanceFixtureIsCurrent(t *testing.T) {
	raw, err := os.ReadFile(conformancePath)
	if err != nil {
		t.Skipf("no fixture yet; run with GATECRASH_UPDATE_FIXTURES=1 (%v)", err)
	}

	var stored conformance
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}

	current := buildConformance(t)
	for name, pair := range map[string][2]string{
		"frame_encoded":    {stored.FrameEncoded, current.FrameEncoded},
		"frame_aad":        {stored.FrameAAD, current.FrameAAD},
		"frame_hopped_aad": {stored.FrameHoppedAAD, current.FrameHoppedAAD},
		"channel_id":       {stored.ChannelID, current.ChannelID},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s changed:\n stored  %s\n current %s\n"+
				"regenerate the fixture and update apps/backstage-android and apps/backstage-ios",
				name, pair[0], pair[1])
		}
	}
	for window, want := range stored.BeaconTokens {
		if got := current.BeaconTokens[window]; got != want {
			t.Errorf("beacon token for window %s changed: stored %s, current %s", window, want, got)
		}
	}
}

// TestTheHoppedAADIsUnchanged states the property the ports most often get wrong, in the
// fixture rather than only in prose.
func TestTheHoppedAADIsUnchanged(t *testing.T) {
	current := buildConformance(t)
	if current.FrameAAD != current.FrameHoppedAAD {
		t.Fatal("the additional data changed when the ttl was decremented, so a relayed " +
			"frame will fail to authenticate at the first hop")
	}
}
