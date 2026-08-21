// Package mesh is the Backstage flooding protocol: frames, dedup, and the decision
// of whether to relay.
//
// The transport is deliberately not here. BLE advertising and GATT are platform
// APIs that look nothing alike on Android and iOS, and pretending otherwise would
// produce an abstraction that fits neither. What is here is everything above the
// radio: the frame on the wire, the filter that stops a message circulating
// forever, the density-adaptive rule that decides who rebroadcasts, and the
// store-and-forward buffer that carries a message from one cluster of people to
// another. That layer is identical on every platform, so it lives in one place and
// is ported rather than reinvented.
//
// # The hard problem is not encryption
//
// It is airtime. In a pit with five hundred phones in radio range, a protocol where
// everybody rebroadcasts everything spends the entire 2.4GHz band on duplicates
// within seconds and flattens every battery in the field. Everything in this
// package that looks like an optimisation — the dedup filter, the probabilistic
// relay, the jitter before a rebroadcast — is load-bearing.
package mesh

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ManasMadan/gatecrash/internal/cuckoo"
	"github.com/ManasMadan/gatecrash/internal/meshcrypto"
)

// MaxFrame is the largest frame the protocol will produce, in bytes.
//
// 200 is not arbitrary. A BLE extended advertisement carries up to 255 bytes of
// payload, but the number that actually matters is what a five-year-old Android
// phone and an iPhone will both reliably transmit and receive in one advertisement
// without falling back to a connection — and in the field that is closer to 200.
// Anything larger gets fragmented, and every fragment is another chance for a
// message to arrive incomplete.
const MaxFrame = 200

// Version is the protocol version, in every frame's first byte.
//
// A version rather than a feature negotiation. Two phones at a festival cannot
// negotiate anything — they may never be in range long enough to exchange two
// frames — so a frame from a version this build does not understand is dropped
// without being relayed, and the field stays quiet rather than filling with
// confusion.
const Version = 1

// HeaderSize is the fixed part of every frame.
const HeaderSize = 18

// MaxTTL is the hop limit.
//
// Six. BLE indoors is 10 to 30 metres, so six hops is a couple of hundred metres of
// crowd, which covers a hall or a field. It is also small enough that the number of
// frames a single message can generate stays bounded: with the relay probability
// below, a message crosses a venue in a few hundred transmissions rather than a few
// hundred thousand.
const MaxTTL = 6

// Kind is what a frame carries.
type Kind uint8

const (
	// KindChannel is a message in a passphrase-protected channel.
	KindChannel Kind = 1

	// KindDirect is a message to one identity, encrypted with a session key.
	KindDirect Kind = 2

	// KindAnnouncement is an organizer broadcast: signed, not encrypted, and
	// relayed at priority.
	KindAnnouncement Kind = 3

	// KindBeacon is a friend-finder token. It is never relayed — the whole point is
	// that hearing it means the friend is nearby, and a relayed beacon would mean
	// hearing it from three hops away and walking the wrong direction.
	KindBeacon Kind = 4
)

// String names a kind for logs and the simulator's output.
func (k Kind) String() string {
	switch k {
	case KindChannel:
		return "channel"
	case KindDirect:
		return "direct"
	case KindAnnouncement:
		return "announcement"
	case KindBeacon:
		return "beacon"
	default:
		return fmt.Sprintf("kind(%d)", uint8(k))
	}
}

// Relayable reports whether a kind is flooded at all.
func (k Kind) Relayable() bool { return k != KindBeacon }

// Flags are the per-frame bits.
type Flags uint8

const (
	// FlagPriority marks a frame that relays unconditionally, ignoring the density
	// rule.
	//
	// Only for organizer-signed announcements. "Lost child at the mixer desk, blue
	// shirt" has to cross the field even when the field is saturated, and the cost
	// of that guarantee is exactly why the flag is not available to attendee
	// traffic: a priority bit anybody could set is a broadcast storm anybody could
	// start.
	FlagPriority Flags = 1 << 0

	// FlagFragment marks one piece of a fragmented message.
	FlagFragment Flags = 1 << 1

	// FlagBoxOrigin marks a frame that entered the mesh from a venue box rather
	// than a phone.
	//
	// Boxes are the super-nodes that bridge mesh islands over the LAN, which is the
	// fix for BLE mesh's worst real-world failure: two clusters of people thirty
	// metres apart that never hear each other. Marking the origin lets the
	// simulator measure how much the bridging actually buys.
	FlagBoxOrigin Flags = 1 << 2
)

// Has reports whether a flag is set.
func (f Flags) Has(flag Flags) bool { return f&flag != 0 }

// Frame is one transmission.
//
// The header is in the clear because a phone has to decide whether a frame is worth
// decrypting before it spends the battery on trying, and because relays need to
// read the hop count without holding any key. What that costs is traffic analysis:
// anybody listening can see that a channel had traffic and roughly how much. On a
// medium that broadcasts to everybody in range by construction, that was never
// hideable, and the threat model says so instead of pretending.
type Frame struct {
	Version uint8
	Kind    Kind
	Flags   Flags

	// TTL is decremented by each relay. It is deliberately outside the
	// authenticated data — see AAD.
	TTL uint8

	// ID identifies the message, not the frame: every copy of one message that
	// crosses the field carries the same id, which is what makes dedup possible.
	ID cuckoo.MessageID

	// Channel is the channel a KindChannel frame belongs to, and zero otherwise. In
	// the clear so a phone knows which of its keys to try instead of trying all of
	// them.
	Channel meshcrypto.ChannelID

	// Fragment position, both zero for an unfragmented message.
	FragmentIndex uint8
	FragmentTotal uint8

	// Body is the encrypted payload, or the signed plaintext for an announcement.
	Body []byte
}

// Errors from the codec.
var (
	ErrTooShort   = errors.New("mesh: frame is shorter than a header")
	ErrTooLong    = errors.New("mesh: frame exceeds the maximum size")
	ErrVersion    = errors.New("mesh: unsupported protocol version")
	ErrBadTTL     = errors.New("mesh: ttl exceeds the hop limit")
	ErrBadKind    = errors.New("mesh: unknown frame kind")
	ErrBadFragile = errors.New("mesh: inconsistent fragment numbering")
)

// MaxBodySize is how much payload fits in one frame.
const MaxBodySize = MaxFrame - HeaderSize

// Encode lays a frame out for the radio.
//
// The layout, byte by byte, so a Kotlin or Swift port has one thing to match:
//
//	0      version
//	1      kind
//	2      flags
//	3      ttl
//	4..11  message id
//	12..15 channel id
//	16     fragment index
//	17     fragment total
//	18..   body
func (f Frame) Encode() ([]byte, error) {
	if len(f.Body) > MaxBodySize {
		return nil, ErrTooLong
	}
	if f.TTL > MaxTTL {
		return nil, ErrBadTTL
	}

	out := make([]byte, HeaderSize+len(f.Body))
	out[0] = f.Version
	out[1] = uint8(f.Kind)
	out[2] = uint8(f.Flags)
	out[3] = f.TTL
	copy(out[4:12], f.ID[:])
	copy(out[12:16], f.Channel[:])
	out[16] = f.FragmentIndex
	out[17] = f.FragmentTotal
	copy(out[HeaderSize:], f.Body)
	return out, nil
}

// Decode parses a frame off the radio.
//
// Every field is validated here rather than at the point of use. This function is
// the boundary between "bytes some stranger transmitted" and the rest of the
// program, and a mesh is the one place where every peer is untrusted by
// construction.
func Decode(raw []byte) (Frame, error) {
	if len(raw) < HeaderSize {
		return Frame{}, ErrTooShort
	}
	if len(raw) > MaxFrame {
		return Frame{}, ErrTooLong
	}

	frame := Frame{
		Version:       raw[0],
		Kind:          Kind(raw[1]),
		Flags:         Flags(raw[2]),
		TTL:           raw[3],
		FragmentIndex: raw[16],
		FragmentTotal: raw[17],
		Body:          append([]byte(nil), raw[HeaderSize:]...),
	}
	copy(frame.ID[:], raw[4:12])
	copy(frame.Channel[:], raw[12:16])

	if frame.Version != Version {
		return Frame{}, ErrVersion
	}
	if frame.TTL > MaxTTL {
		return Frame{}, ErrBadTTL
	}
	switch frame.Kind {
	case KindChannel, KindDirect, KindAnnouncement, KindBeacon:
	default:
		return Frame{}, ErrBadKind
	}

	// A fragment index at or past the total would index off the end of a
	// reassembly buffer, and a total of one is not a fragmentation.
	if frame.Flags.Has(FlagFragment) {
		if frame.FragmentTotal < 2 || frame.FragmentIndex >= frame.FragmentTotal {
			return Frame{}, ErrBadFragile
		}
	} else if frame.FragmentIndex != 0 || frame.FragmentTotal != 0 {
		return Frame{}, ErrBadFragile
	}

	return frame, nil
}

// AAD is the additional authenticated data for a frame's body.
//
// The TTL is zeroed rather than included, and this is the single most important
// detail in the codec. Every relay decrements the TTL, so a TTL inside the
// authenticated data would mean the frame failed to authenticate at the first hop —
// the message would travel exactly one hop and the mesh would not work at all.
//
// The cost is that anybody can rewrite a TTL in flight: raise it to make a message
// travel further, or drop it to zero to stop it. Neither is worth defending against
// here. Raising it is bounded by MaxTTL, which every receiver enforces
// independently, and lowering it is indistinguishable from simply not relaying —
// which any node can do anyway by staying silent.
//
// Everything else is covered: kind, flags, message id, channel and fragment
// position. So a frame cannot be re-labelled as a different channel, promoted to
// priority, or re-stitched into a different message without breaking its tag.
func (f Frame) AAD() []byte {
	out := make([]byte, HeaderSize)
	out[0] = f.Version
	out[1] = uint8(f.Kind)
	out[2] = uint8(f.Flags)
	out[3] = 0 // deliberately not the TTL
	copy(out[4:12], f.ID[:])
	copy(out[12:16], f.Channel[:])
	out[16] = f.FragmentIndex
	out[17] = f.FragmentTotal
	return out
}

// Size is the frame's length on the wire.
func (f Frame) Size() int { return HeaderSize + len(f.Body) }

// Fragmented reports whether this frame is one piece of a larger message.
func (f Frame) Fragmented() bool { return f.Flags.Has(FlagFragment) }

// Priority reports whether the frame relays unconditionally.
func (f Frame) Priority() bool { return f.Flags.Has(FlagPriority) }

// Hop returns a copy of the frame with the TTL decremented, ready to rebroadcast.
//
// A copy rather than a mutation, because the caller may still be holding the
// original for its own store-and-forward buffer, and a shared frame whose TTL
// changes underneath it is a bug that only shows up under load.
func (f Frame) Hop() (Frame, bool) {
	if f.TTL == 0 {
		return Frame{}, false
	}
	out := f
	out.TTL = f.TTL - 1
	return out, true
}

// NewMessageID mints a random message id.
//
// Random rather than a counter plus a device id. A counter would let anybody
// listening group a night's messages by sender and count how many each phone sent,
// which is exactly the metadata the ephemeral identities are there to avoid.
func NewMessageID(read func([]byte) (int, error)) (cuckoo.MessageID, error) {
	var id cuckoo.MessageID
	if _, err := read(id[:]); err != nil {
		return id, fmt.Errorf("mesh: message id: %w", err)
	}
	return id, nil
}

// beaconFrame is the wire form of a friend-finder token, which is small enough that
// it does not use the normal body encoding.
const beaconBodySize = 4

// EncodeBeacon builds a friend-finder frame.
//
// TTL zero, because a beacon that travels is worse than no beacon: the feature
// works by hearing a token directly, and a relayed token means walking towards
// somebody three hops away.
func EncodeBeacon(id cuckoo.MessageID, token [4]byte) Frame {
	return Frame{
		Version: Version,
		Kind:    KindBeacon,
		TTL:     0,
		ID:      id,
		Body:    append([]byte(nil), token[:]...),
	}
}

// BeaconToken reads the token out of a beacon frame.
func (f Frame) BeaconToken() ([4]byte, bool) {
	var out [4]byte
	if f.Kind != KindBeacon || len(f.Body) != beaconBodySize {
		return out, false
	}
	copy(out[:], f.Body)
	return out, true
}

// idOf is a small helper for logs and maps, where an id reads better as a number.
func idOf(id cuckoo.MessageID) uint64 { return binary.BigEndian.Uint64(id[:]) }
