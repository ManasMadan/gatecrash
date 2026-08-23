package mesh

import (
	"errors"
	"math/rand/v2"
	"time"

	"github.com/ManasMadan/gatecrash/internal/cuckoo"
	"github.com/ManasMadan/gatecrash/internal/meshcrypto"
)

// defaultRandom is the relay coin flip when a caller does not supply one.
//
// math/rand/v2's global source: seeded from the runtime, safe from several
// goroutines, and fast enough for a decision taken once per frame. Cryptographic
// randomness would be the wrong tool — nothing here is a secret, and a relay
// decision that costs a syscall would be paid for on every frame in a crowd.
//
// The simulator always injects its own, because a relay decision taken from a
// global source cannot be replayed from a seed, and a failing run that cannot be
// replayed is a failing run nobody can fix.
func defaultRandom() float64 { return rand.Float64() }

// MaxFragments bounds a fragmented message.
//
// Sixteen fragments of 182 usable bytes is a little under three kilobytes, which is
// far more than a chat message and enough for an announcement with a long note. The
// bound exists because reassembly buffers are memory a stranger can make this phone
// allocate: without it, one crafted frame claiming 255 fragments is a way to make
// every phone in range hold a buffer for a message that will never arrive.
const MaxFragments = 16

// Errors from fragmentation and reassembly.
var (
	ErrTooBig      = errors.New("mesh: message needs more fragments than the protocol allows")
	ErrMismatch    = errors.New("mesh: fragment does not match the message being reassembled")
	ErrIncomplete  = errors.New("mesh: message is not fully reassembled")
	ErrDuplicate   = errors.New("mesh: fragment already received")
	ErrNoFragments = errors.New("mesh: no fragments to reassemble")
)

// Fragment splits a message into frames.
//
// Every fragment carries the same message id, which is what lets the receiver
// gather them, and — importantly — means the dedup filter treats the whole message
// as one thing. A fragmented message either propagates as a unit or does not; a
// design where each fragment had its own id would flood sixteen independent
// messages and the reassembly would depend on all sixteen taking the same path.
//
// The consequence is that a relay forwards each fragment it hears, and the dedup
// filter must not suppress fragments two through sixteen as duplicates of the
// first. That is why fragment position is in the AAD and why FragmentKey exists.
func Fragment(template Frame, body []byte) ([]Frame, error) {
	if len(body) <= MaxBodySize {
		out := template
		out.Version = Version
		out.Body = append([]byte(nil), body...)
		out.FragmentIndex = 0
		out.FragmentTotal = 0
		out.Flags &^= FlagFragment
		return []Frame{out}, nil
	}

	total := (len(body) + MaxBodySize - 1) / MaxBodySize
	if total > MaxFragments {
		return nil, ErrTooBig
	}

	out := make([]Frame, 0, total)
	for index := 0; index < total; index++ {
		start := index * MaxBodySize
		end := start + MaxBodySize
		if end > len(body) {
			end = len(body)
		}

		frame := template
		frame.Version = Version
		frame.Flags |= FlagFragment
		frame.FragmentIndex = uint8(index)
		frame.FragmentTotal = uint8(total)
		frame.Body = append([]byte(nil), body[start:end]...)
		out = append(out, frame)
	}
	return out, nil
}

// FragmentKey is the dedup key for one fragment.
//
// The message id alone is not enough: every fragment of a message shares it, so a
// filter keyed on the id would see fragment two as a duplicate of fragment one and
// the message would never arrive. Mixing the index in gives each fragment its own
// key while keeping them recognisably one message.
func FragmentKey(frame Frame) []byte {
	if !frame.Fragmented() {
		return frame.ID[:]
	}
	out := make([]byte, 0, len(frame.ID)+1)
	out = append(out, frame.ID[:]...)
	return append(out, frame.FragmentIndex)
}

// Reassembler gathers fragments back into messages.
//
// Bounded in both directions: at most MaxFragments per message, and partial
// messages are dropped after a timeout. Both bounds exist because everything here
// arrives from strangers, and an unbounded reassembly buffer on a phone in a crowd
// is a way for one person to exhaust everybody else's memory.
type Reassembler struct {
	partial map[cuckoo.MessageID]*assembly
	timeout time.Duration
	limit   int
	now     func() time.Time
}

type assembly struct {
	total    uint8
	pieces   [][]byte
	received int
	started  time.Time
	template Frame
}

// ReassemblerConfig configures a reassembler.
type ReassemblerConfig struct {
	// Timeout is how long to hold an incomplete message.
	//
	// Thirty seconds. A fragmented message's pieces take different paths across a
	// crowd and arrive seconds apart, so this has to be generous; but a piece that
	// has not arrived in half a minute is not going to, and holding the buffer
	// longer only helps somebody trying to fill memory.
	Timeout time.Duration

	// Limit is how many partial messages to hold at once.
	Limit int

	Now func() time.Time
}

// NewReassembler builds a reassembler.
func NewReassembler(cfg ReassemblerConfig) *Reassembler {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Limit <= 0 {
		cfg.Limit = 32
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Reassembler{
		partial: map[cuckoo.MessageID]*assembly{},
		timeout: cfg.Timeout,
		limit:   cfg.Limit,
		now:     cfg.Now,
	}
}

// Accept takes one frame and returns the complete message once the last piece
// arrives.
//
// An unfragmented frame completes immediately, which keeps the caller from having
// to branch on whether a message was fragmented at all.
func (r *Reassembler) Accept(frame Frame) (Frame, bool, error) {
	r.expire()

	if !frame.Fragmented() {
		return frame, true, nil
	}
	if frame.FragmentTotal < 2 || frame.FragmentTotal > MaxFragments {
		return Frame{}, false, ErrBadFragile
	}
	if frame.FragmentIndex >= frame.FragmentTotal {
		return Frame{}, false, ErrBadFragile
	}

	entry, ok := r.partial[frame.ID]
	if !ok {
		if len(r.partial) >= r.limit {
			// Full. Dropping the oldest rather than refusing the new one: a buffer
			// full of messages that never completed should not stop a message that
			// might.
			r.dropOldest()
		}
		entry = &assembly{
			total:    frame.FragmentTotal,
			pieces:   make([][]byte, frame.FragmentTotal),
			started:  r.now(),
			template: frame,
		}
		r.partial[frame.ID] = entry
	}

	// A fragment claiming a different total for the same message id is either a bug
	// or an attempt to corrupt a reassembly in progress. Either way the safe answer
	// is to reject the piece, not to resize the buffer.
	if entry.total != frame.FragmentTotal {
		return Frame{}, false, ErrMismatch
	}
	if entry.pieces[frame.FragmentIndex] != nil {
		return Frame{}, false, ErrDuplicate
	}

	entry.pieces[frame.FragmentIndex] = append([]byte(nil), frame.Body...)
	entry.received++

	if entry.received < int(entry.total) {
		return Frame{}, false, nil
	}

	body := make([]byte, 0, int(entry.total)*MaxBodySize)
	for _, piece := range entry.pieces {
		body = append(body, piece...)
	}
	delete(r.partial, frame.ID)

	// The completed message carries the first fragment's header with the fragment
	// bits cleared, so the caller sees exactly what Fragment was given.
	out := entry.template
	out.Flags &^= FlagFragment
	out.FragmentIndex = 0
	out.FragmentTotal = 0
	out.Body = body
	return out, true, nil
}

// Pending is how many partial messages are held, for the debug screen.
func (r *Reassembler) Pending() int {
	r.expire()
	return len(r.partial)
}

// Wipe drops every partial message. Part of the panic wipe.
func (r *Reassembler) Wipe() {
	r.partial = map[cuckoo.MessageID]*assembly{}
}

func (r *Reassembler) expire() {
	cutoff := r.now().Add(-r.timeout)
	for id, entry := range r.partial {
		if entry.started.Before(cutoff) {
			delete(r.partial, id)
		}
	}
}

func (r *Reassembler) dropOldest() {
	var oldestID cuckoo.MessageID
	var oldest time.Time
	first := true
	for id, entry := range r.partial {
		if first || entry.started.Before(oldest) {
			oldestID, oldest, first = id, entry.started, false
		}
	}
	if !first {
		delete(r.partial, oldestID)
	}
}

// Announcement builds the frames for an organizer announcement.
//
// Signed, not encrypted, and flagged priority so it relays unconditionally. The
// signature is appended to the body rather than kept in the header: the header is
// fixed-width and shared by every frame kind, and an announcement is the only one
// that carries a signature.
//
// The signature covers the whole body, so it has to be verified after reassembly
// rather than per fragment. A phone therefore cannot tell whether a fragment is
// genuine before relaying it, which means somebody can flood priority-flagged junk.
// The mitigation is the hop limit and the dedup filter — the junk propagates once
// and dies — and it is a real limitation rather than a solved problem.
func Announcement(id cuckoo.MessageID, eventID string, body, signature []byte) ([]Frame, error) {
	payload := make([]byte, 0, len(signature)+len(body))
	payload = append(payload, signature...)
	payload = append(payload, body...)

	return Fragment(Frame{
		Kind:  KindAnnouncement,
		Flags: FlagPriority,
		TTL:   MaxTTL,
		ID:    id,
	}, payload)
}

// SplitAnnouncement separates a reassembled announcement into its signature and its
// text.
func SplitAnnouncement(frame Frame) (signature, body []byte, ok bool) {
	const signatureSize = 64
	if frame.Kind != KindAnnouncement || len(frame.Body) < signatureSize {
		return nil, nil, false
	}
	return frame.Body[:signatureSize], frame.Body[signatureSize:], true
}

// ChannelMessage builds the frames for a channel message.
//
// The body is sealed against the frame's own header, so a frame cannot be
// re-labelled into another channel or promoted to priority without breaking its
// authentication tag. That means the header has to be built before the body is
// sealed, which is why this takes a key rather than a ciphertext.
func ChannelMessage(id cuckoo.MessageID, key meshcrypto.ChannelKey, plaintext []byte) ([]Frame, error) {
	template := Frame{
		Version: Version,
		Kind:    KindChannel,
		TTL:     MaxTTL,
		ID:      id,
		Channel: key.ID,
	}

	// Sealed against the unfragmented header. A fragmented message is sealed once
	// as a whole and then cut up, so the AAD is the header the receiver rebuilds
	// after reassembly — not the per-fragment one.
	sealed, err := key.Seal(plaintext, template.AAD())
	if err != nil {
		return nil, err
	}
	return Fragment(template, sealed)
}

// OpenChannelMessage decrypts a reassembled channel frame.
func OpenChannelMessage(frame Frame, key meshcrypto.ChannelKey) ([]byte, error) {
	if frame.Kind != KindChannel {
		return nil, meshcrypto.ErrNotForUs
	}
	if frame.Channel != key.ID {
		// Not an error worth reporting: in a crowd most frames belong to channels
		// this phone is not in, and this check is what avoids paying for a
		// decryption to find that out.
		return nil, meshcrypto.ErrNotForUs
	}
	return key.Open(frame.Body, frame.AAD())
}
