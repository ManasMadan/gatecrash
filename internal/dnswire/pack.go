package dnswire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Builder assembles a DNS message with name compression.
//
// Compression matters here for one specific reason: an mDNS response advertising
// a service repeats the same long name four times across its PTR, SRV, TXT and A
// records. Without compression a full service announcement exceeds the 1,500-byte
// Ethernet MTU and gets fragmented, and fragmented mDNS is unreliable on exactly
// the cheap consumer access points this product is aimed at.
type Builder struct {
	buf []byte

	// offsets maps a name to where it was first written, so later occurrences
	// become two-byte pointers. Pointers must point backwards, which this
	// naturally satisfies since it only ever records names already written.
	offsets map[string]int

	// counts track what has been appended so the header can be finalised.
	questions, answers, authorities, additionals uint16

	// section guards against appending out of order: DNS sections are
	// positional, and an answer written after an additional would be parsed as
	// the wrong kind of record by everybody.
	section int
}

// Message sections, in wire order.
const (
	sectionQuestion = iota
	sectionAnswer
	sectionAuthority
	sectionAdditional
)

// NewBuilder starts a message with the given header. The counts in the header
// are ignored and recomputed from what is appended.
func NewBuilder(header Header) *Builder {
	b := &Builder{
		buf:     make([]byte, 0, 512),
		offsets: make(map[string]int, 8),
	}
	b.buf = binary.BigEndian.AppendUint16(b.buf, header.ID)
	b.buf = binary.BigEndian.AppendUint16(b.buf, packFlags(header))
	// Counts, filled in by Bytes.
	b.buf = append(b.buf, 0, 0, 0, 0, 0, 0, 0, 0)
	return b
}

func packFlags(h Header) uint16 {
	var flags uint16
	if h.Response {
		flags |= 1 << 15
	}
	flags |= uint16(h.Opcode&0xF) << 11
	if h.Authoritative {
		flags |= 1 << 10
	}
	if h.Truncated {
		flags |= 1 << 9
	}
	if h.RecursionDesired {
		flags |= 1 << 8
	}
	if h.RecursionAvailable {
		flags |= 1 << 7
	}
	return flags | uint16(h.RCode&0xF)
}

// AddQuestion appends a question.
func (b *Builder) AddQuestion(q Question) error {
	if b.section > sectionQuestion {
		return errors.New("dnswire: question added after a record")
	}
	if err := b.appendName(q.Name); err != nil {
		return err
	}
	class := uint16(q.Class)
	if q.Unicast {
		class |= UnicastResponse
	}
	b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(q.Type))
	b.buf = binary.BigEndian.AppendUint16(b.buf, class)
	b.questions++
	return nil
}

// AddAnswer appends a record to the answer section. AddAuthority and
// AddAdditional do the same for theirs.
func (b *Builder) AddAnswer(r Record) error {
	if b.section > sectionAnswer {
		return errors.New("dnswire: answer added after a later section")
	}
	b.section = sectionAnswer
	if err := b.appendRecord(r); err != nil {
		return err
	}
	b.answers++
	return nil
}

// AddAuthority appends to the authority section.
func (b *Builder) AddAuthority(r Record) error {
	if b.section > sectionAuthority {
		return errors.New("dnswire: authority added after an additional")
	}
	b.section = sectionAuthority
	if err := b.appendRecord(r); err != nil {
		return err
	}
	b.authorities++
	return nil
}

// AddAdditional appends to the additional section.
func (b *Builder) AddAdditional(r Record) error {
	b.section = sectionAdditional
	if err := b.appendRecord(r); err != nil {
		return err
	}
	b.additionals++
	return nil
}

// Len returns the message's current size, so a caller can stop adding records
// before it has to be truncated.
func (b *Builder) Len() int { return len(b.buf) }

// Bytes finalises the header counts and returns the message.
func (b *Builder) Bytes() []byte {
	out := append([]byte(nil), b.buf...)
	binary.BigEndian.PutUint16(out[4:6], b.questions)
	binary.BigEndian.PutUint16(out[6:8], b.answers)
	binary.BigEndian.PutUint16(out[8:10], b.authorities)
	binary.BigEndian.PutUint16(out[10:12], b.additionals)
	return out
}

func (b *Builder) appendRecord(r Record) error {
	if err := b.appendName(r.Name); err != nil {
		return err
	}
	class := uint16(r.Class)
	if r.CacheFlush {
		class |= CacheFlush
	}
	b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(r.Type))
	b.buf = binary.BigEndian.AppendUint16(b.buf, class)
	b.buf = binary.BigEndian.AppendUint32(b.buf, r.TTL)

	// Reserve the length, write the data, then backfill. Computing the length up
	// front would mean encoding names twice and getting compression offsets
	// wrong the second time.
	lengthAt := len(b.buf)
	b.buf = append(b.buf, 0, 0)
	start := len(b.buf)

	switch r.Type {
	case TypeA:
		if len(r.IP) != 4 {
			return fmt.Errorf("dnswire: A record needs 4 bytes of address, got %d", len(r.IP))
		}
		b.buf = append(b.buf, r.IP...)
	case TypeAAAA:
		if len(r.IP) != 16 {
			return fmt.Errorf("dnswire: AAAA record needs 16 bytes of address, got %d", len(r.IP))
		}
		b.buf = append(b.buf, r.IP...)
	case TypePTR, TypeCNAME:
		if err := b.appendName(r.Target); err != nil {
			return err
		}
	case TypeTXT:
		for _, entry := range r.TXT {
			if len(entry) > 255 {
				return fmt.Errorf("dnswire: TXT string is %d bytes, limit is 255", len(entry))
			}
			b.buf = append(b.buf, byte(len(entry)))
			b.buf = append(b.buf, entry...)
		}
		if len(r.TXT) == 0 {
			// An empty TXT record is a single zero-length string, not zero
			// bytes: some resolvers reject a genuinely empty RDATA.
			b.buf = append(b.buf, 0)
		}
	case TypeSRV:
		b.buf = binary.BigEndian.AppendUint16(b.buf, r.Priority)
		b.buf = binary.BigEndian.AppendUint16(b.buf, r.Weight)
		b.buf = binary.BigEndian.AppendUint16(b.buf, r.Port)
		// RFC 2782 says an SRV target must not be compressed. Some stacks cope
		// and some do not, and the ones that do not are exactly the cheap
		// Android builds this has to work on.
		if err := b.appendNameUncompressed(r.Target); err != nil {
			return err
		}
	default:
		b.buf = append(b.buf, r.Data...)
	}

	length := len(b.buf) - start
	if length > 0xFFFF {
		return fmt.Errorf("dnswire: record data is %d bytes", length)
	}
	binary.BigEndian.PutUint16(b.buf[lengthAt:lengthAt+2], uint16(length))
	return nil
}

// appendName writes a name, using a compression pointer if this suffix has been
// written before, and recording offsets for every suffix it writes.
func (b *Builder) appendName(name string) error {
	labels, err := splitName(name)
	if err != nil {
		return err
	}

	for i := range labels {
		suffix := strings.Join(labels[i:], ".")
		// Pointers are 14 bits, so a name first written past 16,383 bytes cannot
		// be pointed at. Only reachable in a message far larger than anything
		// this box sends, but writing an out-of-range pointer would corrupt the
		// message silently rather than loudly.
		if at, ok := b.offsets[suffix]; ok && at < 0x4000 {
			b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(0xC000|at))
			return nil
		}
		if len(b.buf) < 0x4000 {
			b.offsets[suffix] = len(b.buf)
		}
		b.buf = append(b.buf, byte(len(labels[i])))
		b.buf = append(b.buf, labels[i]...)
	}
	b.buf = append(b.buf, 0)
	return nil
}

// appendNameUncompressed writes a name without pointers and without recording
// offsets, for the fields where compression is forbidden.
func (b *Builder) appendNameUncompressed(name string) error {
	labels, err := splitName(name)
	if err != nil {
		return err
	}
	for _, label := range labels {
		b.buf = append(b.buf, byte(len(label)))
		b.buf = append(b.buf, label...)
	}
	b.buf = append(b.buf, 0)
	return nil
}

// splitName validates a name and returns its labels.
func splitName(name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil, nil
	}
	labels := strings.Split(name, ".")

	total := 1 // the terminating zero
	for _, label := range labels {
		if label == "" {
			return nil, fmt.Errorf("%w: %q has an empty label", ErrBadName, name)
		}
		if len(label) > MaxLabelLen {
			return nil, fmt.Errorf("%w: label %q is %d bytes", ErrBadName, label, len(label))
		}
		total += len(label) + 1
	}
	if total > MaxNameLen {
		return nil, fmt.Errorf("%w: %q encodes to %d bytes", ErrBadName, name, total)
	}
	return labels, nil
}

// EqualNames compares two DNS names case-insensitively and independently of a
// trailing dot.
//
// DNS names are case-insensitive per RFC 4343, and every device on the network
// disagrees about whether to send "Gate.local", "gate.local." or "GATE.LOCAL".
// A responder that compares them byte-for-byte answers some phones and not
// others, which is the single most confusing class of bug in this area.
func EqualNames(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// Fqdn returns a name with a trailing dot.
func Fqdn(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// HasSuffixName reports whether name sits under parent, case-insensitively.
func HasSuffixName(name, parent string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	parent = strings.TrimSuffix(strings.ToLower(parent), ".")
	if name == parent {
		return true
	}
	return strings.HasSuffix(name, "."+parent)
}
