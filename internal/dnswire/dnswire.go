// Package dnswire is a hand-written DNS message codec.
//
// It exists because Gatecrash needs to speak DNS in three places that no
// off-the-shelf library covers together: an mDNS/DNS-SD responder on the
// multicast group, a wildcard unicast resolver for the venue network, and a
// captive-portal interceptor that answers for names it has no authority over.
// Wrapping Avahi would mean shipping a C daemon and giving up the single-binary
// promise; wrapping a full resolver library would mean pulling in a recursive
// resolver the box will never use.
//
// So this is RFC 1035 wire format from raw bytes: header, question, resource
// record, name compression on write and pointer following on read. It handles
// the parts the box actually needs and refuses everything else, which is a much
// smaller surface than a general-purpose DNS library and a much easier one to
// reason about when it is parsing packets from anybody on the venue Wi-Fi.
//
// Hostile input is the design constraint. Any device on the network can send
// this code a packet, so every length is checked against the buffer, compression
// pointers may only point backwards, and the pointer-following loop is bounded.
// Those three rules between them close the classic DNS parser bugs.
package dnswire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Limits from RFC 1035 section 2.3.4, plus a few of our own where the RFC is
// silent and an attacker is not.
const (
	// MaxNameLen is the longest encoded name, in bytes.
	MaxNameLen = 255

	// MaxLabelLen is the longest single label.
	MaxLabelLen = 63

	// maxPointerHops bounds compression-pointer following. A pointer loop is the
	// oldest DNS parser denial of service there is; pointers may only point
	// backwards here, which makes a loop impossible, and this bound is the
	// belt to that braces.
	maxPointerHops = 32

	// headerLen is the fixed header size.
	headerLen = 12

	// MaxMessageLen caps how much this package will parse or produce. 9 KB is
	// the largest useful mDNS message; anything bigger is either a bug or an
	// attempt to make the box allocate.
	MaxMessageLen = 9000
)

// Type is a DNS record type. Only the types the box serves are named; the
// numeric form passes through for everything else so an unknown query can be
// answered with an empty response rather than ignored.
type Type uint16

// The record types the box uses.
const (
	TypeA     Type = 1
	TypePTR   Type = 12
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeNSEC  Type = 47
	TypeOPT   Type = 41
	TypeANY   Type = 255
	TypeCNAME Type = 5
	TypeSOA   Type = 6
)

// String renders a type for logs.
func (t Type) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypePTR:
		return "PTR"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeNSEC:
		return "NSEC"
	case TypeOPT:
		return "OPT"
	case TypeANY:
		return "ANY"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	default:
		return "TYPE" + itoa(int(t))
	}
}

// Class is a DNS record class.
type Class uint16

// The classes the box uses.
const (
	ClassINET Class = 1
	ClassANY  Class = 255

	// CacheFlush is the top bit of the class field in an mDNS response, which
	// tells receivers to discard any previously cached records for this name and
	// type. Set on the box's announcements so a device that saw a previous boot's
	// address does not keep using it.
	CacheFlush uint16 = 1 << 15

	// UnicastResponse is the top bit of the class field in an mDNS question,
	// asking for the answer by unicast instead of multicast. Common on iOS, and
	// honouring it is most of what keeps mDNS traffic off a saturated venue
	// network.
	UnicastResponse uint16 = 1 << 15
)

// RCode is a DNS response code.
type RCode uint8

// The response codes the box returns.
const (
	RCodeSuccess  RCode = 0
	RCodeFormat   RCode = 1
	RCodeServer   RCode = 2
	RCodeNXDomain RCode = 3
	RCodeNotImpl  RCode = 4
	RCodeRefused  RCode = 5
)

// Header is a DNS message header.
type Header struct {
	ID uint16

	// Response is the QR bit.
	Response bool

	Opcode uint8

	// Authoritative, Truncated, RecursionDesired and RecursionAvailable are the
	// AA, TC, RD and RA bits.
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool

	RCode RCode

	Questions   uint16
	Answers     uint16
	Authorities uint16
	Additionals uint16
}

// Question is one query.
type Question struct {
	Name  string
	Type  Type
	Class Class

	// Unicast is the mDNS QU bit: the asker wants a unicast reply.
	Unicast bool
}

// Record is one resource record.
//
// Data is type-specific and pre-encoded for the types this package does not
// build itself; the typed fields are populated for A, AAAA, PTR, TXT and SRV,
// which are the five the box serves.
type Record struct {
	Name  string
	Type  Type
	Class Class
	TTL   uint32

	// CacheFlush is the mDNS cache-flush bit on the class field.
	CacheFlush bool

	// IP is set for A and AAAA.
	IP []byte

	// Target is set for PTR, CNAME and SRV.
	Target string

	// TXT strings, each at most 255 bytes on the wire.
	TXT []string

	// SRV fields.
	Priority uint16
	Weight   uint16
	Port     uint16

	// Data is the raw RDATA for types this package does not model.
	Data []byte
}

// Message is a decoded DNS message.
type Message struct {
	Header      Header
	Questions   []Question
	Answers     []Record
	Authorities []Record
	Additionals []Record
}

// Errors returned by parsing. All of them mean "drop this packet": there is
// nothing useful to say to a sender whose message did not parse, and saying
// anything makes the box a reflector.
var (
	// ErrShort means the message ended in the middle of a field.
	ErrShort = errors.New("dnswire: message truncated")

	// ErrBadName means a name was malformed, too long, or used a forward
	// compression pointer.
	ErrBadName = errors.New("dnswire: malformed name")

	// ErrTooLarge means the message exceeds MaxMessageLen.
	ErrTooLarge = errors.New("dnswire: message too large")
)

// Unpack parses a DNS message.
func Unpack(buf []byte) (Message, error) {
	if len(buf) > MaxMessageLen {
		return Message{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(buf))
	}
	if len(buf) < headerLen {
		return Message{}, fmt.Errorf("%w: %d bytes is shorter than a header", ErrShort, len(buf))
	}

	var msg Message
	flags := binary.BigEndian.Uint16(buf[2:4])
	msg.Header = Header{
		ID:                 binary.BigEndian.Uint16(buf[0:2]),
		Response:           flags&(1<<15) != 0,
		Opcode:             uint8((flags >> 11) & 0xF),
		Authoritative:      flags&(1<<10) != 0,
		Truncated:          flags&(1<<9) != 0,
		RecursionDesired:   flags&(1<<8) != 0,
		RecursionAvailable: flags&(1<<7) != 0,
		RCode:              RCode(flags & 0xF),
		Questions:          binary.BigEndian.Uint16(buf[4:6]),
		Answers:            binary.BigEndian.Uint16(buf[6:8]),
		Authorities:        binary.BigEndian.Uint16(buf[8:10]),
		Additionals:        binary.BigEndian.Uint16(buf[10:12]),
	}

	// Guard the counts against the buffer before allocating for them. A header
	// claiming 65,535 questions in a 12-byte packet is the cheapest possible way
	// to make a naive parser allocate a megabyte per packet.
	//
	// The smallest possible question is 1 byte of name plus 4 of type and class.
	const minQuestion, minRecord = 5, 11
	remaining := len(buf) - headerLen
	if int(msg.Header.Questions)*minQuestion > remaining {
		return Message{}, fmt.Errorf("%w: header claims %d questions", ErrShort, msg.Header.Questions)
	}
	total := int(msg.Header.Answers) + int(msg.Header.Authorities) + int(msg.Header.Additionals)
	if total*minRecord > remaining {
		return Message{}, fmt.Errorf("%w: header claims %d records", ErrShort, total)
	}

	offset := headerLen
	var err error
	for i := 0; i < int(msg.Header.Questions); i++ {
		var q Question
		if q, offset, err = unpackQuestion(buf, offset); err != nil {
			return Message{}, err
		}
		msg.Questions = append(msg.Questions, q)
	}
	if msg.Answers, offset, err = unpackRecords(buf, offset, int(msg.Header.Answers)); err != nil {
		return Message{}, err
	}
	if msg.Authorities, offset, err = unpackRecords(buf, offset, int(msg.Header.Authorities)); err != nil {
		return Message{}, err
	}
	if msg.Additionals, _, err = unpackRecords(buf, offset, int(msg.Header.Additionals)); err != nil {
		return Message{}, err
	}
	return msg, nil
}

func unpackQuestion(buf []byte, offset int) (Question, int, error) {
	name, next, err := UnpackName(buf, offset)
	if err != nil {
		return Question{}, 0, err
	}
	if next+4 > len(buf) {
		return Question{}, 0, fmt.Errorf("%w: question has no type and class", ErrShort)
	}
	rawClass := binary.BigEndian.Uint16(buf[next+2 : next+4])
	return Question{
		Name:    name,
		Type:    Type(binary.BigEndian.Uint16(buf[next : next+2])),
		Class:   Class(rawClass & ^UnicastResponse),
		Unicast: rawClass&UnicastResponse != 0,
	}, next + 4, nil
}

func unpackRecords(buf []byte, offset, count int) ([]Record, int, error) {
	var out []Record
	for i := 0; i < count; i++ {
		var (
			r   Record
			err error
		)
		if r, offset, err = unpackRecord(buf, offset); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, offset, nil
}

func unpackRecord(buf []byte, offset int) (Record, int, error) {
	name, next, err := UnpackName(buf, offset)
	if err != nil {
		return Record{}, 0, err
	}
	if next+10 > len(buf) {
		return Record{}, 0, fmt.Errorf("%w: record header", ErrShort)
	}

	rawClass := binary.BigEndian.Uint16(buf[next+2 : next+4])
	r := Record{
		Name:       name,
		Type:       Type(binary.BigEndian.Uint16(buf[next : next+2])),
		Class:      Class(rawClass & ^CacheFlush),
		CacheFlush: rawClass&CacheFlush != 0,
		TTL:        binary.BigEndian.Uint32(buf[next+4 : next+8]),
	}
	length := int(binary.BigEndian.Uint16(buf[next+8 : next+10]))
	next += 10
	if next+length > len(buf) {
		return Record{}, 0, fmt.Errorf("%w: record data claims %d bytes", ErrShort, length)
	}
	data := buf[next : next+length]

	switch r.Type {
	case TypeA:
		if length != 4 {
			return Record{}, 0, fmt.Errorf("%w: A record with %d bytes", ErrShort, length)
		}
		r.IP = append([]byte(nil), data...)
	case TypeAAAA:
		if length != 16 {
			return Record{}, 0, fmt.Errorf("%w: AAAA record with %d bytes", ErrShort, length)
		}
		r.IP = append([]byte(nil), data...)
	case TypePTR, TypeCNAME:
		// Names inside RDATA may use compression pointers into the whole
		// message, so this is parsed against buf rather than against data.
		if r.Target, _, err = UnpackName(buf, next); err != nil {
			return Record{}, 0, err
		}
	case TypeTXT:
		if r.TXT, err = unpackTXT(data); err != nil {
			return Record{}, 0, err
		}
	case TypeSRV:
		if length < 6 {
			return Record{}, 0, fmt.Errorf("%w: SRV record with %d bytes", ErrShort, length)
		}
		r.Priority = binary.BigEndian.Uint16(data[0:2])
		r.Weight = binary.BigEndian.Uint16(data[2:4])
		r.Port = binary.BigEndian.Uint16(data[4:6])
		if r.Target, _, err = UnpackName(buf, next+6); err != nil {
			return Record{}, 0, err
		}
	default:
		r.Data = append([]byte(nil), data...)
	}
	return r, next + length, nil
}

// unpackTXT splits RDATA into its length-prefixed strings.
func unpackTXT(data []byte) ([]string, error) {
	var out []string
	for i := 0; i < len(data); {
		length := int(data[i])
		i++
		if i+length > len(data) {
			return nil, fmt.Errorf("%w: TXT string claims %d bytes", ErrShort, length)
		}
		out = append(out, string(data[i:i+length]))
		i += length
	}
	return out, nil
}

// UnpackName decodes a possibly-compressed name, returning it and the offset
// just past its encoding in the original message.
//
// The offset returned is past the name as it appears at `offset`, not past
// wherever a compression pointer led. Getting that wrong is how a parser ends up
// reading records out of the middle of a name.
func UnpackName(buf []byte, offset int) (string, int, error) {
	var (
		labels   []string
		next     int
		jumped   bool
		hops     int
		consumed int
	)
	for {
		if offset >= len(buf) {
			return "", 0, fmt.Errorf("%w: name runs past the message", ErrShort)
		}
		length := int(buf[offset])

		switch {
		case length == 0:
			offset++
			if !jumped {
				next = offset
			}
			if consumed > MaxNameLen {
				return "", 0, fmt.Errorf("%w: name is %d bytes", ErrBadName, consumed)
			}
			return strings.Join(labels, ".") + ".", next, nil

		case length&0xC0 == 0xC0:
			// A compression pointer: two bytes, fourteen bits of offset.
			if offset+2 > len(buf) {
				return "", 0, fmt.Errorf("%w: truncated compression pointer", ErrShort)
			}
			target := int(binary.BigEndian.Uint16(buf[offset:offset+2]) & 0x3FFF)
			// Pointers must point strictly backwards. This single rule makes
			// pointer loops impossible rather than merely bounded, and it is the
			// reason this parser cannot be made to spin on a hostile packet.
			if target >= offset {
				return "", 0, fmt.Errorf("%w: compression pointer at %d points forward to %d", ErrBadName, offset, target)
			}
			if hops++; hops > maxPointerHops {
				return "", 0, fmt.Errorf("%w: too many compression pointers", ErrBadName)
			}
			if !jumped {
				next = offset + 2
				jumped = true
			}
			offset = target

		case length&0xC0 != 0:
			// Extended label types were deprecated by RFC 6891 and never used on
			// a venue network.
			return "", 0, fmt.Errorf("%w: reserved label type 0x%02x", ErrBadName, length)

		default:
			if length > MaxLabelLen {
				return "", 0, fmt.Errorf("%w: label is %d bytes", ErrBadName, length)
			}
			offset++
			if offset+length > len(buf) {
				return "", 0, fmt.Errorf("%w: label runs past the message", ErrShort)
			}
			consumed += length + 1
			if consumed > MaxNameLen {
				return "", 0, fmt.Errorf("%w: name is %d bytes", ErrBadName, consumed)
			}
			labels = append(labels, string(buf[offset:offset+length]))
			offset += length
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
