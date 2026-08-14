// Package dhcp is a minimal DHCPv4 server for the box's access-point mode.
//
// In AP mode the box *is* the network: hostapd brings up the radio and this
// hands out addresses, tells clients where the gateway and the DNS server are
// (both of them the box), and — the interesting part — sets DHCP option 114, the
// RFC 8910 captive-portal URI. A phone that reads option 114 goes straight to the
// portal without any of the probe-interception guesswork in internal/portal.
//
// Writing a DHCP server is not the hard part; RFC 2131 is short and the box needs
// five of its message types. The hard part is the details that decide whether a
// cheap Android phone actually gets an address: replying to the broadcast address
// when the client has none yet, honouring the broadcast flag, echoing the client
// identifier so the client accepts the reply, and keeping leases stable across a
// box reboot so a phone that reconnects gets the same address and its open
// connections survive.
//
// This file is the wire format. server.go is the state machine.
package dhcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Wire constants from RFC 2131.
const (
	// ServerPort and ClientPort are the well-known DHCP ports.
	ServerPort = 67
	ClientPort = 68

	// minPacketLen is the fixed header through the magic cookie.
	minPacketLen = 240

	// MaxPacketLen caps what the server will parse. RFC 2131 guarantees 576
	// bytes; 1500 covers anything a real client sends and refuses anything
	// designed to make the box allocate.
	MaxPacketLen = 1500

	// magicCookie identifies the options area, RFC 2132 section 2.
	magicCookie = 0x63825363

	// bootRequest and bootReply are the op field values.
	bootRequest = 1
	bootReply   = 2

	// ethernetHardware is htype for 10 Mb Ethernet, which is what every client
	// on a Wi-Fi network reports.
	ethernetHardware = 1

	// flagBroadcast is the top bit of the flags field: the client cannot receive
	// a unicast reply yet and is asking to be answered by broadcast.
	flagBroadcast = 0x8000
)

// MessageType is the DHCP message type from option 53.
type MessageType byte

// The message types the box handles.
const (
	Discover MessageType = 1
	Offer    MessageType = 2
	Request  MessageType = 3
	Decline  MessageType = 4
	Ack      MessageType = 5
	Nak      MessageType = 6
	Release  MessageType = 7
	Inform   MessageType = 8
)

// String renders a message type for logs.
func (m MessageType) String() string {
	switch m {
	case Discover:
		return "DISCOVER"
	case Offer:
		return "OFFER"
	case Request:
		return "REQUEST"
	case Decline:
		return "DECLINE"
	case Ack:
		return "ACK"
	case Nak:
		return "NAK"
	case Release:
		return "RELEASE"
	case Inform:
		return "INFORM"
	default:
		return fmt.Sprintf("TYPE%d", byte(m))
	}
}

// Option codes from RFC 2132 and friends. Only the ones the box reads or writes.
const (
	OptSubnetMask       byte = 1
	OptRouter           byte = 3
	OptDNS              byte = 6
	OptHostName         byte = 12
	OptDomainName       byte = 15
	OptBroadcastAddress byte = 28
	OptRequestedIP      byte = 50
	OptLeaseTime        byte = 51
	OptMessageType      byte = 53
	OptServerID         byte = 54
	OptParameterList    byte = 55
	OptMessage          byte = 56
	OptRenewalTime      byte = 58
	OptRebindingTime    byte = 59
	OptVendorClass      byte = 60
	OptClientID         byte = 61

	// OptCaptivePortal is RFC 8910's captive-portal URI. The single most useful
	// option in this file: a client that reads it goes straight to the portal and
	// none of the probe-interception guesswork is needed.
	OptCaptivePortal byte = 114

	// OptEnd terminates the options area.
	OptEnd byte = 255

	// OptPad is a no-op filler.
	OptPad byte = 0
)

// Packet is a decoded DHCPv4 message.
type Packet struct {
	Op       byte
	HType    byte
	HLen     byte
	Hops     byte
	XID      uint32
	Secs     uint16
	Flags    uint16
	ClientIP netip.Addr
	YourIP   netip.Addr
	ServerIP netip.Addr
	RelayIP  netip.Addr

	// MAC is the client hardware address, truncated to HLen.
	MAC net.HardwareAddr

	Options map[byte][]byte
}

// Errors returned by parsing.
var (
	// ErrShort means the packet ended in the middle of a field.
	ErrShort = errors.New("dhcp: packet too short")

	// ErrNotDHCP means the magic cookie is missing.
	ErrNotDHCP = errors.New("dhcp: not a dhcp packet")
)

// Unpack parses a DHCPv4 packet.
func Unpack(buf []byte) (Packet, error) {
	if len(buf) > MaxPacketLen {
		return Packet{}, fmt.Errorf("dhcp: %d bytes exceeds the %d byte cap", len(buf), MaxPacketLen)
	}
	if len(buf) < minPacketLen {
		return Packet{}, fmt.Errorf("%w: %d bytes", ErrShort, len(buf))
	}
	if binary.BigEndian.Uint32(buf[236:240]) != magicCookie {
		return Packet{}, ErrNotDHCP
	}

	p := Packet{
		Op:      buf[0],
		HType:   buf[1],
		HLen:    buf[2],
		Hops:    buf[3],
		XID:     binary.BigEndian.Uint32(buf[4:8]),
		Secs:    binary.BigEndian.Uint16(buf[8:10]),
		Flags:   binary.BigEndian.Uint16(buf[10:12]),
		Options: make(map[byte][]byte, 8),
	}
	p.ClientIP = addr4(buf[12:16])
	p.YourIP = addr4(buf[16:20])
	p.ServerIP = addr4(buf[20:24])
	p.RelayIP = addr4(buf[24:28])

	// HLen is client-supplied. Clamping rather than trusting it is the difference
	// between a MAC address and a 255-byte read into the boot filename.
	hlen := int(p.HLen)
	if hlen > 16 {
		hlen = 16
	}
	p.MAC = append(net.HardwareAddr(nil), buf[28:28+hlen]...)

	if err := parseOptions(buf[240:], p.Options); err != nil {
		return Packet{}, err
	}
	return p, nil
}

// parseOptions walks the options area.
func parseOptions(buf []byte, into map[byte][]byte) error {
	for i := 0; i < len(buf); {
		code := buf[i]
		switch code {
		case OptPad:
			i++
			continue
		case OptEnd:
			return nil
		}
		i++
		if i >= len(buf) {
			return fmt.Errorf("%w: option %d has no length", ErrShort, code)
		}
		length := int(buf[i])
		i++
		if i+length > len(buf) {
			return fmt.Errorf("%w: option %d claims %d bytes", ErrShort, code, length)
		}
		// RFC 3396 says a repeated option is concatenated. Rare, but a client
		// that splits its parameter list across two option 55s would otherwise
		// have half of it silently dropped.
		into[code] = append(into[code], buf[i:i+length]...)
		i += length
	}
	// A packet with no OptEnd is technically malformed and universally sent by at
	// least one embedded stack, so it is accepted.
	return nil
}

// MessageType returns the packet's option 53 value.
func (p Packet) MessageType() MessageType {
	if value, ok := p.Options[OptMessageType]; ok && len(value) == 1 {
		return MessageType(value[0])
	}
	return 0
}

// RequestedIP returns the option 50 address, if any.
func (p Packet) RequestedIP() (netip.Addr, bool) {
	value, ok := p.Options[OptRequestedIP]
	if !ok || len(value) != 4 {
		return netip.Addr{}, false
	}
	return addr4(value), true
}

// ServerID returns the option 54 address, if any. A REQUEST naming a different
// server's id is not ours to answer.
func (p Packet) ServerID() (netip.Addr, bool) {
	value, ok := p.Options[OptServerID]
	if !ok || len(value) != 4 {
		return netip.Addr{}, false
	}
	return addr4(value), true
}

// HostName returns the option 12 hostname, which the dashboard shows so an
// operator can tell one connected device from another.
func (p Packet) HostName() string {
	return sanitizeText(p.Options[OptHostName])
}

// VendorClass returns option 60, useful for spotting the device type in logs.
func (p Packet) VendorClass() string {
	return sanitizeText(p.Options[OptVendorClass])
}

// ClientKey is the identity a lease is keyed on.
//
// Option 61 when present, the MAC otherwise. Preferring the client identifier is
// what RFC 2131 asks for and it matters on phones with MAC randomisation: a
// device that rotates its MAC but keeps its client id keeps its address, and its
// open connections to the box survive.
func (p Packet) ClientKey() string {
	if id, ok := p.Options[OptClientID]; ok && len(id) > 0 {
		return "id:" + string(id)
	}
	return "mac:" + p.MAC.String()
}

// WantsBroadcast reports whether the reply must be broadcast.
//
// True when the client set the broadcast flag or has no address yet. A unicast
// reply to a client with no address is dropped by its own IP stack, which
// presents as "DHCP just does not work on this phone".
func (p Packet) WantsBroadcast() bool {
	return p.Flags&flagBroadcast != 0 || !p.ClientIP.IsValid() || p.ClientIP.IsUnspecified()
}

// Reply builds a response packet skeleton addressed at this client.
func (p Packet) Reply(kind MessageType, yourIP, serverIP netip.Addr) *Builder {
	b := &Builder{
		packet: Packet{
			Op:       bootReply,
			HType:    p.HType,
			HLen:     p.HLen,
			XID:      p.XID,
			Flags:    p.Flags,
			ClientIP: p.ClientIP,
			YourIP:   yourIP,
			RelayIP:  p.RelayIP,
			MAC:      p.MAC,
			Options:  map[byte][]byte{},
		},
	}
	if p.HType == 0 {
		b.packet.HType = ethernetHardware
	}
	b.Set(OptMessageType, []byte{byte(kind)})
	b.Set(OptServerID, serverIP.AsSlice())
	// Echo the client identifier. Some clients reject a reply that does not carry
	// back the identifier they sent, and the failure looks like the server being
	// absent.
	if id, ok := p.Options[OptClientID]; ok {
		b.Set(OptClientID, id)
	}
	return b
}

// Builder assembles a reply.
type Builder struct {
	packet Packet
	order  []byte
}

// Set adds or replaces an option.
func (b *Builder) Set(code byte, value []byte) {
	if _, exists := b.packet.Options[code]; !exists {
		b.order = append(b.order, code)
	}
	b.packet.Options[code] = value
}

// SetIP adds an option holding one IPv4 address.
func (b *Builder) SetIP(code byte, addr netip.Addr) {
	if addr.Is4() {
		b.Set(code, addr.AsSlice())
	}
}

// SetIPs adds an option holding several IPv4 addresses, as option 6 takes.
func (b *Builder) SetIPs(code byte, addrs []netip.Addr) {
	value := make([]byte, 0, len(addrs)*4)
	for _, addr := range addrs {
		if addr.Is4() {
			value = append(value, addr.AsSlice()...)
		}
	}
	if len(value) > 0 {
		b.Set(code, value)
	}
}

// SetUint32 adds an option holding one big-endian 32-bit value, as the lease
// timers take.
func (b *Builder) SetUint32(code byte, value uint32) {
	b.Set(code, binary.BigEndian.AppendUint32(nil, value))
}

// SetString adds an option holding text.
func (b *Builder) SetString(code byte, value string) {
	if value == "" {
		return
	}
	if len(value) > 255 {
		value = value[:255]
	}
	b.Set(code, []byte(value))
}

// Bytes serialises the reply.
func (b *Builder) Bytes() []byte {
	// RFC 2131 packets are at least 300 bytes on the wire; some clients ignore
	// anything shorter, which is a memorable afternoon to debug.
	out := make([]byte, minPacketLen, 300)

	out[0] = b.packet.Op
	out[1] = b.packet.HType
	out[2] = b.packet.HLen
	out[3] = b.packet.Hops
	binary.BigEndian.PutUint32(out[4:8], b.packet.XID)
	binary.BigEndian.PutUint16(out[8:10], b.packet.Secs)
	binary.BigEndian.PutUint16(out[10:12], b.packet.Flags)
	copyAddr(out[12:16], b.packet.ClientIP)
	copyAddr(out[16:20], b.packet.YourIP)
	copyAddr(out[20:24], b.packet.ServerIP)
	copyAddr(out[24:28], b.packet.RelayIP)
	copy(out[28:44], b.packet.MAC)
	binary.BigEndian.PutUint32(out[236:240], magicCookie)

	// Options in insertion order, so a packet capture reads the way the code does
	// and two runs produce identical bytes.
	for _, code := range b.order {
		value := b.packet.Options[code]
		if len(value) > 255 {
			value = value[:255]
		}
		out = append(out, code, byte(len(value)))
		out = append(out, value...)
	}
	out = append(out, OptEnd)

	for len(out) < 300 {
		out = append(out, OptPad)
	}
	return out
}

// addr4 reads a four-byte address.
func addr4(buf []byte) netip.Addr {
	if len(buf) < 4 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(buf[:4]))
}

// copyAddr writes an address into a four-byte field, leaving it zero when unset.
func copyAddr(dst []byte, addr netip.Addr) {
	if addr.Is4() {
		copy(dst, addr.AsSlice())
	}
}

// sanitizeText makes a client-supplied string safe to log and display.
//
// Hostnames and vendor classes come from whatever is on the network and end up on
// the dashboard. Stripping control characters here means a device called
// "\r\nADMIN" cannot forge a log line or scramble a terminal.
func sanitizeText(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	if len(value) > 64 {
		value = value[:64]
	}
	out := make([]rune, 0, len(value))
	for _, r := range string(value) {
		switch {
		case r == 0:
			// Some clients null-terminate. Stop rather than render the padding.
			return string(out)
		case r < 0x20 || r == 0x7F:
			out = append(out, '?')
		default:
			out = append(out, r)
		}
	}
	return string(out)
}
