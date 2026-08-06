package ticket

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// GC2 payload layout:
//
//	GC2.<base32(ticket_id:16B)>.<base36(window)>.<base32(mac:10B)>
//
// which is 57 characters at present window magnitudes: a version 3 QR symbol
// (29x29 modules). Small symbols matter more than they sound like they do. The
// attendee app redraws this every 30 seconds on a phone screen that may be
// cracked, greasy and at 20% brightness, and the gate is reading it with a
// ₹6,000 Android camera. Fewer modules means each module is physically larger,
// which is the difference between a one-frame lock and a queue.
const (
	gc2Prefix = "GC2"

	// WindowSeconds is the rotation period. Thirty seconds is the same choice
	// TOTP made and for the same reason: long enough that clock disagreement
	// between the phone and the box is absorbed by the +/-1 window tolerance,
	// short enough that a screenshot forwarded over WhatsApp is dead before the
	// recipient reaches the gate.
	WindowSeconds = 30

	// MACLen is the truncated HMAC length carried in the payload. Ten bytes is
	// 80 bits. A forger who does not hold the ticket secret gets one guess per
	// scan attempt against a gate that rate-limits per device, so 2^80 is
	// several orders of magnitude more than the threat needs; the reason not to
	// go smaller is that the same payload is also the offline-verifiable proof
	// the attendee app shows when the box is unreachable.
	MACLen = 10

	// windowTolerance is how many windows either side of the box's current
	// window are accepted. One window each way gives a 60 to 90 second
	// acceptance band, which covers the phone's clock being wrong by up to half
	// a minute plus the time between the attendee raising their phone and the
	// gate actually decoding it.
	windowTolerance = 1

	encodedMACLen = 16 // base32, unpadded, of 10 bytes
)

// Window is a GC2 rotation window index: unix time divided by WindowSeconds.
//
// The box's absolute wall time is allowed to be wrong; what matters is that the
// phone and the box agree, which is arranged by having the phone take its time
// from the box when it claims its ticket and from any scanner-observed
// timestamp thereafter. Everything is relative, which is the same reason the
// rest of the system runs on HLCs.
type Window int64

// WindowAt returns the rotation window containing the given instant.
func WindowAt(at time.Time) Window { return Window(at.Unix() / WindowSeconds) }

// Start returns the instant at which this window opened.
func (w Window) Start() time.Time { return time.Unix(int64(w)*WindowSeconds, 0).UTC() }

// String renders the window in uppercase base36, which stays inside the QR
// alphanumeric character set and is three characters shorter than decimal.
func (w Window) String() string {
	return strings.ToUpper(strconv.FormatInt(int64(w), 36))
}

// parseWindow reads the base36 window form.
func parseWindow(text string) (Window, error) {
	if text == "" {
		return 0, fmt.Errorf("%w: empty window", ErrBadPayload)
	}
	value, err := strconv.ParseInt(strings.ToLower(text), 36, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: window %q: %v", ErrBadPayload, text, err)
	}
	if value < 0 {
		return 0, fmt.Errorf("%w: window %q is negative", ErrBadPayload, text)
	}
	return Window(value), nil
}

// macMessage is the byte string the truncated HMAC covers. The event id is in
// here even though it is not in the payload: without it, a ticket secret leaked
// from one event could be replayed at another event that happened to reuse the
// ticket id, and ticket ids are random but not coordinated across events.
func macMessage(eventID, ticketID ID, window Window) []byte {
	out := make([]byte, 0, len(domainGC2)+1+IDLen+IDLen+8)
	out = append(out, byte(len(domainGC2)))
	out = append(out, domainGC2...)
	out = append(out, eventID[:]...)
	out = append(out, ticketID[:]...)
	return binary.BigEndian.AppendUint64(out, uint64(window))
}

// computeMAC returns the truncated HMAC for one window.
func computeMAC(secret Secret, eventID, ticketID ID, window Window) []byte {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(macMessage(eventID, ticketID, window))
	return mac.Sum(nil)[:MACLen]
}

// GenerateGC2 produces the rotating payload for a window. This runs on the
// attendee's phone with no network of any kind: the phone holds its own ticket
// secret and a clock, and that is the entire input.
func GenerateGC2(secret Secret, eventID, ticketID ID, window Window) string {
	mac := computeMAC(secret, eventID, ticketID, window)
	return gc2Prefix + "." + ticketID.String() + "." + window.String() + "." + encoding.EncodeToString(mac)
}

// GenerateGC2At is GenerateGC2 for the window containing an instant.
func GenerateGC2At(secret Secret, eventID, ticketID ID, at time.Time) string {
	return GenerateGC2(secret, eventID, ticketID, WindowAt(at))
}

// GC2 is a parsed rotating payload.
type GC2 struct {
	TicketID ID
	Window   Window
	MAC      []byte
}

// IsGC2 reports whether a scanned string claims to be a GC2 payload.
func IsGC2(payload string) bool { return strings.HasPrefix(payload, gc2Prefix+".") }

// ParseGC2 reads a rotating payload without validating its MAC or its window.
func ParseGC2(payload string) (GC2, error) {
	parts := strings.Split(payload, ".")
	if len(parts) != 4 || parts[0] != gc2Prefix {
		return GC2{}, fmt.Errorf("%w: not a GC2 payload", ErrBadPayload)
	}
	ticketID, err := ParseIDBase32(parts[1])
	if err != nil {
		return GC2{}, fmt.Errorf("%w: ticket id: %v", ErrBadPayload, err)
	}
	window, err := parseWindow(parts[2])
	if err != nil {
		return GC2{}, err
	}
	if len(parts[3]) != encodedMACLen {
		return GC2{}, fmt.Errorf("%w: mac is %d characters, want %d", ErrBadPayload, len(parts[3]), encodedMACLen)
	}
	mac, err := encoding.DecodeString(parts[3])
	if err != nil {
		return GC2{}, fmt.Errorf("%w: mac: %v", ErrBadPayload, err)
	}
	if len(mac) != MACLen {
		return GC2{}, fmt.Errorf("%w: mac is %d bytes, want %d", ErrBadPayload, len(mac), MACLen)
	}
	return GC2{TicketID: ticketID, Window: window, MAC: mac}, nil
}

// Errors returned by GC2 validation. These are distinguishable because the gate
// UI treats them differently: a stale window tells the attendee to let their
// phone refresh, which is a recoverable situation, whereas a bad MAC is a
// forgery and gets the red screen.
var (
	// ErrExpiredWindow means the payload's window is outside the box's
	// acceptance band. Either the phone's clock is badly wrong or the code is a
	// screenshot older than a minute.
	ErrExpiredWindow = errors.New("ticket: gc2 window outside tolerance")

	// ErrBadMAC means the authenticator did not verify. The holder does not
	// have the ticket secret.
	ErrBadMAC = errors.New("ticket: gc2 mac does not verify")
)

// ValidateGC2 checks a rotating payload against the box's current window.
//
// The window is passed in rather than read from time.Now for the same reason
// the HLC takes an injected clock: the deterministic simulator needs to drive
// clock skew directly, and a function that reads the wall clock cannot be
// tested for the interesting cases.
func ValidateGC2(master MasterKey, eventID ID, payload GC2, boxWindow Window) error {
	drift := payload.Window - boxWindow
	if drift < -windowTolerance || drift > windowTolerance {
		return fmt.Errorf("%w: payload window %d, box window %d", ErrExpiredWindow, payload.Window, boxWindow)
	}

	secret, err := DeriveSecret(master, payload.TicketID)
	if err != nil {
		return err
	}
	want := computeMAC(secret, eventID, payload.TicketID, payload.Window)

	// Constant time, because the MAC comparison is the one place in the scan
	// path where a timing leak would let an attacker with a scanner-shaped
	// device grind out a valid authenticator byte by byte.
	if subtle.ConstantTimeCompare(want, payload.MAC) != 1 {
		return ErrBadMAC
	}
	return nil
}

// AcceptanceWindow reports the inclusive band of windows a box at boxWindow
// will accept. Exposed so the dashboard can show operators exactly how much
// clock slack the gates are granting, which is the first thing to look at when
// one attendee's phone is being rejected and everyone else's works.
func AcceptanceWindow(boxWindow Window) (earliest, latest Window) {
	return boxWindow - windowTolerance, boxWindow + windowTolerance
}
