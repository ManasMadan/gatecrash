// Package engine is the redemption engine: the part of Gatecrash that decides
// whether a person walks in.
//
// The guarantee it exists to provide, stated precisely:
//
//	For a checkpoint with policy "once", at most one ADMIT is ever recorded for
//	a given (ticket, checkpoint) pair — across every gate, every scanner, every
//	reboot, and every concurrent scan of the same QR code.
//
// That guarantee rests on a single atomic insert (see Admit), and everything
// else in this package exists to make the decision around that insert correct,
// attributable and explainable. The explainable part is not decoration: a gate
// that says "no" without saying why produces an argument, and an argument at the
// front of a queue of four hundred people is an operational failure regardless
// of whether the software was right.
package engine

import (
	"time"

	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// Verdict is the outcome of a scan.
//
// Every failure mode is a first-class value rather than a boolean plus a log
// line. Most ticketing systems collapse these into "invalid", which is how gate
// staff end up unable to distinguish a screenshot from a Wi-Fi retry from
// somebody standing at the wrong door — three situations with three completely
// different correct responses.
type Verdict string

// The verdicts. The string values are wire values: they appear in the audit log,
// in the SSE feed and on the scanner, so they are frozen.
const (
	// Admit means let them in. Recorded, attributed, chained.
	Admit Verdict = "ADMIT"

	// AlreadyUsed means this ticket has already been admitted at this
	// checkpoint. The result carries the winning admission as evidence: which
	// gate, which device, how long ago.
	AlreadyUsed Verdict = "ALREADY_USED"

	// InvalidSig means the payload's cryptography does not check out. Either a
	// forgery or a corrupt decode.
	InvalidSig Verdict = "INVALID_SIG"

	// UnknownTicket means the id is not in this event's manifest.
	UnknownTicket Verdict = "UNKNOWN_TICKET"

	// Revoked means the ticket was cancelled, charged back or reported stolen.
	Revoked Verdict = "REVOKED"

	// WrongEvent means a valid ticket for a different show. Common at multi-day
	// festivals and at venues running two rooms.
	WrongEvent Verdict = "WRONG_EVENT"

	// ExpiredWindow means a rotating GC2 code outside the accepted window. This
	// is a screenshot, or a phone whose clock is badly wrong, and the fix is for
	// the attendee to reopen their app — so it must not look like a forgery.
	ExpiredWindow Verdict = "EXPIRED_WINDOW"

	// WrongZone means the ticket's tier does not entitle the holder to the zone
	// behind this checkpoint. A general-admission ticket at the backstage door.
	WrongZone Verdict = "WRONG_ZONE"

	// WrongDoor means the ticket is entitled to the zone but this is not its
	// door: a Block C holder at Portal A, or a VIP at the general gate. The
	// result carries the doors that do serve them, so staff can point.
	WrongDoor Verdict = "WRONG_DOOR"

	// PrerequisiteMissing means the holder has not yet been admitted somewhere
	// they need to be first: at the pit gate without having entered the arena.
	// The result names the missing zones and where to satisfy them.
	PrerequisiteMissing Verdict = "PREREQUISITE_MISSING"

	// ScannerNotAuthorized means the device is not enrolled, has been revoked,
	// or is not assigned to this checkpoint. A stolen scanner produces this.
	ScannerNotAuthorized Verdict = "SCANNER_NOT_AUTHORIZED"

	// PassLimitReached means a counted checkpoint has issued all its passes:
	// both drink tokens used, both guest passes spent.
	PassLimitReached Verdict = "PASS_LIMIT_REACHED"

	// WrongDirection means a bidirectional checkpoint was scanned in a direction
	// that does not follow: an exit scan for somebody who is not inside.
	WrongDirection Verdict = "WRONG_DIRECTION"

	// DoorsClosed means the checkpoint is outside its opening hours. Not the
	// attendee's fault, and staff need to say something different.
	DoorsClosed Verdict = "DOORS_CLOSED"

	// Malformed means the scanned string is not a Gatecrash payload at all. A
	// supermarket barcode, a boarding pass, a URL.
	Malformed Verdict = "MALFORMED"
)

// Admitted reports whether the verdict lets the holder through.
func (v Verdict) Admitted() bool { return v == Admit }

// Severity classifies a verdict for the scanner's display. This is the value
// the verdict screen keys its colour, sound and haptic pattern off, and it
// exists as a separate concept from the verdict because the number of verdicts
// will grow and the number of things a person standing at a gate can usefully
// distinguish will not.
type Severity string

// The three severities.
const (
	// SeverityAdmit is the green screen: let them through.
	SeverityAdmit Severity = "admit"

	// SeverityDeny is the red screen: do not let them through, and the reason is
	// about the ticket.
	SeverityDeny Severity = "deny"

	// SeverityRedirect is the amber screen: the ticket is fine, the person is in
	// the wrong place or too early. Nothing is wrong and nobody is in trouble;
	// they need directions.
	//
	// Splitting this out of "deny" is the single highest-value UX decision in
	// the product. Most of what a gate rejects on a busy night is people at the
	// wrong door, and showing them the same angry red screen as a forged ticket
	// is how gate staff end up arguing with paying customers.
	SeverityRedirect Severity = "redirect"
)

// Severity returns how the scanner should present this verdict.
func (v Verdict) Severity() Severity {
	switch v {
	case Admit:
		return SeverityAdmit
	case WrongDoor, PrerequisiteMissing, DoorsClosed, ExpiredWindow, WrongDirection:
		return SeverityRedirect
	default:
		return SeverityDeny
	}
}

// Reason returns a short sentence for gate staff, written to be read at a glance
// under a floodlight by somebody who has been on their feet for six hours.
//
// The rules it follows: no jargon, no verdict names, no ticket ids, and it says
// what to do rather than what happened wherever there is something to do.
func (v Verdict) Reason() string {
	switch v {
	case Admit:
		return "Let them in"
	case AlreadyUsed:
		return "Already scanned in"
	case InvalidSig:
		return "Not a real ticket"
	case UnknownTicket:
		return "Not on the list"
	case Revoked:
		return "Cancelled ticket"
	case WrongEvent:
		return "Wrong event"
	case ExpiredWindow:
		return "Code expired, ask them to refresh the app"
	case WrongZone:
		return "Not allowed in this area"
	case WrongDoor:
		return "Wrong door, send them on"
	case PrerequisiteMissing:
		return "Needs to come in the main way first"
	case ScannerNotAuthorized:
		return "This scanner is not signed in here"
	case PassLimitReached:
		return "No passes left"
	case WrongDirection:
		return "They are not inside yet"
	case DoorsClosed:
		return "Doors not open yet"
	case Malformed:
		return "Not a ticket, try again"
	default:
		return "Do not let them in"
	}
}

// Admission is a recorded pass through a checkpoint, used as the evidence a
// denial carries.
type Admission struct {
	Checkpoint     venue.CheckpointCode `json:"checkpoint"`
	CheckpointName string               `json:"checkpoint_name,omitempty"`
	Device         string               `json:"device"`
	Occurrence     uint32               `json:"occurrence"`
	Direction      venue.Direction      `json:"direction"`
	HLC            hlc.Timestamp        `json:"hlc"`

	// At is the box's belief about when, which is good enough to display and
	// never used to decide anything.
	At time.Time `json:"at,omitzero"`

	// Offline marks an admission a scanner made during a partition.
	Offline bool `json:"offline,omitempty"`
}

// Ago renders how long before `now` this admission happened, in the form the
// scanner shows: "41 seconds ago" is what turns a bare denial into evidence a
// person accepts.
func (a Admission) Ago(now time.Time) string {
	if a.At.IsZero() || now.Before(a.At) {
		return ""
	}
	elapsed := now.Sub(a.At).Round(time.Second)
	switch {
	case elapsed < time.Minute:
		return plural(int(elapsed.Seconds()), "second") + " ago"
	case elapsed < time.Hour:
		return plural(int(elapsed.Minutes()), "minute") + " ago"
	default:
		return plural(int(elapsed.Hours()), "hour") + " ago"
	}
}

func plural(n int, unit string) string {
	out := itoa(n) + " " + unit
	if n != 1 {
		out += "s"
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}

// Result is everything the scanner, the dashboard and the audit log need to know
// about one scan.
type Result struct {
	Verdict  Verdict  `json:"verdict"`
	Severity Severity `json:"severity"`

	// Reason is the sentence shown to gate staff.
	Reason string `json:"reason"`

	ScanID ticket.ID `json:"scan_id"`

	// Ticket is the id the payload named, set even for denials so the dashboard
	// can group repeat attempts on one ticket.
	Ticket ticket.ID `json:"ticket,omitzero"`

	Checkpoint     venue.CheckpointCode `json:"checkpoint"`
	CheckpointName string               `json:"checkpoint_name,omitempty"`
	Device         string               `json:"device"`

	Zone     venue.ZoneCode `json:"zone,omitempty"`
	ZoneName string         `json:"zone_name,omitempty"`

	// Tier and seat, when known. These are the big glyphs on the verdict screen:
	// the tier colour band and the seat label are what an usher acts on, and they
	// are more useful than the word "ADMIT".
	Tier        venue.TierCode `json:"tier,omitempty"`
	TierName    string         `json:"tier_name,omitempty"`
	TierColour  string         `json:"tier_colour,omitempty"`
	Seat        venue.SeatRef  `json:"seat,omitzero"`
	SeatLabel   string         `json:"seat_label,omitempty"`
	SectionName string         `json:"section_name,omitempty"`

	Direction  venue.Direction `json:"direction,omitempty"`
	Occurrence uint32          `json:"occurrence,omitempty"`

	// PassesLeft is set for counted checkpoints so the guard can say "one token
	// left" instead of the attendee finding out at the bar.
	PassesLeft *int `json:"passes_left,omitempty"`

	HLC hlc.Timestamp `json:"hlc"`
	Seq uint64        `json:"seq,omitempty"`
	At  time.Time     `json:"at,omitzero"`

	// Previous is the winning admission when the verdict is AlreadyUsed.
	Previous *Admission `json:"previous,omitempty"`

	// Ago is Previous rendered relative to this scan, precomputed here so the
	// scanner can render it without a clock it can trust.
	Ago string `json:"ago,omitempty"`

	// Missing names the unmet prerequisite zones for PrerequisiteMissing.
	Missing []venue.ZoneCode `json:"missing,omitempty"`

	// Redirect names the checkpoints that would serve this ticket, for
	// WrongDoor and PrerequisiteMissing. This is what the amber screen points at.
	Redirect []Redirect `json:"redirect,omitempty"`

	// Idempotent means this is the stored result of an earlier scan with the
	// same scan id, replayed because the network duplicated the request. No
	// state changed. Distinguishing this from AlreadyUsed is the difference
	// between "your Wi-Fi hiccuped" and "this person is reusing a ticket", and
	// most systems conflate the two and then gaslight their own staff.
	Idempotent bool `json:"idempotent,omitempty"`

	// Flagged means this scan produced a double-use flag: a scanner admitted
	// somebody locally during a partition and the box has now discovered that
	// another gate had already admitted the same ticket. The person is inside;
	// the flag is the security feed's problem, not the gate's.
	Flagged bool `json:"flagged,omitempty"`
}

// Redirect is a place to send somebody, carried on amber verdicts.
//
// It is deliberately small: at a gate, "Portal C, to your left" is the whole of
// what can be usefully conveyed. The attendee app gets the full routed
// wayfinding answer from the venue package instead.
type Redirect struct {
	Checkpoint venue.CheckpointCode `json:"checkpoint"`
	Name       string               `json:"name"`
	Lane       string               `json:"lane,omitempty"`
	Zone       venue.ZoneCode       `json:"zone,omitempty"`
}
