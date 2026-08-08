// Package incident carries staff signals from the gates to the control room.
//
// This is the half of the product that has nothing to do with tickets. A bouncer
// on a door has exactly two things they need from the back room and no reliable
// way to ask for them: more people, and help. Shouting into a radio nobody is
// monitoring is the state of the art at most events, and it fails in the two
// situations where it matters most — when a queue is turning into a crush, and
// when something has gone wrong in the crowd.
//
// So the scanner has two buttons. One asks for staff. One raises an alarm. Both
// arrive at the control room with the gate, the device, the zone and the gate's
// current scan rate already filled in, because somebody pressing the crush
// button is not going to stop and fill in a form.
//
// The lifecycle is the point. An alert nobody acknowledged is worse than no
// alert, because everybody assumes somebody else has it. Every transition is
// recorded, every transition names who made it, and the whole thing is chained
// into the same tamper-evident log as the admissions.
//
// That last part is not paranoia. "We called for medical at 23:41 and nobody
// came for nine minutes" is the sentence a liability case turns on, and it is
// either provable or it is one person's word against another's.
package incident

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// Kind is what is being reported.
//
// The set is closed because each kind drives a different response on the
// dashboard: a different colour, a different sound, a different default
// assignee, and for four of them a full-screen takeover that cannot be
// dismissed without acknowledging it. A kind that reached the log but not the UI
// is an alert nobody sees.
type Kind string

// The staffing requests.
const (
	// NeedStaff is the queue-pressure signal: this door cannot keep up.
	NeedStaff Kind = "need-staff"

	// NeedSupervisor asks for somebody with authority, which is what a door
	// actually needs when an attendee is arguing about a verdict.
	NeedSupervisor Kind = "need-supervisor"

	// NeedRelief asks for a break. It sounds trivial and it is the most common
	// reason a gate goes quiet for ten minutes with nobody knowing why.
	NeedRelief Kind = "need-relief"

	// EquipmentFault covers a dead scanner battery, a broken barcode gun, a
	// printer out of paper.
	EquipmentFault Kind = "equipment-fault"
)

// The alarms.
const (
	// Medical is somebody hurt or unwell.
	Medical Kind = "medical"

	// Crush is dangerous crowd density. The most important signal in the set and
	// the one no other event platform has a button for.
	Crush Kind = "crush"

	// Fight is violence or the immediate threat of it.
	Fight Kind = "fight"

	// Fire is fire, smoke, or a pyro failure.
	Fire Kind = "fire"

	// Theft covers pickpocketing, a stolen scanner, a till.
	Theft Kind = "theft"

	// LostChild is a separated child. Every venue treats this as its own
	// category because the response is specific and immediate.
	LostChild Kind = "lost-child"

	// Suspicious is an unattended bag, somebody working the fences, a tout
	// hustling the queue.
	Suspicious Kind = "suspicious"

	// Structural is a barrier giving way, a rigging problem, standing water on a
	// cable run.
	Structural Kind = "structural"

	// Evacuate is the one nobody wants to press.
	Evacuate Kind = "evacuate"
)

// The automatic signals. The box raises these itself, so the control room finds
// out about a problem without anybody having to notice it first.
const (
	// GateOffline means a scanner has stopped talking to the box.
	GateOffline Kind = "gate-offline"

	// QueueSpike means a gate's scan rate has collapsed or its queue estimate
	// has run away.
	QueueSpike Kind = "queue-spike"

	// OverCapacity means a zone's occupancy has passed its declared capacity.
	OverCapacity Kind = "over-capacity"

	// DoubleUseDetected means reconciliation found a ticket admitted twice.
	DoubleUseDetected Kind = "double-use"

	// DegradedEntered means a gate has started admitting without the box.
	DegradedEntered Kind = "degraded-mode"
)

// Severity is how loudly the dashboard reacts.
type Severity string

// The severities.
const (
	// Info is listed and logged, no sound.
	Info Severity = "info"

	// Warning raises a badge and a soft chime.
	Warning Severity = "warning"

	// Urgent raises a persistent banner and a repeating tone.
	Urgent Severity = "urgent"

	// Emergency takes over the dashboard and cannot be dismissed without an
	// acknowledgement. Reserved for the kinds where a delayed response is
	// measured in injuries.
	Emergency Severity = "emergency"
)

// DefaultSeverity is the severity a kind carries unless the reporter escalates.
func DefaultSeverity(k Kind) Severity {
	switch k {
	case Evacuate, Fire, Crush, Structural:
		return Emergency
	case Medical, Fight, LostChild:
		return Urgent
	case NeedStaff, NeedSupervisor, Theft, Suspicious,
		GateOffline, QueueSpike, OverCapacity, DoubleUseDetected, DegradedEntered:
		return Warning
	default:
		return Info
	}
}

// IsAlarm reports whether a kind is an alarm rather than a staffing request.
// The scanner puts the two behind different buttons, and the alarm button asks
// for confirmation, because a pocket press on Evacuate is its own incident.
func IsAlarm(k Kind) bool {
	switch k {
	case Medical, Crush, Fight, Fire, Theft, LostChild, Suspicious, Structural, Evacuate:
		return true
	default:
		return false
	}
}

// IsAutomatic reports whether the box raises this kind itself.
func IsAutomatic(k Kind) bool {
	switch k {
	case GateOffline, QueueSpike, OverCapacity, DoubleUseDetected, DegradedEntered:
		return true
	default:
		return false
	}
}

// Status is where an incident sits in its lifecycle.
type Status string

// The statuses.
const (
	// Open means nobody in the control room has picked it up. This is the state
	// the dashboard is loud about, and the only state that really matters.
	Open Status = "open"

	// Acknowledged means somebody has seen it and owns it. The gate is told, so
	// the person who raised it stops wondering whether anyone is coming.
	Acknowledged Status = "acknowledged"

	// Assigned means staff are on their way, and the record names who.
	Assigned Status = "assigned"

	// Resolved means it is done.
	Resolved Status = "resolved"

	// Cancelled means it was raised in error, which happens and should be cheap
	// to say. Cancelling requires a note, so an inconvenient alarm cannot be
	// made to quietly disappear.
	Cancelled Status = "cancelled"
)

// Live reports whether an incident still needs attention.
func (s Status) Live() bool { return s == Open || s == Acknowledged || s == Assigned }

// ID identifies an incident. Short and human-sayable rather than a UUID, because
// the whole point is that somebody reads it out over a radio: "control, closing
// INC-14".
type ID string

// Event is one transition in an incident's life.
type Event struct {
	Status Status        `json:"status"`
	Actor  string        `json:"actor"`
	Note   string        `json:"note,omitempty"`
	HLC    hlc.Timestamp `json:"hlc"`
	At     time.Time     `json:"at"`
}

// Incident is one report and everything that has happened to it.
type Incident struct {
	ID       ID       `json:"id"`
	Kind     Kind     `json:"kind"`
	Severity Severity `json:"severity"`
	Status   Status   `json:"status"`

	// Where it was raised. Filled in from the reporting device's enrollment
	// rather than typed by the reporter.
	Checkpoint     venue.CheckpointCode `json:"checkpoint,omitempty"`
	CheckpointName string               `json:"checkpoint_name,omitempty"`
	Zone           venue.ZoneCode       `json:"zone,omitempty"`
	ZoneName       string               `json:"zone_name,omitempty"`

	// Device is the enrolled scanner. Reporter is whatever name the staff member
	// entered when they signed in, which is often blank and that is fine.
	Device   string `json:"device,omitempty"`
	Reporter string `json:"reporter,omitempty"`

	Note string `json:"note,omitempty"`

	// HeadCount is how many extra staff a staffing request is asking for.
	HeadCount int `json:"head_count,omitempty"`

	// QueueRate is the gate's scans per minute at the moment of the report,
	// attached automatically. It is the difference between "send help" and "send
	// help, this gate has dropped from 40 scans a minute to 6".
	QueueRate float64 `json:"queue_rate,omitempty"`

	// AssignedTo names the staff or team dispatched.
	AssignedTo string `json:"assigned_to,omitempty"`

	// History is every transition, oldest first. This is what makes the response
	// time provable rather than remembered.
	History []Event `json:"history"`

	RaisedHLC hlc.Timestamp `json:"raised_hlc"`
	RaisedAt  time.Time     `json:"raised_at"`

	Seq uint64 `json:"seq"`
}

// AcknowledgedAfter returns how long the control room took to acknowledge, and
// whether it ever did. This is the number in the post-event report, and the
// number a lawyer asks for.
func (i Incident) AcknowledgedAfter() (time.Duration, bool) {
	for _, event := range i.History {
		if event.Status == Acknowledged || event.Status == Assigned {
			return event.At.Sub(i.RaisedAt), true
		}
	}
	return 0, false
}

// ResolvedAfter returns how long the incident stayed live.
func (i Incident) ResolvedAfter() (time.Duration, bool) {
	for _, event := range i.History {
		if event.Status == Resolved {
			return event.At.Sub(i.RaisedAt), true
		}
	}
	return 0, false
}

// Report is a new incident as the scanner submits it.
type Report struct {
	// Kind and Severity. A zero severity takes the kind's default, and a
	// severity below the default is raised back up to it.
	Kind     Kind
	Severity Severity

	Checkpoint venue.CheckpointCode
	Device     string
	Reporter   string
	Note       string
	HeadCount  int
	QueueRate  float64

	// ClientID is the reporter's idempotency key. A bouncer jabbing the alarm
	// button four times on a flaky link raises one incident, not four.
	ClientID string
}

// Errors returned when validating a report.
var (
	// ErrUnknownKind means the reported kind is not one this box understands,
	// which normally means a scanner is newer than the box.
	ErrUnknownKind = errors.New("incident: unknown kind")

	// ErrNoDevice means the report is unattributed. Every human-raised incident
	// is attributed: an anonymous alarm cannot be followed up and cannot be
	// trusted.
	ErrNoDevice = errors.New("incident: report has no device")
)

// knownKinds is the closed set, used to reject anything the dashboard cannot
// render.
var knownKinds = map[Kind]bool{
	NeedStaff: true, NeedSupervisor: true, NeedRelief: true, EquipmentFault: true,
	Medical: true, Crush: true, Fight: true, Fire: true, Theft: true,
	LostChild: true, Suspicious: true, Structural: true, Evacuate: true,
	GateOffline: true, QueueSpike: true, OverCapacity: true,
	DoubleUseDetected: true, DegradedEntered: true,
}

// Kinds returns every kind the box understands, so the scanner can render its
// buttons from the box rather than from a hardcoded list that drifts.
func Kinds() []Kind {
	// Fixed order: staffing requests, then alarms, then automatic signals. The
	// scanner lays its buttons out in this order and muscle memory depends on it
	// not changing.
	return []Kind{
		NeedStaff, NeedSupervisor, NeedRelief, EquipmentFault,
		Medical, Crush, Fight, Fire, Theft, LostChild, Suspicious, Structural, Evacuate,
		GateOffline, QueueSpike, OverCapacity, DoubleUseDetected, DegradedEntered,
	}
}

// Validate checks a report and fills in its defaults.
func (r *Report) Validate() error {
	r.Kind = Kind(strings.ToLower(strings.TrimSpace(string(r.Kind))))
	if !knownKinds[r.Kind] {
		return fmt.Errorf("%w: %q", ErrUnknownKind, r.Kind)
	}
	if r.Device == "" && !IsAutomatic(r.Kind) {
		return ErrNoDevice
	}

	// A reporter may escalate but never de-escalate. The person standing in the
	// crowd is better placed than a table of defaults to judge how bad it is,
	// and a button that can be quietly downgraded is a button that gets somebody
	// hurt.
	if fallback := DefaultSeverity(r.Kind); rank(r.Severity) < rank(fallback) {
		r.Severity = fallback
	}
	if r.HeadCount < 0 {
		r.HeadCount = 0
	}
	if r.HeadCount > 50 {
		// One door asking for fifty people is a typo, and a typo that pages the
		// entire crew is its own incident.
		r.HeadCount = 50
	}
	r.Note = strings.TrimSpace(r.Note)
	if len(r.Note) > 500 {
		r.Note = r.Note[:500]
	}
	return nil
}

// rank orders severities so they can be compared.
func rank(s Severity) int {
	switch s {
	case Emergency:
		return 4
	case Urgent:
		return 3
	case Warning:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

// Higher reports whether a is more severe than b.
func Higher(a, b Severity) bool { return rank(a) > rank(b) }

// Errors returned when transitioning an incident.
var (
	// ErrNotFound means no incident with that id exists.
	ErrNotFound = errors.New("incident: not found")

	// ErrClosed means the incident is already resolved or cancelled. Reopening
	// is deliberately unsupported: the record is append-only, and a recurrence
	// is a new incident with its own response time.
	ErrClosed = errors.New("incident: already closed")

	// ErrNoteRequired means a cancellation arrived without a reason.
	ErrNoteRequired = errors.New("incident: cancelling needs a note")

	// ErrNoActor means a transition is unattributed.
	ErrNoActor = errors.New("incident: transition has no actor")
)

// Transition is a requested status change.
type Transition struct {
	Status Status
	Actor  string
	Note   string

	// AssignedTo names who is being dispatched, for Assigned.
	AssignedTo string
}

// Apply moves an incident to a new status, returning the updated incident.
//
// The rules are few and all of them are about accountability: every transition
// names an actor, a closed incident stays closed, and cancelling requires a
// reason.
func Apply(i Incident, t Transition, at time.Time, stamp hlc.Timestamp) (Incident, error) {
	if !i.Status.Live() {
		return i, fmt.Errorf("%w: %s is %s", ErrClosed, i.ID, i.Status)
	}
	if t.Actor == "" {
		return i, ErrNoActor
	}
	switch t.Status {
	case Acknowledged, Assigned, Resolved:
	case Cancelled:
		if strings.TrimSpace(t.Note) == "" {
			return i, ErrNoteRequired
		}
	default:
		return i, fmt.Errorf("incident: cannot transition to %q", t.Status)
	}

	i.Status = t.Status
	if t.AssignedTo != "" {
		i.AssignedTo = t.AssignedTo
	}
	i.History = append(i.History, Event{
		Status: t.Status,
		Actor:  t.Actor,
		Note:   strings.TrimSpace(t.Note),
		HLC:    stamp,
		At:     at,
	})
	return i, nil
}

// FormatID renders a sequence number as a human-sayable incident id.
func FormatID(seq uint64) ID { return ID(fmt.Sprintf("INC-%d", seq)) }
