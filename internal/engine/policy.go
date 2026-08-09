package engine

import (
	"errors"
	"time"

	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// payload is a parsed QR string, normalised across the two formats.
type payload struct {
	format   Format
	ticketID ticket.ID

	// Exactly one of these is set, matching format.
	gc1 ticket.GC1
	gc2 ticket.GC2
}

// parsePayload sniffs and parses a scanned string.
//
// Format detection is a prefix comparison and runs before any allocation or
// cryptography, because a gate under a garbage-QR flood should burn nothing on
// input that is obviously not ours.
func parsePayload(raw string) (payload, error) {
	switch {
	case ticket.IsGC1(raw):
		parsed, err := ticket.ParseGC1(raw)
		if err != nil {
			return payload{}, err
		}
		return payload{format: FormatStatic, ticketID: parsed.TicketID, gc1: parsed}, nil
	case ticket.IsGC2(raw):
		parsed, err := ticket.ParseGC2(raw)
		if err != nil {
			return payload{}, err
		}
		return payload{format: FormatRotating, ticketID: parsed.TicketID, gc2: parsed}, nil
	default:
		return payload{}, errors.New("engine: not a gatecrash payload")
	}
}

// verify checks a payload's cryptography and returns Admit when it holds.
//
// It returns a verdict rather than an error because the distinction between a
// forgery and an expired rotating code matters at the gate: one is a red screen
// and a conversation with security, the other is an amber screen and "ask them
// to reopen the app".
func (e *Engine) verify(p payload, record Ticket, now time.Time) Verdict {
	switch p.format {
	case FormatStatic:
		claims := ticket.Claims{
			EventID:  record.EventID,
			TicketID: record.ID,
			Tier:     string(record.Tier),
			IssuedAt: record.IssuedAt,
		}
		if len(record.Signature) > 0 {
			// The manifest carries the organizer's signature, so the box checks
			// the payload's signature against the same claims and does not have
			// to trust its own database: a tampered manifest row changes the
			// claims and the payload signature stops verifying.
			if !bytesEqual(record.Signature, p.gc1.Signature) {
				return InvalidSig
			}
		}
		ok, err := p.gc1.Verify(e.cfg.Verifying, claims)
		if err != nil || !ok {
			return InvalidSig
		}
		return Admit

	case FormatRotating:
		if e.cfg.Master.IsZero() {
			// The event does not carry a master key, so no GC2 code can be
			// validated. This is a configuration state, not a forgery, but the
			// gate has no way to tell the holder apart from one either.
			return InvalidSig
		}
		err := ticket.ValidateGC2(e.cfg.Master, e.cfg.EventID, p.gc2, ticket.WindowAt(now))
		switch {
		case err == nil:
			return Admit
		case errors.Is(err, ticket.ErrExpiredWindow):
			return ExpiredWindow
		default:
			return InvalidSig
		}

	default:
		return Malformed
	}
}

// bytesEqual is a plain comparison. Constant time is unnecessary here: both
// values are already public — one came off a QR code the holder is waving
// around, the other out of a manifest every scanner has a copy of.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// unmetPrerequisites returns the zones a checkpoint requires that this ticket's
// history does not satisfy.
//
// A requirement is satisfied by an admission into the named zone or into any
// zone nested inside it: somebody who is in the pit is, necessarily, in the
// arena. Only inbound admissions count, and an exit undoes them, because a
// person who has left the arena is no longer inside it and should not be able to
// walk straight into the pit.
func (e *Engine) unmetPrerequisites(cp venue.Checkpoint, history []Redemption) []venue.ZoneCode {
	if len(cp.Requires) == 0 {
		return nil
	}
	inside := e.insideZones(history)

	var missing []venue.ZoneCode
	for _, required := range cp.Requires {
		satisfied := false
		for zone := range inside {
			if e.cfg.Venue.SatisfiesZone(zone, required) {
				satisfied = true
				break
			}
		}
		if !satisfied {
			missing = append(missing, required)
		}
	}
	return missing
}

// insideZones replays a ticket's history into the set of zones it is currently
// inside. Inbound passes add, outbound passes remove.
//
// An exit removes the zone and everything nested inside it. Somebody who walks
// out of the perimeter is not still in the arena, and without the cascade a
// holder could leave the site and then walk straight into the pit on the
// strength of an arena scan from an hour earlier.
func (e *Engine) insideZones(history []Redemption) map[venue.ZoneCode]bool {
	inside := make(map[venue.ZoneCode]bool, len(history))
	for _, r := range history {
		switch r.Direction {
		case venue.DirectionOut:
			for zone := range inside {
				if e.cfg.Venue.SatisfiesZone(zone, r.Zone) {
					delete(inside, zone)
				}
			}
		default:
			inside[r.Zone] = true
		}
	}
	return inside
}

// isInside reports whether a ticket is currently inside a zone, counting an
// admission into any zone nested inside it.
func (e *Engine) isInside(zone venue.ZoneCode, history []Redemption) bool {
	for held := range e.insideZones(history) {
		if e.cfg.Venue.SatisfiesZone(held, zone) {
			return true
		}
	}
	return false
}

// InsideZones is insideZones for callers outside the package: the wayfinding
// endpoint needs the same replay so the attendee app's "where to next" agrees
// with what the gates will actually do.
func (e *Engine) InsideZones(history []Redemption) []venue.ZoneCode {
	inside := e.insideZones(history)
	// Authoring order, so the app lists zones the way the organizer wrote them.
	var out []venue.ZoneCode
	for _, zone := range e.cfg.Venue.Zones() {
		if inside[zone.Code] {
			out = append(out, zone.Code)
		}
	}
	return out
}

// pass is the decision about which occurrence and direction a scan would be.
type pass struct {
	occurrence uint32
	direction  venue.Direction
	passesLeft *int
	previous   *Admission
}

// nextPass applies the checkpoint's policy to the ticket's history.
//
// This is where the once-only turnstile, the re-entry door and the drink token
// diverge, and it is all read-then-decide inside the same transaction as the
// insert, so the count it computes cannot be stale by the time it is used.
func (e *Engine) nextPass(cp venue.Checkpoint, scan Scan, history []Redemption) (pass, Verdict) {
	direction := scan.Direction
	if direction == "" || cp.Direction != venue.DirectionBoth {
		direction = cp.Direction
	}
	if cp.Direction == venue.DirectionBoth && direction != venue.DirectionIn && direction != venue.DirectionOut {
		direction = venue.DirectionIn
	}

	var here []Redemption
	for _, r := range history {
		if r.Checkpoint == cp.Code {
			here = append(here, r)
		}
	}

	switch cp.Policy {
	case venue.PolicyOnce:
		// Occurrence is always zero, so the unique constraint on (ticket,
		// checkpoint, occurrence) is what enforces single use. The read below is
		// only for the evidence shown on the denial; the CAS is the authority,
		// which is what makes ten simultaneous scans safe.
		out := pass{occurrence: 0, direction: direction}
		if len(here) > 0 {
			previous := admissionOf(here[0], e.cfg.Venue)
			out.previous = &previous
		}
		return out, Admit

	case venue.PolicyReEntry:
		// Alternation is judged against whether the holder is currently inside
		// the zone, not against prior passes at this particular door.
		//
		// The difference matters for every real venue: people come in through
		// the north gate and leave through the dedicated exit, so an exit door
		// has no prior passes for them at all. Judging by the door would refuse
		// everybody the first time they tried to leave.
		insideNow := e.isInside(cp.Zone, history)
		occurrence := uint32(len(here))

		var previous *Admission
		if len(here) > 0 {
			recent := admissionOf(here[len(here)-1], e.cfg.Venue)
			previous = &recent
		}

		if direction == venue.DirectionOut {
			if !insideNow {
				// Almost always the guard has the in/out toggle the wrong way
				// round, so this is amber and says so rather than calling the
				// ticket bad.
				return pass{occurrence: occurrence, direction: direction, previous: previous}, WrongDirection
			}
			return pass{occurrence: occurrence, direction: direction}, Admit
		}
		if insideNow {
			// Scanning in while already inside. Harmless, and the honest answer
			// is that they are already through this door.
			return pass{occurrence: occurrence, direction: direction, previous: previous}, AlreadyUsed
		}
		return pass{occurrence: occurrence, direction: direction}, Admit

	case venue.PolicyCounted:
		used := len(here)
		remaining := cp.CountLimit - used
		if remaining <= 0 {
			zero := 0
			out := pass{occurrence: uint32(used), direction: direction, passesLeft: &zero}
			if used > 0 {
				previous := admissionOf(here[used-1], e.cfg.Venue)
				out.previous = &previous
			}
			return out, PassLimitReached
		}
		left := remaining - 1
		return pass{occurrence: uint32(used), direction: direction, passesLeft: &left}, Admit

	default:
		// An unknown policy cannot be reached through Compile, which rejects
		// them, but failing closed is the only acceptable default in this
		// function.
		return pass{direction: direction}, WrongZone
	}
}

// redirectsFor lists the checkpoints that would serve this ticket into a zone,
// so an amber screen can point somewhere.
func (e *Engine) redirectsFor(record Ticket, zone venue.ZoneCode) []Redirect {
	// A seated ticket's own section knows its doors, which is a better answer
	// than every door on the zone.
	if !record.Seat.IsZero() {
		if entrances := e.cfg.Venue.SectionEntrances(record.Seat.Section); len(entrances) > 0 {
			return e.describeRedirects(entrances)
		}
	}
	var candidates []venue.CheckpointCode
	for _, code := range e.cfg.Venue.CheckpointsForZone(zone) {
		if e.cfg.Venue.CheckpointServes(code, record.Tier, record.Seat) {
			candidates = append(candidates, code)
		}
	}
	return e.describeRedirects(candidates)
}

// redirectsForZones lists the doors that would satisfy a set of missing
// prerequisite zones.
func (e *Engine) redirectsForZones(record Ticket, zones []venue.ZoneCode) []Redirect {
	var candidates []venue.CheckpointCode
	seen := make(map[venue.CheckpointCode]bool)
	for _, zone := range zones {
		for _, code := range e.cfg.Venue.CheckpointsForZone(zone) {
			if seen[code] {
				continue
			}
			cp, ok := e.cfg.Venue.Checkpoint(code)
			if !ok || cp.Direction == venue.DirectionOut {
				continue
			}
			if !e.cfg.Venue.CheckpointServes(code, record.Tier, record.Seat) {
				continue
			}
			seen[code] = true
			candidates = append(candidates, code)
		}
	}
	return e.describeRedirects(candidates)
}

// describeRedirects turns checkpoint codes into the small shape an amber screen
// shows. Capped at three, because a guard pointing at a queue can convey one
// direction and possibly two, and a list of nine doors is the same as no answer.
func (e *Engine) describeRedirects(codes []venue.CheckpointCode) []Redirect {
	const most = 3
	out := make([]Redirect, 0, min(len(codes), most))
	for _, code := range codes {
		if len(out) == most {
			break
		}
		cp, ok := e.cfg.Venue.Checkpoint(code)
		if !ok {
			continue
		}
		out = append(out, Redirect{Checkpoint: code, Name: cp.Name, Lane: cp.Lane, Zone: cp.Zone})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
