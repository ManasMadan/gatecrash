package venue

import "time"

// Lookups. Every method here is a map read on immutable state, safe to call
// from any goroutine, and cheap enough to sit on the scan path.

// Zone returns a zone by code.
func (v *Venue) Zone(code ZoneCode) (Zone, bool) {
	zone, ok := v.zones[code]
	return zone, ok
}

// Section returns a section by code.
func (v *Venue) Section(code SectionCode) (Section, bool) {
	section, ok := v.sections[code]
	return section, ok
}

// Checkpoint returns a checkpoint by code.
func (v *Venue) Checkpoint(code CheckpointCode) (Checkpoint, bool) {
	cp, ok := v.checkpoints[code]
	return cp, ok
}

// Tier returns a tier by code.
func (v *Venue) Tier(code TierCode) (Tier, bool) {
	tier, ok := v.tiers[code]
	return tier, ok
}

// Amenity returns an amenity by id.
func (v *Venue) Amenity(id string) (Amenity, bool) {
	amenity, ok := v.amenities[id]
	return amenity, ok
}

// Node returns a walk-graph node by id.
func (v *Venue) Node(id NodeID) (Node, bool) {
	node, ok := v.nodes[id]
	return node, ok
}

// Zones returns every zone in authoring order, which is the order the organizer
// expects to see it drawn. Sections, Checkpoints, Tiers and Amenities do the same
// for theirs.
func (v *Venue) Zones() []Zone {
	out := make([]Zone, 0, len(v.zoneOrder))
	for _, code := range v.zoneOrder {
		out = append(out, v.zones[code])
	}
	return out
}

// Sections returns every section in authoring order.
func (v *Venue) Sections() []Section {
	out := make([]Section, 0, len(v.sectionOrder))
	for _, code := range v.sectionOrder {
		out = append(out, v.sections[code])
	}
	return out
}

// Checkpoints returns every checkpoint in authoring order.
func (v *Venue) Checkpoints() []Checkpoint {
	out := make([]Checkpoint, 0, len(v.checkpointOrder))
	for _, code := range v.checkpointOrder {
		out = append(out, v.checkpoints[code])
	}
	return out
}

// Tiers returns every tier in authoring order.
func (v *Venue) Tiers() []Tier {
	out := make([]Tier, 0, len(v.tierOrder))
	for _, code := range v.tierOrder {
		out = append(out, v.tiers[code])
	}
	return out
}

// Amenities returns every amenity in authoring order.
func (v *Venue) Amenities() []Amenity {
	out := make([]Amenity, 0, len(v.amenityOrder))
	for _, id := range v.amenityOrder {
		out = append(out, v.amenities[id])
	}
	return out
}

// Plan returns the normalised authoring form. This is what gets re-exported in
// a manifest and what the attendee app downloads to draw the map, so it has to
// be the compiled truth rather than the original input.
func (v *Venue) Plan() Plan { return v.plan }

// ZoneAncestors returns the zone followed by its parents outward to the root.
func (v *Venue) ZoneAncestors(code ZoneCode) []ZoneCode { return v.ancestors[code] }

// ZoneChildren returns the zones nested directly inside a zone.
func (v *Venue) ZoneChildren(code ZoneCode) []ZoneCode { return v.children[code] }

// TierAdmits reports whether a tier entitles its holder to be inside a zone.
// Grants are expanded through nesting at compile time, so this is one map
// lookup and safe to call on the scan path.
func (v *Venue) TierAdmits(tier TierCode, zone ZoneCode) bool {
	return v.tierZones[tier][zone]
}

// TierZones returns every zone a tier may enter, expanded through nesting.
func (v *Venue) TierZones(tier TierCode) []ZoneCode {
	granted := v.tierZones[tier]
	out := make([]ZoneCode, 0, len(granted))
	// Authoring order, so the attendee app lists "Arena, VIP Lounge" the way
	// the organizer wrote it rather than in map-iteration order.
	for _, code := range v.zoneOrder {
		if granted[code] {
			out = append(out, code)
		}
	}
	return out
}

// SatisfiesZone reports whether being admitted into `admitted` satisfies a
// requirement for `required`. A requirement on the arena is satisfied by an
// admission into the pit, because the pit is inside the arena.
func (v *Venue) SatisfiesZone(admitted, required ZoneCode) bool {
	for _, ancestor := range v.ancestors[admitted] {
		if ancestor == required {
			return true
		}
	}
	return false
}

// CheckpointsForZone returns every checkpoint controlling a zone.
func (v *Venue) CheckpointsForZone(zone ZoneCode) []CheckpointCode {
	return v.checkpointsByZone[zone]
}

// SectionsForZone returns every section inside a zone.
func (v *Venue) SectionsForZone(zone ZoneCode) []SectionCode {
	return v.sectionsByZone[zone]
}

// SectionEntrances returns the checkpoints an attendee holding this section
// should be sent to, in preference order as authored.
func (v *Venue) SectionEntrances(code SectionCode) []CheckpointCode {
	return v.entrancesBySection[code]
}

// Seat resolves a seat reference.
func (v *Venue) Seat(ref SeatRef) (Seat, bool) {
	rows, ok := v.seats[ref.Section]
	if !ok {
		return Seat{}, false
	}
	seats, ok := rows[ref.Row]
	if !ok {
		return Seat{}, false
	}
	seat, ok := seats[ref.Seat]
	return seat, ok
}

// Rows returns a section's row labels in authoring order.
func (v *Venue) Rows(section SectionCode) []string { return v.rowOrder[section] }

// SectionCapacity returns how many people a section holds: its seat count for
// seated and table sections, its declared capacity otherwise. Blocked seats do
// not count, because a broken seat holds nobody.
func (v *Venue) SectionCapacity(code SectionCode) int {
	section, ok := v.sections[code]
	if !ok {
		return 0
	}
	if !section.Kind.Seated() {
		return section.Capacity
	}
	total := 0
	for _, row := range section.Rows {
		for _, seat := range row.Seats {
			if !seat.Blocked {
				total++
			}
		}
	}
	return total
}

// Capacity returns the total capacity of a zone including everything nested
// inside it.
func (v *Venue) Capacity(zone ZoneCode) int {
	total := 0
	for _, code := range v.descendantsOf(zone) {
		if declared := v.zones[code].Capacity; declared > 0 {
			total += declared
		}
	}
	return total
}

// ValidateSeat reports whether a seat reference is usable for a ticket in a
// given tier: the section must exist, the tier must be entitled to its zone,
// and a seated section must name a real, unblocked seat.
//
// This runs at issuance rather than at the gate. A ticket sold for a seat that
// does not exist is a refund conversation, and it should happen at the point of
// sale rather than in a queue.
func (v *Venue) ValidateSeat(tier TierCode, ref SeatRef) error {
	if ref.IsZero() {
		return nil
	}
	section, ok := v.sections[ref.Section]
	if !ok {
		return codeError("seat", ref.String(), "section does not exist")
	}
	if !v.TierAdmits(tier, section.Zone) {
		return codeError("seat", ref.String(), "tier "+string(tier)+" is not entitled to zone "+string(section.Zone))
	}
	if !section.Kind.Seated() {
		if ref.Row != "" || ref.Seat != "" {
			return codeError("seat", ref.String(), "section is standing, so it has no rows or seats")
		}
		return nil
	}
	if ref.Row == "" {
		return codeError("seat", ref.String(), "seated section needs a row")
	}
	seats, ok := v.seats[ref.Section][ref.Row]
	if !ok {
		return codeError("seat", ref.String(), "row does not exist")
	}
	if ref.Seat == "" {
		if section.Kind == SectionTable {
			return nil
		}
		return codeError("seat", ref.String(), "seated section needs a seat number")
	}
	seat, ok := seats[ref.Seat]
	if !ok {
		return codeError("seat", ref.String(), "seat does not exist")
	}
	if seat.Blocked {
		return codeError("seat", ref.String(), "seat is blocked")
	}
	return nil
}

// CheckpointOpen reports whether a checkpoint is accepting scans at an instant.
// A checkpoint with no bounds is always open.
func (v *Venue) CheckpointOpen(code CheckpointCode, at time.Time) bool {
	cp, ok := v.checkpoints[code]
	if !ok {
		return false
	}
	if !cp.OpensAt.IsZero() && at.Before(cp.OpensAt) {
		return false
	}
	if !cp.ClosesAt.IsZero() && at.After(cp.ClosesAt) {
		return false
	}
	return true
}

// CheckpointServes reports whether a checkpoint is the right door for a ticket,
// separately from whether the ticket is entitled to the zone.
//
// The distinction is the whole point: a VIP at the general gate is entitled but
// at the wrong door, and the correct thing to tell them is which way to walk,
// not that their ticket is invalid.
func (v *Venue) CheckpointServes(code CheckpointCode, tier TierCode, seat SeatRef) bool {
	cp, ok := v.checkpoints[code]
	if !ok {
		return false
	}
	if len(cp.Tiers) > 0 {
		matched := false
		for _, allowed := range cp.Tiers {
			if allowed == tier {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(cp.Sections) > 0 {
		if seat.Section == "" {
			return false
		}
		for _, allowed := range cp.Sections {
			if allowed == seat.Section {
				return true
			}
		}
		return false
	}
	return true
}

// HasMap reports whether the venue carries a drawable floor plan.
func (v *Venue) HasMap() bool { return v.plan.Map.Width > 0 && v.plan.Map.Height > 0 }

// HasWalkGraph reports whether the venue carries a routable walk graph. Without
// one, wayfinding still names the right gate and section but cannot give
// turn-by-turn steps.
func (v *Venue) HasWalkGraph() bool { return len(v.adjacency) > 0 }

// SeatLabel renders a seat the way it is printed on a ticket and shouted across a
// concourse: with the section's name rather than its code.
//
// SeatRef.String is the code form, which is right for the audit log and wrong for
// anybody's eyes — "block-a row A seat 1" is a database row, not a seat. This is
// the only version an attendee or an usher should ever see.
func (v *Venue) SeatLabel(ref SeatRef) string {
	if ref.IsZero() {
		return ""
	}
	name := string(ref.Section)
	if section, ok := v.sections[ref.Section]; ok && section.Name != "" {
		name = section.Name
	}
	switch {
	case ref.Row == "" && ref.Seat == "":
		return name
	case ref.Seat == "":
		return name + " row " + ref.Row
	default:
		return name + " row " + ref.Row + " seat " + ref.Seat
	}
}
