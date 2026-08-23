# Zones, seats and doors

A venue is not one door, and modelling it as one is why most systems cannot answer "can
this person be here?".

Gatecrash models it as a graph. That is what makes sequencing possible: perimeter, then
concourse, then arena, then the pit — each with its own doors, its own allowlist of which
tiers may pass, and its own prerequisites.

## Zones

```json
{
  "code": "arena",
  "name": "Arena",
  "kind": "arena",
  "parent": "perimeter",
  "restricted": true,
  "capacity": 2000,
  "shape": [
    { "x": 26, "y": 20 },
    { "x": 94, "y": 20 },
    { "x": 94, "y": 82 },
    { "x": 26, "y": 82 }
  ]
}
```

Zones nest. Somebody inside the pit is inside the arena and inside the perimeter, which is
what lets occupancy be counted at every level from one admission.

**`restricted` is the important one.** A tier's grant cascades down the zone tree, so a
general-admission ticket granted the perimeter would inherit everything nested inside it —
including backstage. `restricted` stops the cascade, so nesting fails closed rather than
open. This was a real bug before it was a flag; see §15 of
[DECISIONS.md](https://github.com/ManasMadan/gatecrash/blob/master/DECISIONS.md).

`capacity` is optional and honest: an open field has no meaningful number, and the dashboard
only shows an occupancy meter for zones that declare one. For a fully seated zone the
compiler fills it in from the seat count, so the two numbers cannot disagree.

## Checkpoints

A checkpoint is a door, and it carries everything needed to decide a scan at it:

```json
{
  "code": "pit-gate",
  "name": "Pit Wristband",
  "zone": "pit",
  "direction": "in",
  "policy": "once",
  "requires": ["arena"],
  "tiers": ["vip"],
  "node": "n-pit"
}
```

- **`requires`** — the zones somebody must already have entered. This is the sequencing: a
  pit wristband scanned before the outer gate is `PREREQUISITE_MISSING`, refused **with a
  redirect** telling the guard where to send them.
- **`tiers`** — who may pass at all. Empty means anybody whose entitlement covers the zone.
- **`sections`** — narrows a door to specific seat blocks. A stadium vomitory serves one
  block and nothing else, and a Block A ticket at Portal B is `WRONG_DOOR`, again with a
  redirect.
- **`policy`** — `once`, `re-entry`, or `counted` with a `count_limit`. Two drink tokens is a
  counted checkpoint, and the guard is told "one left" rather than the attendee finding out
  at the bar.
- **`direction`** — `in`, `out` or `both`. An outbound scan removes the zone and everything
  nested inside it, which is what keeps a capacity meter honest on a room people leave.

## Seats

Rows are described the way a real stand is described — a start, an end, a curve and a seat
count — and the compiler lays the seats out along a quadratic bezier:

```json
{
  "code": "block-a",
  "name": "Block A",
  "kind": "seated",
  "zone": "arena",
  "entrances": ["portal-a"],
  "rows": [
    {
      "label": "A",
      "start": { "x": 30, "y": 55 },
      "end": { "x": 90, "y": 55 },
      "curve": 4,
      "seats": 12
    }
  ]
}
```

Writing per-seat coordinates by hand would be both tedious and a second source of truth.
A positive `curve` bows the row left of the direction of travel, which for a row running
left to right in front of a stage is towards the audience.

## Amenities

Toilets, food, water, medical, exits, charging, cloakrooms. Each has a position and a zone,
and the compiler attaches it to the nearest walk-graph node so routing works without you
having to say which path leads there.

Marking one `accessible` is what makes the wallet's step-free search mean something.

## Checking a plan

The compiler refuses a plan that does not make sense — a zone cycle, a door in a zone that
does not exist, a section whose entrances are not doors into its own zone — and says which
line is wrong:

```sh
gatecrash-keys inspect manifest.json
```

The starter plan from `gatecrash-keys venue` compiles, runs, and contains one of every
interesting shape. It is a better starting point than an empty file.

Full field list: [Venue plan reference](/reference/venue-plan).
