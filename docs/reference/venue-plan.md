# Venue plan

The JSON `gatecrash-keys venue` writes and `gatecrash-keys manifest` signs. The compiler
refuses anything that does not make sense and says which line is wrong, so an invalid plan
fails on your laptop rather than at a door.

The reasoning behind these shapes is in [Zones, seats and doors](/guide/venue).

## Top level

```json
{
  "zones": [],
  "sections": [],
  "checkpoints": [],
  "tiers": [],
  "amenities": [],
  "map": {}
}
```

Codes are normalised — lower-cased, trimmed — so `Block-A`, `block-a` and `BLOCK-A` are the
same section rather than three.

## zones

```json
{
  "code": "pit",
  "name": "Front Pit",
  "kind": "pit",
  "parent": "arena",
  "restricted": true,
  "capacity": 200,
  "colour": "#A855F7",
  "shape": [
    { "x": 42, "y": 21 },
    { "x": 78, "y": 21 },
    { "x": 78, "y": 42 },
    { "x": 42, "y": 42 }
  ]
}
```

| Field        | Notes                                                                                                                                                                                 |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kind`       | `perimeter`, `concourse`, `arena`, `pit`, `backstage`, `campsite`, `vip`. Display and default colour only; nothing decides on it.                                                     |
| `parent`     | Nesting. Somebody in the pit is in the arena and in the perimeter, which is how one admission counts at every level.                                                                  |
| `restricted` | **The security flag.** A tier's grant cascades down the tree, so without this a perimeter grant inherits backstage. Set it and the cascade stops, so nesting fails closed.            |
| `capacity`   | Optional and honest: an open field has no meaningful number, and the dashboard only meters zones that declare one. For a fully seated zone the compiler fills it from the seat count. |
| `shape`      | A polygon in map units. Optional — a venue with no floor plan still runs an event, it just has no map.                                                                                |

## checkpoints

```json
{
  "code": "pit-gate",
  "name": "Pit Wristband",
  "zone": "pit",
  "direction": "in",
  "policy": "once",
  "count_limit": 0,
  "requires": ["arena"],
  "tiers": ["vip"],
  "sections": [],
  "lane": "1",
  "node": "n-pit",
  "position": { "x": 60, "y": 40 },
  "opens_at": "2026-08-21T18:00:00+05:30",
  "closes_at": "2026-08-22T01:00:00+05:30"
}
```

| Field                    | Notes                                                                                                                                                                                                                     |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `direction`              | `in`, `out`, `both`. An outbound scan removes the zone **and everything nested inside it**, which is what keeps a capacity meter honest on a room people leave.                                                           |
| `policy`                 | `once`, `re-entry`, or `counted` with `count_limit`.                                                                                                                                                                      |
| `requires`               | Zones the holder must already have entered. This is the sequencing, and a failure is `PREREQUISITE_MISSING` **with a redirect**.                                                                                          |
| `tiers`                  | Who may pass at all. Empty means anybody whose entitlement covers the zone.                                                                                                                                               |
| `sections`               | Narrows the door to specific seat blocks — what a stadium vomitory is. A mismatch is `WRONG_DOOR`, with a redirect.                                                                                                       |
| `node`                   | The walk-graph node. `position` is taken from it when omitted, so the coordinates are not written twice — two copies of one fact is two chances to disagree, and the way it disagrees is a gate drawn in the wrong place. |
| `opens_at` / `closes_at` | Outside them, `DOORS_CLOSED`.                                                                                                                                                                                             |

::: warning
Every arena door being `sections`-restricted means a standing or VIP ticket with no seat has
no way in at all — and that only shows up when somebody is standing at a gate. The starter
plan includes a general arena entrance for exactly this reason.
:::

## sections

```json
{
  "code": "block-a",
  "name": "Block A",
  "kind": "seated",
  "zone": "arena",
  "entrances": ["portal-a"],
  "node": "n-portal-a",
  "view_note": "Upper tier, behind the mix position",
  "shape": [
    { "x": 28, "y": 50 },
    { "x": 92, "y": 50 },
    { "x": 92, "y": 68 },
    { "x": 28, "y": 68 }
  ],
  "rows": [
    {
      "label": "A",
      "start": { "x": 30, "y": 55 },
      "end": { "x": 90, "y": 55 },
      "curve": 4,
      "aisle": "n-aisle-a",
      "seats": [{ "number": "1", "kind": "standard" }]
    }
  ]
}
```

`kind` is `seated` or `standing`; a standing section takes a `capacity` and no rows.

Rows are described as geometry — a start, an end, a curve, a seat list — and the compiler lays
the seats along a quadratic bezier. A positive `curve` bows the row _left of the direction of
travel_, which for a row running left to right in front of a stage is towards the audience. An
explicit `position` on a seat survives untouched, for the one row that does not fit a formula.

Seat `kind` is `standard`, `accessible`, `companion` or `restricted-view`, and `blocked` takes
a seat out of sale while leaving it on the map.

## tiers

```json
{
  "code": "vip",
  "name": "VIP",
  "zones": ["perimeter", "arena", "pit"],
  "colour": "#A855F7",
  "priority": 20
}
```

`zones` is the entitlement, and it cascades into nested zones except where `restricted` stops
it. `colour` is the band on the verdict screen a guard matches against a wristband, so pick
colours that are distinguishable under a floodlight rather than on a monitor.

## amenities

```json
{
  "id": "wc-concourse",
  "kind": "washroom",
  "name": "Concourse Toilets",
  "zone": "concourse",
  "position": { "x": 45, "y": 92 },
  "node": "n-concourse",
  "accessible": true
}
```

`kind` is one of `washroom`, `food`, `bar`, `water`, `medical`, `exit`, `info`, `lost-found`,
`charging`, `atm`, `smoking`, `merch`, `cloakroom`, `accessible`. `node` is inferred from the
position when omitted. Marking one `accessible` is what makes the wallet's step-free search
mean anything.

## map

```json
{
  "width": 120,
  "height": 110,
  "metres_per_unit": 1.5,
  "outline": [],
  "stage": [],
  "nodes": [],
  "edges": []
}
```

Units are arbitrary and `metres_per_unit` converts them, which is what turns a route into "about
a 2 minute walk". Node kinds: `gate`, `concourse`, `portal`, `aisle`, `seat-block`, `amenity`,
`junction`. An edge marked `stairs` is excluded from the step-free route; `level` on a node is
what makes a route say "up one level".

## Checking it

```sh
gatecrash-keys inspect manifest.json
```

Prints the compiled plan: zone tree, doors with their prerequisites, sections with seat counts,
and anything the compiler filled in for you.
