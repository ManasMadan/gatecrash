# Wayfinding

The wallet does not just say "Block A, Row A, Seat 1". It says which door to use, how to get
there, and where the nearest toilet is that the ticket is actually allowed to reach.

## The walk graph

Separate from the zone graph, and deliberately so. Zones answer _may this person be here_;
the walk graph answers _how do they get there_. They are different questions and conflating
them produces a route through a wall.

```json
{
  "nodes": [
    {
      "id": "n-gate-north",
      "kind": "gate",
      "name": "the North Gate",
      "position": { "x": 15, "y": 100 }
    },
    {
      "id": "n-concourse",
      "kind": "concourse",
      "name": "the concourse",
      "zone": "concourse",
      "position": { "x": 60, "y": 92 }
    },
    {
      "id": "n-aisle-a",
      "kind": "aisle",
      "name": "the Block A aisle",
      "zone": "arena",
      "position": { "x": 28, "y": 58 },
      "level": 1
    }
  ],
  "edges": [
    { "from": "n-gate-north", "to": "n-concourse" },
    { "from": "n-concourse", "to": "n-portal-a" },
    { "from": "n-portal-a", "to": "n-aisle-a", "stairs": true }
  ]
}
```

Edge weights come from the distance between node positions, so you do not maintain them. An
edge marked `stairs` is excluded from the step-free variant, and `level` is what makes a
route say "up one level" rather than silently teleporting somebody between floors.

## Routing

Dijkstra, twice: once normally and once with stairs excluded. Both run on the box in
microseconds, and the wallet asks for whichever the holder tapped.

Routing is constrained by entitlement. A general-admission holder is never routed through
backstage, even if that is the shortest path, because a route somebody cannot walk is worse
than a longer one — it sends them to a door that will refuse them.

## Guidance

What the wallet actually shows is not a route but an answer to "what now":

```json
{
  "next": [{ "checkpoint": "portal-a", "name": "Portal A", "zone_name": "Arena", "route": { "seconds": 95 } }],
  "later": [{ "checkpoint": "pit-gate", "name": "Pit Wristband", "missing": ["arena"] }],
  "destination": { "section_name": "Block A", "seat_label": "Block A row A seat 1", "route": { "legs": [...] } },
  "arrived": false
}
```

- **`next`** — doors usable right now, given where they have already been.
- **`later`** — doors that exist but are not yet available, and **what is missing**. "After
  you have been through the Arena" is a useful thing to be told at 19:40; "denied" is not.
- **`destination`** — their seat, with turn-by-turn legs.
- **`arrived`** — so the app can stop nagging.

This updates as they walk through gates, because the box knows which zones they are in.

## The map

The same component renders for an attendee and for the control room, with different props —
because they are asking different things of the same picture.

For an attendee: their seat lit up, their route drawn over it, zones they may not enter
dimmed rather than hatched (a map covered in warnings is a map nobody reads), and only the
doors that concern them labelled.

Two details that came from getting it wrong: a focused seat map **always includes the
stage**, because somebody holding it cannot otherwise tell which way round they will be
sitting; and area labels are staggered by nesting depth, because a pit sits flush against the
front of the arena that contains it and both labels landed on the same line.

For the control room: every door named, and occupancy shaded onto the zones. "The pit is
filling and the arena is not" is one glance there and four rows of a table anywhere else.

## Finding things

```
GET /v1/ticket/{id}/nearby?kind=washroom&from=n-portal-a&step_free=true
```

Sorted by walking time rather than straight-line distance, and filtered to what the ticket
can reach. The nearest toilet in a zone they cannot enter is not the nearest toilet.
