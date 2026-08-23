import { useMemo } from 'react'
import type { CSSProperties } from 'react'
import type { Amenity, Point, Route, SeatRef, VenuePlan } from 'gatecrash-client'

/**
 * The venue map.
 *
 * One SVG in the venue's own coordinate space. No tiles, no image requests, no map
 * provider — the geometry arrived inside the manifest and is a few kilobytes, which
 * is what makes this work with no signal at all.
 *
 * What is drawn, and in what order, is decided by what the person holding it is
 * looking for: their seat, the route to it, the doors they can use, then context.
 * Everything in the last group is deliberately low contrast, because a map where
 * everything is emphasised is a map where nothing is.
 */

export interface VenueMapProps {
  plan: VenuePlan

  /** The holder's own seat, drawn brightest. */
  seat?: SeatRef

  /** The route to walk, drawn over everything except the seat marker. */
  route?: Route

  /** Where they are now. */
  from?: string

  /**
   * Zones the holder may enter. Everything else is dimmed rather than hatched: a
   * map covered in warnings is a map nobody reads.
   */
  allowedZones?: string[]

  /** Checkpoints they can use now, and ones they will be able to use later. */
  openCheckpoints?: string[]
  laterCheckpoints?: string[]

  /** Amenities to lift out of the background, from a "nearest toilet" search. */
  highlightAmenities?: string[]

  /** Draw individual seats. Off for the dashboard's overview, on for one section. */
  showSeats?: boolean

  /**
   * Live fullness per zone, as inside-over-capacity. Supplied by the control room,
   * absent for an attendee.
   *
   * A map is the only place occupancy can be read as a shape rather than a number:
   * "the pit is filling and the arena is not" is one glance here and four rows of a
   * table anywhere else. Zones with a figure are tinted and carry their count.
   */
  occupancy?: Record<string, { inside: number; capacity: number }>

  /**
   * Label every door rather than only the ones this attendee can use.
   *
   * The control room needs to tell North Gate from the bar; an attendee needs the
   * two doors that concern them and no others. Same map, different question.
   */
  labelEveryGate?: boolean

  /** Fit the view to this section rather than the whole venue. */
  focusSection?: string

  className?: string
}

/**
 * One glyph per amenity kind.
 *
 * Emoji rather than an icon font or SVG paths, for one reason: an icon font is a
 * network request, and at the moment this map is needed there is no network. Every
 * one of these renders on Android 8 and iOS 12, which is the floor this product
 * supports.
 */
const AMENITY_GLYPHS: Record<string, string> = {
  washroom: '🚻',
  food: '🍽',
  bar: '🍺',
  water: '💧',
  medical: '✚',
  exit: '🚪',
  info: 'ℹ',
  'lost-found': '🎒',
  charging: '🔌',
  atm: '💳',
  smoking: '🚬',
  merch: '👕',
  cloakroom: '🧥',
  accessible: '♿',
}

export function VenueMap({
  plan,
  seat,
  route,
  from,
  allowedZones,
  openCheckpoints,
  laterCheckpoints,
  highlightAmenities,
  showSeats = true,
  occupancy,
  labelEveryGate = false,
  focusSection,
  className,
}: VenueMapProps) {
  const map = plan.map
  const nodes = useMemo(() => indexNodes(plan), [plan])

  // A venue with no floor plan still runs an event; it just has no map. Saying so
  // beats an empty box that looks broken.
  if (!map || map.width <= 0 || map.height <= 0) {
    return (
      <div className={className} style={{ padding: 'var(--gc-pad)', color: 'var(--gc-text-dim)' }}>
        This venue has no map. Follow the signs, or ask any steward.
      </div>
    )
  }

  // How deeply each zone is nested, used to stagger the area labels. A pit sits
  // flush against the front of the arena that contains it — that is what a pit is —
  // so their two labels would otherwise be drawn on the same line, on top of each
  // other. Offsetting by depth separates them without moving either zone.
  const depth = useMemo(() => zoneDepths(plan), [plan])

  const allowed = allowedZones ? new Set(allowedZones) : undefined
  const open = new Set(openCheckpoints ?? [])
  const later = new Set(laterCheckpoints ?? [])
  const highlighted = new Set(highlightAmenities ?? [])

  const viewBox = useMemo(() => computeViewBox(plan, focusSection), [plan, focusSection])

  // Label sizes are derived from the view rather than fixed, so text stays legible
  // whether the whole venue or one block is on screen.
  const scale = viewBox.width / map.width
  const label = {
    section: 3 * scale,
    gate: 2.2 * scale,
    stage: 4 * scale,
    amenity: 3 * scale,
    zone: 2.4 * scale,
  }

  return (
    <svg
      className={`gc-map ${className ?? ''}`}
      viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.width} ${viewBox.height}`}
      preserveAspectRatio="xMidYMid meet"
      role="img"
      aria-label={mapDescription(plan, seat)}
    >
      {map.outline && map.outline.length >= 3 ? (
        <polygon className="gc-map__outline" points={toPoints(map.outline)} />
      ) : null}

      {/* Zones. Drawn first and faintest: they are the reason the rest makes sense
          and they are not what anybody is looking for. */}
      {plan.zones.map((zone) => {
        if (!zone.shape || zone.shape.length < 3) return null

        const forbidden = allowed && !allowed.has(zone.code)
        const load = occupancy?.[zone.code]
        const level = load && load.capacity > 0 ? load.inside / load.capacity : null

        return (
          <g key={zone.code}>
            <polygon
              className={forbidden ? 'gc-map__zone gc-map__zone--forbidden' : 'gc-map__zone'}
              points={toPoints(zone.shape)}
              style={fillFor(zone.colour, level)}
            />
            {/* Named along the top edge rather than at the centre, because the
                centre is where the seat blocks are and two labels on one spot is
                worse than none. */}
            {/* Clamped into the visible box. A focused view crops zones that run off
                the edge, and a label sliced down the middle reads as a rendering
                bug rather than as "this area continues". */}
            <text
              className="gc-map__zone-label"
              x={Math.max(topLeft(zone.shape).x, viewBox.x) + 1.5}
              y={
                Math.max(topLeft(zone.shape).y, viewBox.y) +
                label.zone * (1 + 0.9 * (depth.get(zone.code) ?? 0)) +
                0.5
              }
              fontSize={label.zone}
            >
              {zone.name}
              {load ? ` · ${load.inside.toLocaleString()}` : ''}
              {load && load.capacity > 0 ? ` / ${load.capacity.toLocaleString()}` : ''}
            </text>
          </g>
        )
      })}

      {map.stage && map.stage.length >= 3 ? (
        <g>
          <polygon className="gc-map__stage" points={toPoints(map.stage)} />
          <text
            className="gc-map__stage-label"
            x={centroid(map.stage).x}
            y={centroid(map.stage).y}
            fontSize={label.stage}
          >
            STAGE
          </text>
        </g>
      ) : null}

      {/* Sections, then their seats. */}
      {(plan.sections ?? []).map((section) => {
        const mine = seat?.section === section.code
        const shape = section.shape && section.shape.length >= 3 ? section.shape : undefined
        const anchor = shape ? centroid(shape) : sectionAnchor(section)

        return (
          <g key={section.code}>
            {shape ? (
              <polygon
                className={mine ? 'gc-map__section gc-map__section--mine' : 'gc-map__section'}
                points={toPoints(shape)}
                style={section.colour ? { stroke: section.colour } : undefined}
              />
            ) : null}

            {showSeats
              ? (section.rows ?? []).flatMap((row) =>
                  (row.seats ?? []).map((entry) => {
                    if (!entry.position) return null
                    const isMine = mine && seat?.row === row.label && seat?.seat === entry.number
                    const className = entry.blocked
                      ? 'gc-map__seat gc-map__seat--blocked'
                      : isMine
                        ? 'gc-map__seat gc-map__seat--mine'
                        : 'gc-map__seat'
                    return (
                      <g key={`${section.code}-${row.label}-${entry.number}`}>
                        {isMine ? (
                          <circle
                            className="gc-map__seat-halo"
                            cx={entry.position.x}
                            cy={entry.position.y}
                            r={3}
                          />
                        ) : null}
                        <circle
                          className={className}
                          cx={entry.position.x}
                          cy={entry.position.y}
                          r={isMine ? 1.6 : 1}
                        />
                      </g>
                    )
                  }),
                )
              : null}

            {anchor ? (
              <text
                className="gc-map__section-label"
                x={anchor.x}
                y={anchor.y}
                fontSize={label.section}
                style={mine ? { fill: 'var(--gc-text)' } : undefined}
              >
                {section.name}
              </text>
            ) : null}
          </g>
        )
      })}

      {/* Amenities. Drawn under the route so a route never disappears behind a pin. */}
      {(plan.amenities ?? []).map((amenity) => (
        <g
          key={amenity.id}
          className={highlighted.has(amenity.id) ? 'gc-map__amenity--highlight' : undefined}
        >
          <circle
            className="gc-map__amenity"
            cx={amenity.position.x}
            cy={amenity.position.y}
            r={highlighted.has(amenity.id) ? 2.6 : 2}
          />
          <text
            className="gc-map__amenity-glyph"
            x={amenity.position.x}
            y={amenity.position.y}
            fontSize={label.amenity}
          >
            {AMENITY_GLYPHS[amenity.kind] ?? '•'}
          </text>
          <title>{amenityTitle(amenity)}</title>
        </g>
      ))}

      {/* The route. A dark casing underneath so it stays visible over a light
          section fill, and a dashed animated line on top so the direction of travel
          is unambiguous. */}
      {route && route.nodes.length > 1 ? (
        <g>
          <polyline className="gc-map__route-casing" points={routePoints(route, nodes)} />
          <polyline className="gc-map__route" points={routePoints(route, nodes)} />
        </g>
      ) : null}

      {/* Checkpoints, drawn over the route because a door is a destination. */}
      {plan.checkpoints.map((checkpoint) => {
        const position = checkpoint.position ?? nodes.get(checkpoint.node ?? '')
        if (!position) return null

        const state = open.has(checkpoint.code)
          ? 'gc-map__gate gc-map__gate--open'
          : later.has(checkpoint.code)
            ? 'gc-map__gate gc-map__gate--later'
            : 'gc-map__gate'
        const notable = labelEveryGate || open.has(checkpoint.code) || later.has(checkpoint.code)

        return (
          <g key={checkpoint.code}>
            <rect
              className={state}
              x={position.x - 2.2}
              y={position.y - 1.6}
              width={4.4}
              height={3.2}
              rx={1}
            />
            {notable ? (
              <text
                className="gc-map__gate-label"
                x={position.x}
                y={position.y - 2.6}
                fontSize={label.gate}
              >
                {checkpoint.name}
              </text>
            ) : null}
            <title>{`${checkpoint.name} — ${checkpoint.zone}`}</title>
          </g>
        )
      })}

      {/* Where they are now, drawn last so nothing covers it. */}
      {from && nodes.has(from) ? (
        <circle className="gc-map__here" cx={nodes.get(from)!.x} cy={nodes.get(from)!.y} r={2.2}>
          <title>You are here</title>
        </circle>
      ) : null}
    </svg>
  )
}

/**
 * The tint for one zone.
 *
 * Occupancy is the reason to colour a zone at all, so it wins over the organizer's
 * signage colour when both are present: an operator looking at a map during a show
 * is asking how full the pit is, not what colour its wristbands are. The thresholds
 * are deliberately coarse — under 70% is fine, 70–90% is worth watching, over 90%
 * needs a decision — because a continuous gradient reads as "somewhat busy" at
 * every value and prompts nothing.
 */
function fillFor(colour: string | undefined, level: number | null): CSSProperties | undefined {
  if (level !== null) {
    const fill =
      level >= 0.9 ? 'var(--gc-deny)' : level >= 0.7 ? 'var(--gc-warning)' : 'var(--gc-admit)'
    // Floored so an empty zone is still visible as a zone, capped so a full one
    // never becomes an unreadable block of colour with a label on top.
    return { fill, fillOpacity: 0.08 + Math.min(level, 1) * 0.24 }
  }
  return colour ? { fill: colour, fillOpacity: 0.1 } : undefined
}

/** Nesting depth per zone, for staggering labels. Cycles cannot happen — Compile
 * rejects them — but the guard costs nothing and a hung render is unforgivable. */
function zoneDepths(plan: VenuePlan): Map<string, number> {
  const parents = new Map(plan.zones.map((zone) => [zone.code, zone.parent]))
  const out = new Map<string, number>()
  for (const zone of plan.zones) {
    let steps = 0
    let at = zone.parent
    while (at && steps < plan.zones.length) {
      steps += 1
      at = parents.get(at)
    }
    out.set(zone.code, steps)
  }
  return out
}

/** The top-left corner of a polygon, for hanging a label off. */
function topLeft(shape: Point[]): Point {
  return {
    x: Math.min(...shape.map((point) => point.x)),
    y: Math.min(...shape.map((point) => point.y)),
  }
}

/** Indexes walk-graph nodes by id, for drawing the route. */
function indexNodes(plan: VenuePlan): Map<string, Point> {
  const out = new Map<string, Point>()
  for (const node of plan.map?.nodes ?? []) out.set(node.id, node.position)
  return out
}

function routePoints(route: Route, nodes: Map<string, Point>): string {
  return route.nodes
    .map((id) => nodes.get(id))
    .filter((point): point is Point => point !== undefined)
    .map((point) => `${point.x},${point.y}`)
    .join(' ')
}

function toPoints(shape: Point[]): string {
  return shape.map((point) => `${point.x},${point.y}`).join(' ')
}

function centroid(shape: Point[]): Point {
  if (shape.length === 0) return { x: 0, y: 0 }
  let x = 0
  let y = 0
  for (const point of shape) {
    x += point.x
    y += point.y
  }
  return { x: x / shape.length, y: y / shape.length }
}

/** Where to put a section's label when it has no polygon: the middle of its seats. */
function sectionAnchor(
  section: VenuePlan['sections'] extends (infer S)[] | undefined ? S : never,
): Point | undefined {
  const positions: Point[] = []
  for (const row of section.rows ?? []) {
    for (const entry of row.seats ?? []) {
      if (entry.position) positions.push(entry.position)
    }
  }
  if (positions.length === 0) return undefined
  const middle = centroid(positions)
  // Nudged above the block so the label does not sit on top of a row of seats.
  return { x: middle.x, y: middle.y - 4 }
}

/**
 * The view box, fitted to one section when asked.
 *
 * Zooming to a section is what makes a seat map usable on a phone: a stadium drawn
 * whole puts a seat at less than a pixel, and "your seat is somewhere in that grey
 * rectangle" is not wayfinding.
 */
function computeViewBox(
  plan: VenuePlan,
  focusSection?: string,
): { x: number; y: number; width: number; height: number } {
  const map = plan.map!
  const whole = { x: 0, y: 0, width: map.width, height: map.height }
  if (!focusSection) return whole

  const section = (plan.sections ?? []).find((entry) => entry.code === focusSection)
  if (!section) return whole

  const points: Point[] = [...(section.shape ?? [])]
  for (const row of section.rows ?? []) {
    for (const entry of row.seats ?? []) {
      if (entry.position) points.push(entry.position)
    }
  }
  if (points.length === 0) return whole

  // The stage is always in view.
  //
  // A seat map that crops the stage out is disorienting in the one way that matters
  // — somebody holding it cannot tell which way round they will be sitting — and
  // every seat map anybody has ever used shows the stage for exactly that reason.
  points.push(...(map.stage ?? []))

  let minX = Number.POSITIVE_INFINITY
  let minY = Number.POSITIVE_INFINITY
  let maxX = Number.NEGATIVE_INFINITY
  let maxY = Number.NEGATIVE_INFINITY
  for (const point of points) {
    minX = Math.min(minX, point.x)
    minY = Math.min(minY, point.y)
    maxX = Math.max(maxX, point.x)
    maxY = Math.max(maxY, point.y)
  }

  // A generous margin, because a block cropped to its exact bounds gives no sense
  // of which way round it is.
  const margin = Math.max(6, (maxX - minX) * 0.25)
  return {
    x: minX - margin,
    y: minY - margin,
    width: maxX - minX + margin * 2,
    height: maxY - minY + margin * 2,
  }
}

/**
 * The map's accessible description.
 *
 * A map is an image, and an image with no description is nothing at all to somebody
 * using a screen reader. The apps also render the route as a text list beside it,
 * which is the part that is actually usable — this is the summary above it.
 */
function mapDescription(plan: VenuePlan, seat?: SeatRef): string {
  const parts = [`Map of the venue: ${plan.zones.length} areas`]
  if (plan.sections?.length) parts.push(`${plan.sections.length} blocks`)
  if (plan.amenities?.length) parts.push(`${plan.amenities.length} facilities`)
  if (seat?.section) {
    parts.push(
      `your seat is in ${seat.section}${seat.row ? ` row ${seat.row}` : ''}${seat.seat ? ` seat ${seat.seat}` : ''}`,
    )
  }
  return parts.join(', ')
}

function amenityTitle(amenity: Amenity): string {
  const bits = [amenity.name]
  if (amenity.accessible) bits.push('step-free')
  if (amenity.note) bits.push(amenity.note)
  return bits.join(' — ')
}
