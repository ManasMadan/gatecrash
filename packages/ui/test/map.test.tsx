import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import type { VenuePlan } from '@gatecrash/protocol'

import { VenueMap } from '@/map'

/**
 * The map is rendered to markup and the markup is read back.
 *
 * Every bug this file has caught was geometric — a label on top of another label, a
 * seat block that never drew, a zone tinted the wrong colour — and none of them are
 * visible from the outside of a component that returns "an SVG".
 */

function plan(): VenuePlan {
  return {
    zones: [
      {
        code: 'perimeter',
        name: 'Festival Ground',
        capacity: 2000,
        shape: [
          { x: 0, y: 0 },
          { x: 100, y: 0 },
          { x: 100, y: 100 },
          { x: 0, y: 100 },
        ],
      },
      {
        code: 'arena',
        name: 'Arena',
        parent: 'perimeter',
        capacity: 500,
        shape: [
          { x: 20, y: 20 },
          { x: 80, y: 20 },
          { x: 80, y: 80 },
          { x: 20, y: 80 },
        ],
      },
      {
        // Flush against the front of the arena, which is what a pit is. The two
        // labels used to land on the same line and cover each other.
        code: 'pit',
        name: 'Front Pit',
        parent: 'arena',
        capacity: 200,
        shape: [
          { x: 30, y: 21 },
          { x: 70, y: 21 },
          { x: 70, y: 40 },
          { x: 30, y: 40 },
        ],
      },
    ],
    sections: [
      {
        code: 'block-a',
        name: 'Block A',
        kind: 'seated',
        zone: 'arena',
        rows: [
          {
            label: 'A',
            seats: [
              { number: '1', kind: 'standard', position: { x: 40, y: 60 } },
              { number: '2', kind: 'standard', position: { x: 44, y: 60 } },
            ],
          },
        ],
      },
    ],
    checkpoints: [
      { code: 'gate-north', name: 'North Gate', zone: 'perimeter', position: { x: 10, y: 95 } },
      { code: 'pit-gate', name: 'Pit Wristband', zone: 'pit', position: { x: 50, y: 38 } },
    ],
    tiers: [],
    amenities: [
      {
        id: 'wc-1',
        kind: 'washroom',
        name: 'Toilets',
        zone: 'perimeter',
        position: { x: 15, y: 80 },
      },
    ],
    map: {
      width: 100,
      height: 100,
      outline: [
        { x: 0, y: 0 },
        { x: 100, y: 0 },
        { x: 100, y: 100 },
        { x: 0, y: 100 },
      ],
    },
  } as unknown as VenuePlan
}

const render = (node: Parameters<typeof renderToStaticMarkup>[0]) => renderToStaticMarkup(node)

/**
 * The rendered viewBox, parsed.
 *
 * Written out rather than destructured from the regex match because
 * `noUncheckedIndexedAccess` makes every capture group possibly undefined — correctly, since
 * a regex that did not match returns null. Throwing here names the actual problem instead
 * of failing later on a comparison against NaN.
 */
function viewBoxOf(html: string): { x: number; y: number; width: number; height: number } {
  const match = /viewBox="([-\d.]+) ([-\d.]+) ([\d.]+) ([\d.]+)"/.exec(html)
  if (!match) throw new Error('the map rendered without a viewBox')

  const [, x, y, width, height] = match as unknown as [string, string, string, string, string]
  return { x: Number(x), y: Number(y), width: Number(width), height: Number(height) }
}

/** Every y attribute of a zone label, in document order. */
function zoneLabelYs(html: string): number[] {
  return [...html.matchAll(/class="gc-map__zone-label"[^>]*y="([\d.]+)"/g)].map((m) => Number(m[1]))
}

describe('VenueMap', () => {
  it('draws a zone for every footprint and names it', () => {
    const html = render(<VenueMap plan={plan()} />)
    expect([...html.matchAll(/class="gc-map__zone"/g)]).toHaveLength(3)
    expect(html).toContain('Festival Ground')
    expect(html).toContain('Front Pit')
  })

  it('staggers the labels of nested zones so they do not cover each other', () => {
    // The regression: a pit sits flush against the front of its arena, so both
    // labels were drawn a fraction apart and neither was readable.
    const ys = zoneLabelYs(render(<VenueMap plan={plan()} />))
    expect(ys).toHaveLength(3)
    for (const [i, y] of ys.entries()) {
      for (const other of ys.slice(i + 1)) {
        expect(Math.abs(y - other)).toBeGreaterThan(2)
      }
    }
  })

  it('tints a zone by how full it is and puts the count on the label', () => {
    const html = render(
      <VenueMap
        plan={plan()}
        occupancy={{
          arena: { inside: 480, capacity: 500 },
          perimeter: { inside: 100, capacity: 2000 },
        }}
      />,
    )
    // Over 90%: the colour an operator has to make a decision about.
    expect(html).toContain('--gc-deny')
    // Under 70%: fine, and drawn as fine.
    expect(html).toContain('--gc-admit')
    expect(html).toContain('480')
  })

  it('does not invent an occupancy for a zone nobody reported', () => {
    const html = render(<VenueMap plan={plan()} />)
    expect(html).not.toContain('--gc-deny')
    expect(html).not.toContain('--gc-admit')
  })

  it('draws seats when asked and not when not', () => {
    expect([...render(<VenueMap plan={plan()} />).matchAll(/gc-map__seat"/g)]).toHaveLength(2)
    expect([
      ...render(<VenueMap plan={plan()} showSeats={false} />).matchAll(/gc-map__seat"/g),
    ]).toHaveLength(0)
  })

  it('lights up the holder’s own seat', () => {
    const html = render(
      <VenueMap plan={plan()} seat={{ section: 'block-a', row: 'A', seat: '2' }} />,
    )
    expect(html).toContain('gc-map__seat--mine')
    expect(html).toContain('gc-map__seat-halo')
  })

  it('dims the zones this ticket may not enter', () => {
    const html = render(<VenueMap plan={plan()} allowedZones={['perimeter']} />)
    expect([...html.matchAll(/gc-map__zone--forbidden/g)].length).toBeGreaterThan(0)
  })

  it('labels only the doors that concern an attendee', () => {
    const attendee = render(<VenueMap plan={plan()} openCheckpoints={['gate-north']} />)
    expect(attendee).toContain('North Gate')
    expect(attendee).not.toContain('Pit Wristband<')

    // The control room needs to tell one door from another.
    const control = render(<VenueMap plan={plan()} labelEveryGate />)
    expect(control).toContain('North Gate')
    expect(control).toContain('Pit Wristband')
  })

  it('says so rather than drawing an empty box when there is no floor plan', () => {
    const bare = { ...plan(), map: undefined } as unknown as VenuePlan
    expect(render(<VenueMap plan={bare} />)).toContain('Follow the signs')
  })
})

describe('VenueMap focused on one section', () => {
  it('keeps the stage in view, so the holder knows which way round they are', () => {
    const withStage = plan()
    withStage.map = {
      ...withStage.map!,
      stage: [
        { x: 40, y: 2 },
        { x: 60, y: 2 },
        { x: 60, y: 8 },
        { x: 40, y: 8 },
      ],
    }

    const html = render(<VenueMap plan={withStage} focusSection="block-a" />)
    // The stage's near edge is at y=8, and the seats are at y=60. A box that starts
    // below the stage has cropped it out.
    expect(viewBoxOf(html).y).toBeLessThanOrEqual(8)
  })

  it('keeps a clipped zone’s label inside the view rather than slicing it', () => {
    const html = render(<VenueMap plan={plan()} focusSection="block-a" />)
    const { x } = viewBoxOf(html)
    for (const [, labelX] of html.matchAll(/class="gc-map__zone-label"[^>]*x="([-\d.]+)"/g)) {
      expect(Number(labelX)).toBeGreaterThanOrEqual(x)
    }
  })
})
