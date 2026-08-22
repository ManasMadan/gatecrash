import { useState } from 'react'
import type { DashboardStats, VenuePlan } from '@gatecrash/protocol'
import { VenueMap } from '@gatecrash/ui'

/**
 * The seat map, with fill per section.
 *
 * This is the view a promoter asks for: not how many people are in, but whether the
 * expensive seats showed up. A block at 40% when the cheap seats are at 95% is a
 * commercial fact somebody will want to know before the second show goes on sale.
 */
export function SeatMap({
  venue,
  stats,
}: {
  venue: VenuePlan | null
  stats: DashboardStats | null
}) {
  const [focus, setFocus] = useState<string | null>(null)

  if (!venue) return <p className="muted">No venue plan loaded.</p>
  const sections = stats?.live.sections ?? []

  return (
    <>
      <div className="panel">
        <h2>Sections</h2>
        <div className="rows">
          {sections.map((section) => {
            const fill = section.capacity ? section.admitted / section.capacity : 0
            return (
              <button
                key={section.code}
                type="button"
                className="row"
                style={{ width: '100%', textAlign: 'left' }}
                onClick={() => setFocus(focus === section.code ? null : section.code)}
              >
                <span className="row__name">{section.name}</span>
                <span className="meter__track" style={{ flex: 1, marginTop: 0 }}>
                  <span
                    className="meter__fill"
                    data-state={fill > 0.8 ? 'busy' : 'normal'}
                    style={{ width: `${Math.min(1, fill) * 100}%` }}
                  />
                </span>
                <span className="row__figure">
                  {section.admitted} / {section.capacity ?? '—'}
                  {section.capacity ? ` · ${Math.round(fill * 100)}%` : ''}
                </span>
              </button>
            )
          })}
          {sections.length === 0 ? (
            <p className="muted">This venue has no seated sections.</p>
          ) : null}
        </div>
        <p className="muted" style={{ marginTop: 'var(--gc-gap)' }}>
          Tap a section to zoom the map to it. A stadium drawn whole puts a seat at less than a
          pixel, which is not a seat map.
        </p>
      </div>

      <div className="panel">
        <h2>{focus ? `Map — ${focus}` : 'Map'}</h2>
        <div className="map-frame">
          <VenueMap plan={venue} showSeats {...(focus ? { focusSection: focus } : {})} />
        </div>
      </div>
    </>
  )
}
