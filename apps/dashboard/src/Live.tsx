import { severityOf } from 'gatecrash-client'
import type { DashboardStats, GateStat, VenuePlan, ZoneStat } from 'gatecrash-client'
import { VenueMap } from 'gatecrash-ui'

/**
 * The live picture.
 *
 * Four headline tiles, then occupancy, gates and verdicts. The choice of what is
 * here is the opinionated part: not "total scans", which is a vanity number nobody
 * acts on, but the three things an operator is actually asked all night — where are
 * people, which door is struggling, and has something stopped working.
 */
export function Live({ stats, venue }: { stats: DashboardStats | null; venue: VenuePlan | null }) {
  if (!stats) return <p className="muted">Connecting to the box…</p>

  const live = stats.live
  const quiet = live.gates.filter((gate) => gate.quiet)
  const over = live.zones.filter((zone) => zone.over)

  return (
    <>
      <div className="tiles">
        <div className="tile">
          <div className="tile__label">Inside</div>
          <div className="tile__value">{live.inside.toLocaleString()}</div>
          <div className="tile__detail">
            of {live.issued.toLocaleString()} tickets ·{' '}
            {live.issued > 0 ? Math.round((live.inside / live.issued) * 100) : 0}% turnout
          </div>
        </div>

        <div className="tile">
          <div className="tile__label">Coming through</div>
          <div className="tile__value">{Math.round(live.rate)}</div>
          <div className="tile__detail">per minute, last minute</div>
        </div>

        <div className="tile">
          <div className="tile__label">Refused</div>
          <div className="tile__value">{live.denied.toLocaleString()}</div>
          <div className="tile__detail">
            of {live.scans.toLocaleString()} scans ·{' '}
            {live.scans > 0 ? Math.round((live.denied / live.scans) * 100) : 0}%
          </div>
        </div>

        <div className={over.length > 0 || quiet.length > 0 ? 'tile tile--alarm' : 'tile'}>
          <div className="tile__label">Attention</div>
          <div className="tile__value">{over.length + quiet.length}</div>
          <div className="tile__detail">
            {over.length > 0 ? `${over.length} over capacity` : ''}
            {over.length > 0 && quiet.length > 0 ? ' · ' : ''}
            {quiet.length > 0
              ? `${quiet.length} gate${quiet.length === 1 ? '' : 's'} gone quiet`
              : ''}
            {over.length === 0 && quiet.length === 0 ? 'nothing' : ''}
          </div>
        </div>
      </div>

      <div className="grid">
        <div className="panel">
          <h2>Where people are</h2>
          {live.zones
            .filter((zone) => zone.occupied > 0 || zone.capacity)
            .map((zone) => (
              <Meter key={zone.code} zone={zone} />
            ))}
          {live.zones.every((zone) => zone.occupied === 0) ? (
            <p className="muted">Nobody has come through yet.</p>
          ) : null}
        </div>

        <div className="panel">
          <h2>Gates</h2>
          <div className="rows">
            {live.gates
              .filter((gate) => gate.admitted > 0 || gate.denied > 0)
              .map((gate) => (
                <Gate key={gate.code} gate={gate} />
              ))}
            {live.gates.every((gate) => gate.admitted === 0 && gate.denied === 0) ? (
              <p className="muted">No gate has scanned anything yet.</p>
            ) : null}
          </div>
        </div>

        <div className="panel">
          <h2>What the gates are seeing</h2>
          <Verdicts verdicts={live.verdicts} total={live.scans} />
        </div>

        <div className="panel">
          <h2>Turnout by tier</h2>
          <div className="rows">
            {live.tiers
              // A tier with no tickets issued is noise on a wall display: it is in
              // the venue plan for a future event, not for this one.
              .filter((tier) => tier.issued > 0 || tier.admitted > 0)
              .map((tier) => (
                <div className="row" key={tier.code}>
                  <span
                    aria-hidden="true"
                    style={{
                      width: 10,
                      height: 10,
                      borderRadius: 999,
                      flex: 'none',
                      background: tier.colour ?? 'var(--gc-text-faint)',
                    }}
                  />
                  <span className="row__name">{tier.name}</span>
                  <span className="row__figure">
                    {tier.admitted} / {tier.issued}
                    {tier.issued > 0
                      ? ` · ${Math.round((tier.admitted / tier.issued) * 100)}%`
                      : ''}
                  </span>
                </div>
              ))}
          </div>
        </div>

        <div className="panel">
          <h2>Scanners</h2>
          <div className="rows">
            {live.devices.map((device) => (
              <div className="row" key={device.id}>
                <span className="row__name">{device.name ?? device.id}</span>
                {device.quiet ? <span className="row__flag">quiet</span> : null}
                <span className="row__figure">{device.scans} scans</span>
              </div>
            ))}
            {live.devices.length === 0 ? (
              <p className="muted">No scanner has connected yet.</p>
            ) : null}
          </div>
        </div>

        <div className="panel">
          <h2>Box</h2>
          <div className="rows">
            <div className="row">
              <span className="row__name">Audit log</span>
              <span className="row__figure">{stats.chain_rows.toLocaleString()} rows</span>
            </div>
            <div className="row">
              <span className="row__name">Double uses flagged</span>
              <span className="row__figure">{stats.flags}</span>
            </div>
            <div className="row">
              <span className="row__name">Connected screens</span>
              <span className="row__figure">
                {stats.streams}
                {stats.dropped_streams > 0 ? ` · ${stats.dropped_streams} dropped` : ''}
              </span>
            </div>
            {stats.certificate_expires ? (
              <div className="row">
                <span className="row__name">Certificate</span>
                <span className="row__figure">
                  expires {new Date(stats.certificate_expires).toLocaleDateString()}
                </span>
              </div>
            ) : null}
          </div>
          <p className="mono" style={{ marginTop: 'var(--gc-gap)' }}>
            chain head {stats.chain_head}
          </p>
        </div>
      </div>

      {venue ? (
        <div className="panel">
          <h2>Venue</h2>
          <div className="map-frame">
            {/* The occupancy meters above answer "how full", this answers "where".
                Same numbers, and the shape is the part an operator acts on: a red
                block against the barrier is a decision, a row in a table is not. */}
            <VenueMap
              plan={venue}
              showSeats={false}
              labelEveryGate
              occupancy={Object.fromEntries(
                live.zones.map((zone) => [
                  zone.code,
                  { inside: zone.occupied, capacity: zone.capacity ?? 0 },
                ]),
              )}
            />
          </div>
        </div>
      ) : null}
    </>
  )
}

function Meter({ zone }: { zone: ZoneStat }) {
  const fill = zone.capacity ? Math.min(1, zone.occupied / zone.capacity) : 0
  // Amber past 80%, red over. Colour here is a warning rather than decoration: an
  // operator scanning this panel should be able to find the problem without reading
  // any numbers.
  const state = zone.over ? 'over' : fill > 0.8 ? 'busy' : 'normal'

  return (
    <div className="meter">
      <div className="meter__head">
        <span>{zone.name}</span>
        <span className="meter__count">
          {zone.occupied.toLocaleString()}
          {zone.capacity ? ` / ${zone.capacity.toLocaleString()}` : ''}
        </span>
      </div>
      {zone.capacity ? (
        <div className="meter__track">
          <div className="meter__fill" data-state={state} style={{ width: `${fill * 100}%` }} />
        </div>
      ) : null}
    </div>
  )
}

function Gate({ gate }: { gate: GateStat }) {
  return (
    <div className="row">
      <span className="row__name">{gate.name}</span>
      {gate.quiet ? <span className="row__flag">quiet</span> : null}
      <Spark trend={gate.trend} />
      <span className="row__figure">
        {gate.admitted} in
        {gate.denied > 0 ? ` · ${gate.denied} refused` : ''}
        {gate.rate > 0 ? ` · ${Math.round(gate.rate)}/min` : ''}
      </span>
    </div>
  )
}

/**
 * A sparkline over the last minute.
 *
 * Hand-drawn SVG rather than a charting library: it is twelve numbers and a
 * polyline, and a chart dependency would be the largest single thing in this
 * bundle — on a screen that has to load from a Raspberry Pi over venue Wi-Fi.
 */
function Spark({ trend }: { trend: number[] }) {
  if (trend.length === 0) return null
  const peak = Math.max(1, ...trend)
  const points = trend
    .map((value, index) => {
      const x = (index / Math.max(1, trend.length - 1)) * 66 + 1
      const y = 20 - (value / peak) * 18
      return `${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')

  return (
    <svg
      className="spark"
      viewBox="0 0 68 22"
      role="img"
      aria-label={`Throughput trend, peak ${peak}`}
    >
      <polyline points={points} />
    </svg>
  )
}

/**
 * The verdict breakdown.
 *
 * The single most useful diagnostic on the screen. A wall of INVALID_SIG at one gate
 * means somebody is working a forgery; a wall of WRONG_DOOR means the signage is
 * wrong; a wall of UNKNOWN_TICKET means the manifest was never loaded. Each has a
 * completely different response, and none of them are visible from a total.
 */
function Verdicts({ verdicts, total }: { verdicts: Record<string, number>; total: number }) {
  const entries = Object.entries(verdicts).sort(([, a], [, b]) => b - a)
  if (entries.length === 0) return <p className="muted">Nothing scanned yet.</p>

  const peak = Math.max(...entries.map(([, count]) => count))

  return (
    <div className="verdict-bars">
      {entries.map(([verdict, count]) => (
        <div className="verdict-bar" key={verdict}>
          <span className="verdict-bar__label">{verdict.replace(/_/g, ' ').toLowerCase()}</span>
          <span className="verdict-bar__track">
            <span
              className="verdict-bar__fill"
              data-kind={severityOf(verdict)}
              style={{ width: `${(count / peak) * 100}%` }}
            />
          </span>
          <span className="verdict-bar__count">{count}</span>
        </div>
      ))}
      <p className="muted" style={{ marginTop: 'var(--gc-gap)' }}>
        {total.toLocaleString()} scans decided.
      </p>
    </div>
  )
}
