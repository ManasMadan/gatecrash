import { useCallback, useEffect, useMemo, useState } from 'react'
import { ApiError, Client, severityOf } from 'gatecrash-client'
import type { DashboardStats, Incident, VenuePlan } from 'gatecrash-client'

import { Enrollment } from '@/Enrollment'
import { Incidents } from '@/Incidents'
import { Live } from '@/Live'
import { Settlement } from '@/Settlement'
import { SeatMap } from '@/SeatMap'

/**
 * The organizer's control room.
 *
 * One screen, four tabs, and a polling loop. Deliberately not a single-page
 * application with routes and a state library: it is one operator watching one event
 * for one evening, on a laptop that is often the only thing keeping the venue
 * informed, and the smallest possible amount of machinery between the box and the
 * screen is the right amount.
 *
 * The token arrives in the URL because the box prints exactly one line an operator
 * has to act on at boot, and that line is a URL with a token in it. It is moved into
 * sessionStorage immediately and stripped from the address bar, so it does not end up
 * in a screenshot of a projector.
 */

type Tab = 'live' | 'incidents' | 'seats' | 'setup'

export function App() {
  const [token, setToken] = useState<string | null>(() => takeToken())
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [venue, setVenue] = useState<VenuePlan | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('live')

  const client = useMemo(
    () => (token ? new Client({ baseUrl: window.location.origin, token }) : null),
    [token],
  )

  const refresh = useCallback(async () => {
    if (!client) return
    try {
      setStats(await client.stats())
      setError(null)
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) {
        // The token is wrong or has been rotated. Clearing it puts the sign-in
        // screen up rather than leaving a dead dashboard on a wall.
        sessionStorage.removeItem('gatecrash.dashboard.token')
        setToken(null)
        return
      }
      setError(
        caught instanceof ApiError && caught.status === 0
          ? 'Lost the box. Check the cable and the Wi-Fi — the gates keep working without this screen.'
          : (caught as Error).message,
      )
    }
  }, [client])

  // A fire-and-forget wrapper for children that just want to say "something
  // changed, go and look again". They have no use for the promise, and handing them
  // one only invites an unhandled rejection.
  const reload = useCallback(() => void refresh(), [refresh])

  useEffect(() => {
    void refresh()
    // Two seconds. Fast enough that an operator sees a gate go quiet before somebody
    // walks over to tell them, slow enough that a Pi serving twelve gates does not
    // notice. A stream would be fewer bytes and more machinery; this is one request.
    const timer = setInterval(() => void refresh(), 2_000)
    return () => clearInterval(timer)
  }, [refresh])

  useEffect(() => {
    if (!client) return
    client
      .venue()
      .then((response) => setVenue(response.plan))
      .catch(() => setVenue(null))
  }, [client])

  if (!client) return <SignIn onToken={setToken} />

  const loud = (stats?.incidents ?? []).filter(
    (incident) => incident.severity === 'emergency' && incident.status === 'open',
  )
  const live = (stats?.incidents ?? []).filter((incident) =>
    ['open', 'acknowledged', 'assigned'].includes(incident.status),
  )

  return (
    <div className="shell">
      <div className="topbar">
        <h1>{stats?.live ? 'Control' : 'Control'}</h1>
        {stats ? (
          <span className="topbar__mode" data-mode={stats.mode}>
            {stats.mode === 'degraded' ? 'degraded — gates admit offline' : 'strict'}
          </span>
        ) : null}
        <div className="tabs" role="tablist">
          {(
            [
              ['live', 'Live'],
              ['incidents', 'Incidents'],
              ['seats', 'Seats'],
              ['setup', 'Setup'],
            ] as [Tab, string][]
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              role="tab"
              aria-selected={tab === key}
              onClick={() => setTab(key)}
            >
              {label}
              {key === 'incidents' && live.length > 0 ? (
                <span className="tabs__badge">{live.length}</span>
              ) : null}
            </button>
          ))}
        </div>
      </div>

      {error ? <div className="error">{error}</div> : null}

      {/* An unacknowledged emergency is shown on every tab, because an operator who
          has wandered onto the seat map still needs to see it. */}
      {loud.length > 0 && tab !== 'incidents' ? (
        <div className="panel" style={{ borderColor: 'var(--gc-emergency)' }}>
          <h2>Needs you now</h2>
          {loud.map((incident) => (
            <Loud key={incident.id} incident={incident} onGo={() => setTab('incidents')} />
          ))}
        </div>
      ) : null}

      {tab === 'live' ? <Live stats={stats} venue={venue} /> : null}
      {tab === 'incidents' ? (
        <Incidents
          client={client}
          incidents={stats?.incidents ?? []}
          response={stats?.incident_response}
          onChanged={reload}
        />
      ) : null}
      {tab === 'seats' ? <SeatMap venue={venue} stats={stats} /> : null}
      {tab === 'setup' ? (
        <div className="grid">
          <Enrollment client={client} venue={venue} stats={stats} onChanged={reload} />
          <Settlement client={client} stats={stats} />
        </div>
      ) : null}
    </div>
  )
}

function Loud({ incident, onGo }: { incident: Incident; onGo: () => void }) {
  // Ticks on its own so the stopwatch counts seconds rather than poll intervals.
  useSecond()

  return (
    <div className="incident" data-severity={incident.severity} data-status={incident.status}>
      <div className="incident__head">
        <span className="incident__kind">{incident.kind.replace(/-/g, ' ')}</span>
        <span className="incident__where">
          {incident.checkpoint_name ?? ''}
          {incident.zone_name ? ` · ${incident.zone_name}` : ''}
        </span>
        <span className="incident__elapsed" data-late="true">
          {since(incident.raised_at)}
        </span>
      </div>
      {incident.note ? <p className="incident__note">{incident.note}</p> : null}
      <div className="incident__actions">
        <button type="button" className="button" onClick={onGo}>
          Handle it
        </button>
      </div>
    </div>
  )
}

function SignIn({ onToken }: { onToken: (token: string) => void }) {
  const [value, setValue] = useState('')
  return (
    <div className="shell" style={{ maxWidth: '30rem' }}>
      <div className="panel">
        <h2>Sign in</h2>
        <p className="muted">
          The box printed a dashboard link when it started. Open that, or paste the token from it
          here.
        </p>
        <div className="field" style={{ marginTop: 'var(--gc-gap)' }}>
          <label htmlFor="token">Dashboard token</label>
          <input
            id="token"
            value={value}
            onChange={(event) => setValue(event.target.value.trim())}
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <button
          type="button"
          className="button"
          disabled={!value}
          onClick={() => {
            sessionStorage.setItem('gatecrash.dashboard.token', value)
            onToken(value)
          }}
        >
          Open the dashboard
        </button>
      </div>
    </div>
  )
}

/**
 * Takes the token from the URL, then removes it from the address bar.
 *
 * The box prints one actionable line at boot and it contains a token, so a token in
 * a URL is the reality of the product rather than a shortcut. Moving it into
 * sessionStorage and rewriting the URL means it does not survive into a screenshot
 * of a projector or a shared browser history.
 */
function takeToken(): string | null {
  const params = new URLSearchParams(window.location.search)
  const fromUrl = params.get('token')
  if (fromUrl) {
    sessionStorage.setItem('gatecrash.dashboard.token', fromUrl)
    params.delete('token')
    const query = params.toString()
    window.history.replaceState({}, '', window.location.pathname + (query ? `?${query}` : ''))
    return fromUrl
  }
  return sessionStorage.getItem('gatecrash.dashboard.token')
}

/**
 * A clock that advances every wall-clock second.
 *
 * Elapsed times used to be recomputed only when the poll landed, so a timer on an
 * open alarm counted 0s, 2s, 4s — the data refresh rate leaking into a number that
 * has nothing to do with it. A stopwatch that skips is the one thing on this screen
 * an operator is most likely to be reading out loud, and a display clock has no
 * business being coupled to a network interval.
 *
 * Sampled four times a second and returned floored to the second: React bails out
 * of a re-render when the value is unchanged, so this costs three no-op setState
 * calls a second and never drifts away from the second boundary the way a bare
 * one-second interval does.
 */
export function useSecond(): number {
  const [second, setSecond] = useState(() => Math.floor(Date.now() / 1000))
  useEffect(() => {
    const timer = setInterval(() => setSecond(Math.floor(Date.now() / 1000)), 250)
    return () => clearInterval(timer)
  }, [])
  return second
}

/** Elapsed time, in the form an operator reads out over a radio. */
export function since(iso: string): string {
  const elapsed = Math.max(0, Date.now() - new Date(iso).getTime())
  const seconds = Math.floor(elapsed / 1000)
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`
}

export { severityOf }
