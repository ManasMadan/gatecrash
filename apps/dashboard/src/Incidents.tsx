import { useState } from 'react'
import type { Client, DashboardStats, Incident } from 'gatecrash-client'

import { since, useSecond } from '@/App'

/**
 * The incident board.
 *
 * The lifecycle is the product here, not the list. An alert nobody acknowledged is
 * worse than no alert, because everybody assumes somebody else has it — so the
 * elapsed time on an open alarm is shown large and turns red after a minute, and
 * every transition demands a name.
 *
 * Cancelling requires a reason. That is a deliberate piece of friction: it is the one
 * action that makes an inconvenient alarm disappear, and it should be on the record
 * who made it disappear and why.
 */
export function Incidents({
  client,
  incidents,
  response,
  onChanged,
}: {
  client: Client
  incidents: Incident[]
  response: DashboardStats['incident_response'] | undefined
  onChanged: () => void
}) {
  const [actor, setActor] = useState(
    () => sessionStorage.getItem('gatecrash.dashboard.actor') ?? '',
  )
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const live = incidents.filter((incident) =>
    ['open', 'acknowledged', 'assigned'].includes(incident.status),
  )
  const closed = incidents.filter((incident) => ['resolved', 'cancelled'].includes(incident.status))

  const act = async (
    incident: Incident,
    status: 'acknowledged' | 'assigned' | 'resolved' | 'cancelled',
  ) => {
    if (!actor.trim()) {
      setError('Put your name in first. Every action on this board is recorded against somebody.')
      return
    }
    let note = ''
    let assignedTo = ''

    if (status === 'cancelled') {
      // The one action that makes an alarm disappear, so it needs a reason on the
      // record.
      const reason = window.prompt('Why is this being cancelled? This goes in the log.')
      if (!reason?.trim()) return
      note = reason.trim()
    }
    if (status === 'assigned') {
      const who = window.prompt('Who is going?')
      if (!who?.trim()) return
      assignedTo = who.trim()
    }
    if (status === 'resolved') {
      note = window.prompt('What happened? (optional)')?.trim() ?? ''
    }

    setBusy(incident.id)
    setError(null)
    try {
      sessionStorage.setItem('gatecrash.dashboard.actor', actor.trim())
      await client.transitionIncident(incident.id, {
        status,
        actor: actor.trim(),
        ...(note ? { note } : {}),
        ...(assignedTo ? { assigned_to: assignedTo } : {}),
      })
      onChanged()
    } catch (caught) {
      setError((caught as Error).message)
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      {error ? <div className="error">{error}</div> : null}

      <div className="panel">
        <h2>You</h2>
        <div className="field" style={{ marginBottom: 0 }}>
          <label htmlFor="actor">Your name</label>
          <input
            id="actor"
            value={actor}
            onChange={(event) => setActor(event.target.value)}
            placeholder="control"
            autoComplete="off"
          />
        </div>
      </div>

      {response && response.total > 0 ? (
        <div className="tiles">
          <div className="tile">
            <div className="tile__label">Raised</div>
            <div className="tile__value">{response.total}</div>
            <div className="tile__detail">{response.resolved} resolved</div>
          </div>
          <div className="tile">
            <div className="tile__label">Median pickup</div>
            <div className="tile__value">{Math.round(response.median_ack_seconds)}s</div>
            <div className="tile__detail">worst {Math.round(response.worst_ack_seconds)}s</div>
          </div>
          {/* Two different questions. "Unattended" is the live one — open, past the
              grace period, still nobody. "Never picked up" is the post-event
              judgement, and it only counts incidents somebody closed without ever
              acknowledging. */}
          <div className={response.unattended > 0 ? 'tile tile--alarm' : 'tile'}>
            <div className="tile__label">Unattended</div>
            <div className="tile__value">{response.unattended}</div>
            <div className="tile__detail">
              {response.unattended > 0
                ? 'open, and nobody has said they have it'
                : 'everything open has an owner'}
            </div>
          </div>
          <div className="tile">
            <div className="tile__label">Still open</div>
            <div className="tile__value">{response.still_open}</div>
            <div className="tile__detail">
              {response.cancelled} cancelled
              {response.never_acknowledged > 0
                ? ` · ${response.never_acknowledged} closed unacknowledged`
                : ''}
            </div>
          </div>
        </div>
      ) : null}

      <div className="panel">
        <h2>Live</h2>
        {live.length === 0 ? (
          <p className="muted">Nothing open. The gates are quiet.</p>
        ) : (
          live.map((incident) => (
            <Card
              key={incident.id}
              incident={incident}
              busy={busy === incident.id}
              onAct={(status) => void act(incident, status)}
            />
          ))
        )}
      </div>

      {closed.length > 0 ? (
        <div className="panel">
          <h2>Closed</h2>
          {closed
            .slice(-20)
            .reverse()
            .map((incident) => (
              <Card key={incident.id} incident={incident} busy={false} onAct={() => {}} />
            ))}
        </div>
      ) : null}
    </>
  )
}

function Card({
  incident,
  busy,
  onAct,
}: {
  incident: Incident
  busy: boolean
  onAct: (status: 'acknowledged' | 'assigned' | 'resolved' | 'cancelled') => void
}) {
  // Own clock, so the elapsed time climbs a second at a time and crosses the
  // one-minute line the moment it actually crosses it.
  useSecond()

  const open = incident.status === 'open'
  const closed = incident.status === 'resolved' || incident.status === 'cancelled'

  // Red after a minute. The number nobody wants to see climbing is the one this
  // makes impossible to ignore.
  const late = open && Date.now() - new Date(incident.raised_at).getTime() > 60_000

  return (
    <div className="incident" data-severity={incident.severity} data-status={incident.status}>
      <div className="incident__head">
        <span className="incident__kind">{incident.kind.replace(/-/g, ' ')}</span>
        <span className="incident__id">{incident.id}</span>
        <span className="incident__where">
          {incident.checkpoint_name ?? ''}
          {incident.zone_name ? ` · ${incident.zone_name}` : ''}
          {incident.reporter ? ` · ${incident.reporter}` : ''}
        </span>
        <span className="incident__elapsed" data-late={String(late)}>
          {closed ? incident.status : since(incident.raised_at)}
        </span>
      </div>

      {incident.note ? <p className="incident__note">{incident.note}</p> : null}

      {/* The two facts a staffing request is really made of, attached by the box so
          the person on the door did not have to say them. */}
      {incident.head_count || incident.queue_rate ? (
        <p className="incident__note">
          {incident.head_count ? `Asking for ${incident.head_count} people. ` : ''}
          {incident.queue_rate
            ? `This gate is doing ${Math.round(incident.queue_rate)} a minute.`
            : ''}
        </p>
      ) : null}

      {incident.assigned_to ? (
        <p className="incident__note">Assigned to {incident.assigned_to}.</p>
      ) : null}

      {!closed ? (
        <div className="incident__actions">
          {open ? (
            <button
              type="button"
              className="button"
              disabled={busy}
              onClick={() => onAct('acknowledged')}
            >
              I have it
            </button>
          ) : null}
          <button
            type="button"
            className="button button--quiet"
            disabled={busy}
            onClick={() => onAct('assigned')}
          >
            Send somebody
          </button>
          <button
            type="button"
            className="button button--quiet"
            disabled={busy}
            onClick={() => onAct('resolved')}
          >
            Done
          </button>
          <button
            type="button"
            className="button button--danger"
            disabled={busy}
            onClick={() => onAct('cancelled')}
          >
            False alarm
          </button>
        </div>
      ) : null}

      {incident.history.length > 1 ? (
        <ul className="incident__history">
          {incident.history.map((event, index) => (
            <li key={`${event.status}-${index}`}>
              {event.status} · {event.actor} · {new Date(event.at).toLocaleTimeString()}
              {event.note ? ` · ${event.note}` : ''}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}
