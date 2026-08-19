import { useState } from 'react'
import type { Client, Incident, IncidentKindOption } from '@gatecrash/protocol'

import { newScanId } from '@/store'

/**
 * The bouncer's two buttons, expanded.
 *
 * A door has exactly two things it needs from the back room and no reliable way to
 * ask for them: more people, and help. This is that, and the design is shaped by the
 * circumstances it gets used in.
 *
 * Staffing requests send immediately — somebody asking for a hand does not need a
 * confirmation dialog. Alarms ask once, because a pocket press on "evacuate" is its
 * own incident, and because the half-second it costs is nothing next to the cost of
 * a false evacuation. Everything else — which gate, which zone, the queue rate — is
 * filled in by the box from the device's own enrollment, because somebody pressing
 * the crush button is not going to fill in a form.
 *
 * The button list comes from the box rather than from a constant here, so a scanner
 * never draws a button the box will reject.
 */

interface Props {
  client: Client
  kinds: IncidentKindOption[]
  checkpoint: string
  reporter: string
  onClose: () => void
  onRaised: (incident: Incident) => void
}

/** Copy for each kind. Written to be read at a glance, in a hurry, in the dark. */
const LABELS: Record<string, { title: string; hint: string; glyph: string }> = {
  'need-staff': { title: 'More people', hint: 'This door cannot keep up', glyph: '👥' },
  'need-supervisor': { title: 'Supervisor', hint: 'Someone is arguing', glyph: '🧑‍✈️' },
  'need-relief': { title: 'Break', hint: 'I need relieving', glyph: '☕' },
  'equipment-fault': { title: 'Kit broken', hint: 'Battery, gun, printer', glyph: '🔧' },
  medical: { title: 'Medical', hint: 'Someone is hurt or unwell', glyph: '✚' },
  crush: { title: 'Crush', hint: 'Dangerous crowd pressure', glyph: '🚨' },
  fight: { title: 'Fight', hint: 'Violence or the threat of it', glyph: '✊' },
  fire: { title: 'Fire', hint: 'Fire, smoke, pyro failure', glyph: '🔥' },
  theft: { title: 'Theft', hint: 'Pickpocket, stolen kit', glyph: '🥷' },
  'lost-child': { title: 'Lost child', hint: 'A child is separated', glyph: '🧒' },
  suspicious: { title: 'Suspicious', hint: 'Unattended bag, fence climber', glyph: '👁' },
  structural: { title: 'Structural', hint: 'Barrier, rigging, water', glyph: '🏗' },
  evacuate: { title: 'Evacuate', hint: 'Clear the area now', glyph: '🏃' },
}

export function Signals({ client, kinds, checkpoint, reporter, onClose, onRaised }: Props) {
  const [confirming, setConfirming] = useState<IncidentKindOption | null>(null)
  const [headCount, setHeadCount] = useState(2)
  const [note, setNote] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const staffing = kinds.filter((kind) => !kind.alarm)
  const alarms = kinds.filter((kind) => kind.alarm)

  const raise = async (kind: IncidentKindOption, count?: number) => {
    setSending(true)
    setError(null)
    try {
      const incident = await client.raiseIncident({
        kind: kind.kind,
        checkpoint,
        ...(reporter ? { reporter } : {}),
        ...(note.trim() ? { note: note.trim() } : {}),
        ...(count ? { head_count: count } : {}),
        // The idempotency key is what turns four panicked jabs at the alarm button
        // into one incident rather than four.
        client_id: newScanId(),
      })
      onRaised(incident)
      onClose()
    } catch (caught) {
      setSending(false)
      setError(caught instanceof Error ? caught.message : String(caught))
    }
  }

  if (confirming) {
    const label = LABELS[confirming.kind] ?? { title: confirming.kind, hint: '', glyph: '⚠' }
    return (
      <div className="sheet" role="dialog" aria-modal="true" aria-label={`Confirm ${label.title}`}>
        <div className="sheet__panel">
          <h2 className="sheet__title">
            {label.glyph} {label.title}?
          </h2>
          <p className="sheet__note">
            This goes straight to the control room and takes over their screen. {label.hint}.
          </p>

          {error ? <div className="error">{error}</div> : null}

          <div className="field">
            <label htmlFor="note">Anything they should know? (optional)</label>
            <input
              id="note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="front barrier is buckling"
              autoComplete="off"
            />
          </div>

          <button
            type="button"
            className="button button--danger"
            disabled={sending}
            onClick={() => void raise(confirming)}
          >
            {sending ? 'Sending…' : `Send ${label.title}`}
          </button>
          <button
            type="button"
            className="button button--quiet"
            onClick={() => setConfirming(null)}
            style={{ marginTop: 'var(--gc-gap)' }}
          >
            Cancel
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="sheet" role="dialog" aria-modal="true" aria-label="Call the control room">
      <div className="sheet__panel">
        <h2 className="sheet__title">Call the control room</h2>
        <p className="sheet__note">
          They see which gate you are on, which area it covers, and how fast this door is moving.
          You do not need to tell them.
        </p>

        {error ? <div className="error">{error}</div> : null}

        <h3 className="sheet__title" style={{ fontSize: 'var(--gc-body)' }}>
          Staffing
        </h3>
        <div className="sheet__grid">
          {staffing.map((kind) => {
            const label = LABELS[kind.kind] ?? { title: kind.kind, hint: '', glyph: '•' }
            const isHeadcount = kind.kind === 'need-staff'
            return (
              <button
                key={kind.kind}
                type="button"
                className="signal"
                data-severity={kind.severity}
                disabled={sending}
                // Staffing requests send immediately: somebody asking for a hand
                // does not need a confirmation dialog.
                onClick={() => void raise(kind, isHeadcount ? headCount : undefined)}
              >
                <span className="signal__severity">{kind.severity}</span>
                <span>
                  {label.glyph} {label.title}
                  {isHeadcount ? ` ×${headCount}` : ''}
                </span>
                <span className="signal__severity" style={{ opacity: 0.6 }}>
                  {label.hint}
                </span>
              </button>
            )
          })}
        </div>

        <div className="field" style={{ marginTop: 'var(--gc-pad)' }}>
          <label htmlFor="heads">How many extra people?</label>
          <input
            id="heads"
            type="number"
            min={1}
            max={20}
            value={headCount}
            onChange={(event) => setHeadCount(Math.max(1, Number(event.target.value) || 1))}
          />
        </div>

        <h3
          className="sheet__title"
          style={{ fontSize: 'var(--gc-body)', marginTop: 'var(--gc-pad)' }}
        >
          Alarms
        </h3>
        <p className="sheet__note">These ask you to confirm.</p>
        <div className="sheet__grid">
          {alarms.map((kind) => {
            const label = LABELS[kind.kind] ?? { title: kind.kind, hint: '', glyph: '⚠' }
            return (
              <button
                key={kind.kind}
                type="button"
                className="signal"
                data-severity={kind.severity}
                disabled={sending}
                onClick={() => setConfirming(kind)}
              >
                <span className="signal__severity">{kind.severity}</span>
                <span>
                  {label.glyph} {label.title}
                </span>
                <span className="signal__severity" style={{ opacity: 0.6 }}>
                  {label.hint}
                </span>
              </button>
            )
          })}
        </div>

        {kinds.length === 0 ? (
          <div className="notice">
            This scanner has not synced yet, so it does not know what it can report. Reconnect to
            the box and try again.
          </div>
        ) : null}

        <button
          type="button"
          className="button button--quiet"
          onClick={onClose}
          style={{ marginTop: 'var(--gc-pad)' }}
        >
          Close
        </button>
      </div>
    </div>
  )
}
