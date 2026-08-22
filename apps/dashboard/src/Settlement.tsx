import { useState } from 'react'
import type { Client, DashboardStats } from 'gatecrash-client'

/**
 * Announcements and settlement.
 *
 * Two jobs that both belong to the organizer rather than to a gate. The
 * announcement box is the one place in the product where a message reaches every
 * phone in the venue, including the ones with no signal — it goes out over the mesh
 * at organizer priority as well as over the network.
 *
 * The settlement panel is the end of the evening: seal the log, publish the root,
 * download the signed report. The point of showing the root here is that an operator
 * can read those sixty-four characters out over a phone to an artist's manager and
 * that is the whole handover.
 */
export function Settlement({ client, stats }: { client: Client; stats: DashboardStats | null }) {
  const [text, setText] = useState('')
  const [priority, setPriority] = useState(false)
  const [sealed, setSealed] = useState<{ rows: number; root: string; head: string } | null>(null)
  const [verified, setVerified] = useState<{ ok: boolean; rows: number; error?: string } | null>(
    null,
  )
  const [note, setNote] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const announce = async () => {
    if (!text.trim()) return
    setBusy(true)
    setError(null)
    try {
      await client.announce({ text: text.trim(), priority })
      setText('')
      setPriority(false)
      setNote('Sent to every phone in the venue.')
    } catch (caught) {
      setError((caught as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const seal = async () => {
    setBusy(true)
    setError(null)
    try {
      setSealed(await client.seal())
      setNote('Sealed. Publish that root — it is the whole commitment.')
    } catch (caught) {
      setError((caught as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const verify = async () => {
    setBusy(true)
    setError(null)
    try {
      setVerified(await client.verifyChain())
    } catch (caught) {
      setError((caught as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel">
      <h2>Tell everybody</h2>
      {error ? <div className="error">{error}</div> : null}
      {note ? <div className="ok">{note}</div> : null}

      <div className="field">
        <label htmlFor="announcement">Message</label>
        <textarea
          id="announcement"
          rows={3}
          maxLength={280}
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder="Gate 4 is now open. Pit is at capacity."
        />
        <span className="muted">
          {280 - text.length} characters left. This is read on a lock screen in a crowd, so keep it
          to one thing.
        </span>
      </div>

      <label className="checkboxes" style={{ display: 'block', marginBottom: 'var(--gc-gap)' }}>
        <label>
          <input
            type="checkbox"
            checked={priority}
            onChange={(event) => setPriority(event.target.checked)}
          />
          Urgent — override do not disturb
        </label>
      </label>

      <button
        type="button"
        className="button"
        disabled={busy || !text.trim()}
        onClick={() => void announce()}
      >
        Send
      </button>

      <h2 style={{ marginTop: 'var(--gc-pad)' }}>Settlement</h2>
      <p className="muted">
        Every decision this box made is in a hash chain. Sealing publishes one 32-byte root that
        commits to all of it, and any single admission can then be proved against that root with
        about twenty hashes — by somebody who does not have the log and does not trust you.
      </p>

      <div
        style={{
          display: 'flex',
          gap: 'var(--gc-gap)',
          flexWrap: 'wrap',
          marginTop: 'var(--gc-gap)',
        }}
      >
        <button type="button" className="button" disabled={busy} onClick={() => void seal()}>
          Seal the log
        </button>
        <button
          type="button"
          className="button button--quiet"
          disabled={busy}
          onClick={() => void verify()}
        >
          Check it
        </button>
        <a
          className="button button--quiet"
          style={{ display: 'inline-flex', alignItems: 'center', textDecoration: 'none' }}
          href={`/v1/admin/export?token=${encodeURIComponent(
            sessionStorage.getItem('gatecrash.dashboard.token') ?? '',
          )}`}
        >
          Download the signed report
        </a>
      </div>

      {sealed ? (
        <div style={{ marginTop: 'var(--gc-gap)' }}>
          <p className="muted">Sealed over {sealed.rows.toLocaleString()} recorded decisions.</p>
          <p className="mono">root {sealed.root}</p>
          <p className="mono">head {sealed.head}</p>
        </div>
      ) : null}

      {verified ? (
        <div className={verified.ok ? 'ok' : 'error'} style={{ marginTop: 'var(--gc-gap)' }}>
          {verified.ok
            ? `The chain checks out across all ${verified.rows.toLocaleString()} rows. Nothing has been inserted, deleted, edited or reordered.`
            : `The chain does not check out: ${verified.error ?? 'unknown'}`}
        </div>
      ) : null}

      {stats && stats.flags > 0 ? (
        <div className="error" style={{ marginTop: 'var(--gc-gap)' }}>
          {stats.flags} double use{stats.flags === 1 ? '' : 's'} detected. Somebody got in on a
          ticket that had already been used, during a network partition. Both records are in the
          report.
        </div>
      ) : null}
    </div>
  )
}
