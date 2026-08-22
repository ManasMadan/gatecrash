import { useEffect, useRef, useState } from 'react'
import QRCode from 'qrcode'
import type { Client, DashboardStats, VenuePlan } from 'gatecrash-client'

/**
 * Enrollment and the scanner roster.
 *
 * The QR this produces is the whole trust ceremony: it carries the box's address, the
 * certificate fingerprint to pin, and a single-use code. Possession of the printed
 * sheet is the authorisation, which is why it is drawn large enough to hold up to a
 * phone across a table and why the expiry is stated in plain words.
 *
 * Revoking a scanner is one tap and takes effect on the very next scan, because the
 * box reads the device row inside every scan's transaction rather than caching it.
 * That is the answer to "somebody walked off with a phone".
 */
export function Enrollment({
  client,
  venue,
  stats,
  onChanged,
}: {
  client: Client
  venue: VenuePlan | null
  stats: DashboardStats | null
  onChanged: () => void
}) {
  const [selected, setSelected] = useState<string[]>([])
  const [name, setName] = useState('')
  const [uses, setUses] = useState(1)
  const [invite, setInvite] = useState<{ code: string; qr: string; expires: string } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const canvas = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    if (!invite || !canvas.current) return
    void QRCode.toCanvas(canvas.current, invite.qr, {
      // Error correction M and a generous size: this gets printed, photocopied, and
      // photographed off a laptop screen at an angle.
      errorCorrectionLevel: 'M',
      margin: 0,
      width: 600,
      color: { dark: '#000000ff', light: '#ffffffff' },
    })
  }, [invite])

  const issue = async () => {
    if (selected.length === 0) {
      setError('Pick at least one gate. A scanner with no gate scans nothing.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const response = await client.invite({
        checkpoints: selected,
        ...(name.trim() ? { name: name.trim() } : {}),
        ...(uses > 1 ? { uses } : {}),
      })
      setInvite({ code: response.invite.code, qr: response.qr, expires: response.invite.expires })
    } catch (caught) {
      setError((caught as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const revoke = async (id: string) => {
    if (!window.confirm(`Stop scanner ${id} working? This takes effect on its next scan.`)) return
    try {
      await client.revokeDevice(id)
      onChanged()
    } catch (caught) {
      setError((caught as Error).message)
    }
  }

  return (
    <div className="panel">
      <h2>Sign a scanner in</h2>
      {error ? <div className="error">{error}</div> : null}

      <div className="field">
        <label>Which gates?</label>
        <div className="checkboxes">
          {(venue?.checkpoints ?? []).map((checkpoint) => (
            <label key={checkpoint.code}>
              <input
                type="checkbox"
                checked={selected.includes(checkpoint.code)}
                onChange={(event) =>
                  setSelected((current) =>
                    event.target.checked
                      ? [...current, checkpoint.code]
                      : current.filter((code) => code !== checkpoint.code),
                  )
                }
              />
              {checkpoint.name}
              {checkpoint.lane ? ` · ${checkpoint.lane}` : ''}
            </label>
          ))}
        </div>
      </div>

      <div className="field">
        <label htmlFor="gate-name">Name for this position (optional)</label>
        <input
          id="gate-name"
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="North Gate"
          autoComplete="off"
        />
      </div>

      <div className="field">
        <label htmlFor="uses">How many phones will use this code?</label>
        <input
          id="uses"
          type="number"
          min={1}
          max={20}
          value={uses}
          onChange={(event) => setUses(Math.max(1, Number(event.target.value) || 1))}
        />
        <span className="muted">
          One sheet can sign several phones in. Each still gets its own identity, so every scan is
          still attributable.
        </span>
      </div>

      <button type="button" className="button" disabled={busy} onClick={() => void issue()}>
        {busy ? 'Making a code…' : 'Make a gate code'}
      </button>

      {invite ? (
        <div className="invite">
          <canvas ref={canvas} aria-label="Enrollment code" role="img" />
          <span className="invite__code">{invite.code}</span>
          <span className="invite__expiry">
            Works once. Expires {new Date(invite.expires).toLocaleTimeString()}.
          </span>
          <button type="button" className="button button--quiet" onClick={() => window.print()}>
            Print this
          </button>
        </div>
      ) : null}

      <h2 style={{ marginTop: 'var(--gc-pad)' }}>Scanners</h2>
      <div className="rows">
        {(stats?.devices ?? []).map((device) => (
          <div className="row" key={device.id}>
            <span className="row__name">
              {device.name || device.id}
              {device.revoked ? ' · revoked' : ''}
            </span>
            <span className="row__figure">{device.checkpoints.join(', ')}</span>
            {device.revoked ? null : (
              <button
                type="button"
                className="button button--danger"
                onClick={() => void revoke(device.id)}
              >
                Stop
              </button>
            )}
          </div>
        ))}
        {(stats?.devices ?? []).length === 0 ? (
          <p className="muted">No scanner has signed in yet.</p>
        ) : null}
      </div>

      {stats && stats.pending_codes > 0 ? (
        <p className="muted" style={{ marginTop: 'var(--gc-gap)' }}>
          {stats.pending_codes} gate code{stats.pending_codes === 1 ? '' : 's'} still unused. They
          expire on their own.
        </p>
      ) : null}
    </div>
  )
}
