import type { Enrollment, Mirrors, Queue, Settings as SettingsShape } from '@/store'

/**
 * Setup and diagnostics.
 *
 * Two audiences in one sheet. The top half is for a guard mid-shift: which gate this
 * phone is on, sound and buzz, gun mode. The bottom half is for whoever is trying to
 * work out why a gate has stopped, and it exists because the alternative is somebody
 * reading a phone's browser console over a radio.
 *
 * Everything in the diagnostics section answers a question that gets asked at an
 * event: is this phone synced, how far behind is it, how many scans are stuck, is it
 * talking to the right box.
 */

interface HistoryEntry {
  at: number
  verdict: string
  severity: 'admit' | 'deny' | 'redirect'
  what: string
}

interface Props {
  enrollment: Enrollment
  settings: SettingsShape
  mirrors: Mirrors
  queue: Queue
  connection: string
  history: HistoryEntry[]
  onSettings: (settings: SettingsShape) => void
  onClose: () => void
  onResync: () => void
  onCheckpoint: (checkpoint: string) => void
  onSignOut: () => void
}

export function Settings({
  enrollment,
  settings,
  mirrors,
  queue,
  connection,
  history,
  onSettings,
  onClose,
  onResync,
  onCheckpoint,
  onSignOut,
}: Props) {
  const set = <K extends keyof SettingsShape>(key: K, value: SettingsShape[K]) => {
    onSettings({ ...settings, [key]: value })
  }

  return (
    <div className="sheet" role="dialog" aria-modal="true" aria-label="Scanner setup">
      <div className="sheet__panel">
        <h2 className="sheet__title">Setup</h2>

        {enrollment.assignments.length > 1 ? (
          <div className="field">
            <label htmlFor="checkpoint">Which gate is this phone on?</label>
            <select
              id="checkpoint"
              value={enrollment.activeCheckpoint}
              onChange={(event) => onCheckpoint(event.target.value)}
            >
              {enrollment.assignments.map((assignment) => (
                <option key={assignment.checkpoint} value={assignment.checkpoint}>
                  {assignment.name}
                  {assignment.lane ? ` · lane ${assignment.lane}` : ''}
                </option>
              ))}
            </select>
          </div>
        ) : null}

        <div className="field">
          <label htmlFor="reporter">Your name (goes on anything you report)</label>
          <input
            id="reporter"
            value={settings.reporter}
            onChange={(event) => set('reporter', event.target.value)}
            placeholder="Aditi"
            autoComplete="off"
          />
        </div>

        <Toggle
          label="Sound"
          hint="The two-tone chime is what staff actually work off."
          checked={settings.sound}
          onChange={(value) => set('sound', value)}
        />
        <Toggle
          label="Buzz"
          hint="Felt through a jacket when the sound is drowned out."
          checked={settings.haptics}
          onChange={(value) => set('haptics', value)}
        />
        <Toggle
          label="Barcode gun mode"
          hint="Turns the camera off and reads from a USB reader instead."
          checked={settings.gunMode}
          onChange={(value) => set('gunMode', value)}
        />

        {enrollment.mode === 'degraded' ? (
          <Toggle
            label="Admit when the box is unreachable"
            hint="This event allows it. Anyone let in this way is checked when the network returns, and a double use is flagged to the control room."
            checked={settings.admitOffline}
            onChange={(value) => set('admitOffline', value)}
          />
        ) : (
          <div className="notice">
            This event runs in strict mode: if the box cannot be reached, this gate holds rather
            than admitting. That is the organizer&rsquo;s choice, not a setting on this phone.
          </div>
        )}

        {history.length > 0 ? (
          <>
            <h3
              className="sheet__title"
              style={{ fontSize: 'var(--gc-body)', marginTop: 'var(--gc-pad)' }}
            >
              Last few scans
            </h3>
            <div className="history">
              {history.map((entry) => (
                <div key={entry.at} className="history__row">
                  <span
                    className="history__dot"
                    data-severity={entry.severity}
                    aria-hidden="true"
                  />
                  <span className="history__what">
                    {entry.verdict.replace(/_/g, ' ').toLowerCase()}
                    {entry.what ? ` — ${entry.what}` : ''}
                  </span>
                  <span className="history__when">{clockOf(entry.at)}</span>
                </div>
              ))}
            </div>
          </>
        ) : null}

        <h3
          className="sheet__title"
          style={{ fontSize: 'var(--gc-body)', marginTop: 'var(--gc-pad)' }}
        >
          Diagnostics
        </h3>
        <dl className="diagnostics">
          <dt>event</dt>
          <dd>{enrollment.event}</dd>
          <dt>box</dt>
          <dd>{enrollment.boxUrl}</dd>
          <dt>device</dt>
          <dd>
            {enrollment.deviceName} ({enrollment.deviceId})
          </dd>
          <dt>connection</dt>
          <dd>{connection}</dd>
          <dt>ticket list</dt>
          <dd>
            {mirrors.synced
              ? `${mirrors.ticketCount} tickets, ${Math.round(mirrors.filterBytes / 1024)} KB filter`
              : 'not synced'}
          </dd>
          <dt>mirror</dt>
          <dd>
            up to sequence {mirrors.seq}
            {mirrors.syncedAt ? `, synced ${relative(mirrors.syncedAt)}` : ''}
          </dd>
          <dt>queue</dt>
          <dd>
            {queue.length} waiting
            {queue.offlineAdmissions > 0 ? `, ${queue.offlineAdmissions} admitted offline` : ''}
          </dd>
          <dt>certificate</dt>
          <dd>{enrollment.caFingerprint ?? 'not pinned'}</dd>
        </dl>

        <button
          type="button"
          className="button"
          onClick={onResync}
          style={{ marginTop: 'var(--gc-gap)' }}
        >
          Sync the ticket list again
        </button>

        <button
          type="button"
          className="button button--quiet"
          onClick={onClose}
          style={{ marginTop: 'var(--gc-gap)' }}
        >
          Done
        </button>

        <button
          type="button"
          className="button button--danger"
          style={{ marginTop: 'var(--gc-pad)' }}
          onClick={() => {
            // Confirmed, because signing out throws away the queue and the mirror,
            // and a mis-tap here means re-enrolling a phone in the middle of doors.
            if (
              window.confirm(
                queue.length > 0
                  ? `${queue.length} scans have not reached the box yet. Signing out will lose them. Continue?`
                  : 'Sign this scanner out? You will need a new gate code to use it again.',
              )
            ) {
              onSignOut()
            }
          }}
        >
          Sign this scanner out
        </button>
      </div>
    </div>
  )
}

function Toggle({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string
  hint: string
  checked: boolean
  onChange: (value: boolean) => void
}) {
  return (
    <button
      type="button"
      className="signal"
      aria-pressed={checked}
      onClick={() => onChange(!checked)}
      style={{
        borderColor: checked ? 'var(--gc-accent)' : undefined,
        background: checked
          ? 'color-mix(in srgb, var(--gc-accent) 18%, var(--gc-surface-raised))'
          : undefined,
      }}
    >
      <span>
        {checked ? '☑' : '☐'} {label}
      </span>
      <span
        className="signal__severity"
        style={{ opacity: 0.7, textTransform: 'none', letterSpacing: 0 }}
      >
        {hint}
      </span>
    </button>
  )
}

function clockOf(at: number): string {
  return new Date(at).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/** "4 minutes ago", for somebody deciding whether a sync is stale. */
function relative(iso: string): string {
  const elapsed = Date.now() - new Date(iso).getTime()
  const minutes = Math.round(elapsed / 60_000)
  if (minutes < 1) return 'just now'
  if (minutes === 1) return '1 minute ago'
  if (minutes < 60) return `${minutes} minutes ago`
  const hours = Math.round(minutes / 60)
  return hours === 1 ? '1 hour ago' : `${hours} hours ago`
}
