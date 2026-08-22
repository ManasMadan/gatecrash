import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ApiError, type Incident, type ScanResult } from '@gatecrash/protocol'
import { VerdictScreen, playAlarm, playQueued } from '@gatecrash/ui'

import { createDecoder, hasTorch, openCamera, setTorch, type Decoder } from '@/decode'
import { Settings as SettingsSheet } from '@/Settings'
import { Signals } from '@/Signals'
import {
  Mirrors,
  Queue,
  clearEnrollment,
  clientFor,
  localVerdict,
  newScanId,
  saveEnrollment,
  type Enrollment,
  type Settings,
} from '@/store'

/**
 * The gate screen: a camera, a verdict, and two buttons.
 *
 * Everything here is arranged around one fact: the person holding this phone is
 * watching a queue, not a screen. So the camera runs continuously with no shutter to
 * press, the verdict takes over the whole display with a sound and a buzz, and the
 * only controls are the ones that get used — torch, ask for staff, raise an alarm.
 *
 * The offline behaviour is the other half. A scan is queued before it is sent and
 * removed when the box acknowledges, so a browser killed mid-request loses nothing.
 * When the box is unreachable the scanner decides from its own mirror: refusing
 * what it knows is invalid, and — only if the organizer chose DEGRADED mode for this
 * event — admitting what it has no reason to refuse.
 */

interface Props {
  enrollment: Enrollment
  settings: Settings
  onSettings: (settings: Settings) => void
  onSignedOut: () => void
  onEnrollment: (enrollment: Enrollment) => void
}

type Connection = 'online' | 'syncing' | 'offline'

/** One entry in the recent-scan strip, so a guard can see what just happened. */
interface HistoryEntry {
  at: number
  verdict: string
  severity: 'admit' | 'deny' | 'redirect'
  what: string
}

export function Gate({ enrollment, settings, onSettings, onSignedOut, onEnrollment }: Props) {
  const client = useMemo(() => clientFor(enrollment), [enrollment])
  const mirrors = useMemo(() => Mirrors.load(), [])
  const queue = useMemo(() => Queue.load(), [])

  const [connection, setConnection] = useState<Connection>('syncing')
  const [verdict, setVerdict] = useState<ScanResult | null>(null)
  const [verdictOffline, setVerdictOffline] = useState(false)
  const [queued, setQueued] = useState(queue.length)
  const [sheet, setSheet] = useState<'none' | 'signals' | 'settings'>('none')
  const [torchOn, setTorchOn] = useState(false)
  const [torchAvailable, setTorchAvailable] = useState(false)
  const [alarm, setAlarm] = useState<Incident | null>(null)
  const [history, setHistory] = useState<HistoryEntry[]>([])
  const [gunValue, setGunValue] = useState('')
  const [problem, setProblem] = useState<string | null>(null)

  const video = useRef<HTMLVideoElement>(null)
  const stream = useRef<MediaStream | undefined>(undefined)
  const scanning = useRef(true)

  // Payloads seen very recently, so a camera holding a code in frame for a second
  // does not fire thirty scans. Keyed on the payload rather than the ticket, because
  // a rotating code legitimately changes and should be allowed through again.
  const recent = useRef(new Map<string, number>())

  const assignment = enrollment.assignments.find(
    (entry) => entry.checkpoint === enrollment.activeCheckpoint,
  )

  const remember = useCallback((result: ScanResult) => {
    setHistory((current) =>
      [
        {
          at: Date.now(),
          verdict: result.verdict,
          severity: result.severity,
          what: result.seat_label || result.tier_name || result.reason,
        },
        ...current,
      ].slice(0, 12),
    )
  }, [])

  /**
   * Sends one scan, queueing it first.
   *
   * The order is the guarantee: in the queue, then sent, then removed on
   * acknowledgement. A crash at any point leaves the scan queued rather than lost.
   */
  const submit = useCallback(
    async (payload: string, direction?: 'in' | 'out') => {
      const scanId = newScanId()
      const checkpoint = enrollment.activeCheckpoint

      // The mirror's opinion first. It can refuse a garbage QR with no network at
      // all, which is what makes a flood of them free.
      const local = mirrors.judge(payload)

      if (local === 'malformed') {
        const result = localVerdict(
          scanId,
          checkpoint,
          enrollment.deviceId,
          'MALFORMED',
          'Not a ticket, try again',
          'deny',
        )
        setVerdictOffline(false)
        setVerdict(result)
        remember(result)
        return
      }

      queue.add({
        scanId,
        payload,
        checkpoint,
        ...(direction ? { direction } : {}),
        observedAt: new Date().toISOString(),
        offlineAdmitted: false,
        attempts: 0,
        localVerdict: '',
      })
      setQueued(queue.length)

      try {
        const result = await client.scan({
          scan_id: scanId,
          payload,
          checkpoint,
          ...(direction ? { direction } : {}),
          observed_at: new Date().toISOString(),
        })
        queue.remove(scanId)
        setQueued(queue.length)
        setConnection('online')
        setProblem(null)

        if (result.verdict === 'ADMIT' && result.ticket) {
          mirrors.observe(result.ticket, result.seq ?? 0)
        }
        setVerdictOffline(false)
        setVerdict(result)
        remember(result)
      } catch (caught) {
        // The box could not be reached, or could not decide. Either way the scanner
        // is on its own for this one.
        setConnection('offline')
        if (caught instanceof ApiError && !caught.retryable) {
          // A refusal the box means: a revoked device, a gate this phone is not
          // assigned to. Retrying would never help, so the scan leaves the queue.
          queue.remove(scanId)
          setQueued(queue.length)
          setProblem(caught.message)
          const result = localVerdict(
            scanId,
            checkpoint,
            enrollment.deviceId,
            'SCANNER_NOT_AUTHORIZED',
            caught.message,
            'deny',
          )
          setVerdictOffline(true)
          setVerdict(result)
          remember(result)
          return
        }

        const result = decideOffline(local, scanId, checkpoint, enrollment, settings)
        if (result.verdict === 'ADMIT') {
          // Mark the queued scan as an offline admission, so when it drains the box
          // knows a real person really did walk through and can flag a double use
          // with both records rather than silently disagreeing.
          const entry = queue.all.find((item) => item.scanId === scanId)
          if (entry) {
            entry.offlineAdmitted = true
            entry.localVerdict = 'ADMIT'
            queue.add({ ...entry })
            queue.remove(scanId)
          }
        }
        setVerdictOffline(true)
        setVerdict(result)
        remember(result)
        playQueued(settings)
      }
    },
    [client, enrollment, mirrors, queue, remember, settings],
  )

  /** Sync at start, and whenever the box comes back. */
  const sync = useCallback(async () => {
    setConnection('syncing')
    try {
      const response = await client.sync(enrollment.activeCheckpoint)
      mirrors.replace(response, enrollment.activeCheckpoint)
      // The assignments can change under a device: a supervisor moves a phone from
      // one door to another from the dashboard.
      if (response.assignments.length > 0) {
        saveEnrollment({ ...enrollment, assignments: response.assignments })
        onEnrollment({ ...enrollment, assignments: response.assignments })
      }
      setConnection('online')
      setProblem(null)
    } catch (caught) {
      setConnection('offline')
      if (caught instanceof ApiError && !caught.retryable) setProblem(caught.message)
    }
  }, [client, enrollment, mirrors, onEnrollment])

  useEffect(() => {
    void sync()
  }, [sync])

  /**
   * Drains the queue.
   *
   * Exponential backoff, capped at fifteen seconds. Uncapped backoff means a scanner
   * that was offline for an hour then takes another hour to notice the network came
   * back, which is exactly wrong: the moment the box returns is the moment somebody
   * is standing at the gate.
   */
  useEffect(() => {
    let cancelled = false
    let delay = 1_000

    const drain = async () => {
      if (cancelled) return
      const next = queue.next()

      if (!next) {
        delay = 1_000
        setTimeout(() => void drain(), 2_000)
        return
      }

      try {
        const result = await client.scan({
          scan_id: next.scanId,
          payload: next.payload,
          checkpoint: next.checkpoint,
          ...(next.direction ? { direction: next.direction } : {}),
          offline_admitted: next.offlineAdmitted,
          observed_at: next.observedAt,
        })
        queue.remove(next.scanId)
        setQueued(queue.length)
        setConnection('online')
        if (result.verdict === 'ADMIT' && result.ticket) {
          mirrors.observe(result.ticket, result.seq ?? 0)
        }
        // A flagged double use is worth interrupting for: somebody got in twice and
        // the control room needs to know it came from this gate.
        if (result.flagged) {
          setProblem(`Double use flagged for a ticket admitted offline at ${next.checkpoint}.`)
        }
        delay = 1_000
        setTimeout(() => void drain(), 50)
      } catch (caught) {
        queue.markAttempt(next.scanId)
        if (caught instanceof ApiError && !caught.retryable) {
          // The box has a definite answer and it is not going to change.
          queue.remove(next.scanId)
          setQueued(queue.length)
          setTimeout(() => void drain(), 50)
          return
        }
        setConnection('offline')
        delay = Math.min(delay * 2, 15_000)
        setTimeout(() => void drain(), delay)
      }
    }

    const timer = setTimeout(() => void drain(), 500)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [client, mirrors, queue])

  /** Watches the box's stream for emergencies pushed down to the gates. */
  useEffect(() => {
    let source: EventSource | undefined
    try {
      source = client.stream('/v1/stream', mirrors.seq)
      source.addEventListener('incident', (event) => {
        try {
          const incident = JSON.parse((event as MessageEvent<string>).data) as Incident
          if (incident.severity === 'emergency' && incident.status !== 'resolved') {
            setAlarm(incident)
            playAlarm(settings)
          }
        } catch {
          // A malformed event is not worth tearing the stream down for.
        }
      })
      source.addEventListener('open', () => setConnection('online'))
      source.addEventListener('error', () => setConnection('offline'))
    } catch {
      // EventSource unavailable. The gate still works; it just will not be told
      // about an evacuation, which is what the PA system is for.
    }
    return () => source?.close()
  }, [client, mirrors, settings])

  /** The camera loop. Paused while a verdict is showing or a sheet is open. */
  useEffect(() => {
    if (settings.gunMode) return

    let decoder: Decoder | undefined
    let frame = 0
    let live = true

    const start = async () => {
      try {
        stream.current = await openCamera()
        setTorchAvailable(hasTorch(stream.current))
        decoder = await createDecoder()
        if (video.current) {
          video.current.srcObject = stream.current
          await video.current.play()
        }
      } catch (caught) {
        setProblem(caught instanceof Error ? caught.message : String(caught))
        return
      }

      const tick = async () => {
        if (!live) return
        if (scanning.current && decoder && video.current) {
          const found = await decoder.decode(video.current)
          if (found && !seenRecently(recent.current, found)) {
            scanning.current = false
            await submit(found)
          }
        }
        frame = requestAnimationFrame(() => void tick())
      }
      frame = requestAnimationFrame(() => void tick())
    }

    void start()
    return () => {
      live = false
      cancelAnimationFrame(frame)
      for (const track of stream.current?.getTracks() ?? []) track.stop()
      stream.current = undefined
    }
  }, [settings.gunMode, submit])

  // Scanning resumes when the verdict clears and no sheet is covering the camera.
  useEffect(() => {
    scanning.current = verdict === null && sheet === 'none'
  }, [verdict, sheet])

  const gateName = assignment?.name ?? enrollment.activeCheckpoint

  return (
    <>
      {alarm ? (
        <button type="button" className="alarm-banner" onClick={() => setAlarm(null)}>
          {alarm.kind.replace(/-/g, ' ').toUpperCase()}
          {alarm.zone_name ? ` — ${alarm.zone_name}` : ''}
          {alarm.note ? `: ${alarm.note}` : ''}
        </button>
      ) : null}

      <div className="strip">
        <span className="strip__gate">
          {gateName}
          {assignment?.lane ? <span className="strip__lane"> · lane {assignment.lane}</span> : null}
        </span>
        <span className={`pill pill--${connection}`}>
          {connectionLabel(connection, mirrors.synced)}
        </span>
        {queued > 0 ? <span className="pill pill--queued">{queued} queued</span> : null}
      </div>

      {problem ? (
        <div className="error" style={{ margin: 'var(--gc-gap)' }}>
          {problem}
        </div>
      ) : null}

      {settings.gunMode ? (
        <GunMode
          value={gunValue}
          onValue={setGunValue}
          onSubmit={(payload) => void submit(payload)}
        />
      ) : (
        <div className="viewfinder">
          <video ref={video} playsInline muted />
          <div className="reticle" aria-hidden="true" />
          <p className="viewfinder__hint">
            {mirrors.synced
              ? `${mirrors.ticketCount} tickets loaded — works with no signal`
              : 'Syncing the ticket list…'}
          </p>
        </div>
      )}

      {history.length > 0 && !settings.gunMode ? null : null}

      <div className="controls">
        {torchAvailable ? (
          <button
            type="button"
            className="control"
            aria-pressed={torchOn}
            onClick={() => {
              const next = !torchOn
              setTorchOn(next)
              void setTorch(stream.current, next)
            }}
          >
            <span className="control__glyph" aria-hidden="true">
              🔆
            </span>
            Light
          </button>
        ) : (
          <button type="button" className="control" onClick={() => setSheet('settings')}>
            <span className="control__glyph" aria-hidden="true">
              ⚙
            </span>
            Setup
          </button>
        )}

        <button
          type="button"
          className="control control--staff"
          onClick={() => setSheet('signals')}
        >
          <span className="control__glyph" aria-hidden="true">
            👥
          </span>
          Need staff
        </button>

        <button
          type="button"
          className="control control--alarm"
          onClick={() => setSheet('signals')}
        >
          <span className="control__glyph" aria-hidden="true">
            ⚠
          </span>
          Alarm
        </button>
      </div>

      {verdict ? (
        <VerdictScreen
          result={verdict}
          onDismiss={() => setVerdict(null)}
          offline={verdictOffline}
          feedback={settings}
          gateName={gateName}
        />
      ) : null}

      {sheet === 'signals' ? (
        <Signals
          client={client}
          kinds={mirrors.incidentKinds}
          checkpoint={enrollment.activeCheckpoint}
          reporter={settings.reporter}
          onClose={() => setSheet('none')}
          onRaised={(incident) => setProblem(`Sent. Control room has ${incident.id}.`)}
        />
      ) : null}

      {sheet === 'settings' ? (
        <SettingsSheet
          enrollment={enrollment}
          settings={settings}
          mirrors={mirrors}
          queue={queue}
          connection={connection}
          history={history}
          onSettings={onSettings}
          onClose={() => setSheet('none')}
          onResync={() => void sync()}
          onCheckpoint={(checkpoint) => {
            const next = { ...enrollment, activeCheckpoint: checkpoint }
            saveEnrollment(next)
            onEnrollment(next)
          }}
          onSignOut={() => {
            clearEnrollment()
            onSignedOut()
          }}
        />
      ) : null}
    </>
  )
}

/**
 * Gun mode: a USB barcode reader types the payload into a field and presses enter.
 *
 * Worth supporting because a wired gun is faster and more reliable than any phone
 * camera, and venues that already own them expect to use them. The field is
 * invisible-ish and always focused, so the operator never touches the screen.
 */
function GunMode({
  value,
  onValue,
  onSubmit,
}: {
  value: string
  onValue: (value: string) => void
  onSubmit: (payload: string) => void
}) {
  const input = useRef<HTMLInputElement>(null)

  // Refocused aggressively: a gun that types into nothing looks like a broken
  // scanner, and the field loses focus every time the browser does anything.
  useEffect(() => {
    const focus = () => input.current?.focus()
    focus()
    const timer = setInterval(focus, 1_000)
    return () => clearInterval(timer)
  }, [])

  return (
    <div
      className="viewfinder"
      style={{ display: 'grid', placeItems: 'center', background: 'var(--gc-ink)' }}
    >
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault()
          const payload = value.trim()
          onValue('')
          if (payload) onSubmit(payload)
        }}
      >
        <p className="sheet__note" style={{ textAlign: 'center' }}>
          Gun mode. Scan a ticket with the reader.
        </p>
        <div className="field">
          <label htmlFor="gun">Ticket</label>
          <input
            ref={input}
            id="gun"
            value={value}
            onChange={(event) => onValue(event.target.value)}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            style={{ fontFamily: 'var(--gc-font-mono)' }}
          />
        </div>
        <button type="submit" className="button">
          Scan
        </button>
      </form>
    </div>
  )
}

/**
 * Decides a verdict with no box.
 *
 * The `unknown` case is definitive and free: a Bloom filter has no false negatives,
 * so an id it does not hold was never issued for this event. `used` is a strong hint
 * from a mirror that may be stale.
 *
 * The `ask` case is where the CAP position becomes a user-facing choice. In STRICT
 * mode the gate shows amber and does not admit, because the guarantee is that at
 * most one person ever gets in on a ticket. In DEGRADED mode — which the organizer
 * opted into, per event — the gate admits and the box flags any double use within
 * seconds of the network healing. Prevention under partition is impossible; this is
 * the honest choice between the two things that are possible.
 */
function decideOffline(
  local: 'unknown' | 'used' | 'ask' | 'malformed',
  scanId: string,
  checkpoint: string,
  enrollment: Enrollment,
  settings: Settings,
): ScanResult {
  if (local === 'unknown') {
    return localVerdict(
      scanId,
      checkpoint,
      enrollment.deviceId,
      'UNKNOWN_TICKET',
      'Not on the list',
      'deny',
    )
  }
  if (local === 'used') {
    return localVerdict(
      scanId,
      checkpoint,
      enrollment.deviceId,
      'ALREADY_USED',
      'Already scanned in',
      'deny',
    )
  }

  const degraded = enrollment.mode === 'degraded' && settings.admitOffline
  if (degraded) {
    return localVerdict(
      scanId,
      checkpoint,
      enrollment.deviceId,
      'ADMIT',
      'Let them in — box offline, will be checked',
      'admit',
    )
  }
  return localVerdict(
    scanId,
    checkpoint,
    enrollment.deviceId,
    'DOORS_CLOSED',
    'Box unreachable — hold and try again',
    'redirect',
  )
}

/**
 * Suppresses a payload seen in the last couple of seconds.
 *
 * Without this, a code held steady in frame fires a scan every frame: thirty
 * requests, thirty audit rows, and a queue of identical scans. Keyed on the payload
 * rather than the ticket so a rotating code that has legitimately changed still gets
 * through.
 */
function seenRecently(seen: Map<string, number>, payload: string): boolean {
  const now = Date.now()
  for (const [key, at] of seen) {
    if (now - at > 2_500) seen.delete(key)
  }
  if (seen.has(payload)) return true
  seen.set(payload, now)
  return false
}

function connectionLabel(connection: Connection, synced: boolean): string {
  if (connection === 'online') return 'online'
  if (connection === 'syncing') return 'syncing'
  return synced ? 'offline · ready' : 'offline · not synced'
}
