import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from 'gatecrash-client'

import { anonymousClient } from '@/App'
import { createDecoder, openCamera, type Decoder } from '@/decode'
import { saveEnrollment, type Enrollment } from '@/store'

/**
 * The enrollment ceremony.
 *
 * A staff phone points at a QR the organizer printed and is done. The QR carries
 * three things, and it is worth being clear about why each is there rather than
 * asking somebody to type it:
 *
 *   - the box's URL, so the phone does not have to discover anything on a network
 *     that may not cooperate;
 *   - the CA fingerprint, so the phone can pin the box's self-signed certificate
 *     rather than trusting whatever answers;
 *   - a single-use code, so possession of the printed sheet is the authorisation.
 *
 * That last one is what makes this secure with no pre-shared secret and no
 * internet: trust arrives out of band, on paper, from the person allowed to grant
 * it.
 *
 * Typing the code by hand is offered as well, because a camera that will not focus
 * at 7pm is not a reason to be unable to open a gate.
 */

interface Props {
  onEnrolled: (enrollment: Enrollment) => void
}

type Stage = 'scan' | 'typing' | 'working'

export function Enroll({ onEnrolled }: Props) {
  const [stage, setStage] = useState<Stage>('scan')
  const [error, setError] = useState<string | null>(null)
  const [deviceName, setDeviceName] = useState(() => suggestName())
  const [boxUrl, setBoxUrl] = useState('')
  const [code, setCode] = useState('')

  const video = useRef<HTMLVideoElement>(null)
  const stream = useRef<MediaStream | undefined>(undefined)
  const running = useRef(false)

  const redeem = useCallback(
    async (url: string, enrollCode: string, name: string, caFingerprint?: string) => {
      setStage('working')
      setError(null)
      try {
        const response = await anonymousClient(url).enroll(enrollCode, name)
        const first = response.assignments[0]
        // Whatever the box reported, falling back to what the QR carried. Spread
        // conditionally rather than assigned as undefined: exactOptionalPropertyTypes
        // distinguishes an absent property from an explicit undefined, and the stored
        // shape should say "not pinned" by absence.
        const fingerprint = response.ca_fingerprint ?? caFingerprint
        const enrollment: Enrollment = {
          boxUrl: url,
          token: response.token,
          deviceId: response.device_id,
          deviceName: response.name,
          event: response.event,
          mode: response.mode,
          checkpoints: response.checkpoints,
          assignments: response.assignments,
          activeCheckpoint: first?.checkpoint ?? response.checkpoints[0] ?? '',
          ...(fingerprint === undefined ? {} : { caFingerprint: fingerprint }),
        }
        saveEnrollment(enrollment)
        onEnrolled(enrollment)
      } catch (caught) {
        setStage('typing')
        setError(describe(caught, url))
      }
    },
    [onEnrolled],
  )

  // The camera loop. Only running while the scan stage is showing: holding a camera
  // open behind a form is a battery drain nobody asked for.
  useEffect(() => {
    if (stage !== 'scan') return

    let decoder: Decoder | undefined
    let frame = 0
    running.current = true

    const start = async () => {
      try {
        stream.current = await openCamera()
        decoder = await createDecoder()
        if (video.current) {
          video.current.srcObject = stream.current
          await video.current.play()
        }
      } catch (caught) {
        // No camera almost always means the page is not in a secure context, which
        // is a fixable thing worth saying plainly rather than a dead end.
        setError(caught instanceof Error ? caught.message : String(caught))
        setStage('typing')
        return
      }

      const tick = async () => {
        if (!running.current || !decoder || !video.current) return
        const found = await decoder.decode(video.current)
        if (found) {
          const invite = parseInvite(found)
          if (invite) {
            running.current = false
            await redeem(invite.url, invite.code, deviceName, invite.ca)
            return
          }
        }
        frame = requestAnimationFrame(() => void tick())
      }
      frame = requestAnimationFrame(() => void tick())
    }

    void start()

    return () => {
      running.current = false
      cancelAnimationFrame(frame)
      // Releasing the track matters: a camera left open keeps the phone's indicator
      // light on and a warm phone throttles.
      for (const track of stream.current?.getTracks() ?? []) track.stop()
      stream.current = undefined
    }
  }, [stage, deviceName, redeem])

  if (stage === 'scan') {
    return (
      <>
        <div className="strip">
          <span className="strip__gate">Sign this scanner in</span>
        </div>
        <div className="viewfinder">
          <video ref={video} playsInline muted />
          <div className="reticle" aria-hidden="true" />
          <p className="viewfinder__hint">Point at the enrollment code on the gate sheet</p>
        </div>
        <div className="controls" style={{ gridTemplateColumns: '1fr' }}>
          <button type="button" className="control" onClick={() => setStage('typing')}>
            <span className="control__glyph">⌨</span>
            Type the code instead
          </button>
        </div>
      </>
    )
  }

  return (
    <div className="form">
      <h1 className="sheet__title">Sign this scanner in</h1>
      <p className="sheet__note">
        Ask the organizer for a gate code. Each one works once and expires after ten minutes.
      </p>

      {error ? <div className="error">{error}</div> : null}

      <div className="field">
        <label htmlFor="name">This phone&rsquo;s name</label>
        <input
          id="name"
          value={deviceName}
          onChange={(event) => setDeviceName(event.target.value)}
          placeholder="North 1"
          autoComplete="off"
        />
      </div>

      <div className="field">
        <label htmlFor="box">Box address</label>
        <input
          id="box"
          value={boxUrl}
          onChange={(event) => setBoxUrl(event.target.value)}
          placeholder="https://10.11.0.1:8443"
          inputMode="url"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
        />
      </div>

      <div className="field">
        <label htmlFor="code">Gate code</label>
        <input
          id="code"
          value={code}
          onChange={(event) => setCode(event.target.value.trim())}
          placeholder="ClZLQb9xFaFPYQ"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
        />
      </div>

      <button
        type="button"
        className="button"
        disabled={stage === 'working' || !boxUrl || !code || !deviceName.trim()}
        onClick={() => void redeem(normaliseUrl(boxUrl), code, deviceName)}
      >
        {stage === 'working' ? 'Signing in…' : 'Sign in'}
      </button>

      <button type="button" className="button button--quiet" onClick={() => setStage('scan')}>
        Use the camera instead
      </button>
    </div>
  )
}

/** The enrollment QR's payload. */
interface Invite {
  url: string
  code: string
  ca?: string
}

/**
 * Parses an enrollment QR.
 *
 * The `GCE1.` prefix matches the ticket formats, so a scanner can tell from three
 * characters whether it is looking at an enrollment code or somebody's ticket — which
 * matters because staff will absolutely point this screen at a ticket.
 */
function parseInvite(raw: string): Invite | null {
  if (!raw.startsWith('GCE1.')) return null
  try {
    const body = raw.slice('GCE1.'.length)
    const padded = body + '='.repeat((4 - (body.length % 4)) % 4)
    const json = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
    const parsed = JSON.parse(json) as { url?: string; code?: string; ca?: string }
    if (!parsed.url || !parsed.code) return null
    return { url: parsed.url, code: parsed.code, ...(parsed.ca ? { ca: parsed.ca } : {}) }
  } catch {
    return null
  }
}

/**
 * A default name for this phone.
 *
 * Guessed from the platform rather than left blank, because a roster full of blank
 * names is a roster nobody can use to find the phone that has stopped scanning.
 */
function suggestName(): string {
  const platform = navigator.userAgent
  if (/iPhone/i.test(platform)) return 'iPhone'
  if (/iPad/i.test(platform)) return 'iPad'
  if (/Pixel/i.test(platform)) return 'Pixel'
  if (/Android/i.test(platform)) return 'Android'
  return 'Scanner'
}

/** Fills in the scheme somebody left off. */
function normaliseUrl(input: string): string {
  const trimmed = input.trim().replace(/\/+$/, '')
  if (/^https?:\/\//i.test(trimmed)) return trimmed
  // https by default: the camera needs a secure context, so a plain-http box cannot
  // run the scanner anyway.
  return `https://${trimmed}`
}

/**
 * Turns a failure into something a person at a gate can act on.
 *
 * The certificate case is the one worth spelling out: a self-signed box that has not
 * had its CA installed fails with an opaque network error, and "check your internet"
 * is exactly the wrong advice.
 */
function describe(caught: unknown, url: string): string {
  if (caught instanceof ApiError) {
    if (caught.status === 0) {
      return `Could not reach ${url}. If this is the first time this phone has used this box, open ${url}/ca.crt and install the certificate, then try again.`
    }
    if (caught.code === 'bad_code') {
      return 'That code is not valid any more. Ask the organizer for a new one.'
    }
    return caught.message
  }
  return caught instanceof Error ? caught.message : String(caught)
}
