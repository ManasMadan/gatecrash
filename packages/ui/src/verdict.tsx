import { useEffect, useRef } from 'react'
import type { ScanResult, Severity } from '@gatecrash/protocol'
import { severityOf, verdictCopy } from '@gatecrash/protocol'

import { playVerdict, type FeedbackOptions } from '@/feedback'

/**
 * The gate's verdict screen.
 *
 * A full-viewport colour flood with one enormous glyph and one enormous word,
 * because it is read at arm's length by somebody watching a queue rather than the
 * phone. Everything else on the screen — the tier band, the seat, the evidence, the
 * redirect — is there for a specific person: the guard matching a wristband, the
 * usher pointing at a seat, the supervisor settling an argument.
 *
 * The screen is one of three channels and the least reliable of them. The sound and
 * the buzz fire from here too, and they are what actually gets used.
 */

export interface VerdictScreenProps {
  result: ScanResult

  /**
   * Called when the screen clears, either on its own or when tapped.
   *
   * Clearing matters: a verdict left up is a verdict the next person's scan gets
   * confused with, and at a busy gate that is a real error.
   */
  onDismiss: () => void

  /**
   * How long to hold the screen, in milliseconds.
   *
   * Admits clear fast because the queue is moving; refusals hold longer because
   * somebody is about to be told why. Zero holds until tapped, which is what the
   * gun-mode screen uses.
   */
  holdMillis?: number

  /** True when this verdict was decided by the scanner from its own mirror. */
  offline?: boolean

  feedback?: FeedbackOptions

  /** The gate's own name, shown small so a mis-assigned scanner is obvious. */
  gateName?: string
}

/** Defaults chosen against how long somebody actually looks. */
const HOLD_ADMIT = 1_400
const HOLD_REFUSAL = 4_000

export function VerdictScreen({
  result,
  onDismiss,
  holdMillis,
  offline,
  feedback,
  gateName,
}: VerdictScreenProps) {
  const severity: Severity = result.severity ?? severityOf(result.verdict)
  const copy = verdictCopy(result.verdict)

  // The box sends a reason written for staff; prefer it over the local table so
  // every gate says the same thing and a reworded message ships without a scanner
  // rebuild.
  const detail = result.reason || copy.detail

  const hold = holdMillis ?? (severity === 'admit' ? HOLD_ADMIT : HOLD_REFUSAL)

  // Fired once per verdict, keyed on the scan id: a re-render must not re-buzz, and
  // two scans that happen to share a verdict must both buzz.
  const announced = useRef<string>('')
  useEffect(() => {
    if (announced.current === result.scan_id) return
    announced.current = result.scan_id
    playVerdict(severity, feedback)
  }, [result.scan_id, severity, feedback])

  useEffect(() => {
    if (hold <= 0) return
    const timer = setTimeout(onDismiss, hold)
    return () => clearTimeout(timer)
  }, [hold, onDismiss, result.scan_id])

  const style = result.tier_colour
    ? ({ '--gc-tier-colour': result.tier_colour } as React.CSSProperties)
    : undefined

  return (
    <div
      className="gc-verdict"
      data-severity={severity}
      data-verdict={result.verdict}
      style={style}
      // Announced to a screen reader as one utterance. Gate staff do use
      // VoiceOver, and a screen that reads out nine separate labels is useless.
      role="alert"
      aria-live="assertive"
      aria-label={`${copy.headline}. ${detail}${result.seat_label ? `. ${result.seat_label}` : ''}`}
    >
      <button
        type="button"
        className="gc-verdict__dismiss"
        onClick={onDismiss}
        aria-label="Clear"
      />

      <header>
        {result.tier_colour ? <div className="gc-verdict__tier-band" aria-hidden="true" /> : null}
        <div className="gc-verdict__top">
          <span>{gateName ?? result.checkpoint_name ?? result.checkpoint}</span>
          <span>
            {offline ? <span className="gc-verdict__offline">OFFLINE</span> : null}
            {result.idempotent ? ' · RETRY' : ''}
          </span>
        </div>
      </header>

      <div className="gc-verdict__body">
        <div className="gc-verdict__glyph" aria-hidden="true">
          {copy.glyph}
        </div>
        <div className="gc-verdict__headline">{copy.headline}</div>
        <div className="gc-verdict__detail">{detail}</div>

        {/* On an admit, the tier and the seat are what somebody acts on. */}
        {severity === 'admit' && (result.tier_name || result.seat_label) ? (
          <div className="gc-verdict__seat">
            {result.tier_name ? <span className="gc-verdict__tier">{result.tier_name}</span> : null}
            {result.seat_label ? <span>{formatSeat(result.seat_label)}</span> : null}
          </div>
        ) : null}

        {/* Counted checkpoints: the guard says "one left" rather than the attendee
            finding out at the bar. */}
        {typeof result.passes_left === 'number' ? (
          <div className="gc-verdict__evidence">
            {result.passes_left === 0 ? 'That was the last one' : `${result.passes_left} left`}
          </div>
        ) : null}

        {/* Evidence for a refusal: which gate, how long ago. This is what settles an
            argument, and without it a denial is just an assertion. */}
        {result.previous ? (
          <div className="gc-verdict__evidence">
            In at {result.previous.checkpoint_name ?? result.previous.checkpoint}
            {result.ago ? `, ${result.ago}` : ''}
          </div>
        ) : null}

        {/* Where to send them: the entire reason the amber screen exists. */}
        {result.redirect && result.redirect.length > 0 ? (
          <div className="gc-verdict__redirect">
            <span className="gc-verdict__redirect-label">Send them to</span>
            <span className="gc-verdict__redirect-name">
              {result.redirect.map((entry) => entry.name).join(' or ')}
            </span>
          </div>
        ) : null}

        {result.flagged ? (
          <div className="gc-verdict__flag">Double use — flagged to control</div>
        ) : null}
      </div>

      <footer className="gc-verdict__bottom">
        <span>{result.ticket ? shortId(result.ticket) : ''}</span>
        <span>{result.seq ? `#${result.seq}` : ''}</span>
      </footer>

      {hold > 0 ? (
        <div
          className="gc-verdict__timer"
          style={{ animationDuration: `${hold}ms` }}
          aria-hidden="true"
        />
      ) : null}
    </div>
  )
}

/**
 * Renders a seat label the way an usher says it out loud.
 *
 * "block-a row A seat 12" becomes "A · A12". The compression matters: the long form
 * does not fit at the size this is drawn, and the short form is what somebody
 * actually shouts across a concourse.
 */
export function formatSeat(label: string): string {
  const match = /^(\S+)\s+row\s+(\S+)\s+seat\s+(\S+)$/i.exec(label)
  if (!match) return label.toUpperCase()

  const [, section, row, seat] = match as unknown as [string, string, string, string]
  const block = section.replace(/^block-/i, '').toUpperCase()
  return `${block} · ${row.toUpperCase()}${seat}`
}

/** The last few characters of an id, which is all anybody reads out. */
function shortId(id: string): string {
  return id.length <= 8 ? id : `…${id.slice(-6)}`
}
