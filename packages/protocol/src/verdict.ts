import type { Severity, Verdict } from '@/api'

/**
 * The scanner's presentation table for verdicts.
 *
 * The box already sends a `reason` and a `severity`, and the scanner uses those:
 * one source of truth means every gate says the same thing, and a reworded message
 * ships without a scanner rebuild. This table is the fallback for when the box
 * cannot be reached — a scanner deciding offline from its own mirror still has to
 * put something on the screen.
 *
 * Every string here is written for somebody who has been on their feet for six
 * hours and is reading a phone at arm's length under a floodlight. No jargon, no
 * verdict names, no ticket ids, and it says what to do rather than what happened
 * wherever there is something to do.
 */

export interface VerdictCopy {
  /** The one word in the largest type on the screen. */
  headline: string
  /** The sentence underneath it. */
  detail: string
  /**
   * A single glyph, drawn enormous.
   *
   * A shape as well as a colour, because about one man in twelve cannot reliably
   * tell the green screen from the red one, and because in direct sunlight the
   * colour washes out before the shape does.
   */
  glyph: string
}

const COPY: Record<Verdict, VerdictCopy> = {
  ADMIT: { headline: 'IN', detail: 'Let them through', glyph: '✓' },
  ALREADY_USED: { headline: 'USED', detail: 'Already scanned in', glyph: '✕' },
  INVALID_SIG: { headline: 'FAKE', detail: 'Not a real ticket', glyph: '✕' },
  UNKNOWN_TICKET: { headline: 'NOT LISTED', detail: 'Not on the guest list', glyph: '✕' },
  REVOKED: { headline: 'CANCELLED', detail: 'This ticket was cancelled', glyph: '✕' },
  WRONG_EVENT: { headline: 'WRONG SHOW', detail: 'This is for another event', glyph: '✕' },
  EXPIRED_WINDOW: { headline: 'REFRESH', detail: 'Ask them to reopen their app', glyph: '↻' },
  WRONG_ZONE: { headline: 'NO ACCESS', detail: 'Not allowed in this area', glyph: '✕' },
  WRONG_DOOR: { headline: 'WRONG DOOR', detail: 'Ticket is fine — send them on', glyph: '→' },
  PREREQUISITE_MISSING: {
    headline: 'COME ROUND',
    detail: 'Needs the main entrance first',
    glyph: '→',
  },
  SCANNER_NOT_AUTHORIZED: {
    headline: 'SIGN IN',
    detail: 'This scanner is not signed in here',
    glyph: '!',
  },
  PASS_LIMIT_REACHED: {
    headline: 'NONE LEFT',
    detail: 'No passes left on this ticket',
    glyph: '✕',
  },
  WRONG_DIRECTION: { headline: 'CHECK WAY', detail: 'They are not inside yet', glyph: '↔' },
  DOORS_CLOSED: { headline: 'NOT YET', detail: 'Doors are not open', glyph: '⏱' },
  MALFORMED: { headline: 'NOT A TICKET', detail: 'Try scanning again', glyph: '?' },
}

const FALLBACK: VerdictCopy = { headline: 'NO', detail: 'Do not let them in', glyph: '✕' }

/** Copy for a verdict, with a safe fallback for one this build does not know. */
export function verdictCopy(verdict: string): VerdictCopy {
  return COPY[verdict as Verdict] ?? FALLBACK
}

/**
 * Severity for a verdict, used only when the box did not send one.
 *
 * The `redirect` group is the point: a misrouted paying customer, a phone whose
 * code has gone stale, and somebody who arrived before doors are all situations
 * where nothing is wrong and nobody is in trouble. Showing them the same red screen
 * as a forgery is how gate staff end up arguing with customers.
 */
export function severityOf(verdict: string): Severity {
  if (verdict === 'ADMIT') return 'admit'
  switch (verdict) {
    case 'WRONG_DOOR':
    case 'PREREQUISITE_MISSING':
    case 'DOORS_CLOSED':
    case 'EXPIRED_WINDOW':
    case 'WRONG_DIRECTION':
      return 'redirect'
    default:
      return 'deny'
  }
}
