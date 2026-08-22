import { describe, expect, it } from 'vitest'

import { severityOf, verdictCopy } from '@/verdict'

describe('gatecrash-client verdict copy', () => {
  // The redirect group is the highest-value UX decision in the product: a
  // misrouted paying customer, a stale in-app code and somebody who arrived early
  // are all situations where nothing is wrong and nobody is in trouble. Showing
  // them the same red screen as a forgery is how gate staff end up arguing with
  // customers.
  it('puts the recoverable verdicts on the amber screen', () => {
    for (const verdict of [
      'WRONG_DOOR',
      'PREREQUISITE_MISSING',
      'DOORS_CLOSED',
      'EXPIRED_WINDOW',
      'WRONG_DIRECTION',
    ]) {
      expect(severityOf(verdict), verdict).toBe('redirect')
    }
  })

  it('puts the real refusals on the red screen', () => {
    for (const verdict of [
      'ALREADY_USED',
      'INVALID_SIG',
      'UNKNOWN_TICKET',
      'REVOKED',
      'WRONG_EVENT',
      'WRONG_ZONE',
      'PASS_LIMIT_REACHED',
      'MALFORMED',
    ]) {
      expect(severityOf(verdict), verdict).toBe('deny')
    }
  })

  it('admits exactly one verdict', () => {
    expect(severityOf('ADMIT')).toBe('admit')
  })

  it('gives every verdict a glyph as well as a colour', () => {
    // About one man in twelve cannot reliably tell the green screen from the red
    // one, and in direct sunlight the colour washes out before the shape does. The
    // glyph is the redundant channel, so no verdict may be without one.
    for (const verdict of [
      'ADMIT',
      'ALREADY_USED',
      'INVALID_SIG',
      'UNKNOWN_TICKET',
      'REVOKED',
      'WRONG_EVENT',
      'EXPIRED_WINDOW',
      'WRONG_ZONE',
      'WRONG_DOOR',
      'PREREQUISITE_MISSING',
      'SCANNER_NOT_AUTHORIZED',
      'PASS_LIMIT_REACHED',
      'WRONG_DIRECTION',
      'DOORS_CLOSED',
      'MALFORMED',
    ]) {
      const copy = verdictCopy(verdict)
      expect(copy.glyph, verdict).toBeTruthy()
      expect(copy.headline, verdict).toBeTruthy()
      expect(copy.detail, verdict).toBeTruthy()
    }
  })

  it('keeps headlines short enough to read at a glance', () => {
    // The headline is drawn at up to 12rem across a phone screen. Anything long
    // shrinks until it is no longer the thing somebody notices first.
    for (const verdict of ['ADMIT', 'ALREADY_USED', 'WRONG_DOOR', 'PREREQUISITE_MISSING']) {
      expect(verdictCopy(verdict).headline.length, verdict).toBeLessThanOrEqual(12)
    }
  })

  it('never leaks a verdict name or jargon into staff-facing copy', () => {
    // Written for somebody who has been on their feet for six hours, not for
    // somebody who has read the protocol docs.
    for (const verdict of [
      'ALREADY_USED',
      'INVALID_SIG',
      'PREREQUISITE_MISSING',
      'PASS_LIMIT_REACHED',
    ]) {
      const copy = verdictCopy(verdict)
      expect(copy.detail).not.toMatch(/_/)
      expect(copy.detail).not.toMatch(/\b(HLC|CAS|idempotenc|bloom|merkle)\b/i)
    }
  })

  it('falls back safely for a verdict this build does not know', () => {
    // A newer box may send a verdict an older scanner has never heard of. Failing
    // closed with a refusal is the only acceptable default.
    const copy = verdictCopy('SOMETHING_NEW')
    expect(copy.glyph).toBeTruthy()
    expect(severityOf('SOMETHING_NEW')).toBe('deny')
  })
})
