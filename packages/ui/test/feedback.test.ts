import { describe, expect, it } from 'vitest'

import { cues } from '@/feedback'

/**
 * The sound and the buzz are the channels that actually get used at a gate: the
 * screen is looked at, these are felt. What matters is that a refusal is
 * unmistakable against an admit through a jacket pocket, without looking.
 */
describe('cues', () => {
  it('covers every severity, so no verdict is silent', () => {
    for (const severity of ['admit', 'deny', 'redirect'] as const) {
      expect(cues[severity].notes.length).toBeGreaterThan(0)
      expect(cues[severity].vibrate.length).toBeGreaterThan(0)
    }
  })

  it('makes a refusal unmistakable against an admit without looking', () => {
    const total = (pattern: readonly number[]) => pattern.reduce((sum, ms) => sum + ms, 0)

    // Longer overall and more pulses: felt through a jacket and impossible to read
    // as the single short tap that means "go".
    expect(total(cues.deny.vibrate)).toBeGreaterThan(total(cues.admit.vibrate) * 3)
    expect(cues.deny.vibrate.length).toBeGreaterThan(cues.admit.vibrate.length)

    // And lower. A high two-note rise means go, a low harsh pair means stop; that
    // distinction survives a PA system and a crowd.
    const lowest = (cue: (typeof cues)['deny']) => Math.min(...cue.notes.map((note) => note.hz))
    expect(lowest(cues.deny)).toBeLessThan(lowest(cues.admit))
  })

  it('gives redirect its own pattern, since it is neither go nor stop', () => {
    expect(cues.redirect.vibrate).not.toEqual(cues.admit.vibrate)
    expect(cues.redirect.vibrate).not.toEqual(cues.deny.vibrate)
  })
})
