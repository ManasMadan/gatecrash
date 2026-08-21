import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import type { ScanResult } from '@gatecrash/protocol'

import { VerdictScreen, formatSeat } from '@/verdict'

/**
 * These render the real component to markup rather than poking at helpers.
 *
 * The verdict screen's whole job is to be readable across a queue at arm's length,
 * and every regression that has mattered here was a rendering one: the word missing,
 * the colour class wrong, the seat label not making it through. Static markup is
 * enough to catch all three and needs no DOM.
 */

function result(over: Partial<ScanResult> = {}): ScanResult {
  return {
    verdict: 'ADMIT',
    severity: 'admit',
    reason: 'Let them in.',
    scan_id: 'SCAN1',
    checkpoint: 'gate-north',
    checkpoint_name: 'North Gate',
    device: 'dev-1',
    hlc: '1',
    ...over,
  }
}

const render = (node: Parameters<typeof renderToStaticMarkup>[0]) => renderToStaticMarkup(node)

describe('VerdictScreen', () => {
  it('floods the screen with the severity, not just the verdict text', () => {
    const html = render(<VerdictScreen result={result()} onDismiss={() => {}} />)
    // The severity drives the colour flood. A screen that carried only the verdict
    // word would be unreadable in a crowd, which is the reason this component exists.
    expect(html).toContain('data-severity="admit"')
  })

  it('shows the tier and the seat, which is what an usher acts on', () => {
    const html = render(
      <VerdictScreen
        result={result({
          tier_name: 'VIP',
          tier_colour: '#A855F7',
          seat_label: 'block-a row A seat 7',
        })}
        onDismiss={() => {}}
      />,
    )
    expect(html).toContain('VIP')
    expect(html).toContain('#A855F7')
    expect(html).toContain('A · A7')
  })

  it('names the gate, so a scanner assigned to the wrong door is obvious', () => {
    const html = render(
      <VerdictScreen result={result()} onDismiss={() => {}} gateName="Portal A" />,
    )
    expect(html).toContain('Portal A')
  })

  it('carries a refusal reason and its evidence', () => {
    const html = render(
      <VerdictScreen
        result={result({
          verdict: 'ALREADY_USED',
          severity: 'deny',
          reason: 'This ticket came through North Gate 4 minutes ago.',
        })}
        onDismiss={() => {}}
      />,
    )
    expect(html).toContain('data-severity="deny"')
    expect(html).toContain('4 minutes ago')
  })

  it('says a counted pass was the last one rather than leaving it to the bar', () => {
    const html = render(<VerdictScreen result={result({ passes_left: 0 })} onDismiss={() => {}} />)
    expect(html).toContain('That was the last one')
  })

  it('marks a verdict the scanner decided by itself', () => {
    const html = render(<VerdictScreen result={result()} onDismiss={() => {}} offline />)
    expect(html.toLowerCase()).toMatch(/offline|on this phone|not confirmed/)
  })
})

describe('formatSeat', () => {
  it('shortens a seat label to what somebody shouts across a concourse', () => {
    expect(formatSeat('block-a row A seat 12')).toBe('A · A12')
  })

  it('leaves an unrecognised label alone rather than mangling it', () => {
    expect(formatSeat('standing')).toBe('STANDING')
  })
})
