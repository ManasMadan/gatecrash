import { describe, expect, it } from 'vitest'

import { decodeBase32, encodeBase32, encodeHex, decodeHex } from '@/base32'
import {
  GC1_LENGTH,
  ID_CHARS,
  WINDOW_SECONDS,
  generateRotating,
  millisUntilNextWindow,
  parsePayload,
  windowAt,
} from '@/qr'

describe('@gatecrash/protocol base32', () => {
  it('round trips', () => {
    for (const length of [1, 5, 10, 16, 64]) {
      const bytes = new Uint8Array(length)
      for (let i = 0; i < length; i++) bytes[i] = (i * 37 + 11) & 0xff
      const encoded = encodeBase32(bytes)
      expect(decodeBase32(encoded)).toEqual(bytes)
    }
  })

  it('emits only QR-alphanumeric characters', () => {
    // Base32's alphabet is a subset of the QR alphanumeric set, which lets the
    // encoder use alphanumeric mode instead of byte mode: a smaller, lower-density
    // symbol that cheap cameras decode more reliably. Anything outside it silently
    // costs two QR versions.
    const bytes = new Uint8Array(32)
    for (let i = 0; i < 32; i++) bytes[i] = i * 7
    expect(encodeBase32(bytes)).toMatch(/^[A-Z2-7]+$/)
  })

  it('accepts lowercase on decode but never emits it', () => {
    // A human retyping a code will not hold shift.
    const bytes = new Uint8Array([1, 2, 3, 4])
    const upper = encodeBase32(bytes)
    expect(decodeBase32(upper.toLowerCase())).toEqual(bytes)
    expect(upper).toBe(upper.toUpperCase())
  })

  it('returns null rather than throwing on garbage', () => {
    // This runs on decoded camera output, where malformed input is the normal case.
    for (const bad of ['', '!!!!', '0189', 'ABC$DEF']) {
      expect(decodeBase32(bad)).toBeNull()
    }
  })

  it('refuses non-zero padding bits, which is what a scratched QR produces', () => {
    // A corrupted decode dressed up as a valid one is the dangerous case: it
    // produces a plausible id for a ticket that does not exist.
    expect(decodeBase32('AB')).toBeNull()
  })

  it('round trips hex', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
    expect(encodeHex(bytes)).toBe('deadbeef')
    expect(decodeHex('DEADBEEF')).toEqual(bytes)
    expect(decodeHex('abc')).toBeNull()
    expect(decodeHex('zz')).toBeNull()
  })
})

describe('@gatecrash/protocol qr', () => {
  const ticketId = 'GTNA4OA55FXIBGKBLOVYM36YO4'

  it('parses a printed ticket', () => {
    const signature = encodeBase32(new Uint8Array(64).fill(7))
    const payload = `GC1.${ticketId}.${signature}`
    expect(payload.length).toBe(GC1_LENGTH)

    const parsed = parsePayload(payload)
    expect(parsed.format).toBe('gc1')
    if (parsed.format !== 'gc1') throw new Error('unreachable')
    expect(parsed.ticketId).toBe(ticketId)
    expect(parsed.signature).toHaveLength(64)
  })

  it('parses an in-app code', () => {
    const mac = encodeBase32(new Uint8Array(10).fill(3))
    const parsed = parsePayload(`GC2.${ticketId}.ZGY24.${mac}`)
    expect(parsed.format).toBe('gc2')
    if (parsed.format !== 'gc2') throw new Error('unreachable')
    expect(parsed.ticketId).toBe(ticketId)
    // Base36, which is what keeps the payload inside a version 3 QR symbol.
    expect(parsed.window).toBe(Number.parseInt('ZGY24', 36))
    expect(parsed.mac).toHaveLength(10)
  })

  it('rejects everything that is not a ticket, with a reason', () => {
    // A reason rather than a bare false, because the scanner's diagnostics panel is
    // what somebody looks at when a whole batch of tickets will not scan.
    for (const raw of [
      '',
      'hello',
      'https://example.com',
      '4006381333931',
      `GC1.${ticketId}`,
      `GC1.${ticketId}.tooshort`,
      `GC2.${ticketId}.ZZZ`,
      `GC2.${ticketId}.!!!.${encodeBase32(new Uint8Array(10))}`,
      `GC2.${ticketId}.1.short`,
      `GC1.${'A'.repeat(ID_CHARS)}.${encodeBase32(new Uint8Array(32))}`,
    ]) {
      const parsed = parsePayload(raw)
      expect(parsed.format, raw).toBe('unknown')
      if (parsed.format !== 'unknown') throw new Error('unreachable')
      expect(parsed.reason).toBeTruthy()
    }
  })

  it('tolerates surrounding whitespace, which barcode guns add', () => {
    // A USB barcode gun in keyboard mode types the payload and then a newline.
    const mac = encodeBase32(new Uint8Array(10).fill(3))
    expect(parsePayload(`  GC2.${ticketId}.1.${mac}\n`).format).toBe('gc2')
  })

  it('computes rotation windows', () => {
    expect(windowAt(0)).toBe(0)
    expect(windowAt(WINDOW_SECONDS * 1000)).toBe(1)
    expect(windowAt(WINDOW_SECONDS * 1000 - 1)).toBe(0)

    // The countdown the app draws under the QR.
    expect(millisUntilNextWindow(0)).toBe(WINDOW_SECONDS * 1000)
    expect(millisUntilNextWindow(1_000)).toBe(WINDOW_SECONDS * 1000 - 1_000)
  })

  it('generates a rotating code that fits a version 3 QR symbol', async () => {
    // Version 3 at error correction level L holds 77 alphanumeric characters. This
    // is what makes the code readable off a cracked screen at low brightness, and
    // the README says so.
    const secret = new Uint8Array(32).fill(9)
    const payload = await generateRotating(secret, '0'.repeat(32), ticketId, 59_577_196)

    expect(payload.length).toBeLessThanOrEqual(77)
    expect(payload.startsWith(`GC2.${ticketId}.`)).toBe(true)
    expect(parsePayload(payload).format).toBe('gc2')
    expect(payload).toMatch(/^[A-Z0-9.]+$/)
  })

  it('generates a different code for every window', async () => {
    // The entire anti-screenshot property.
    const secret = new Uint8Array(32).fill(9)
    const first = await generateRotating(secret, '0'.repeat(32), ticketId, 100)
    const second = await generateRotating(secret, '0'.repeat(32), ticketId, 101)
    expect(first).not.toBe(second)
  })

  it('generates a different code for a different secret', async () => {
    const eventId = '0'.repeat(32)
    const first = await generateRotating(new Uint8Array(32).fill(1), eventId, ticketId, 100)
    const second = await generateRotating(new Uint8Array(32).fill(2), eventId, ticketId, 100)
    expect(first).not.toBe(second)
  })

  it('generates a different code for a different event', async () => {
    // Two events that happen to issue the same ticket id must not accept each
    // other's codes, which is why the event id is inside the MAC.
    const secret = new Uint8Array(32).fill(9)
    const first = await generateRotating(secret, '0'.repeat(32), ticketId, 100)
    const second = await generateRotating(secret, 'f'.repeat(32), ticketId, 100)
    expect(first).not.toBe(second)
  })

  it('refuses to generate from malformed inputs', async () => {
    const secret = new Uint8Array(32)
    await expect(generateRotating(secret, 'not-hex', ticketId, 1)).rejects.toThrow()
    await expect(generateRotating(secret, '0'.repeat(32), 'not-base32!', 1)).rejects.toThrow()
  })
})
