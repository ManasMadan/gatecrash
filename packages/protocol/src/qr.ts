import { decodeBase32, encodeBase32 } from '@/base32'

/**
 * The two QR ticket formats, decoded on the scanner and generated on the phone.
 *
 * There are exactly two and they exist for different threat models:
 *
 * - `GC1` is static, printed or emailed. Ed25519-signed and verifiable offline by
 *   anyone with the event public key. A screenshot of one is valid until first
 *   use, exactly like every printed ticket ever issued; single use is enforced by
 *   the box, not by the QR.
 * - `GC2` is rotating, generated inside the attendee app. TOTP-style 30-second
 *   windows over an HMAC of a per-ticket secret, so a screenshot dies in at most
 *   60 seconds. Generated fully offline by the phone.
 *
 * The parsing here is deliberately format-sniffing-first and crypto-never: the
 * scanner parses on every camera frame and only sends a payload to the box once
 * its Bloom filter says the id might be real. No verification happens on the
 * device, because the device does not hold the keys — which is the point.
 */

/** Length of a ticket or event identifier in bytes. */
export const ID_BYTES = 16

/** Length of an identifier in its base32 wire form. */
export const ID_CHARS = 26

/** Rotation period of a GC2 code, in seconds. */
export const WINDOW_SECONDS = 30

/** Exact character length of a GC1 payload. Checked before anything is parsed. */
export const GC1_LENGTH = 134

/** A parsed static ticket payload. */
export interface StaticPayload {
  readonly format: 'gc1'
  /** The ticket id in base32, which is how it appears on the API. */
  readonly ticketId: string
  readonly signature: Uint8Array
}

/** A parsed rotating ticket payload. */
export interface RotatingPayload {
  readonly format: 'gc2'
  readonly ticketId: string
  /** The rotation window the code was generated for. */
  readonly window: number
  readonly mac: Uint8Array
}

/** Anything the scanner might read that is not a Gatecrash ticket. */
export interface UnknownPayload {
  readonly format: 'unknown'
  /** Why it was rejected, for the scanner's diagnostics panel. */
  readonly reason: string
}

export type Payload = StaticPayload | RotatingPayload | UnknownPayload

/**
 * Parses a scanned string.
 *
 * Runs on every decoded camera frame, so the ordering matters: a prefix
 * comparison rejects a supermarket barcode before any allocation happens.
 */
/**
 * Mints an idempotency key for a scan.
 *
 * The box wants the same 26-character base32 form as a ticket id, not a UUID — and a UUID is
 * exactly what somebody reaches for, which is why this exists. Reaching for `crypto.randomUUID()`
 * gets a 400 from the parser, and the API comment that suggested it has been corrected.
 *
 * Mint one per *presentation*, not per request, and reuse it on every retry. That is the whole
 * idempotency contract: the same id returns the verdict the box already gave, while a fresh one
 * asks a new question — and the answer to that question is `ALREADY_USED`.
 */
export function newScanId(): string {
  const bytes = new Uint8Array(ID_BYTES)
  crypto.getRandomValues(bytes)
  return encodeBase32(bytes)
}

export function parsePayload(raw: string): Payload {
  const text = raw.trim()

  if (text.startsWith('GC1.')) return parseStatic(text)
  if (text.startsWith('GC2.')) return parseRotating(text)
  return { format: 'unknown', reason: 'not a Gatecrash ticket' }
}

function parseStatic(text: string): Payload {
  if (text.length !== GC1_LENGTH) {
    return {
      format: 'unknown',
      reason: `a printed ticket is ${GC1_LENGTH} characters, this is ${text.length}`,
    }
  }
  const parts = text.split('.')
  if (parts.length !== 3) return { format: 'unknown', reason: 'malformed printed ticket' }

  const [, id, signature] = parts as [string, string, string]
  if (id.length !== ID_CHARS) return { format: 'unknown', reason: 'malformed ticket id' }

  const decodedId = decodeBase32(id)
  const decodedSignature = decodeBase32(signature)
  if (!decodedId || decodedId.length !== ID_BYTES)
    return { format: 'unknown', reason: 'malformed ticket id' }
  if (!decodedSignature || decodedSignature.length !== 64) {
    return { format: 'unknown', reason: 'malformed signature' }
  }
  // The id is carried in its base32 form rather than as bytes because that is
  // what the API takes and what the Bloom filter is keyed on; converting back and
  // forth per frame would be waste.
  return { format: 'gc1', ticketId: id.toUpperCase(), signature: decodedSignature }
}

function parseRotating(text: string): Payload {
  const parts = text.split('.')
  if (parts.length !== 4) return { format: 'unknown', reason: 'malformed in-app code' }

  const [, id, windowText, mac] = parts as [string, string, string, string]
  if (id.length !== ID_CHARS) return { format: 'unknown', reason: 'malformed ticket id' }

  const decodedId = decodeBase32(id)
  if (!decodedId || decodedId.length !== ID_BYTES)
    return { format: 'unknown', reason: 'malformed ticket id' }

  const window = Number.parseInt(windowText, 36)
  if (!Number.isSafeInteger(window) || window < 0) {
    return { format: 'unknown', reason: 'malformed code window' }
  }
  const decodedMac = decodeBase32(mac)
  if (!decodedMac || decodedMac.length !== 10)
    return { format: 'unknown', reason: 'malformed code' }

  return { format: 'gc2', ticketId: id.toUpperCase(), window, mac: decodedMac }
}

/** The rotation window containing an instant. */
export function windowAt(atMillis: number): number {
  return Math.floor(atMillis / 1000 / WINDOW_SECONDS)
}

/** Milliseconds until the current window rolls over, for the app's countdown. */
export function millisUntilNextWindow(atMillis: number): number {
  const period = WINDOW_SECONDS * 1000
  return period - (atMillis % period)
}

/**
 * Generates a rotating payload from a claimed ticket secret.
 *
 * This runs on the attendee's phone with no network of any kind: the phone holds
 * its own secret and a clock, and that is the entire input. WebCrypto's HMAC is
 * used rather than a bundled implementation because it is available everywhere the
 * app runs and it is a great deal faster than JavaScript.
 *
 * The domain string and the field order are frozen; they have to match the box's
 * `internal/ticket` byte for byte or nothing verifies.
 */
export async function generateRotating(
  secret: Uint8Array,
  eventIdHex: string,
  ticketIdBase32: string,
  window: number,
): Promise<string> {
  const eventId = hexToBytes(eventIdHex)
  const ticketId = decodeBase32(ticketIdBase32)
  if (!eventId || eventId.length !== ID_BYTES) throw new Error('protocol: bad event id')
  if (!ticketId || ticketId.length !== ID_BYTES) throw new Error('protocol: bad ticket id')

  const domain = new TextEncoder().encode('gatecrash/gc2/v1')
  const message = new Uint8Array(1 + domain.length + ID_BYTES * 2 + 8)
  let at = 0
  message[at++] = domain.length
  message.set(domain, at)
  at += domain.length
  message.set(eventId, at)
  at += ID_BYTES
  message.set(ticketId, at)
  at += ID_BYTES
  // A big-endian 64-bit window. Written by hand rather than with a DataView on a
  // BigInt because the window fits in 53 bits for the next twenty million years
  // and BigInt arithmetic is slow on the phones this has to run on.
  const high = Math.floor(window / 0x100000000)
  const low = window >>> 0
  message[at++] = (high >>> 24) & 0xff
  message[at++] = (high >>> 16) & 0xff
  message[at++] = (high >>> 8) & 0xff
  message[at++] = high & 0xff
  message[at++] = (low >>> 24) & 0xff
  message[at++] = (low >>> 16) & 0xff
  message[at++] = (low >>> 8) & 0xff
  message[at++] = low & 0xff

  const key = await crypto.subtle.importKey(
    'raw',
    secret as unknown as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const full = new Uint8Array(await crypto.subtle.sign('HMAC', key, message))

  // Truncated to 10 bytes, matching the box. Eighty bits against a gate that
  // rate-limits per device is far more than the threat needs, and the short
  // payload is what keeps the symbol inside QR version 3 — which is what makes it
  // readable off a cracked screen at low brightness.
  return `GC2.${ticketIdBase32.toUpperCase()}.${window.toString(36).toUpperCase()}.${encodeBase32(full.subarray(0, 10))}`
}

function hexToBytes(text: string): Uint8Array | null {
  if (text.length % 2 !== 0) return null
  const bytes = new Uint8Array(text.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    const byte = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16)
    if (Number.isNaN(byte)) return null
    bytes[i] = byte
  }
  return bytes
}
