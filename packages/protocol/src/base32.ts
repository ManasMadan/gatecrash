/**
 * RFC 4648 base32 without padding, which is how every identifier in Gatecrash
 * appears inside a QR payload.
 *
 * Base32's alphabet (A-Z, 2-7) is a subset of the QR alphanumeric character set,
 * so an encoder can use alphanumeric mode instead of byte mode: the same payload
 * fits in a smaller, lower-density symbol that cheap phone cameras decode more
 * reliably in bad light. That is the entire reason this is not base64.
 *
 * Hand-written rather than a dependency because it is thirty lines, it runs on
 * every camera frame, and a QR decoder that pauses to load a polyfill is a QR
 * decoder that misses the frame.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/** Reverse lookup, built once. */
const VALUES = (() => {
  const table = new Int8Array(128).fill(-1)
  for (let i = 0; i < ALPHABET.length; i++) table[ALPHABET.charCodeAt(i)] = i
  // Lowercase is accepted on decode because a human retyping a code will not
  // hold shift, and the encoder only ever emits uppercase.
  for (let i = 0; i < ALPHABET.length; i++) table[ALPHABET.toLowerCase().charCodeAt(i)] = i
  return table
})()

/** Encodes bytes as unpadded uppercase base32. */
export function encodeBase32(bytes: Uint8Array): string {
  let out = ''
  let buffer = 0
  let bits = 0

  for (const byte of bytes) {
    buffer = (buffer << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += ALPHABET[(buffer >>> bits) & 31]
    }
  }
  // Trailing bits are left-aligned into a final character, which is what
  // unpadded base32 means.
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31]
  return out
}

/**
 * Decodes unpadded base32, returning null on anything malformed.
 *
 * Null rather than throwing: this runs on decoded camera output, where malformed
 * input is the normal case rather than an exception. A throw per frame on a
 * partially-decoded QR is a measurable cost on a slow phone.
 */
export function decodeBase32(text: string): Uint8Array | null {
  if (text.length === 0) return null

  const bytes: number[] = []
  let buffer = 0
  let bits = 0

  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i)
    const value = code < 128 ? VALUES[code] : -1
    if (value === undefined || value < 0) return null

    buffer = (buffer << 5) | value
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push((buffer >>> bits) & 0xff)
    }
  }
  // Leftover bits must be zero padding. Anything else is a corrupted decode
  // dressed up as a valid one, which is exactly what a scratched QR produces.
  if (bits >= 5 || (buffer & ((1 << bits) - 1)) !== 0) return null
  return new Uint8Array(bytes)
}

/** Encodes bytes as lowercase hex, which is how identifiers appear on the API. */
export function encodeHex(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0')
  return out
}

/** Decodes lowercase or uppercase hex, returning null on anything malformed. */
export function decodeHex(text: string): Uint8Array | null {
  if (text.length % 2 !== 0) return null
  const bytes = new Uint8Array(text.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    const byte = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16)
    if (Number.isNaN(byte)) return null
    bytes[i] = byte
  }
  return bytes
}

/** Decodes standard base64, returning null on anything malformed. */
export function decodeBase64(text: string): Uint8Array | null {
  try {
    const binary = atob(text)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    return bytes
  } catch {
    return null
  }
}
