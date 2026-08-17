/**
 * Reader for the Bloom filter the box hands a scanner at doors.
 *
 * This is what makes a gate fast and a garbage-QR flood boring. The scanner
 * downloads one filter over every valid ticket id; from then on a random QR code
 * off the internet, a supermarket barcode or a script firing junk payloads is
 * rejected on the device in microseconds with zero network traffic.
 *
 * What a false positive costs is worth being precise about, because it is the only
 * reason this is safe: a false positive means the scanner believes an id *might*
 * be valid, so it asks the box, which knows for certain. A Bloom filter has no
 * false negatives, so it can only ever be over-cautious — never wrong in the
 * direction that admits somebody.
 *
 * The wire format is fixed-width little-endian precisely so this can parse it with
 * a DataView in four reads and no dependencies.
 */

const MAGIC = 0x46424347 // "GCBF" little-endian
const VERSION = 1
const HEADER_BYTES = 30

/** FNV-1a 64 constants, held as 32-bit halves because JavaScript has no u64. */
const FNV_PRIME_LOW = 0x01b3
const FNV_PRIME_HIGH = 0x0100

export interface FilterStats {
  readonly bits: number
  readonly hashes: number
  /** How many ids the box put in. */
  readonly elements: number
  readonly bytes: number
}

/**
 * A parsed Bloom filter.
 *
 * Immutable: the scanner receives one and only ever tests against it. Additions
 * happen on the box, where the ticket list lives.
 */
export class BloomFilter {
  private constructor(
    private readonly words: Uint32Array,
    private readonly bits: number,
    private readonly hashes: number,
    private readonly elements: number,
    private readonly seedLow: number,
    private readonly seedHigh: number,
    private readonly byteLength: number,
  ) {}

  /**
   * Parses a filter, returning null on anything malformed.
   *
   * Null rather than throwing, and every length checked against the buffer: this
   * parses a payload from the network, and a scanner that crashes on a truncated
   * download is a gate that has stopped working.
   */
  static parse(raw: Uint8Array): BloomFilter | null {
    if (raw.length < HEADER_BYTES) return null

    const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength)
    if (view.getUint32(0, true) !== MAGIC) return null
    if (view.getUint8(4) !== VERSION) return null

    const hashes = view.getUint8(5)
    const seedLow = view.getUint32(6, true)
    const seedHigh = view.getUint32(10, true)
    const bitsLow = view.getUint32(14, true)
    const bitsHigh = view.getUint32(18, true)
    const elementsLow = view.getUint32(22, true)

    // A filter with no hash functions matches everything, which would turn every
    // scan into a round trip.
    if (hashes === 0) return null
    // Bit counts beyond 2^32 are not something the box produces and would need
    // BigInt arithmetic on the hot path to handle.
    if (bitsHigh !== 0 || bitsLow === 0) return null

    const bits = bitsLow
    const words64 = Math.ceil(bits / 64)
    // Guard the declared size against the actual body before touching it: a
    // corrupt or hostile header must not be able to read past the buffer.
    if (raw.length - HEADER_BYTES !== words64 * 8) return null

    const words = new Uint32Array(words64 * 2)
    for (let i = 0; i < words.length; i++) {
      words[i] = view.getUint32(HEADER_BYTES + i * 4, true)
    }
    return new BloomFilter(words, bits, hashes, elementsLow, seedLow, seedHigh, raw.length)
  }

  /**
   * Reports whether an id might be present.
   *
   * False is definitive: this id was never added, and the scanner can refuse it
   * with no network at all. True means "ask the box".
   */
  test(id: Uint8Array): boolean {
    const [firstLow, firstHigh, secondLow, secondHigh] = this.hash(id)

    for (let i = 0; i < this.hashes; i++) {
      // Kirsch-Mitzenmacher double hashing: g_i(x) = h1(x) + i·h2(x), taken
      // modulo the bit count. Done in 32-bit halves because the box's indices are
      // 64-bit and JavaScript numbers lose precision past 2^53 — and a filter
      // lookup that is off by one bit is a filter lookup that is wrong.
      const index = mod64(addMul64(firstLow, firstHigh, secondLow, secondHigh, i), this.bits)
      const word = index >>> 5
      if ((this.words[word]! & (1 << (index & 31))) === 0) return false
    }
    return true
  }

  /** Reports whether a base32 identifier might be present. */
  testBase32(id: string): boolean {
    const bytes = decodeIdentifier(id)
    return bytes ? this.test(bytes) : false
  }

  stats(): FilterStats {
    return {
      bits: this.bits,
      hashes: this.hashes,
      elements: this.elements,
      bytes: this.byteLength,
    }
  }

  /**
   * FNV-1a over the key, then two splitmix finalizers, matching the box exactly.
   *
   * FNV-1a rather than a better hash because the box needs the filter to be
   * byte-identical across processes — a scanner detects a stale filter by
   * comparing bytes — and the standard library hash on the Go side seeds itself
   * randomly. The poor avalanche is what the finalizers are for.
   */
  private hash(key: Uint8Array): [number, number, number, number] {
    // FNV offset basis 14695981039346656037, in halves.
    let low = 0x84222325 ^ this.seedLow
    let high = 0xcbf29ce4 ^ this.seedHigh

    for (const byte of key) {
      low = (low ^ byte) >>> 0
      // 64-bit multiply by the FNV prime, in 32-bit pieces.
      const lowLow = Math.imul(low, FNV_PRIME_LOW) >>> 0
      const carry = Math.floor((low * FNV_PRIME_LOW) / 0x100000000)
      const highPart =
        (Math.imul(high, FNV_PRIME_LOW) + Math.imul(low, FNV_PRIME_HIGH) + carry) >>> 0
      low = lowLow
      high = highPart
    }

    const [firstLow, firstHigh] = mix64(low, high)
    // The second value comes from the first mixed with the seed again, which is
    // how the box derives it without walking the key twice.
    const [secondLowRaw, secondHigh] = mix64(
      (firstLow ^ this.seedLow) >>> 0,
      (firstHigh ^ this.seedHigh) >>> 0,
    )
    // h2 must be odd, or the probe sequence can only ever reach half the bits.
    return [firstLow, firstHigh, (secondLowRaw | 1) >>> 0, secondHigh]
  }
}

/** Decodes a base32 or hex identifier into bytes. */
function decodeIdentifier(id: string): Uint8Array | null {
  if (id.length === 32) {
    const bytes = new Uint8Array(16)
    for (let i = 0; i < 16; i++) {
      const byte = Number.parseInt(id.slice(i * 2, i * 2 + 2), 16)
      if (Number.isNaN(byte)) return null
      bytes[i] = byte
    }
    return bytes
  }
  // Deferred to the base32 module for the 26-character form.
  return decodeBase32Local(id)
}

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function decodeBase32Local(text: string): Uint8Array | null {
  const bytes: number[] = []
  let buffer = 0
  let bits = 0
  for (const character of text.toUpperCase()) {
    const value = ALPHABET.indexOf(character)
    if (value < 0) return null
    buffer = (buffer << 5) | value
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push((buffer >>> bits) & 0xff)
    }
  }
  return new Uint8Array(bytes)
}

/** splitmix64's finalizer, in 32-bit halves. */
function mix64(low: number, high: number): [number, number] {
  ;[low, high] = xorShiftRight(low, high, 30)
  ;[low, high] = multiply64(low, high, 0x1ce4e5b9, 0xbf58476d)
  ;[low, high] = xorShiftRight(low, high, 27)
  ;[low, high] = multiply64(low, high, 0x133111eb, 0x94d049bb)
  ;[low, high] = xorShiftRight(low, high, 31)
  return [low >>> 0, high >>> 0]
}

function xorShiftRight(low: number, high: number, shift: number): [number, number] {
  if (shift < 32) {
    const shiftedLow = ((low >>> shift) | (high << (32 - shift))) >>> 0
    const shiftedHigh = high >>> shift
    return [(low ^ shiftedLow) >>> 0, (high ^ shiftedHigh) >>> 0]
  }
  const shiftedLow = high >>> (shift - 32)
  return [(low ^ shiftedLow) >>> 0, high]
}

function multiply64(
  low: number,
  high: number,
  factorLow: number,
  factorHigh: number,
): [number, number] {
  // Schoolbook 64x64 in 16-bit limbs. Verbose, and the only way to get an exact
  // 64-bit product in JavaScript without BigInt, which is far slower on the
  // phones this runs on.
  const a0 = low & 0xffff
  const a1 = low >>> 16
  const a2 = high & 0xffff
  const a3 = high >>> 16
  const b0 = factorLow & 0xffff
  const b1 = factorLow >>> 16
  const b2 = factorHigh & 0xffff
  const b3 = factorHigh >>> 16

  let c0 = a0 * b0
  let c1 = (c0 >>> 16) + a0 * b1 + a1 * b0
  let c2 = (c1 >>> 16) + a0 * b2 + a1 * b1 + a2 * b0
  const c3 = (c2 >>> 16) + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0

  c0 &= 0xffff
  c1 &= 0xffff
  c2 &= 0xffff
  return [((c1 << 16) | c0) >>> 0, (((c3 & 0xffff) << 16) | c2) >>> 0]
}

/** Computes (first + second·i) as a 64-bit value in halves. */
function addMul64(
  firstLow: number,
  firstHigh: number,
  secondLow: number,
  secondHigh: number,
  times: number,
): [number, number] {
  let low = firstLow
  let high = firstHigh
  for (let i = 0; i < times; i++) {
    const sum = low + secondLow
    low = sum >>> 0
    high = (high + secondHigh + (sum >= 0x100000000 ? 1 : 0)) >>> 0
  }
  return [low, high]
}

/**
 * Computes a 64-bit value modulo a 32-bit divisor.
 *
 * Long division in 32-bit halves. The box computes `index % m` on a real uint64,
 * and getting this wrong by one bit means a filter lookup that disagrees with the
 * box — which presents as a scanner rejecting real tickets.
 */
function mod64([low, high]: [number, number], divisor: number): number {
  if (high === 0) return low % divisor
  const remainderHigh = high % divisor
  // Fold the high half in 16 bits at a time, so no intermediate exceeds 2^53.
  let remainder = remainderHigh
  for (let shift = 16; shift >= 0; shift -= 16) {
    remainder = (remainder * 0x10000 + ((low >>> shift) & 0xffff)) % divisor
  }
  return remainder
}
