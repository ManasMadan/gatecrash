import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import { BloomFilter } from '@/bloom'
import { decodeBase64 } from '@/base32'

interface Fixture {
  filter: string
  present: string[]
  absent: string[]
  bits: number
  hashes: number
  elements: number
}

const fixture: Fixture = JSON.parse(
  readFileSync(fileURLToPath(new URL('./testdata/bloom.json', import.meta.url)), 'utf8'),
) as Fixture

describe('@gatecrash/protocol bloom', () => {
  // This is the most important test in the package. The Bloom filter is the one
  // data structure in Gatecrash implemented twice — once in Go on the box, once
  // here on the scanner. If the two disagree by a single bit, the scanner rejects
  // real tickets offline with no round trip to catch it, which is the worst
  // failure mode the system has because it is silent.
  //
  // The fixture is written by Go. Nothing here is checked against a
  // TypeScript-side reimplementation of the hash; it is checked against the bytes
  // the box actually produces.
  it('agrees with the Go implementation on every id in the filter', () => {
    const raw = decodeBase64(fixture.filter)
    expect(raw).not.toBeNull()

    const filter = BloomFilter.parse(raw!)
    expect(filter).not.toBeNull()

    const stats = filter!.stats()
    expect(stats.bits).toBe(fixture.bits)
    expect(stats.hashes).toBe(fixture.hashes)
    expect(stats.elements).toBe(fixture.elements)

    for (const id of fixture.present) {
      expect(filter!.testBase32(id), `${id} was in the filter Go built`).toBe(true)
    }
  })

  it('rejects ids that were never added, at about the designed rate', () => {
    const filter = BloomFilter.parse(decodeBase64(fixture.filter)!)!

    let falsePositives = 0
    for (const id of fixture.absent) {
      if (filter.testBase32(id)) falsePositives++
    }

    // The fixture is sized for one in ten thousand. A handful of false positives
    // across two thousand probes is the filter working; hundreds would mean the
    // probe sequence is clustering, which is what a broken hash looks like.
    const rate = falsePositives / fixture.absent.length
    expect(rate, `${falsePositives} of ${fixture.absent.length} absent ids matched`).toBeLessThan(
      0.01,
    )
  })

  it('accepts both the base32 and hex forms of an id', () => {
    const filter = BloomFilter.parse(decodeBase64(fixture.filter)!)!
    const first = fixture.present[0]!

    expect(filter.testBase32(first)).toBe(true)
    // The same id in hex, which is how it appears on some API responses.
    const bytes = base32ToBytes(first)
    const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
    expect(filter.testBase32(hex)).toBe(true)
  })

  // Every one of these arrives over the network, and a scanner that crashes on a
  // truncated download is a gate that has stopped working.
  it('refuses malformed filters rather than throwing', () => {
    const valid = decodeBase64(fixture.filter)!

    expect(BloomFilter.parse(new Uint8Array(0))).toBeNull()
    expect(BloomFilter.parse(valid.subarray(0, 10))).toBeNull()
    expect(BloomFilter.parse(valid.subarray(0, valid.length - 8))).toBeNull()

    const badMagic = Uint8Array.from(valid)
    badMagic[0] = 0
    expect(BloomFilter.parse(badMagic)).toBeNull()

    const badVersion = Uint8Array.from(valid)
    badVersion[4] = 99
    expect(BloomFilter.parse(badVersion)).toBeNull()

    // Zero hash functions would match everything, turning every scan into a round
    // trip.
    const zeroHashes = Uint8Array.from(valid)
    zeroHashes[5] = 0
    expect(BloomFilter.parse(zeroHashes)).toBeNull()

    // A header claiming a huge bit count must be refused before anything is
    // allocated, or a hostile manifest can make a phone run out of memory at a
    // gate.
    const absurd = Uint8Array.from(valid)
    new DataView(absurd.buffer, absurd.byteOffset).setUint32(14, 0xffffffff, true)
    expect(BloomFilter.parse(absurd)).toBeNull()
  })

  it('reports its own size so a scanner can show what it downloaded', () => {
    const filter = BloomFilter.parse(decodeBase64(fixture.filter)!)!
    const stats = filter.stats()
    expect(stats.bytes).toBeGreaterThan(0)
    expect(stats.elements).toBe(fixture.present.length)
  })
})

function base32ToBytes(text: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bytes: number[] = []
  let buffer = 0
  let bits = 0
  for (const character of text) {
    buffer = (buffer << 5) | alphabet.indexOf(character)
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push((buffer >>> bits) & 0xff)
    }
  }
  return new Uint8Array(bytes)
}
