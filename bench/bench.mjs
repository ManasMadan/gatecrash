// The load rig.
//
// `go test -bench` gives a mean, and a mean is the wrong statistic for a queue. What matters is
// the p99 of a scan under twelve gates of concurrent load, because the p99 is the guard standing
// at a barrier wondering whether it worked.
//
// So this measures percentiles, and it measures them without coordinated omission: requests are
// issued on a schedule and a slow response delays the *measurement*, not the schedule. A rig that
// waits for each response before sending the next one stops offering load exactly when the system
// slows down, which is the moment you were trying to observe — and it reports beautiful numbers
// for a box that is falling over.
//
//   node bench.mjs --box http://127.0.0.1:8080 --token <device-token> \
//                  --checkpoint gate-north --rate 200 --seconds 30
//
// Point it at a demo box, not an event.

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, arg, i, all) => {
    if (arg.startsWith('--')) pairs.push([arg.slice(2), all[i + 1]])
    return pairs
  }, []),
)

const box = args.box ?? 'http://127.0.0.1:8080'

// One token per simulated gate, round-robined.
//
// The scan endpoint is rate limited **per device**, deliberately: a scanner cannot be made to
// hammer the box faster than a human can present tickets, which is the difference between one
// misconfigured phone and a box that stops answering the other eleven gates.
//
// So a rig driving one token at 150/s measures the rate limiter and nothing else. The first
// version of this did exactly that and reported a perfectly respectable p99 for a run in which
// three quarters of the requests were rejected at the door. Twelve gates is twelve tokens.
const tokens = (args.tokens ?? args.token ?? '').split(',').filter(Boolean)
const checkpoint = args.checkpoint ?? 'gate-north'
const rate = Number(args.rate ?? 100)
const seconds = Number(args.seconds ?? 20)
const concurrency = Number(args.concurrency ?? 12) // twelve gates

if (tokens.length === 0) {
  console.error(
    'usage: node bench.mjs --tokens t1,t2,... [--box URL] [--rate N] [--seconds N]\n' +
      '       one token per gate; the scan endpoint is rate limited per device',
  )
  process.exit(2)
}

/**
 * An HDR-style histogram: log-linear buckets, so a million samples cost a few kilobytes and the
 * tail keeps its resolution.
 *
 * Storing every sample and sorting would be simpler and would also mean the rig's own memory
 * growth becomes part of what it measures.
 */
class Histogram {
  #buckets = new Int32Array(4096)
  #count = 0
  #max = 0

  // Microsecond resolution up to a few seconds, which is well past the point at which a gate has
  // already given up.
  #index(micros) {
    if (micros <= 0) return 0
    const magnitude = Math.floor(Math.log2(micros))
    const within = Math.floor((micros / 2 ** magnitude - 1) * 64)
    return Math.min(this.#buckets.length - 1, magnitude * 64 + within)
  }

  #value(index) {
    const magnitude = Math.floor(index / 64)
    return 2 ** magnitude * (1 + (index % 64) / 64)
  }

  record(micros) {
    this.#buckets[this.#index(micros)]++
    this.#count++
    if (micros > this.#max) this.#max = micros
  }

  get count() {
    return this.#count
  }

  percentile(fraction) {
    if (this.#count === 0) return 0
    const target = Math.ceil(this.#count * fraction)
    let seen = 0
    for (let i = 0; i < this.#buckets.length; i++) {
      seen += this.#buckets[i]
      if (seen >= target) return this.#value(i)
    }
    return this.#max
  }

  get max() {
    return this.#max
  }
}

const latency = new Histogram()
const verdicts = new Map()
let sent = 0
let failed = 0

// Payloads to replay.
//
// Well-formed GC1 with a signature that will not verify, so every one reaches the engine and is
// refused as INVALID_SIG. That is the measurement worth having: a full trip through parse,
// signature check, audit row and hash chain.
//
// The alphabet matters. Ticket ids are RFC 4648 base32 — A–Z and 2–7 — and the first version of
// this used uppercased hex, whose `0` and `1` are not in that alphabet. Every request came back
// 400 from the parser without the engine ever running, and the rig cheerfully reported an
// excellent p99 for work it had not done.
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const base32 = (length) =>
  Array.from({ length }, () => BASE32[Math.floor(Math.random() * BASE32.length)]).join('')

const payloads = Array.from({ length: 512 }, () => `GC1.${base32(26)}.${base32(103)}`)

let limited = 0

async function one(payload, gateToken) {
  const started = process.hrtime.bigint()
  try {
    const response = await fetch(`${box}/v1/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${gateToken}` },
      // A scan id is the same 26-character base32 form as a ticket id, not a UUID.
      body: JSON.stringify({ scan_id: base32(26), payload, checkpoint }),
    })
    const body = await response.json()
    // Recorded whatever the answer was. A refusal is a full trip through the engine and the
    // audit chain, which is what we are timing.
    latency.record(Number(process.hrtime.bigint() - started) / 1000)
    if (response.status === 429) limited++
    const verdict = body.verdict ?? `http ${response.status}`
    verdicts.set(verdict, (verdicts.get(verdict) ?? 0) + 1)
  } catch {
    // The reason does not change what the rig does: a failure is a failure, and it is
    // counted and timed like any other outcome.
    failed++
    latency.record(Number(process.hrtime.bigint() - started) / 1000)
  }
}

console.log(`box        ${box}`)
console.log(`checkpoint ${checkpoint}`)
console.log(`gates      ${tokens.length}`)
console.log(`offering   ${rate}/s for ${seconds}s, ${concurrency} in flight\n`)

const intervalMicros = 1_000_000 / rate
const startedAt = process.hrtime.bigint()
const deadline = startedAt + BigInt(seconds) * 1_000_000_000n

// The open-loop schedule. Requests are launched on the clock; the number in flight is bounded so
// a stalled box cannot exhaust file descriptors, and anything the bound drops is counted rather
// than quietly skipped.
let inFlight = 0
let dropped = 0
let index = 0

await new Promise((resolve) => {
  const tick = setInterval(() => {
    const now = process.hrtime.bigint()
    if (now >= deadline) {
      clearInterval(tick)
      resolve()
      return
    }

    const due = Math.floor(Number(now - startedAt) / 1000 / intervalMicros) - sent
    for (let i = 0; i < due; i++) {
      if (inFlight >= concurrency) {
        dropped++
        sent++
        continue
      }
      sent++
      inFlight++
      // Round-robin the gates, so the per-device limit is not what is being measured.
      void one(payloads[index % payloads.length], tokens[index % tokens.length]).finally(
        () => inFlight--,
      )
      index++
    }
  }, 2)
})

// Let what is in flight land before reporting, or the tail is truncated by the report itself.
const settleUntil = Date.now() + 3_000
while (inFlight > 0 && Date.now() < settleUntil) {
  await new Promise((r) => setTimeout(r, 20))
}

const elapsed = Number(process.hrtime.bigint() - startedAt) / 1e9
const ms = (micros) => `${(micros / 1000).toFixed(2)} ms`

console.log(`offered    ${sent} in ${elapsed.toFixed(1)}s (${Math.round(sent / elapsed)}/s)`)
console.log(`completed  ${latency.count}`)
if (dropped > 0) {
  // Reported rather than hidden: a rig that silently drops what it could not offer is a rig
  // reporting a load it never applied.
  console.log(`not sent   ${dropped} — concurrency bound reached, so the box was the bottleneck`)
}
if (failed > 0) console.log(`errors     ${failed}`)

console.log('\nlatency')
for (const p of [0.5, 0.9, 0.99, 0.999]) {
  console.log(`  p${String(p * 100).padEnd(5)} ${ms(latency.percentile(p))}`)
}
console.log(`  max    ${ms(latency.max)}`)

console.log('\nverdicts')
for (const [verdict, count] of [...verdicts].sort((a, b) => b[1] - a[1])) {
  console.log(`  ${verdict.padEnd(24)} ${count}`)
}

// The rate limiter, called out rather than buried in the verdict table.
//
// A run where most requests were rejected before reaching the engine has measured the limiter,
// and reporting its latency as though it were the box's would be worse than reporting nothing.
if (limited > latency.count * 0.05) {
  const share = ((limited / latency.count) * 100).toFixed(0)
  console.log(
    `\n  ${share}% of these were rate limited, so this run measured the per-device limit\n` +
      `  rather than the engine. Add more gates (--tokens) or lower --rate.`,
  )
}

// The number that matters for a gate. Forty scans a minute per gate across twelve gates is eight
// a second, so anything here with a p99 under a few hundred milliseconds has three orders of
// magnitude of headroom — and saying so is more useful than the raw figure.
const p99 = latency.percentile(0.99) / 1000
console.log(
  `\np99 is ${p99.toFixed(0)}ms. Twelve gates at forty scans a minute is eight a second;` +
    ` this run offered ${Math.round(sent / elapsed)}.`,
)
