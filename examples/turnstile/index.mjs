// A turnstile.
//
// No screen, no app, no UI framework. A barcode gun on a serial port, a relay on a GPIO pin,
// and about sixty lines. This is the smallest thing that is genuinely a gate, and it is the
// example worth reading first because everything else is decoration on top of it.
//
//   node index.mjs --box https://10.11.0.1:8443 --token <device-token> --checkpoint gate-north

import { createInterface } from 'node:readline'
import { Client, newScanId, severityOf } from 'gatecrash-client'

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, arg, i, all) => {
    if (arg.startsWith('--')) pairs.push([arg.slice(2), all[i + 1]])
    return pairs
  }, []),
)

if (!args.box || !args.token || !args.checkpoint) {
  console.error('usage: node index.mjs --box URL --token TOKEN --checkpoint CODE')
  process.exit(2)
}

const client = new Client({
  baseUrl: args.box,
  token: args.token,
  // Two and a half seconds. Longer than this and the person at the barrier has already
  // decided the machine is broken and started talking to the guard.
  timeoutMillis: 2_500,
})

/**
 * Pulse the barrier.
 *
 * On a Pi this is a GPIO write. Here it is a log line, because the interesting part of this
 * example is everything above it.
 */
async function open() {
  console.log('  → barrier open')
}

/** A queue of scans that could not be delivered. */
const pending = []

async function present(payload) {
  // The scan id is generated once per physical presentation and reused on every retry. That
  // is the whole idempotency contract: resend the same id and the box returns the verdict it
  // gave before, rather than counting a network blip as a second use.
  // newScanId rather than a UUID: the box wants the same base32 form as a ticket id, and a
  // UUID gets a 400 from the parser.
  const scan = { scanId: newScanId(), payload, checkpoint: args.checkpoint }

  try {
    const result = await client.scan(scan)
    report(result)
    if (severityOf(result.verdict) === 'admit') await open()
  } catch (error) {
    // The box is unreachable. A turnstile has no operator to ask, so it holds — which is
    // STRICT behaviour, and the right default when nobody is watching. A DEGRADED gate would
    // check its mirror here; see the offline guide.
    console.log(`  ? cannot reach the box (${error.message}) — holding, queued`)
    pending.push(scan)
  }
}

function report(result) {
  const mark = { admit: '✓', deny: '✗', redirect: '→' }[severityOf(result.verdict)] ?? '?'
  console.log(`  ${mark} ${result.verdict}: ${result.reason}`)
  if (result.redirect_name) console.log(`     send them to ${result.redirect_name}`)
  if (typeof result.passes_left === 'number') console.log(`     ${result.passes_left} left`)
}

/** Drain whatever the network ate, oldest first, in order. */
async function drain() {
  while (pending.length > 0) {
    try {
      report(await client.scan(pending[0]))
      pending.shift()
    } catch {
      return // still down; try again on the next tick
    }
  }
}
setInterval(() => void drain(), 5_000)

console.log(`turnstile at ${args.checkpoint}, box ${args.box}`)
console.log('paste a payload and press enter (a barcode gun does exactly this)\n')

const input = createInterface({ input: process.stdin })
for await (const line of input) {
  const payload = line.trim()
  if (payload) await present(payload)
}
