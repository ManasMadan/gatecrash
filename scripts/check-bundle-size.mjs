#!/usr/bin/env node
//
// check-bundle-size.mjs — a budget, not a report.
//
// These bundles are served by a Raspberry Pi over venue Wi-Fi to a phone with one
// bar, in a queue. The attendee wallet in particular is loaded by somebody who is
// about to reach a gate, and a dependency that quietly adds 400KB to it is a
// dependency that costs them their place in the line.
//
// A report tells you the number went up. A budget fails the build. The difference is
// whether anybody notices before the number has gone up ten times.
//
// The limits below are set with headroom over what the bundles actually are, so this
// fails on a step change — somebody reaching for a chart library, a date library, an
// icon font — rather than on ordinary growth. Raising one is a normal thing to do; it
// just has to be a decision rather than a side effect.

import { readdir, readFile, stat } from 'node:fs/promises'
import { gzipSync } from 'node:zlib'
import { join } from 'node:path'

const DIST = 'internal/webassets/dist'

// Gzipped, because that is what the box sends and therefore what the phone waits for.
// Raw size is the wrong number to budget: it penalises the verbose-but-compressible
// and lets a small binary blob through.
const BUDGETS = {
  attendee: {
    js: 110,
    css: 12,
    // The tightest budget of the three, and deliberately so. This is the one loaded
    // by twenty thousand phones on a network that is already struggling, and the one
    // where the person loading it is in a hurry.
    why: 'loaded by every attendee, in a queue, on one bar',
  },
  scanner: {
    js: 160,
    css: 12,
    // Roomier: it carries a QR decoder fallback for phones without BarcodeDetector,
    // which is real functionality rather than bloat. It is also loaded once per gate
    // phone per night rather than once per person.
    why: 'carries the jsQR fallback; loaded once per gate phone',
  },
  dashboard: {
    js: 120,
    css: 16,
    why: 'one wall display, on the venue LAN',
  },
}

let failed = false

function report(ok, text) {
  const mark = ok ? '[32m✓[0m' : '[31m✗[0m'
  console.log(`  ${mark} ${text}`)
  if (!ok) failed = true
}

async function measure(app) {
  const assets = join(DIST, app, 'assets')

  let entries
  try {
    entries = await readdir(assets)
  } catch {
    console.log(`\n[31m${app}[0m — no build output at ${assets}`)
    console.log('  run `pnpm -r build` first')
    failed = true
    return
  }

  const totals = { js: 0, css: 0 }
  for (const entry of entries) {
    const kind = entry.endsWith('.js') ? 'js' : entry.endsWith('.css') ? 'css' : null
    if (!kind) continue
    const contents = await readFile(join(assets, entry))
    totals[kind] += gzipSync(contents, { level: 9 }).length
  }

  const budget = BUDGETS[app]
  console.log(`\n[1m${app}[0m — ${budget.why}`)

  for (const kind of ['js', 'css']) {
    const kb = totals[kind] / 1024
    const limit = budget[kind]
    const headroom = (((limit - kb) / limit) * 100).toFixed(0)
    report(
      kb <= limit,
      `${kind.toUpperCase().padEnd(3)} ${kb.toFixed(1).padStart(6)} KB gzipped  ` +
        `of ${String(limit).padStart(3)} KB` +
        (kb <= limit ? `  (${headroom}% spare)` : `  [31mover by ${(kb - limit).toFixed(1)} KB[0m`),
    )
  }
}

// The box binary itself. The claim is one static file small enough to sit on an SD
// card next to an operating system, and it is worth a number rather than an
// adjective.
async function measureBinary() {
  for (const candidate of ['dist/gatecrash-linux-arm64', 'dist/gatecrash']) {
    try {
      const info = await stat(candidate)
      const mb = info.size / (1024 * 1024)
      console.log('\n[1mthe box[0m — one static binary, no shared libraries')
      report(mb <= 20, `${mb.toFixed(1)} MB of 20 MB  (${candidate})`)
      return
    } catch {
      // Not built in this job. The go job checks the cross-compile separately, so a
      // missing binary here is not a failure — it just means there is nothing to
      // measure.
    }
  }
}

console.log('\nbundle budgets — gzipped, because that is what the phone waits for')

for (const app of Object.keys(BUDGETS)) {
  await measure(app)
}
await measureBinary()

if (failed) {
  console.log(
    '\n[31mover budget.[0m Either take something out, or raise the limit in ' +
      'scripts/check-bundle-size.mjs — deliberately, with a reason.\n',
  )
  process.exit(1)
}

console.log('\n[32mevery bundle is inside its budget.[0m\n')
