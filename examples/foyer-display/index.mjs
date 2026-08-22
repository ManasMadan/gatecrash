// A screen in the foyer.
//
// "How many people are in?" is a question the box already answers, and a television in the
// lobby answering it is worth more than a dashboard nobody has open. This is that, in a
// terminal, so you can point it at a real box and see what the numbers do.
//
//   node index.mjs --box https://10.11.0.1:8443 --token <admin-token>
//
// The admin token is in the boot log. Anything showing it on a public screen should be
// read-only and on a machine nobody can walk up to — the token can revoke devices.

import { Client } from 'gatecrash-client'

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, arg, i, all) => {
    if (arg.startsWith('--')) pairs.push([arg.slice(2), all[i + 1]])
    return pairs
  }, []),
)

const client = new Client({ baseUrl: args.box, adminToken: args.token, timeoutMillis: 4_000 })

const bar = (value, total, width = 28) => {
  if (!total) return ' '.repeat(width)
  const filled = Math.min(width, Math.round((value / total) * width))
  return '█'.repeat(filled) + '·'.repeat(width - filled)
}

async function draw() {
  let stats
  try {
    stats = await client.stats()
  } catch (error) {
    // A screen that goes blank looks broken; a screen that says why looks like a screen with
    // a network problem. Somebody walking past can tell the difference.
    process.stdout.write(`\x1b[2J\x1b[H  lost the box — ${error.message}\n`)
    return
  }

  const live = stats.live
  const lines = [
    '',
    `  ${String(live.inside).padStart(6)} inside`,
    `  ${String(live.issued).padStart(6)} tickets sold`,
    '',
  ]

  for (const zone of live.zones) {
    if (!zone.capacity) continue
    lines.push(
      `  ${zone.name.padEnd(18)} ${bar(zone.occupied, zone.capacity)} ` +
        `${zone.occupied}/${zone.capacity}`,
    )
  }

  lines.push('')
  for (const gate of live.gates) {
    if (!gate.admitted && !gate.denied) continue
    // The rate matters more than the total on a live screen: a gate doing forty a minute and
    // a gate that has stopped both have large totals.
    const rate = gate.rate > 0 ? `${Math.round(gate.rate)}/min` : 'quiet'
    lines.push(`  ${gate.name.padEnd(18)} ${String(gate.admitted).padStart(5)} in   ${rate}`)
  }

  process.stdout.write('\x1b[2J\x1b[H' + lines.join('\n') + '\n')
}

// Two seconds, matching the dashboard. Fast enough that somebody watching sees the number
// move; slow enough that a Pi serving twelve gates does not notice a television.
await draw()
setInterval(() => void draw(), 2_000)
