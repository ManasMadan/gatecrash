// Selling at the door.
//
// Somebody turns up without a ticket, pays cash, and needs to be inside thirty seconds later.
// This is the awkward case for any ticketing system, because the box deliberately cannot mint
// a ticket: it has the organizer's *public* key, not the private one. A box that could sign
// its own tickets could invent them, and that is the property the whole trust model rests on.
//
// So there are two honest ways to do this, and this example shows the second:
//
//   1. Pre-issue a block of "door sale" tickets before the event and hand them out as needed.
//      Boring, works with no extra software, and the block is a fixed ceiling.
//
//   2. Run this on the organizer's laptop, which does hold the key. It mints a ticket, appends
//      it to the manifest sequence, and prints or displays it.
//
// What you must not do is copy the private key onto the box. The box is in a cupboard behind a
// bar all night; the laptop is with you.
//
//   node index.mjs --keys keys.json --venue venue.json --event <event-id> --tier ga

import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { createInterface } from 'node:readline'

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, arg, i, all) => {
    if (arg.startsWith('--')) pairs.push([arg.slice(2), all[i + 1]])
    return pairs
  }, []),
)

for (const required of ['keys', 'venue', 'event']) {
  if (!args[required]) {
    console.error(`usage: node index.mjs --keys k.json --venue v.json --event ID [--tier ga]`)
    process.exit(2)
  }
}

const tier = args.tier ?? 'ga'
let sold = 0

/**
 * Mint one ticket.
 *
 * Shelling out to `gatecrash-keys` rather than reimplementing the signing. The signing format
 * is the one thing in this system that must not have a second implementation with no tests:
 * a payload this script got subtly wrong would be a ticket somebody paid for that no gate
 * accepts.
 */
function issue() {
  const out = `/tmp/door-sale-${Date.now()}.json`
  execFileSync(
    'gatecrash-keys',
    [
      'issue',
      '-keys',
      args.keys,
      '-venue',
      args.venue,
      '-event',
      args.event,
      '-tier',
      tier,
      '-n',
      '1',
      '-out',
      out,
    ],
    { stdio: 'pipe' },
  )

  const [ticket] = JSON.parse(readFileSync(out, 'utf8')).tickets
  return ticket
}

console.log(`door sales — tier ${tier}, event ${args.event}`)
console.log('press enter to sell one, or type a number to sell several\n')

const input = createInterface({ input: process.stdin })
for await (const line of input) {
  const count = Math.max(1, Number.parseInt(line.trim() || '1', 10) || 1)

  for (let i = 0; i < count; i++) {
    const ticket = issue()
    sold++
    console.log(`  ${sold}. ${ticket.id}`)
    console.log(`     ${ticket.url}`)
    // A thermal printer would print the payload as a QR here. Showing the URL works too:
    // the attendee opens it on their own phone and the wallet caches it immediately.
  }

  console.log(`\n  ${sold} sold this session`)
  console.log('  the box picks these up on its next manifest reload\n')
}
