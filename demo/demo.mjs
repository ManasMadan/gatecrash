// The showcase: a box, an event, and a browser pointed at all three apps.
//
// `go run ./cmd/gatecrash-demo` proves the system works and prints text. This one is for
// *showing* it: it seeds a box with a plausible half-finished event — some people inside, a
// couple of gates busy, an open crush alarm, a staffing request — and prints the three URLs to
// open. What you get is a dashboard that looks like 21:40 rather than one that looks like zero.
//
//   node demo.mjs
//
// Nothing here is a test. The tests are `go test ./...` and the simulator.

import { execFileSync, spawn } from 'node:child_process'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const dir = mkdtempSync(join(tmpdir(), 'gatecrash-demo-'))
const bin = (name) => join(process.cwd(), 'dist', name)

console.log(`data directory ${dir}\n`)

function run(command, args, options = {}) {
  return execFileSync(command, args, { encoding: 'utf8', cwd: dir, ...options })
}

console.log('==> building')
execFileSync('./scripts/build.sh', [], { stdio: 'inherit' })

console.log('==> minting keys and an event')
run(bin('gatecrash-keys'), ['keygen', '-out', 'keys.json'])
run(bin('gatecrash-keys'), ['venue', '-out', 'venue.json'])

const issued = run(bin('gatecrash-keys'), [
  'issue',
  '-keys',
  'keys.json',
  '-venue',
  'venue.json',
  '-n',
  '240',
  '-tier',
  'ga',
  '-section',
  'block-a',
  '-out',
  'ga.json',
])
// The event id is printed once and every later batch has to reuse it, or the second batch
// belongs to a different event and every one of those tickets is WRONG_EVENT at the door.
const eventId = /event id\s+(\S+)/.exec(issued)?.[1]
if (!eventId) throw new Error(`could not find the event id in:\n${issued}`)

run(bin('gatecrash-keys'), [
  'issue',
  '-keys',
  'keys.json',
  '-venue',
  'venue.json',
  '-event',
  eventId,
  '-n',
  '60',
  '-tier',
  'vip',
  '-format',
  'gc2',
  '-out',
  'vip.json',
])

const doors = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
const curfew = new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString()

run(bin('gatecrash-keys'), [
  'manifest',
  '-keys',
  'keys.json',
  '-venue',
  'venue.json',
  '-tickets',
  'ga.json,vip.json',
  '-event',
  'Sundown Sessions',
  '-venue-name',
  'Kingdom of Dreams',
  '-doors',
  doors,
  '-curfew',
  curfew,
  '-support',
  'WhatsApp +91 90000 00000',
  '-out',
  'manifest.json',
])

console.log('==> starting the box')
const box = spawn(
  bin('gatecrash'),
  [
    'serve',
    '--data',
    dir,
    '--manifest',
    join(dir, 'manifest.json'),
    '--listen',
    '127.0.0.1:18443',
    '--log',
    'warn',
  ],
  { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] },
)

process.on('exit', () => box.kill())
process.on('SIGINT', () => {
  box.kill()
  process.exit(0)
})

// Wait for it to answer rather than sleeping a fixed amount. A fixed sleep is either too short
// on a slow machine or wasted on a fast one.
const base = 'http://127.0.0.1:18080'
for (let attempt = 0; attempt < 100; attempt++) {
  try {
    const response = await fetch(`${base}/healthz`)
    if (response.ok) break
  } catch {
    await new Promise((r) => setTimeout(r, 100))
  }
}

const token = readFileSync(join(dir, 'admin-token'), 'utf8').trim()
const admin = (path, init) =>
  fetch(`${base}${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...init?.headers,
    },
  })

console.log('==> enrolling scanners and walking people in')

const tickets = JSON.parse(readFileSync(join(dir, 'ga.json'), 'utf8')).tickets
const vips = JSON.parse(readFileSync(join(dir, 'vip.json'), 'utf8')).tickets

async function enrol(name, checkpoints) {
  const invite = await (
    await admin('/v1/admin/invite', {
      method: 'POST',
      body: JSON.stringify({ name, checkpoints }),
    })
  ).json()

  const enrolled = await (
    await fetch(`${base}/v1/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: invite.invite.code, name }),
    })
  ).json()

  return enrolled
}

const north = await enrol('North 1', ['gate-north'])
const portal = await enrol('Portal A', ['portal-a'])

// A scan id is the same 26-character base32 form as a ticket id, not a UUID. `newScanId()` in
// gatecrash-client does this for a real client; the demo shells out to nothing, so it is inline.
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const scanId = () =>
  Array.from({ length: 26 }, () => BASE32[Math.floor(Math.random() * 32)]).join('')

async function scan(device, checkpoint, payload) {
  return (
    await fetch(`${base}/v1/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${device.token}` },
      body: JSON.stringify({ scan_id: scanId(), payload, checkpoint }),
    })
  ).json()
}

// A plausible mid-event picture rather than a full house: most of the GA in, a third of them
// through to their seats, and a handful of things that went wrong.
for (const ticket of tickets.slice(0, 160)) {
  await scan(north, 'gate-north', ticket.payload)
}
for (const ticket of tickets.slice(0, 55)) {
  await scan(portal, 'portal-a', ticket.payload)
}
// Somebody trying a second time at the same door, and somebody's screenshot.
await scan(north, 'gate-north', tickets[0].payload)
await scan(north, 'gate-north', 'GC1.NOTAREALTICKETATALLXXXXX.' + 'A'.repeat(103))
// A VIP at the pit gate without having been through the arena first.
await scan(north, 'gate-north', vips[0].payload)

console.log('==> raising the kind of thing that happens at 21:40')

await fetch(`${base}/v1/incidents`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', authorization: `Bearer ${portal.token}` },
  body: JSON.stringify({ kind: 'crush', reporter: 'Aditi', note: 'front barrier is buckling' }),
})
await fetch(`${base}/v1/incidents`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', authorization: `Bearer ${north.token}` },
  body: JSON.stringify({
    kind: 'need-staff',
    reporter: 'Rahul',
    head_count: 3,
    note: 'queue is 200 deep',
  }),
})
await admin('/v1/admin/announce', {
  method: 'POST',
  body: JSON.stringify({ body: 'Gate 4 is now open', priority: true }),
})

const stats = await (await admin('/v1/admin/stats')).json()

console.log(`
  Sundown Sessions is live — ${stats.live.inside} inside of ${stats.live.issued}

    dashboard  ${base}/dashboard/?token=${token}
    scanner    ${base}/scanner/
    attendee   ${base}/attendee/#/t/${tickets[200].id}

  The dashboard has an open crush alarm and a staffing request. The attendee link is a seated
  ticket that has not come in yet, so it shows the route to their door.

  Ctrl-C to stop. The data directory is ${dir}
`)

// Hold the box open so the URLs above are usable.
await new Promise(() => {})
