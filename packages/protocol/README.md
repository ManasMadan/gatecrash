# gatecrash-client

The wire types and a thin client for a [gatecrash](https://github.com/ManasMadan/gatecrash)
box. Zero dependencies.

This is the package to install if you are writing something that talks to a box: a
turnstile controller, a till that sells tickets at the door, a screen in the foyer, or your
own scanner. The three apps that ship with gatecrash are built on it, so anything they can
do, you can do.

```sh
pnpm add gatecrash-client
```

## What is in it

**The types.** Every request and response the box serves, including all fifteen verdicts
and the venue plan. If it is on the wire, it is typed here.

**A client.** `fetch`, a deadline, and typed responses. Nothing else — no retry policy, no
cache, no state machine, because at a gate those are decisions only the caller can make.

**The QR codecs.** GC1 static payloads and GC2 rotating ones, encode and decode. The same
code the attendee wallet uses to generate a rotating code locally with no network.

**The offline filter.** A reader for the Bloom filter the box ships to scanners. This is
the piece that lets a gate tell "a ticket I cannot confirm right now" from "a QR somebody
generated in a car park" while the network is down — the first is a hold, the second is a
refusal.

## Using it

```ts
import { Client, newScanId, parsePayload, severityOf } from 'gatecrash-client'

const client = new Client({
  baseUrl: 'https://10.11.0.1:8443',
  token: deviceToken, // from the enrollment ceremony
  timeoutMillis: 2_500, // a gate cannot wait longer than this
})

const result = await client.scan({
  scanId: newScanId(),
  payload: whateverTheCameraRead,
  checkpoint: 'gate-north',
})

if (severityOf(result.verdict) === 'admit') {
  open()
} else {
  refuse(result.reason) // written by the box, so every gate says the same thing
}
```

The `scanId` is yours to generate and it matters: resend the same one and you get the
original verdict back rather than a spurious `ALREADY_USED`. That is what makes a retry
over bad Wi-Fi safe, and it is the difference between a network blip and turning somebody
away.

## The offline path

```ts
import { BloomFilter, parsePayload } from 'gatecrash-client'

const manifest = await client.manifest() // cache this
const filter = BloomFilter.parse(manifest.filter)

// The network is gone. What can still be decided?
const parsed = parsePayload(whateverTheCameraRead)
if (!parsed) refuse('malformed')
else if (!filter.mightContain(parsed.ticketId)) refuse('unknown ticket')
else hold('cannot confirm right now')
```

Whether that last case should hold or admit is the STRICT/DEGRADED choice, and it belongs
to the organizer rather than to your code —
[the guarantees](https://github.com/ManasMadan/gatecrash/blob/master/DELIVERY-GUARANTEES.md)
sets out what each mode promises.

## Compatibility

The formats are versioned and the box refuses anything it does not recognise, so a client
built against this package will not silently misread a newer box. Breaking wire changes get
a major version and a note in
[DECISIONS.md](https://github.com/ManasMadan/gatecrash/blob/master/DECISIONS.md).

MIT.
