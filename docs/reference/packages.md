# Packages

Two npm packages, both unscoped and both MIT.

## gatecrash-client

```sh
pnpm add gatecrash-client
```

The wire types and a thin client, with zero dependencies. Install this if you are writing
anything that talks to a box: a turnstile controller, a till that sells at the door, a screen
in the foyer, or your own scanner. The three shipped apps are built on it, so anything they can
do, you can do.

**The types** — every request and response, including all fifteen verdicts and the venue plan.

**A client** — `fetch`, a deadline, and typed responses. Nothing else: no retry policy, no
cache, no state machine, because at a gate those are decisions only the caller can make.

**The QR codecs** — GC1 static and GC2 rotating, encode and decode. The same code the wallet
uses to generate a rotating code locally with no network.

**The offline filter** — a reader for the Bloom filter the box ships to scanners. This is what
lets a gate tell "a ticket I cannot confirm right now" from "a QR somebody generated in a car
park".

```ts
import { Client, newScanId, severityOf } from 'gatecrash-client'

const client = new Client({
  baseUrl: 'https://10.11.0.1:8443',
  token: deviceToken,
  timeoutMillis: 2_500, // a gate cannot wait longer than this
})

const result = await client.scan({
  scanId: newScanId(),
  payload: whateverTheCameraRead,
  checkpoint: 'gate-north',
})

if (severityOf(result.verdict) === 'admit') open()
else refuse(result.reason)
```

Generate your own `scanId` and reuse it on retry. Resend the same one and you get the original
verdict rather than a spurious `ALREADY_USED`, which is the difference between a network blip
and turning somebody away.

## gatecrash-ui

```sh
pnpm add gatecrash-ui gatecrash-client react
```

The verdict screen and the venue map, as React components. They are a package rather than app
internals because if you build your own scanner or wallet, these are the parts worth not
rewriting — and the parts where the details took longest to get right.

```tsx
<VerdictScreen result={result} onDismiss={clear} gateName="North Gate" />

// An attendee: their seat, their route, only the doors they can use.
<VenueMap plan={plan} seat={seat} route={route} openCheckpoints={next} focusSection="block-a" />

// The control room: every door named, occupancy shaded onto the zones.
<VenueMap plan={plan} showSeats={false} labelEveryGate occupancy={occupancy} />
```

Styles are three separate imports so you can take the components without the theme, and
everything is driven by custom properties on `:root`:

```ts
import 'gatecrash-ui/tokens.css'
import 'gatecrash-ui/verdict.css'
import 'gatecrash-ui/map.css'
```

## Versioning

Both are released together from the same repository, and breaking wire changes get a major
version and a note in
[DECISIONS.md](https://github.com/ManasMadan/gatecrash/blob/master/DECISIONS.md). The formats
are versioned and the box refuses what it does not recognise, so a client built against an
older release will not silently misread a newer box.

## Not published

The three apps (`scanner`, `attendee`, `dashboard`) are private. They are embedded in the box
binary and served from it, so there is nothing to install — and a separately versioned scanner
that drifted from the box serving it is a problem nobody needs.
