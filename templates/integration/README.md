# gatecrash integration template

A starting point for something that reacts to what happens at a gate: a turnstile, a
printer, a screen, a row in somebody else's database.

Copy the directory, rename it, replace `handle`. What is worth keeping is the part that
is not about your integration at all.

```sh
cp -r templates/integration my-integration
cd my-integration
# change `"gatecrash-client": "workspace:*"` to a version range, e.g. "^0.1.0"
pnpm install
pnpm test
```

That one line is the only edit needed to take it out of this repository. It is
`workspace:*` in here so CI compiles the template and runs its tests — a template that
does not build is not a starting point, it is an afternoon.

## The three problems it already solves

Nothing below is specific to what you do with an admission, and all three are easy to get
subtly wrong in a way that only shows up on the night.

**Resuming.** The box numbers every redemption. Reconnect without a sequence and you miss
whatever happened while you were away — which, for anything reconciling money, is the
worst possible failure because nothing reports it.

**Duplicates.** Resuming replays, so delivery is at-least-once. The box commits each
redemption exactly once — that is what the single `INSERT ... ON CONFLICT DO NOTHING` is
for — but that guarantees the _decision_ is unique, not that you see it once. `run()`
drops anything at or below the highest sequence it has handled, which turns at-least-once
delivery into effectively-once handling.

If your side effect is not idempotent — a charge, a printed wristband — an in-memory
counter is not enough. The sequence has to land in your own storage, in the same
transaction as the effect, or the restart you were trying to survive loses it.

**Refusals are not errors.** `ALREADY_USED`, `WRONG_ZONE`, `PASS_LIMIT_REACHED`: every one
is the venue's rules working. On a bad night most of what a gate emits is refusals, and an
integration that raises them as faults pages somebody at 1am about a wristband from last
year. They go to `onRefusal`, never to `handle`, so an attendance figure counts admissions
and nothing else.

## Cursor ordering

`handle` runs, then the cursor advances. Crash between the two and the event is replayed —
which is the case the de-duplication exists for. The other order loses events instead, and
a lost admission cannot be reconstructed from anywhere.

If `handle` throws, the cursor is left where it was and the event is retried on reconnect.

## Wiring it to a real box

```ts
import { Client } from 'gatecrash-client'
import { fileCursor, run } from './src/index'

const client = new Client({ baseUrl: 'https://10.11.0.1:8443', adminToken: process.env.TOKEN })
const cursor = fileCursor('.cursor')

run({
  source: client.stream('/v1/stream', await cursor.read()),
  cursor,
  handle: async (result) => {
    console.log(result.seq, result.ticket, result.checkpoint_name)
  },
  onRefusal: (result) => console.log('refused:', result.verdict, result.reason),
  onError: (error) => console.error(error),
})
```

`client.stream` returns the raw `EventSource` on purpose: it already retries with backoff
and replays `Last-Event-ID`, and wrapping it would mean reimplementing both.

## Worked examples

`examples/` has three that are finished rather than templates — a turnstile, door sales
and a foyer display. Read those for what a real one looks like; start from this for a new
one.
