# Contributing

## Getting set up

You need Go 1.24 and Node 22. Everything else comes from the lockfiles.

```sh
git clone https://github.com/ManasMadan/gatecrash
cd gatecrash
pnpm install
pnpm -r build          # the PWAs are embedded in the binary, so build them first
go run ./cmd/gatecrash-demo
```

If the demo prints an event and ends with a Merkle proof, everything works.

## The one thing to read first

`go run ./cmd/gatecrash-demo` runs a whole event: keys, tickets, a venue, a box,
enrolled scanners, and tickets walking through three stages of gates including
everything that goes wrong. Reading its output next to `cmd/gatecrash-demo/acts.go` is
the fastest way to understand what this system does, and it takes about ten minutes.

## Before you open a pull request

```sh
go test ./...
go test -race ./...              # the box serves twelve gates from one process
gofmt -l .                       # should print nothing
go vet ./...
pnpm -r typecheck && pnpm -r lint && pnpm -r test
```

And if you touched the redemption engine, the audit chain, or the mesh:

```sh
gatecrash-sim event -seeds 500
gatecrash-sim crowd -sweep
```

The pre-commit hook runs the fast subset of this. It is not optional and it is not
slow.

## How this code is written

Some of these are unusual enough to be worth stating, because a pull request that
follows the surrounding style is a pull request that gets merged quickly.

**Comments explain why, not what.** `// increment the counter` above `i++` is noise.
`// Counted at processing time rather than at the scan's own timestamp, because a
scanner draining a twenty-minute offline queue would otherwise look idle at exactly
the moment it is busiest` is the reason the line exists, and it is the thing a reader
cannot recover from the code. If a decision could have gone the other way, say which
way it went and what it cost.

**Name the failure, not the feature.** Tests are named after what breaks:
`TestAHungBoxStopsPinging`, `TestTheSimulatorActuallyAdmitsPeople`,
`TestExitDoorsDoNotRefuseEverybody`. A test called `TestScan` tells a future reader
nothing about why it exists or what regressing it would cost.

**No new dependencies without a paragraph.** Every dependency is something that can
fail to cross-compile for `linux/arm64`, and every frontend dependency is bytes a
phone in a queue waits for. There is a bundle budget in CI that will tell you the
number. The DNS codec, the mDNS responder, the DHCP server, the Noise handshake and
two hash filters are hand-written for this reason — not for fun.

**Injected clocks and injected randomness.** Nothing calls `time.Now()` or a global
random source in code that a test or the simulator drives. That is what makes a failing
seed reproducible, and a simulator that cannot reproduce its failures has found
nothing.

**Errors say what to do.** `"the manifest is sealed; set GATECRASH_MANIFEST_PASSPHRASE"`
rather than `"decryption failed"`. Somebody reads these on a phone screen in a field.

**Prose in user-facing strings.** The verdict screens, the boot log and the dashboard
are read by people who did not write this and are in a hurry. No jargon, no error
codes without a sentence, no "an error occurred".

## The commit style

Conventional commits, enforced by commitlint:

```
feat(engine): admit exactly once, and say which gate refused
fix(mesh): stop the carry buffer becoming a broadcast storm
docs(mesh): replace the guessed relay numbers with measured ones
```

The body is where the reasoning goes, and it is worth writing. A commit that says
_what_ is recoverable from the diff; a commit that says _why_ is the only record of the
alternative that was rejected. Several commits in this repository are longer than the
change they describe, deliberately.

Use `pnpm changeset` if you changed a published package.

## Where to start

**A gate incident.** If you ran an event on this and something happened at a door,
that report is worth more than any feature. There is
[an issue template](.github/ISSUE_TEMPLATE/gate-incident.yml) for it.

**A failing seed.** `gatecrash-sim event -seeds 20000` on a machine with time to spare.
If it finds something, the seed is the whole bug report.

**The mesh on a phone.** The protocol is written and specified; the two platform layers
are not. See [ROADMAP.md](ROADMAP.md).

**Anything in ROADMAP.md marked "considered, and not now"** — those have a stated reason
for waiting, and if the reason no longer holds, that is the conversation to open.

## What will not be merged

- A cloud dependency in the event path. The box works with no internet; that is the
  whole product.
- Personal data on the box. It knows ticket ids.
- Anything that removes the STRICT/DEGRADED distinction, or makes the choice implicit.
  It is the one place this project refuses to pretend CAP is negotiable.
- A dependency that could have been forty lines.
- A test that passes when the thing it tests is broken. If you are unsure, break the
  code deliberately and check the test fails — §16 of [DECISIONS.md](DECISIONS.md) is
  what happens when nobody does.
