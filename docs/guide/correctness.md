# Correctness

A test suite says "the cases I thought of pass". That is worth having and it is not what makes
this trustworthy.

## Deterministic simulation

The redemption engine is written against abstract clock, storage and network interfaces —
nothing in it calls `time.Now()` or a global random source. The simulator drives thousands of
seeded event-days through it with faults injected at rates far worse than a real event:

- scans redelivered with the same id (a scanner that lost the response)
- tickets presented again with a fresh id (a genuine second attempt)
- messages reordered
- scanners admitting offline during a partition
- clocks two minutes apart in either direction
- writes rejected, as a full disk would
- the box losing power mid-run

Then it checks the invariants:

- never two admissions for one ticket at a once-only door in **STRICT**
- never an _undetected_ double use in **DEGRADED**
- the audit chain unbroken and densely numbered
- an audit row behind every admission
- the hybrid logical clock never going backwards
- nothing the box acknowledged lost across a power cut

```sh
go run ./cmd/gatecrash-sim event -seeds 5000
```

Eighty event-days is 240,000 scans, 69,000 admissions, 472 power cuts and 5,000 detected
double uses, with zero violations. **Any failure replays exactly from its seed**, which is
what makes "it failed on seed 23" a complete bug report.

## It has paid for itself twice

Both worth stating, because a page about correctness that only reports successes is the thing
it is warning against.

**A green sweep that meant nothing.** The first working version reported zero violations on
every seed. Every scan was failing signature verification — and since every invariant is of
the form "this bad thing never happened", nothing happened, so nothing bad happened, and
everything passed. There is now a test that insists people are actually admitted.

**A violation that was the model's fault.** It reported an idempotency failure that looked like
an engine bug. The simulator was only flushing to durable storage after admissions, so a power
cut ate a stored refusal and the retry re-decided. The real box runs `synchronous=FULL`, which
commits a refusal as firmly as an admission. A simulator that models a weaker system than the
real one reports bugs the real one does not have, and they are indistinguishable from the real
kind until you look.

## The crowd simulator

The same idea for the mesh: thousands of routers against people walking a field with radios
that fade and collide, with a random-waypoint mobility model and a spatial index so five
thousand nodes finish while you watch.

```sh
go run ./cmd/gatecrash-sim crowd -sweep
```

It produced the relay constant, and two findings of its own. Offering the store-and-forward
buffer to every newly met peer is a broadcast storm in a dense crowd, so it is gated on the
same sparseness test the relay rule uses. And observing density only from frames that decoded
meant almost nothing was observed in a crowd, so the estimate stayed at zero, the probability
stayed at one, and the rule under study never engaged at all.

The mobility model is wrong in a stated direction: real crowds move in correlated groups
towards stages and bars, so the published numbers are optimistic about how easily a message
crosses a field.

## Cross-language conformance

The same formats exist more than once — the Bloom filter and QR codecs in Go and TypeScript,
the whole mesh protocol in Go, Kotlin and Swift. Every pair is a chance to disagree, and a
disagreement does not look like a failing test; it looks like a gate refusing a valid ticket
at 21:00.

So Go generates fixtures, everything else asserts against them, and CI checks the committed
fixture is still what the current Go code produces. A golden file that has drifted from its
source is worse than none, because it makes both sides look like they agree.

## The rest of it

```sh
go test ./...          # unit and property tests
go test -race ./...    # the box serves twelve gates from one process
pnpm -r test
./scripts/check-conformance.sh
```

A weekly CI run fuzzes every parser reachable from an untrusted byte — the DNS and DHCP codecs
read packets from anybody within Wi-Fi range of a field full of strangers.

What is **not** covered: the two BLE radio layers, and real hardware durability. The simulator
pulling a virtual plug is a model; a smart plug, a real Pi and a real SD card is a measurement,
and that rig is in
[ROADMAP.md](https://github.com/ManasMadan/gatecrash/blob/master/ROADMAP.md) rather than
claimed as done.
