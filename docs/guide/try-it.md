# Try it in one command

No Pi, no hardware, no configuration:

```sh
git clone https://github.com/ManasMadan/gatecrash
cd gatecrash
pnpm install && pnpm -r build
go run ./cmd/gatecrash-demo
```

It mints an organizer key, issues tickets, compiles a three-stage venue, boots a box,
enrols scanners through the real QR ceremony, and walks tickets through the gates — then
ends by proving one admission against a published Merkle root and tampering with it to show
the proof fail.

Everything it does goes through the same code the box runs. It is also the end-to-end test
CI runs on every pull request, which is deliberate: the demo cannot drift from the software
without turning the build red.

## What you will see

The interesting part is not the admissions. It is the refusals, because those are the
decisions:

- **`ADMIT`** — through the north gate, with the tier colour and seat an usher acts on.
- **`ALREADY_USED`** — with which gate and how long ago. That evidence is what settles an
  argument at a door.
- **`WRONG_DOOR`** — a Block A ticket at Portal B, refused with a redirect to the right one.
- **`PREREQUISITE_MISSING`** — a pit wristband scanned before the outer gate. The venue is a
  graph, and this is what sequencing looks like at the door.
- **`EXPIRED_WINDOW`** — a screenshot of a rotating code, ninety seconds old.
- **A retry** — the same scan id resent, returning the original verdict rather than
  `ALREADY_USED`. Bad Wi-Fi must not turn somebody away.
- **Counted passes** — two drink tokens, then `PASS_LIMIT_REACHED`.
- **Re-entry** — out through the exit and back in, which is a different door from the one
  they came in by.

## Keeping the box afterwards

```sh
go run ./cmd/gatecrash-demo -keep ./demo-data
```

Leaves the data directory behind, so you can start a box on it and poke at the real thing:

```sh
go run ./cmd/gatecrash serve --data ./demo-data
```

The boot log prints the dashboard URL with its token, the certificate fingerprint to
compare when enrolling a scanner, and the addresses to open the apps at.

## The simulator

The demo shows one event going right. The simulator runs thousands going wrong:

```sh
go run ./cmd/gatecrash-sim event -seeds 500
go run ./cmd/gatecrash-sim crowd -sweep
```

The first injects partitions, retries, reordering, clock skew and power cuts, then asserts
the guarantees hold. The second is the mesh, across crowd density. See
[Correctness](/guide/correctness).
