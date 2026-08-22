<div align="center">

# gatecrash

**An entire event — gates, dashboard, wallet, and attendee-to-attendee chat — off one
Raspberry Pi, with no internet.**

[![ci](https://github.com/ManasMadan/gatecrash/actions/workflows/ci.yml/badge.svg)](https://github.com/ManasMadan/gatecrash/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![go](https://img.shields.io/badge/go-1.24-00ADD8.svg)](go.mod)

</div>

---

Ticketing platforms charge a convenience fee per ticket and stop working when the
venue's Wi-Fi does. That is fine for a stadium with fibre and a contract. It is
useless for a college fest in a basketball hall, an indie gig above a bar, a comedy
room, a wedding, or a farm party where the nearest tower is a kilometre away — which
is most events, and all of the ones where the fee hurts most.

Gatecrash is one static binary on a Raspberry Pi. It validates tickets at as many
gates as you have phones, runs the control-room dashboard, serves every attendee their
ticket, and carries messages between phones over Bluetooth when there is no network at
all. Nothing it does during an event touches the internet, because during an event
there usually isn't one.

```
                        ┌──────────────────────────────────┐
   scanner phones  ───▶ │           the box                │ ◀───  wall display
   (QR, offline-ok)     │  Raspberry Pi · one binary        │       (dashboard)
                        │  SQLite · own CA · own Wi-Fi      │
   attendee phones ───▶ │  DNS · DHCP · captive portal      │
   (wallet PWA)         └──────────────────────────────────┘
                                       │
                              no uplink required
                                       │
   attendee phones ◀───── BLE mesh ─────┴──▶ attendee phones
   (Backstage chat, works with the box switched off)
```

## Try it in one command

No Pi, no hardware, no setup. This mints keys, issues tickets, builds a three-stage
venue, boots a box, enrols scanners through the real QR ceremony, and walks tickets
through it — including everything that goes wrong:

```sh
go run ./cmd/gatecrash-demo
```

It prints what happened at each door and why, and it is the same code path CI runs, so
this README cannot quietly drift from the software.

## What makes it different

**It admits exactly once, and can prove it.** Ten scanners hammering one QR is a
single SQLite statement:

```sql
INSERT INTO redemptions (ticket_id, checkpoint, occurrence, ...)
VALUES (?, ?, ?, ...) ON CONFLICT DO NOTHING;
```

`changes() == 1` is an admission; `0` means somebody already came through, and the
screen shows which gate and how long ago. That one statement is the linearization
point of the whole system. Everything else — the hybrid logical clocks, the
idempotency keys, the hash-chained audit log — exists to make that statement's answer
meaningful under a network that is failing.

**It tells the truth about CAP.** When a scanner cannot reach the box, something has
to give, and no amount of engineering removes the choice:

| Mode                  | A gate that has lost the box | What is guaranteed                                                                                              |
| --------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **STRICT** (default)  | Stops admitting, shows amber | At most one admission per ticket, ever. Linearizable.                                                           |
| **DEGRADED** (opt-in) | Admits from its local mirror | Every double use is **detected and flagged within seconds of the network healing**, with both records attached. |

Prevention under partition is impossible — that is CAP, not a missing feature — so the
mode is in the signed manifest, chosen by the organizer, and shown on every screen.

**It survives the power going out.** The box is a Pi in a cupboard behind a bar. The
simulator pulls its plug hundreds of times a run and asserts that no acknowledged scan
is ever lost. The dashboard token, the certificate authority and the enrollment secret
all persist, so a reboot mid-event does not sign out the control room or log out a
single scanner, and the live occupancy figure is rebuilt from the audit log rather than
coming back as zero.

**The verdict is readable across a queue.** A guard at a gate at 22:00 is watching
people, not a phone. So a scan floods the whole screen with one colour and one glyph,
plays a two-note rise or a low buzz, and vibrates in a pattern you can tell apart
through a jacket. Text is the third channel, not the first.

**Attendees can talk to each other with no signal.** Twenty thousand phones in a field
is a dead network. Backstage is a Bluetooth mesh: passphrase channels, direct messages
over X25519, organizer announcements that are signed rather than encrypted so nobody
can invent "Gate 4 is now open", and a friend finder that plays warmer-and-colder on
signal strength. The venue boxes join in as super-nodes and bridge the islands over the
LAN, which fixes the thing that actually kills BLE meshes in the field: two groups of
people thirty metres apart who never hear each other.

## What it is not

No cloud during the event. No per-ticket fee. No account for an attendee. No personal
data on the box — it knows ticket ids, and nothing else. No Docker, because the whole
appeal is a machine with no runtime on it. No automatic updates, because a box that
upgrades itself upgrades itself during a show.

It is also not a stadium product. One Pi's radio is comfortable with a dozen scanners
and a few staff phones; twenty thousand attendee phones associating to it is not a
thing that works, which is why the wallet is built to run with the network off and the
comparison table stays honest.

## The numbers

Everything here is measured by something in this repository, and the command that
produced it is next to it.

|                                                  |                                                                   |                                                   |
| ------------------------------------------------ | ----------------------------------------------------------------- | ------------------------------------------------- |
| Box binary, `linux/arm64`                        | **12.3 MB**, statically linked                                    | `./scripts/build.sh`                              |
| Scans per second, over HTTP                      | **~2,300**                                                        | `go test ./internal/httpapi -bench ScanOverHTTP`  |
| Scans per second, straight to SQLite             | **~3,200**                                                        | `go test ./internal/store -bench ScanAdmitSQLite` |
| Offline filter, 50,000 tickets                   | **175 KB**, 49ns lookups, 1-in-a-million false positives          | `go test ./internal/bloom -bench .`               |
| Mesh dedup memory                                | **64 KiB** for a ten-minute window                                | `go test ./internal/cuckoo -bench .`              |
| Mesh delivery, 5,000 phones                      | **99.4%**, p95 **556ms**                                          | `gatecrash-sim crowd -nodes 5000`                 |
| Mesh delivery, 500 phones in a hall              | **98.8%**                                                         | `gatecrash-sim crowd -nodes 500`                  |
| Seeded event-days with zero invariant violations | **240,000 scans**, 472 power cuts, 5,000 double uses all detected | `gatecrash-sim event -seeds 64`                   |
| Attendee wallet, gzipped                         | **77 KB** of JavaScript                                           | `node scripts/check-bundle-size.mjs`              |
| Printed ticket QR                                | 134 characters — version 7, still scans off paper in bad light    | `go test ./internal/ticket`                       |

## How an event runs

**Before.** On your laptop, never on the box:

```sh
gatecrash-keys keygen  -out keys.json
gatecrash-keys venue   -out venue.json          # a worked example; edit it
gatecrash-keys issue   -keys keys.json -venue venue.json -n 500 -tier ga -section block-a -out ga.json
gatecrash-keys manifest -keys keys.json -venue venue.json -tickets ga.json \
  -event "Sundown Sessions" -doors 2026-08-21T18:00:00Z -out manifest.json
gatecrash-keys seal    -in manifest.json -out manifest.sealed.json
```

The box gets the manifest. You keep the private key — a box that could sign its own
manifest could invent tickets.

**On the day.** Copy the manifest onto the box and start it. The boot log prints the
dashboard URL with its token, the certificate fingerprint to compare when enrolling a
scanner, and the addresses to type into a gate phone.

Guards open `/scanner/`, scan an invite QR from the dashboard, and check the
fingerprint on their screen matches the one on the box's. If it does not, somebody is
standing between them, and that is the moment to find out.

**After.** Seal the log, verify the chain, export the attendance report with the proof
that goes with it. An organizer arguing with a promoter about turnout has a number
nobody has to take on trust:

```sh
gatecrash verify        # every row still hashes to the head
gatecrash export        # attendance, with a Merkle proof per ticket
```

## Zones, seats and where to go next

A venue is not one door. Gatecrash models it as a graph, and the graph is what makes
sequencing possible: perimeter, then concourse, then arena, then the pit — each with
its own doors, its own allowlist of which tiers may pass, and its own prerequisites.
A pit wristband scanned before the outer gate is `PREREQUISITE_MISSING` with a
redirect telling the guard exactly where to send them.

On top of that: seated sections with rows laid out along a curve, a walk graph with
Dijkstra routing and a step-free variant, and the amenities somebody at a festival
actually looks for. The wallet shows the holder their seat on a map that always
includes the stage — a seat map that crops the stage out cannot tell you which way
round you will be sitting — with turn-by-turn directions and a "nearest toilet"
search that respects which zones their ticket is allowed into.

The dashboard sees the same map with live occupancy shaded onto it. "The pit is
filling and the arena is not" is one glance there and four rows of a table anywhere
else.

## When something goes wrong at a gate

A bouncer holding a barrier is not going to fill in a form. So the scanner has one
screen of buttons — crush, medical, fight, _send me two more people_ — and the box
attaches the gate, the zone and the current queue rate on the way through. The control
room sees "Asking for 3 people. This gate is doing 14 a minute", and every response is
attributed: I have it, send somebody, done, false alarm. "Somebody assumed somebody
else had it" is the failure that board exists to prevent.

## Threat model

| Attack                                       | What stops it                                                                                       |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Forged QR                                    | Ed25519 signature over the claims, verifiable at a gate with no network                             |
| Screenshotted ticket, shared before the show | Rotating TOTP-style code, 30-second windows, ±1 tolerance                                           |
| One ticket, two gates, at once               | The CAS above. Exactly one insert wins, deterministically                                           |
| One ticket, two gates, during a partition    | Prevented in STRICT; detected and flagged in DEGRADED, both records attached                        |
| Somebody's own phone as a scanner            | Enrollment ceremony, client certificate, per-device checkpoint allowlist                            |
| A stolen scanner                             | Revoked from the dashboard in one tap; the certificate stops working immediately                    |
| A tampered audit log                         | Hash-chained rows plus RFC 6962 Merkle checkpoints; any edit breaks the head                        |
| A fake box on the venue Wi-Fi                | Self-minted CA with name constraints, fingerprint pinned during enrollment                          |
| Reading mesh chat                            | Argon2id channel keys; X25519 and ChaCha20-Poly1305 for direct messages                             |
| Forging an announcement                      | Ed25519 against the organizer key every phone already has from the manifest                         |
| Following somebody by their friend beacon    | Tokens rotate every window — a constant identifier is how Bluetooth trackers became a stalking tool |
| Attendee privacy                             | The box stores ticket ids. Names, if they exist at all, stay in the optional presale layer          |

Two things it does **not** stop, stated because a threat model that only lists wins is
marketing. A BLE mesh broadcasts to everybody in range by construction, so the fact
that a channel had traffic is visible even though its contents are not. And the mesh
hop count is outside the authenticated data — it has to be, since every relay
decrements it — so anybody can shorten a message's reach, which is indistinguishable
from simply staying silent.

## Correctness

The redemption engine is written against abstract clock, storage and network
interfaces, and the simulator drives thousands of seeded event-days through it with
partitions, crashes, reordering, duplicate delivery, clock skew and power cuts injected
at rates far worse than a real event. Then it checks the invariants:

- never two admissions for one ticket at a once-only door in STRICT
- never an undetected double use in DEGRADED
- the audit chain unbroken and densely numbered
- an audit row behind every admission
- the hybrid logical clock never going backwards, with scanners two minutes apart
- nothing the box acknowledged lost across a power cut

```sh
gatecrash-sim event -seeds 5000        # any failure replays exactly from its seed
```

It has already paid for itself twice. It caught a green sweep that meant nothing —
every scan was failing signature verification, and every invariant of the form "this
bad thing never happened" passed because nothing ever happened. And it caught an
idempotency violation that turned out to be the model's fault rather than the box's,
which is its own kind of useful.

## Repository

```
cmd/gatecrash          the box
cmd/gatecrash-keys     the organizer's toolkit: keys, venues, tickets, manifests
cmd/gatecrash-sim      the simulator — event-days and crowds
cmd/gatecrash-demo     a whole event in one command
internal/engine        the verdict, and the CAS at the centre of it
internal/audit         hash-chained log, Merkle checkpoints, attendance proofs
internal/venue         zones, seats, checkpoints, routing, wayfinding
internal/ticket        GC1 static and GC2 rotating payloads
internal/mesh          the Backstage frame, dedup, and the relay decision
internal/noise         Noise XX, by hand
internal/dnsd internal/dhcp internal/mdns internal/portal   the box being a network
packages/protocol      the wire types, shared by all three apps
packages/ui            the verdict screen and the venue map
apps/scanner           the gate PWA
apps/attendee          the wallet PWA
apps/dashboard         the control room
deploy/                Pi image, systemd, AP mode, A/B updates
```

## Docs

- [DECISIONS.md](DECISIONS.md) — every choice that could have gone the other way, and why it did not
- [DELIVERY-GUARANTEES.md](DELIVERY-GUARANTEES.md) — precisely what is promised, and what is not
- [deploy/README.md](deploy/README.md) — getting a box into a venue
- [ROADMAP.md](ROADMAP.md) — what is deliberately not built yet
- [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md)

## License

MIT. Run your own event on it, sell tickets with it, fork it, charge for it.

<sub>Built by <a href="https://github.com/ManasMadan">Manas Madan</a>.</sub>
