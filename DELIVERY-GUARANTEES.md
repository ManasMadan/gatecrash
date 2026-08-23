# Delivery guarantees

What this system promises, what it does not, and how you can check either.

Guarantees written down like this are worth more than guarantees implied by marketing,
because the ones that matter are the ones somebody relies on at 22:00 with a queue
behind them. Everything below is either enforced by a test in this repository or
stated as a non-guarantee. There is no third category.

---

## 1. Ticket redemption

### Guaranteed: at most one admission per ticket per once-only checkpoint

**In STRICT mode, absolutely.** One `INSERT ... ON CONFLICT DO NOTHING` against a
primary key of `(ticket_id, checkpoint, occurrence)` is the linearization point. Ten
scanners presenting the same QR at the same instant produce exactly one winner, decided
by SQLite's single-writer serialisation rather than by anything this project wrote.

**Checked by:** `gatecrash-sim event -seeds 5000 -mode strict`, which injects
partitions, retries, reordering, clock skew and power cuts and asserts no ticket is
ever admitted twice at a once-only door.

**In DEGRADED mode, no** — and the mode exists precisely to say so out loud. See §2.

### Guaranteed: a retry is not a second use

A scanner that sends a scan, loses the response and sends it again gets the original
verdict back. The scan id is client-generated and the result is stored against it, so
bad Wi-Fi cannot turn a valid ticket into `ALREADY_USED`.

**Checked by:** the simulator's idempotency invariant, on every retry, in every run.
This one has already fired in anger — see [DECISIONS.md](DECISIONS.md).

### Guaranteed: every decision is recorded, not just the admissions

Refusals are chained too. A log that only records successes cannot prove a gate was
working, and "we never saw that ticket" is exactly the claim a dispute turns on.

### Not guaranteed: that a refusal is the same refusal twice

A retry always returns _a_ refusal for a refused scan, and it may be a different one.
If somebody is refused at a portal for missing a prerequisite, walks through the outer
gate, gets admitted at the portal by a second scan, and _then_ the first scanner's
retry finally arrives, that retry reports `ALREADY_USED` rather than
`PREREQUISITE_MISSING`.

Both are refusals, the person is not admitted twice, and nothing a guard does depends
on which reason came back. Making it identical would mean storing a result row for
every refused scan — and refused scans are unbounded, driven by whatever anybody
waves at a camera.

---

## 2. Under a network partition

This is where the honest answer is a trade rather than a guarantee, so it is a table.

|                                      | STRICT (default)                  | DEGRADED (opt-in per event)                       |
| ------------------------------------ | --------------------------------- | ------------------------------------------------- |
| A gate that cannot reach the box     | Holds. Amber screen, no admission | Admits from its local mirror                      |
| Double admission possible?           | **No**                            | **Yes**                                           |
| Double use detected?                 | n/a                               | **Always**, within seconds of the network healing |
| Evidence kept                        | n/a                               | Both scan records, on the security feed           |
| Queue behaviour when the box is down | Stops                             | Keeps moving                                      |

Prevention under partition is impossible. That is CAP, not a missing feature, and any
product claiming both is either lying or has not thought about it. What gatecrash does
instead is make the choice explicit: the mode lives in the signed manifest, so it is
the organizer's decision rather than a default somebody discovers at a gate, and every
screen shows which one is in force.

**Checked by:** `gatecrash-sim event -seeds 5000 -mode degraded`, which asserts that
every double use that occurs is flagged. An _undetected_ one is a test failure.

---

## 3. Durability

### Guaranteed: an acknowledged scan survives a power cut

If a guard saw a green screen, the admission is on the card. SQLite runs with
`synchronous=FULL`, so the commit is durable before the response is written.

**Checked by:** the simulator drops everything written since the last durable point,
hundreds of times per sweep, and asserts every admission it acknowledged is still
there afterwards.

### Guaranteed: the box comes back on its own

A reboot restores the audit chain head, rebuilds the live occupancy picture from the
log, and keeps the same dashboard token, certificate authority and enrollment secret.
Nobody has to re-enrol a scanner and nobody has to find a new token on a Pi in a
cupboard.

### Not guaranteed: that nothing is lost

A power cut loses whatever was in flight and not yet acknowledged. That is the correct
behaviour — the alternative is acknowledging something that is not written — and it is
why the guarantee above is scoped to _acknowledged_ scans.

### Not guaranteed: survival of a lying SD card that lies about everything

`synchronous=FULL` is the strongest thing SQLite can ask for, and a card that ignores
a flush entirely can still lose a committed transaction. Mitigations, in order of how
much they help: a USB SSD instead of a card, a UPS HAT, and
`deploy/scripts/harden.sh` to make the root filesystem read-only so the only writable
thing on the box is the data directory.

---

## 4. The audit log

### Guaranteed: tampering is evident

Every row carries the hash of the previous one. Changing, inserting or deleting a row
changes the head, and the head is published in periodic Merkle checkpoints.

### Guaranteed: an admission can be proved to somebody who does not trust the box

An RFC 6962 inclusion proof: `O(log n)` sibling hashes against a published root. At
fifty thousand admissions that is sixteen hashes, 512 bytes, and it verifies with the
root alone — no log, no database, no trust in the machine that produced it.

**See it:** `go run ./cmd/gatecrash-demo` ends by proving one admission and then
tampering with it.

### Not guaranteed: that the box did not lie from the start

A hash chain proves the log has not been edited since it was written. It cannot prove
the box wrote down what actually happened — a compromised box can write a consistent
chain of fiction. What limits that is that admissions are attributed to enrolled
devices with client certificates, and the attendance report is signed by the box's own
key whose fingerprint the organizer publishes in advance.

---

## 5. Mesh chat (Backstage)

### Guaranteed: nothing

Best-effort store-and-forward. That is the whole guarantee, and it is stated first
because every other property below is a measurement rather than a promise.

### Measured, not guaranteed

| Crowd                | Delivery | p95 latency |
| -------------------- | -------- | ----------- |
| 500 phones in a hall | 98.8%    | 293ms       |
| 2,000 phones         | 99.9%    | 292ms       |
| 5,000 phones         | 99.4%    | 556ms       |
| 50 phones in a hall  | 86.1%    | —           |

`gatecrash-sim crowd -sweep` reproduces the table. The fifty-phone row is the honest
one: a sparse field is simply not connected, so delivery there is bounded by whether a
path exists at all. What helps is the store-and-forward buffer — a message carried in
somebody's pocket until they walk into the next group — not a larger relay constant.

These come from a simulator with a deliberately simple radio model, and the mobility
model is random-waypoint, which is wrong in a specific direction: real crowds move in
correlated groups towards stages and bars, so the numbers above are optimistic about
how easily a message crosses a field.

### Guaranteed: contents are confidential; the fact of a transmission is not

Channel messages are ChaCha20-Poly1305 under an Argon2id-derived key; direct messages
are X25519 and per-direction keys; announcements are Ed25519-signed and deliberately
not encrypted. But a BLE mesh broadcasts to everybody in range by construction. That a
channel had traffic, and roughly how much, is visible to anybody listening. It was
never hideable, and a design claiming otherwise would be lying.

### Not guaranteed: iOS in your pocket

iOS restricts Bluetooth advertising aggressively when the screen is locked. A phone in
a pocket is a much worse mesh node than a phone in a hand, and the mitigations —
foreground use, box bridging, local notifications — reduce the problem rather than
remove it. Android is better and not unlimited.

---

## 6. Discovery and the network

### Guaranteed: a scanner can find the box without configuration, four ways

mDNS, a UDP beacon every two seconds, wildcard DNS in AP mode, and a typed IP address
as the floor. Any one of them working is enough, and they are independent — which
matters because venue access points routinely disable multicast without telling
anybody.

### Guaranteed: a captive portal only in AP mode

Intercepting DNS is defensible on a network the box owns and is hijacking on anybody
else's. So it is not configurable: in router mode the interception code does not run.

### Not guaranteed: that TLS is warning-free before enrollment

There is no Let's Encrypt without internet, so the box mints its own CA. Until a device
has been through the enrollment ceremony, its browser will complain, and it should. The
ceremony exists to turn that warning into a fingerprint comparison somebody actually
performs.

---

## 7. Capacity

Honest numbers rather than aspirational ones:

|                                                   | Comfortable      | Where it stops                                         |
| ------------------------------------------------- | ---------------- | ------------------------------------------------------ |
| Scanners per box                                  | 12               | The Pi's radio, not the software                       |
| Scans per second                                  | ~2,300 over HTTP | SQLite's single writer                                 |
| Tickets per event                                 | 50,000           | Nothing structural; the offline filter is 175 KB there |
| Attendee phones on the box's own Wi-Fi (AP mode)  | ~30              | The Pi's radio, firmly                                 |
| Attendee phones served (router mode, venue Wi-Fi) | Thousands        | The wallet is cached and works offline                 |

The AP-mode row is the one that surprises people. A Raspberry Pi is not an access
point, and the answer is not to pretend otherwise — it is that the attendee wallet
caches on first open and generates its rotating codes locally, so a phone that cannot
associate still shows a valid ticket.

---

## How to check any of this yourself

```sh
go test ./...                          # every unit and property test
go test -race ./...                    # the box serves twelve gates from one process
gatecrash-sim event -seeds 5000        # the redemption guarantees, under injected faults
gatecrash-sim crowd -sweep             # the mesh numbers above
go run ./cmd/gatecrash-demo            # a whole event, including the settlement proof
```

If one of these fails on your machine, that is a bug worth reporting, and the seed in
the failure message reproduces it exactly.
