# Roadmap

What is deliberately not built, and what would have to be true for it to be worth
building. A roadmap that lists everything anybody might want is a wish list; this one
lists the things that were considered and postponed, with the reason.

## Next

**Backstage on Android and iOS.** The mesh protocol is written, tested and specified —
frame format, dedup, relay rule, crypto, and a Noise XX transcript fixture the ports can
be checked against. What is missing is the two platform layers: BLE advertising and GATT
on Android, Core Bluetooth on iOS. They are the reason the protocol lives in one place
and is ported rather than reinvented.

**A load rig with real percentiles.** `go test -bench` gives a mean, and a mean is the
wrong statistic for a queue. What matters is the p99 of a scan under twelve gates of
concurrent load, because the p99 is the guard standing there wondering if it worked.
An HDR histogram and a coordinated-omission-free load generator.

**A cable-pull rig.** The simulator drops the box's power hundreds of times a run, and
that is a model. A smart plug, a real Pi, a real SD card and a hundred real power cuts
under write load is a measurement — and the difference between the two is exactly where
SD cards lie.

## Considered, and not now

**Multiple boxes with a shared view.** One box handles thirty times the load of a large
event, so the reason to want two is redundancy rather than throughput. Two boxes sharing
the exactly-once guarantee is Raft or a CRDT OR-set, and either is a large amount of
machinery in the middle of the one path that must not be wrong.

The design is worth stating because the shape is unusual: with an OR-set, a _merge
conflict is the double-use detector_. Two boxes that both admitted a ticket produce a
set with two elements, and that is precisely the flag DEGRADED mode already raises. So
the CRDT is the natural backbone for DEGRADED and Raft is the only honest answer for
STRICT.

**Would build it when:** somebody runs a 10,000-person event on this and wants a warm
standby. Until then, the answer is a second SD card with the same image and a five-minute
recovery, which is a better answer than a distributed system nobody has operated.

**A cloud presale layer.** Selling tickets needs the internet, a payment gateway and
somewhere to keep names — all three of which the box deliberately does not have. That is
a separate service that produces a manifest, and keeping it separate is what lets the box
store no personal data at all.

**Would build it when:** there is a real event to sell tickets for. Building a payments
integration with no transactions to process is how you end up with an integration that
has never seen a refund.

**LoRa for staff comms.** A LoRa HAT on the boxes would give a staff channel with
kilometre range across a festival site, which is genuinely useful and genuinely
regulated — the legal duty cycle in most countries is around 1%, which is fine for
"gate 4 is backing up" and useless for anything conversational. It needs hardware to
develop against.

**Thermal printing for door sales.** ESC/POS over USB, for an event selling at the gate.
Straightforward, and it needs a printer on a desk to be worth writing.

**A UPS HAT integration.** The box already flushes its WAL on `SIGTERM`, so a clean
shutdown on battery leaves a database `cp` can copy. Reading the battery state to
initiate that shutdown needs the HAT.

## Not planned

**A hosted version.** The entire premise is that the venue owns the box and pays nothing
per ticket. A hosted gatecrash is a ticketing platform with extra steps, and there are
enough of those.

**An attendee account.** The box knows ticket ids. Adding identity would mean storing
personal data on a machine in a cupboard behind a bar, and every feature that seems to
need it — resale, transfer, "my friend has my ticket" — is better served by reissuing a
ticket from the presale layer.

**Face recognition, or any biometric gate.** No.

**Automatic updates.** A box that upgrades itself upgrades itself during a show.

**Telemetry.** An air-gapped venue box that dials out is not air-gapped.
