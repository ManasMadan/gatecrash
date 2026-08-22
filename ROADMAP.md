# Roadmap

What is deliberately not built, and what would have to be true for it to be worth
building. A roadmap that lists everything anybody might want is a wish list; this one
lists the things that were considered and postponed, with the reason.

## Next

**Backstage on two phones in a room.** Both apps are now built: the protocol, the BLE
transport, and a screen. Android assembles a real APK in CI; iOS compiles every view and
the whole Core Bluetooth layer under `swift build`, which works because Core Bluetooth and
SwiftUI both exist on macOS.

What has not happened is the only test that counts. Whether two handsets actually find
each other across a field is not a thing any Mac can answer, and it is where the failures
will be: Android's peripheral role is the least-travelled path in every vendor's stack,
and iOS rewrites an advertisement out from under you when the app backgrounds. Everything
above the radio is checked against the Go reference — frame format, dedup filter, relay
probability, carry rule, Argon2id. Everything at the radio is checked by reading it.

An `.ipa` also needs Xcode and a signing identity, which is why the iOS app is archived by
hand rather than in CI. `apps/backstage-ios/README.md` has the steps.

**A cable-pull rig.** The simulator drops the box's power hundreds of times a run, and
that is a model. A smart plug, a real Pi, a real SD card and a hundred real power cuts
under write load is a measurement — and the difference between the two is exactly where
SD cards lie.

**A read-only dashboard token.** Today there is one admin token and it can do everything:
watch the numbers, revoke a device, export the attendance report. A screen in the foyer showing
occupancy therefore needs a credential that could also cancel every scanner, which is the wrong
shape for the job — the `foyer-display` example says so and works around it with a reverse
proxy.

The fix is small: a second token, or a scope on the existing one, that reaches
`GET /v1/admin/stats` and nothing else. It is not done because every screen so far has been on
a machine in the same locked room as the box.

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
