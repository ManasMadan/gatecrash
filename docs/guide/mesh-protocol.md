# The mesh protocol

The full specification is
[`proto/backstage.md`](https://github.com/ManasMadan/gatecrash/blob/master/proto/backstage.md)
in the repository. This page is why it looks the way it does.

## The hard problem is airtime

Not encryption. With five hundred phones in radio range, a protocol where everybody
rebroadcasts everything spends the entire 2.4GHz band on duplicates within seconds and
flattens every battery in the field.

Everything that looks like an optimisation is load-bearing:

**Dedup.** A cuckoo filter of message ids, two generations, rotated every ten minutes. Without
it a message ping-pongs between two phones forever. A cuckoo filter rather than a Bloom filter
because entries have to expire and Bloom filters cannot forget — a filter that fills up and
starts refusing to remember new messages is worse than no filter. 64 KiB for 8192 ids.

**Density-adaptive relay.** `p = min(1, k / neighbours)`, with `k = 3` and neighbours
estimated from distinct senders in a thirty-second window. In a field of five people
everybody relays; in a pit of five hundred about three phones per neighbourhood do, and the
message still crosses because five hundred phones each roll that die.

**Jitter.** Up to 250ms before a rebroadcast. Without it, every node that decided to relay
transmits at the same instant, and on a shared medium simultaneous transmissions are
collisions rather than deliveries.

**Priority.** Organizer announcements ignore the density rule. That is also why the priority
bit is not available to attendee traffic: a flag anybody could set is a broadcast storm
anybody could start.

## Where k = 3 comes from

The crowd simulator, not intuition. `gatecrash-sim crowd -sweep` produces the table, and the
first version of the comment justifying `k` quoted figures that turned out to be wrong when
finally measured.

Five buys the last half a point of delivery for 40% more airtime, which is the wrong trade
when the cost is everybody's battery.

## The one detail that breaks ports

The AEAD's additional data is the frame header **with the TTL byte zeroed**.

It has to be. Every relay decrements the TTL, so a TTL inside the authenticated data would
mean a frame failed to authenticate at the first hop — the message would travel exactly one
hop and the protocol would not work at all.

What that costs: anybody can rewrite a TTL in flight. Raising it is bounded by the limit every
receiver enforces independently, and lowering it is indistinguishable from staying silent,
which any node can do anyway. Neither is worth defending against, and both are written down
rather than glossed over.

Everything else _is_ covered, so a frame cannot be re-labelled into another channel, promoted
to priority, or re-stitched into a different message without breaking its tag.

## Three implementations, one reference

Go, Kotlin and Swift. Three implementations that _almost_ agree is worse than one, because
the failure does not look like a failing test — it looks like a message that never arrives.

So Go is the reference, it generates the fixtures, and both ports assert against them in CI on
every pull request. Neither port needs an SDK, an emulator or a device, because the protocol
layer imports nothing from Android or CoreBluetooth — which is exactly why it is separated
from the radio.

That separation earned itself immediately. The Kotlin disagreed with Go on `splitmix64(1)`,
which turned out to be a hand-written expectation rather than a code bug. The Swift had a
`Data` slice bug that would have read the wrong bytes from any frame a radio callback handed
over as a subrange. And `a * a >> 32` means different things in Swift and Go — Swift gives the
shift higher precedence — which broke Argon2id in a way that still matched the reference for
the first two slices.

Verify them yourself:

```sh
./apps/backstage-android/verify.sh   # needs kotlinc
./apps/backstage-ios/verify.sh       # needs a Swift toolchain
```
