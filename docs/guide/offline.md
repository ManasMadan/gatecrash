# When the box is unreachable

This is the one place gatecrash refuses to pretend. When a gate cannot reach the box,
something has to give, and no amount of engineering removes the choice.

|                                      | STRICT (default)                  | DEGRADED (opt-in per event)                       |
| ------------------------------------ | --------------------------------- | ------------------------------------------------- |
| A gate that has lost the box         | Holds. Amber screen, no admission | Admits from its local mirror                      |
| Double admission possible?           | **No**                            | **Yes**                                           |
| Double use detected?                 | n/a                               | **Always**, within seconds of the network healing |
| Evidence kept                        | n/a                               | Both scan records, on the security feed           |
| Queue behaviour when the box is down | Stops                             | Keeps moving                                      |

Prevention under partition is impossible. That is CAP, not a missing feature, and any
product claiming both is either lying or has not thought about it.

So the mode lives in the **signed manifest** — the organizer's decision, made in advance,
not a default somebody discovers at a gate at 21:00 — and every screen shows which one is in
force.

## Which to pick

**STRICT** if the tickets are expensive or the capacity is legally binding. A queue that
stops is a problem you can see and solve with a second door or a manual list. A double
admission is a problem you find out about from a fire officer.

**DEGRADED** if the venue's Wi-Fi is genuinely bad and the cost of a stalled queue is worse
than the cost of a handful of duplicates you will hear about within seconds. A free college
fest with four thousand people arriving in twenty minutes is the case this exists for.

## What a scanner can still decide alone

Quite a lot, which is why STRICT holding is not the same as a gate going dark:

- **Malformed** — refuse. No network needed to know a QR is not a ticket.
- **Unknown ticket** — refuse. The box ships every scanner a Bloom filter of valid ticket
  ids: 175 KB for fifty thousand tickets, with a one-in-a-million false positive rate. This
  is what separates "a ticket I cannot confirm" from "a QR somebody generated in a car park".
- **Expired rotating code** — refuse. The window arithmetic is local.
- **Already used, as far as this phone knows** — refuse, from its own mirror of what it has
  admitted.
- **Everything else** — this is the STRICT/DEGRADED fork.

## What happens when it comes back

The scanner drains its queue. Every scan carries the `scan_id` it was given at the time, the
scanner's clock reading, and — in DEGRADED — a flag saying the person was already let
through.

The box replays them. A queued scan that loses the CAS but was flagged as offline-admitted
means a real person really did walk through a real door twice, so it is **flagged** with both
records attached and appears on the dashboard's security feed within seconds.

Because the timestamps are hybrid logical clocks rather than wall time, a scanner whose clock
is two minutes out does not reorder the log. And because throughput is measured at processing
time rather than at the scan's own timestamp, a scanner draining a twenty-minute backlog
shows as busy rather than idle — which was a bug once, and is the kind that makes an operator
think a gate has died at the moment it is working hardest.

## Not guaranteed

An SD card that ignores flushes entirely can still lose a committed transaction, and a
scanner phone that is lost before it reconnects takes its queue with it. Both are in
[DELIVERY-GUARANTEES.md](https://github.com/ManasMadan/gatecrash/blob/master/DELIVERY-GUARANTEES.md),
which is written as guaranteed / not guaranteed / measured for exactly this reason.
