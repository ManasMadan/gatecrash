# Incidents and staffing

A bouncer holding a barrier is not going to fill in a form.

So the scanner has one screen of buttons — crush, medical, fight, refusal dispute, gate
offline, and _send me more people_ — and the box attaches everything else on the way through.

## What the box fills in

The gate, the zone, the device, and the current queue rate. The control room does not see
"help"; it sees:

> **NEED STAFF** · North Gate · Festival Ground
> Asking for 3 people. This gate is doing 14 a minute.

That second sentence is the box's, not the bouncer's. Somebody with a hand on a barrier
pressed one button.

Crush and medical are `emergency` severity, which means they cross zone filters — an
ordinary alert is only shown to the gates it concerns, because a door does not need somebody
else's traffic, but everybody needs to know about a crush.

## Who has it

Four actions, and nothing else:

- **I have it** — acknowledged, by name.
- **Send somebody** — assigned.
- **Done** — resolved.
- **False alarm** — cancelled, and it asks for a reason rather than letting an alarm
  silently disappear.

Every transition records who made it. "Somebody assumed somebody else had it" is the failure
this board exists to prevent, and it is not preventable without attribution.

## The numbers on the board

Two of them are easy to get wrong, and both were wrong here first:

**Unattended** — open, past a thirty-second grace period, and still nobody has said they
have it. This is the live number, the one an operator watches.

**Never picked up** — closed without anybody ever acknowledging it. This is the post-event
number, for the debrief.

The first version counted every open incident as never-acknowledged, including one raised
four seconds ago. The number never read zero, so it meant nothing. Splitting them is what
made both useful.

Alongside those: median time to pickup, worst time to pickup, and median time to resolution.

## The alarm strip

An emergency puts a red panel across the top of the dashboard with a timer that climbs and
turns red after a minute. The timer runs off its own one-second clock rather than the
two-second poll — a stopwatch that counts 0, 2, 4 is a data refresh rate leaking into the
number most likely to be read out loud over a radio.

## Gates going quiet

The dashboard raises this on its own, and the distinction it draws matters: a gate with no
queue is quiet and fine. A gate that was doing forty scans a minute and has done none for two
is a problem. "Quiet" requires both silence **and** a recent history of not being silent,
which is why an unopened door does not sit there as a permanent false alarm.
