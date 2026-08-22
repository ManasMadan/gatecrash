# door-sales

Somebody turns up without a ticket, pays cash, and needs to be inside thirty seconds later.

This is the awkward case for any ticketing system, and gatecrash makes it _more_ awkward on
purpose: the box holds the organizer's **public** key, not the private one, so it cannot mint a
ticket. A box that could sign its own tickets could invent them, and that is the property the
whole trust model rests on.

Two honest ways to do it:

**Pre-issue a block.** Before the event, issue a few hundred tickets marked as door sales and
hand them out as needed. Boring, needs no extra software, and the block is a hard ceiling on
how many can exist.

**Run this on the laptop that holds the key.** It mints one at a time and prints or displays it.

```sh
node index.mjs --keys keys.json --venue venue.json --event <event-id> --tier ga
```

## What not to do

Do not copy the private key onto the box. The box spends the night in a cupboard behind a bar;
the laptop is with you. That is the entire difference, and it is why this example lives outside
the box rather than as an endpoint on it.

## Why it shells out

It calls `gatecrash-keys issue` rather than signing payloads itself. The signing format is the
one thing here that must not have a second, untested implementation — a payload this script got
subtly wrong is a ticket somebody paid for that no gate will accept, discovered at the door.
