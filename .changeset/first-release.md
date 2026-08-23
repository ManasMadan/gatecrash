---
'gatecrash-client': minor
'gatecrash-ui': minor
---

First release, alongside the box they talk to.

`gatecrash-client` is the wire types and a thin client, with zero dependencies: everything the
box serves, all fifteen verdicts, both QR formats, and a reader for the offline Bloom filter that
lets a gate tell "a ticket I cannot confirm" from "a QR somebody generated in a car park".

`gatecrash-ui` is the verdict screen and the venue map. The verdict screen is a colour flood with
one glyph, a synthesised tone and a distinct haptic pattern, because a guard at 22:00 is watching
a queue rather than a phone. The map renders for an attendee and for the control room from the
same component, since they are asking different questions of the same picture.
