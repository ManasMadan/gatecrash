# Mesh chat

Twenty thousand phones in a field is a dead network. Backstage carries messages between them
over Bluetooth with no infrastructure at all.

It is a separate app from the ticket, deliberately: the wallet is a web app because a guard
or an attendee should not have to install anything, and the mesh **cannot** be a web app
because Web Bluetooth has no peripheral mode and does not exist on iOS Safari. A browser
cannot advertise, and a node that can only listen is not a mesh node.

The wallet links to it from under the QR. The ticket works entirely without it.

## What it does

**Channels.** `#lost-and-found`, `#gate-3`, `#campsite`. The group is whoever knows the
passphrase, and the key comes from that passphrase through Argon2id — so a passphrase
somebody says out loud at a campsite is still expensive to brute-force from a captured frame.

**Direct messages.** X25519 to agree a key, ChaCha20-Poly1305 to use it, with the two
directions on separate keys so a message cannot be replayed back at its own sender.
Identities are ephemeral per event: no account, nothing to subpoena, and nothing linking this
festival to the next one.

**Announcements.** From the organizer, originating at the box, Ed25519-signed and **not**
encrypted — "Gate 4 is now open" is not a secret, and the property that matters is that
nobody else can say it. They relay at priority, so they cross a saturated field.

**Friend finder.** Two people exchange a beacon key once, and after that each phone
advertises a rotating token the other recognises; the app plays warmer and colder on signal
strength. The token rotates every window, because a constant identifier broadcast in a field
is how early Bluetooth trackers became a stalking tool.

## The boxes join in

This is the part that makes it work in practice. BLE mesh's worst real-world failure is two
clusters of people thirty metres apart who never hear each other, and no amount of relaying
fixes a gap nobody can bridge.

The venue boxes are super-nodes: they hear the mesh on their own radios and bridge it between
themselves over the LAN. Two groups at opposite ends of a field are then one hop apart
through the wire.

## What it promises

Nothing. Best-effort store-and-forward, and that is the whole guarantee.

What it has been _measured_ to do, in the simulator:

| Crowd                | Delivery | p95 latency |
| -------------------- | -------- | ----------- |
| 500 phones in a hall | 98.8%    | 293ms       |
| 2,000 phones         | 99.9%    | 292ms       |
| 5,000 phones         | 99.4%    | 556ms       |
| 50 phones in a hall  | 86.1%    | —           |

The fifty-phone row is the honest one. A sparse field is simply not connected, so delivery
there is bounded by whether a path exists at all — and what helps is a message carried in
somebody's pocket until they walk into the next group, not more relaying.

## Honest physics

- BLE is 10–30 metres indoors, and what makes that range vary so much is what is between the
  two radios, which at a concert is bodies.
- **iOS restricts advertising aggressively when the screen is locked.** A phone in a pocket
  is a much worse node than a phone in a hand. The mitigations — foreground use, box
  bridging, local notifications — reduce the problem rather than remove it.
- Android is better and not unlimited: background scanning is throttled, and some OEM power
  managers kill it outright.
- Contents are confidential; the _fact_ of a transmission is not. A BLE mesh broadcasts to
  everybody in range by construction, and a design claiming otherwise would be lying.

## Status

The protocol is written, specified and verified in all three languages — Go for the box,
Kotlin for Android, Swift for iOS — against fixtures the Go side generates. What is not done
is the two platform radio layers, which need devices. See
[the protocol](/guide/mesh-protocol) and
[ROADMAP.md](https://github.com/ManasMadan/gatecrash/blob/master/ROADMAP.md).
