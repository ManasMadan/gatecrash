---
layout: home

hero:
  name: gatecrash
  text: An entire event from one Raspberry Pi
  tagline: >
    Ticket validation at every gate, the control-room dashboard, every attendee's wallet,
    and Bluetooth mesh chat between phones — with no internet at all.
  actions:
    - theme: brand
      text: Try it in one command
      link: /guide/try-it
    - theme: alt
      text: What it is
      link: /guide/what-it-is
    - theme: alt
      text: GitHub
      link: https://github.com/ManasMadan/gatecrash

features:
  - title: Exactly once, and provable
    details: >
      Ten scanners hammering one QR is a single SQLite compare-and-set. That statement is
      the linearization point of the whole system, and every admission can be proved to
      somebody who does not trust the box with sixteen hashes.
    link: /guide/scanning
    linkText: How a scan is decided

  - title: Honest about CAP
    details: >
      When a gate cannot reach the box, something has to give. STRICT stops admitting;
      DEGRADED keeps the queue moving and detects every double use within seconds of the
      network healing. The choice is in the signed manifest, not a default somebody
      discovers at a door.
    link: /guide/offline
    linkText: When the box is unreachable

  - title: Built for the power going out
    details: >
      The box is a Pi in a cupboard behind a bar. The simulator pulls its plug hundreds of
      times a run and asserts that no acknowledged scan is ever lost, that the control room
      is not signed out, and that occupancy comes back as the truth rather than zero.
    link: /guide/correctness
    linkText: Correctness

  - title: Readable across a queue
    details: >
      A guard at 22:00 is watching people, not a phone. A scan floods the screen with one
      colour and one glyph, plays a two-note rise or a low buzz, and vibrates in a pattern
      you can tell apart through a jacket. Text is the third channel.
    link: /guide/scanning
    linkText: At the gate

  - title: Chat with no signal
    details: >
      Twenty thousand phones in a field is a dead network. Backstage is a Bluetooth mesh
      with passphrase channels, X25519 direct messages, signed announcements and a friend
      finder — and the venue boxes bridge the islands over the LAN.
    link: /guide/mesh
    linkText: Mesh chat

  - title: A venue, not a door
    details: >
      Zones with prerequisites, per-tier door allowlists, seated sections laid out along a
      curve, and Dijkstra wayfinding with a step-free variant. A pit wristband scanned
      before the outer gate is refused with directions.
    link: /guide/venue
    linkText: Zones, seats and doors
---

## The numbers

Every one of these is produced by something in the repository, and the command that
produces it is next to it in the [README](https://github.com/ManasMadan/gatecrash).

|                                                  |                                                                   |
| ------------------------------------------------ | ----------------------------------------------------------------- |
| Box binary, `linux/arm64`                        | **12.3 MB**, statically linked                                    |
| Scans per second, over HTTP                      | **~2,300**                                                        |
| Seeded event-days with zero invariant violations | **240,000 scans**, 472 power cuts, 5,000 double uses all detected |
| Mesh delivery, 5,000 phones                      | **99.4%**, p95 **556ms**                                          |
| Offline filter, 50,000 tickets                   | **175 KB**, 49ns lookups                                          |
| Attendee wallet, gzipped                         | **77 KB** of JavaScript                                           |

## What it is not

No cloud during the event. No per-ticket fee. No account for an attendee, and no personal
data on the box — it knows ticket ids and nothing else. No Docker, because the appeal is a
machine with no runtime on it. No automatic updates, because a box that upgrades itself
upgrades itself during a show.

It is also not a stadium product, and the
[capacity table](/guide/deploying#capacity) says where it stops.
