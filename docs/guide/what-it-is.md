# What it is

Gatecrash runs an entire event off one Raspberry Pi with no internet.

That is the whole idea, and everything else in these docs follows from it. Ticket
validation at as many gates as you have phones, the control-room dashboard, every
attendee's wallet, and Bluetooth mesh chat between phones — all of it from a single static
binary on a machine that costs less than a night's bar takings.

## The problem it exists for

Ticketing platforms charge a convenience fee per ticket and stop working when the venue's
Wi-Fi does. For a stadium with fibre and a contract, that is fine. For a college fest in a
basketball hall, an indie gig above a bar, a comedy room, a wedding, or a farm party where
the nearest tower is a kilometre away, it is useless — and those are most events, and all
of the ones where the fee hurts most.

Nothing gatecrash does during an event touches the internet, because during an event there
usually isn't one.

## The shape of it

```
                        ┌──────────────────────────────────┐
   scanner phones  ───▶ │           the box                │ ◀───  wall display
   (QR, offline-ok)     │  Raspberry Pi · one binary        │       (dashboard)
                        │  SQLite · own CA · own Wi-Fi      │
   attendee phones ───▶ │  DNS · DHCP · captive portal      │
   (wallet PWA)         └──────────────────────────────────┘
                                       │
                              no uplink required
                                       │
   attendee phones ◀───── BLE mesh ─────┴──▶ attendee phones
   (Backstage chat, works with the box switched off)
```

**The box** is `gatecrash serve`. One binary, one config file, one data directory. It holds
the tickets, decides every scan, serves the three web apps, and — in AP mode — is the
network: its own Wi-Fi, DHCP, DNS and captive portal.

**The scanner** is a web app a guard opens on a phone. It works offline, queues what it
cannot send, and shows a verdict you can read from across a queue.

**The wallet** is a web app an attendee opens once. After that it works with the network
off: the ticket is cached and rotating codes are generated on the phone.

**The dashboard** is the back room: who is inside, which door is struggling, what the gates
are refusing, and who has picked up the alarm somebody just raised.

**Backstage** is the mesh: chat between phones over Bluetooth when there is no network at
all, with the boxes joining in to bridge groups of people who cannot hear each other.

## What you keep and what the box gets

The organizer's private key never touches the box. You mint keys and issue tickets on your
own machine; the box gets a signed **manifest** and can verify tickets without being able
to invent one. That separation is what makes it safe to hand a box to a venue.

## Where to go next

- [Try it in one command](/guide/try-it) — a whole event, no hardware
- [Running an event](/guide/running-an-event) — the actual workflow, start to finish
- [When the box is unreachable](/guide/offline) — the one honest trade in the system
- [Correctness](/guide/correctness) — how any of these claims are checked
