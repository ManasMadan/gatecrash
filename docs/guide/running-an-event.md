# Running an event

Three phases: before, during, after. The private key stays with you the whole way.

## Before — on your machine, never on the box

```sh
gatecrash-keys keygen -out keys.json
```

This is the organizer key. The box never sees it, and that is the point: a box that could
sign its own manifest could invent tickets. Keep it the way you would keep the key to the
venue.

```sh
gatecrash-keys venue -out venue.json
```

A worked example rather than an empty skeleton, because the interesting part of a venue plan
is the relationships — which zone is nested in which, which door requires which zone — and
an empty file teaches none of that. Edit it. [Zones, seats and doors](/guide/venue) explains
what each field does.

```sh
gatecrash-keys issue -keys keys.json -venue venue.json \
  -n 400 -tier ga -section block-a -out ga.json

gatecrash-keys issue -keys keys.json -venue venue.json \
  -n 80 -tier vip -out vip.json -event <the event id printed above>
```

Seated tiers fill rows in order. Reuse the event id from the first run, or the second batch
belongs to a different event and every one of those tickets is a `WRONG_EVENT` at the door.

```sh
gatecrash-keys manifest -keys keys.json -venue venue.json -tickets ga.json,vip.json \
  -event "Sundown Sessions" -venue-name "Kingdom of Dreams" \
  -doors 2026-08-21T18:00:00+05:30 -curfew 2026-08-22T01:00:00+05:30 \
  -support "WhatsApp +91 90000 00000" -out manifest.json
```

The manifest is what the box gets. It carries the venue, the tickets, the event master key
and the organizer's signature.

```sh
gatecrash-keys seal -in manifest.json -out manifest.sealed.json
```

Seal it if the file is going to travel. Unsealed, the manifest can mint a rotating code for
every ticket at that event, so treat the file the way you would treat the key — and see
[After the event](/guide/settlement) for what to do with it afterwards.

## During — at the venue

Put the manifest where the box can read it and start it. [Deploying a box](/guide/deploying)
covers the machine itself.

```sh
sudo install -o gatecrash -g gatecrash -m 0600 manifest.json /var/lib/gatecrash/
sudo systemctl start gatecrash
sudo journalctl -u gatecrash -f
```

The boot log prints three things you need:

```
  Sundown Sessions is live

    scanner    https://10.11.0.1:8443/scanner/
    attendee   https://10.11.0.1:8443/attendee/
    dashboard  https://10.11.0.1:8443/dashboard/?token=8ViqVKt4hsuAxiFQZpEjZFGuqJE8X1zr
    friendly   http://gate.local:8443  ·  http://go.gate

    certificate fingerprint  09:A7:DD:AA:9F:1D:46:06:...
```

**Open the dashboard** on the wall display. The token is in the URL and the app strips it
from the address bar immediately, so it does not sit in somebody's browser history. It
survives a reboot, so a power cut mid-event does not sign the control room out.

**Enrol each scanner.** On the dashboard's Setup tab, mint an invite; the guard scans it
with their phone at `/scanner/`. The phone then shows the certificate fingerprint it
pinned — if that does not match the one in the boot log, somebody is standing between them,
and this is the moment to find out.

Assign each scanner to its checkpoints while you are there. A device with no assignment
scans nothing, which is deliberate: a scanner that works everywhere is a scanner that admits
to the pit when somebody picks up the wrong phone.

**Send the wallet link** with the ticket. The id is in the URL fragment, so it never reaches
a server log.

## After

```sh
gatecrash seal      # a Merkle checkpoint over the whole log
gatecrash verify    # every row still hashes to the head
gatecrash export    # attendance, with a proof per ticket
```

[After the event](/guide/settlement) covers what those proofs are for.
