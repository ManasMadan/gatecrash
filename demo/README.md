# demo

A box seeded to look like 21:40 rather than like zero.

```sh
pnpm demo
```

`go run ./cmd/gatecrash-demo` proves the system works and prints text. This one is for _showing_
it: it mints keys, issues 300 tickets, boots a box, enrols two scanners, walks 160 people in
through the north gate and 55 of them through to their seats, then raises the kind of thing that
actually happens — a crush alarm from the pit, a request for three more staff with the queue rate
attached, and a priority announcement.

Then it prints three URLs and holds the box open:

```
  Sundown Sessions is live — 158 inside of 300

    dashboard  http://127.0.0.1:18080/dashboard/?token=...
    scanner    http://127.0.0.1:18080/scanner/
    attendee   http://127.0.0.1:18080/attendee/#/t/PV725ZYDHUZ7627WG4PBOXATYU
```

The dashboard is worth opening first: occupancy against capacity per zone, per-gate throughput
with sparklines, the verdict breakdown, and the alarm strip with a timer climbing. The attendee
link is a seated ticket that has **not** come in yet, so it shows the route to their door rather
than a map of where they already are.

## Docker

```sh
docker compose up
```

Same thing in a container, if you would rather not have Go and Node on the machine. It is a
convenience for trying it — the real box is a single static binary and
[deploy/](https://github.com/ManasMadan/gatecrash/blob/master/deploy/README.md) explains why
there is no Docker in the deployment story.

## This is not a test

The tests are `go test ./...` and the simulator. This is a fixture with a nice front door, and
if it breaks, that is worth fixing but it does not mean the box is wrong.
