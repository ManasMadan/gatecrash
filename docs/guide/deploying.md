# Deploying a box

A box is a Raspberry Pi, a static binary, a config file and a manifest. No database server,
no message broker, no cloud project, and nothing to configure at the venue that cannot be done
from a phone.

The full detail is in
[`deploy/README.md`](https://github.com/ManasMadan/gatecrash/blob/master/deploy/README.md).

## The short version

```sh
./scripts/build.sh                                  # dist/gatecrash-linux-arm64
scp dist/gatecrash-linux-arm64 pi@gate.local:
scp -r deploy pi@gate.local:
ssh pi@gate.local 'sudo ./deploy/scripts/install.sh --binary ./gatecrash-linux-arm64'
```

`install.sh` is idempotent on purpose: run it again and it upgrades the binary and leaves the
data, the CA and the enrollment secret alone. The alternative is an upgrade that logs every
scanner out on the morning of an event.

## Router mode or AP mode

**Router mode** is the default and right whenever the venue has Wi-Fi. The box joins it like
any other device; scanners find it by mDNS, by the UDP beacon, or by IP address. Nothing about
the venue's network is touched.

**AP mode** is for a field. The box becomes the access point, hands out addresses, answers DNS
for every name, and serves a captive portal:

```sh
sudo ./deploy/scripts/install.sh --ap --ssid "SUNDOWN-GATES" --country IN --binary ./gatecrash
```

It configures the access point and does **not** start it, because starting hostapd drops the
SSH session you are using. Start it from the console or over Ethernet.

Two things to know before choosing AP mode. The Pi's radio is not a commercial access point —
a dozen scanners and a handful of staff phones are comfortable, a hundred attendee phones are
not, which is why the wallet is built to work with the network off. And intercepting DNS is
only defensible on a network the box owns, which is why the captive portal is disabled in
router mode rather than configurable.

## Upgrading during an event

Don't. If you must:

```sh
sudo ./deploy/scripts/update.sh ./gatecrash-linux-arm64
sudo ./deploy/scripts/update.sh --rollback
```

Two slots, an atomic symlink swap, a health check, and an automatic revert if the new binary
does not answer within twenty seconds. A package upgrade that fails halfway leaves a box that
is neither version, on the one evening nobody has time to debug it.

## Power

The box is expected to lose power. That is designed for rather than guarded against: SQLite
runs with `synchronous=FULL`, the admin token and CA and enrollment secret persist, and the
live occupancy picture is rebuilt from the audit log at boot rather than coming back as zero.

What none of that fixes is a cheap SD card, which lies about having completed a write. In
order of how much they help: a USB SSD instead of a card, a UPS HAT, and

```sh
sudo ./deploy/scripts/harden.sh
```

which makes the root filesystem read-only so the only writable thing on the box is the data
directory. A power cut can then damage the database and nothing else, and the database is built
to survive one.

## Watching it

`Type=notify` with a thirty-second watchdog, and the heartbeat comes from the **committed scan
count** rather than a timer. That distinction is the whole point: a box whose store has
deadlocked is still running, still scheduled, and no longer answering anybody, and a liveness
check a hung server can pass is not a liveness check.

```sh
systemctl status gatecrash
```

The status line carries the numbers you would otherwise open the dashboard for — because the
moment you most need them is the moment the dashboard is what has broken.

## Capacity

Honest numbers rather than aspirational ones:

|                                        | Comfortable      | Where it stops                         |
| -------------------------------------- | ---------------- | -------------------------------------- |
| Scanners per box                       | 12               | The Pi's radio, not the software       |
| Scans per second                       | ~2,300 over HTTP | SQLite's single writer                 |
| Tickets per event                      | 50,000           | Nothing structural                     |
| Attendee phones on the box's own Wi-Fi | ~30              | The Pi's radio, firmly                 |
| Attendee phones served on venue Wi-Fi  | Thousands        | The wallet is cached and works offline |

The AP-mode row surprises people. A Raspberry Pi is not an access point, and the answer is not
to pretend otherwise — it is that the wallet caches on first open and generates its rotating
codes locally, so a phone that cannot associate still shows a valid ticket.
