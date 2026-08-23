# Deploying a box

A box is a Raspberry Pi, a static binary, a config file and a manifest. There is no
database server to provision, no message broker, no cloud project, and nothing to
configure at the venue that cannot be done from a phone.

This directory is what turns a fresh Raspberry Pi OS install into that box.

```
deploy/
  systemd/gatecrash.service   the unit: Type=notify, watchdog, hardened
  ap/hostapd.conf             the box's own Wi-Fi, for a field with no infrastructure
  scripts/install.sh          fresh Pi to working box, idempotent
  scripts/update.sh           A/B binary swap with an automatic revert
  scripts/harden.sh           read-only rootfs, so a power cut cannot corrupt the OS
  image/build.sh              a flashable image, built from a manifest and a config
```

## The short version

Cross-compile, copy, install:

```sh
./scripts/build.sh                                  # produces dist/gatecrash-linux-arm64
scp dist/gatecrash-linux-arm64 pi@gate.local:
scp -r deploy pi@gate.local:
ssh pi@gate.local 'sudo ./deploy/scripts/install.sh --binary ./gatecrash-linux-arm64'
```

Then put a manifest where the box can read it and start it:

```sh
scp manifest.json pi@gate.local:
ssh pi@gate.local '
  sudo install -o gatecrash -g gatecrash -m 0600 manifest.json /var/lib/gatecrash/
  sudo systemctl start gatecrash
  sudo journalctl -u gatecrash -f'
```

The boot log prints the three things you need: the dashboard URL with its token, the
certificate fingerprint to compare against when enrolling a scanner, and the
addresses to type into a scanner phone.

## Router mode or AP mode

**Router mode** is the default and the right choice whenever the venue has Wi-Fi.
The box joins it like any other device, and the scanners find it by mDNS, by the UDP
beacon, or by IP address. Nothing about the venue's network is touched.

**AP mode** is for a field. The box becomes the access point, hands out addresses,
answers DNS for every name, and serves a captive portal. Nothing has an uplink, and
that is fine: none of the ticketing needs one.

```sh
sudo ./deploy/scripts/install.sh --ap --ssid "SUNDOWN-GATES" --country IN --binary ./gatecrash
```

The install script configures the access point and does not start it, because
starting it drops the SSH session you are using. Start it from the console or over
Ethernet.

Two things about AP mode are worth knowing before choosing it. The Pi's radio is not
a commercial access point: a dozen scanners and a handful of staff phones are
comfortable, a hundred attendee phones are not, which is why the attendee wallet is
built to work with the network off. And intercepting DNS is only defensible on a
network the box owns — which is why the captive portal is disabled in router mode
rather than configurable.

## Upgrading during an event

Do not. If you must:

```sh
scp dist/gatecrash-linux-arm64 pi@gate.local:
ssh pi@gate.local 'sudo ./deploy/scripts/update.sh ./gatecrash-linux-arm64'
```

Two slots, an atomic symlink swap, a health check, and an automatic revert if the new
binary does not answer within twenty seconds. The old slot stays on disk:

```sh
sudo ./deploy/scripts/update.sh --rollback
```

The reason this exists rather than a package upgrade: a package upgrade that fails
halfway leaves a box that is neither version, and the failure happens on the one
evening nobody has time to debug it.

## Power

The box is expected to lose power. That is designed for rather than guarded against:

- SQLite runs with `synchronous=FULL`, so an acknowledged scan is on the card before
  the guard sees a green screen.
- The admin token, the CA and the enrollment secret are persisted, so a reboot is
  invisible to the control room and does not log a single scanner out.
- The live occupancy picture is rebuilt from the audit log at boot, so the dashboard
  comes back reading the truth instead of zero.

What none of that fixes is a cheap SD card. Cards lie about having completed a write,
and the mitigation is `harden.sh` — a read-only root filesystem, so the only writable
thing on the box is the data directory:

```sh
sudo ./deploy/scripts/harden.sh
sudo reboot
```

A UPS HAT is better still, and the box cooperates with one: it flushes the WAL on
SIGTERM, so a clean shutdown on battery leaves a database a plain `cp` can copy.

## Watching it

`Type=notify` with a thirty-second watchdog, and the heartbeat comes from the
committed scan count rather than from a timer. The distinction matters: a box whose
store has deadlocked is still running, still scheduled, and no longer answering
anybody — and a liveness check that a hung server can pass is not a liveness check.

```sh
systemctl status gatecrash
```

The status line carries the numbers you would otherwise open the dashboard for:
how many are inside, how many gates are scanning, how many were refused. That is
deliberate — the moment you most need those numbers is the moment the dashboard is
what has broken.

## What this does not do

No Docker. The box is one static binary with no shared libraries; a container would
add a runtime, a daemon and an image registry to a machine whose whole appeal is that
it has none of those.

No automatic updates. A box that upgrades itself is a box that upgrades itself during
a show.

No remote access. There is no phone-home, no telemetry and no management plane,
because an air-gapped venue box that dials out is not air-gapped. If you want to
reach it, you are on its network or you are on its Ethernet port.
