# Configuration

One JSON file, usually `/etc/gatecrash/config.json`. Everything has a working default: a box
with no configuration at all boots, mints its own certificate authority, serves on `:8443`,
and waits for a manifest.

Precedence, lowest to highest: **defaults → file → `GATECRASH_*` environment → flags.**

## Router mode

```json
{
  "mode": "router",
  "data_dir": "/var/lib/gatecrash",
  "listen": ":8443",
  "listen_plain": ":8080",
  "hostname": "gate",
  "mdns": true,
  "beacon": true,
  "synchronous": "FULL",
  "seal_every": "5m",
  "log_level": "info",
  "log_json": true
}
```

## AP mode

Adds the fields that only mean something when the box _is_ the network:

```json
{
  "mode": "ap",
  "subnet": "10.11.0.0/24",
  "box_ip": "10.11.0.1",
  "ssid": "GATECRASH",
  "iface": "wlan0",
  "dns_port": 53,
  "upstream_dns": []
}
```

## Fields

| Field                   | Default                     | Notes                                                                                                                                                                                                                                                    |
| ----------------------- | --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mode`                  | `router`                    | `router` joins the venue's network; `ap` becomes it. The captive portal only runs in `ap`, because intercepting DNS is defensible on a network you own and hijacking on anybody else's.                                                                  |
| `data_dir`              | `/var/lib/gatecrash`        | The database, the WAL, the CA, the enrollment secret and the admin token. The only path the box writes to.                                                                                                                                               |
| `listen`                | `:8443`                     | HTTPS. The camera needs a secure context, so this is where the apps are served.                                                                                                                                                                          |
| `listen_plain`          | `:8080`                     | HTTP. Serves the CA certificate, the captive portal and `/healthz` — the things a device needs _before_ it trusts the CA.                                                                                                                                |
| `hostname`              | `gate`                      | The mDNS name and the certificate's subject: `gate.local`.                                                                                                                                                                                               |
| `manifest`              | —                           | A manifest to load at boot. Empty means read the cached copy from `data_dir`.                                                                                                                                                                            |
| `manifest_passphrase`   | —                           | For a sealed manifest. Set it via the environment, never in this file.                                                                                                                                                                                   |
| `organizer_fingerprint` | —                           | The only key the box will accept a manifest from. **Set this for a real event.** Without it, the box accepts any self-consistent manifest, which is fine for a demo and wrong at a venue — and the boot log says so loudly.                              |
| `admin_token`           | —                           | Empty means mint one on first boot, keep it `0600` in `data_dir`, and print it at every boot. That is the right default: a hardcoded token is no token, and a token minted fresh on every boot signs the control room out every time the power flickers. |
| `mdns`                  | `true`                      | Answers `gate.local`. Venue access points routinely disable multicast, which is why this is one of four discovery paths rather than the only one.                                                                                                        |
| `beacon`                | `true`                      | A UDP broadcast on `:47474` every two seconds carrying the name, address and CA fingerprint. Immune to multicast being switched off.                                                                                                                     |
| `synchronous`           | `FULL`                      | SQLite durability. `FULL` is what a real box runs: the card lies about fsync and this is the closest SQLite can get to insisting.                                                                                                                        |
| `seal_every`            | `5m`                        | How often to cut a Merkle checkpoint.                                                                                                                                                                                                                    |
| `log_level`             | `info`                      | `debug`, `info`, `warn`, `error`.                                                                                                                                                                                                                        |
| `log_json`              | `false`                     | Structured output, which is what the systemd unit sets.                                                                                                                                                                                                  |
| `subnet`, `box_ip`      | `10.11.0.0/24`, `10.11.0.1` | AP mode only. The DHCP pool and the box's own address.                                                                                                                                                                                                   |
| `ssid`, `iface`         | `GATECRASH`, `wlan0`        | AP mode only.                                                                                                                                                                                                                                            |
| `dns_port`              | `53`                        | AP mode only.                                                                                                                                                                                                                                            |
| `upstream_dns`          | none                        | AP mode only. Empty means the box answers everything itself and forwards nothing, which is the point of a box with no uplink.                                                                                                                            |

## Environment

Every one of these overrides the file, which is what the systemd unit uses so that secrets
live in `/etc/gatecrash/secrets.env` at `0600` rather than in a world-readable config:

```
GATECRASH_MODE                   GATECRASH_LOG_LEVEL
GATECRASH_DATA_DIR               GATECRASH_LOG_JSON
GATECRASH_LISTEN                 GATECRASH_SSID
GATECRASH_LISTEN_PLAIN           GATECRASH_IFACE
GATECRASH_HOSTNAME               GATECRASH_MDNS
GATECRASH_MANIFEST               GATECRASH_BEACON
GATECRASH_MANIFEST_PASSPHRASE    GATECRASH_SYNCHRONOUS
GATECRASH_ORGANIZER_FINGERPRINT  GATECRASH_ADVERTISE
GATECRASH_ADMIN_TOKEN            GATECRASH_SEAL_EVERY
```

## What is deliberately not configurable

**The consistency mode.** It lives in the signed manifest, not here, because whether gates
may admit during a partition is the organizer's decision and must not be changeable at the
venue by whoever has SSH.

**The captive portal.** On in AP mode, off in router mode, no switch. See above.

**The audit log.** There is no option to disable it, thin it, or skip refusals. A log that can
be turned off is not evidence.
