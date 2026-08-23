# HTTP API

Everything the box serves. `api v1`, and the version is in the path so a newer box and an
older client fail loudly rather than subtly.

Three tiers of access, and they are enforced differently:

- **Open** — needed before a device trusts anything. Served on the plain HTTP listener too.
- **Device** — a client certificate from the enrollment ceremony plus a bearer token.
- **Admin** — the dashboard token.

## Open

|                   |                                                                                                                                                                                                                                                                |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /healthz`    | Liveness. What `deploy/scripts/update.sh` polls before deciding a new binary works.                                                                                                                                                                            |
| `GET /v1/meta`    | Event name, api version, mode, and the CA fingerprint.                                                                                                                                                                                                         |
| `GET /v1/time`    | The box's clock and its HLC reading. How a phone with a wrong clock learns its offset without trusting its own.                                                                                                                                                |
| `GET /ca.crt`     | The certificate authority, so a device can install it and stop seeing warnings. Necessarily plain HTTP: a device cannot fetch this over TLS it does not yet trust.                                                                                             |
| `GET /v1/venue`   | The compiled venue plan. `ETag` is a hash of the response body — not the manifest digest, which is a bug this had once: move a gate on the morning of the event and every phone got a `304` forever, so the map went on pointing at a door that was not there. |
| `POST /v1/enroll` | The enrollment ceremony. An invite code in, a client certificate and device token out.                                                                                                                                                                         |

## Device

|                      |                                                                                                                                     |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/scan`      | The one that matters. A `scan_id`, a payload and a checkpoint in; a verdict out.                                                    |
| `GET /v1/manifest`   | The scanner's mirror: ticket ids as a Bloom filter, the device's checkpoints, the venue, and the consistency mode.                  |
| `GET /v1/stream`     | Server-sent events — redemptions by other gates, so a scanner's mirror stays current without polling.                               |
| `POST /v1/incidents` | The bouncer's button. Crush, medical, need-staff. The box attaches the gate, zone and queue rate.                                   |
| `GET /v1/incidents`  | What the control room has said back, filtered to this gate — a door does not need somebody else's traffic. Emergencies cross zones. |
| `GET /v1/guidance`   | Where a ticket should go next, for a scanner showing an attendee the way.                                                           |

### POST /v1/scan

```json
{
  "scan_id": "9f8c2b1e4d6a47f0",
  "payload": "GC1.PV725ZYDHUZ7627WG4PBOXATYU.k3f...",
  "checkpoint": "gate-north",
  "device_hlc": "1787413618470.0",
  "offline_admitted": false,
  "observed_at": "2026-08-21T19:42:10+05:30"
}
```

`scan_id` is client-generated and it matters: resend the same one and you get the original
verdict rather than a spurious `ALREADY_USED`. That is what makes a retry over bad Wi-Fi safe.

`offline_admitted` says the scanner already let this person through during a partition. In
DEGRADED that is how a double use gets flagged with both records attached; see
[when the box is unreachable](/guide/offline).

```json
{
  "verdict": "ADMIT",
  "severity": "admit",
  "reason": "Let them in",
  "tier_name": "General Admission",
  "tier_colour": "#3B82F6",
  "seat_label": "Block A row A seat 1",
  "occurrence": 0,
  "hlc": "1787413618471.0"
}
```

A refusal carries its evidence — `ALREADY_USED` names the gate and how long ago — and a
`redirect` carries the checkpoint to send them to.

## Attendee

Open, because a wallet has no credential to present. The ticket id is the capability, which is
why the wallet keeps it in the URL **fragment**: a fragment is never sent to a server, so the
id does not end up in an access log, a referer header or a proxy cache.

|                              |                                                                                                                               |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `GET /v1/ticket/{id}`        | The wallet's view: tier, seat, where they have been, and the rotating secret so the phone can generate codes with no network. |
| `POST /v1/ticket/{id}/claim` | Binds a ticket to a device, so a forwarded link stops working.                                                                |
| `GET /v1/ticket/{id}/nearby` | Nearest amenities by walking time, filtered to zones this ticket may enter, with `step_free=true` honoured.                   |
| `GET /v1/announcements`      | Organizer messages, signed.                                                                                                   |

## Admin

Bearer token, from the boot log. Persisted across reboots so a power cut does not sign the
control room out.

|                                      |                                                                                                                                                                                         |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /v1/admin/stats`                | The whole dashboard in one object: occupancy per zone, throughput per gate with a sparkline, verdict breakdown, turnout per tier, scanner liveness, incidents and the response summary. |
| `GET /v1/admin/stream`               | The same, as server-sent events.                                                                                                                                                        |
| `GET /v1/admin/incidents`            | The board.                                                                                                                                                                              |
| `POST /v1/admin/incidents/{id}`      | Acknowledge, assign, resolve, cancel. Requires an actor; cancelling requires a reason.                                                                                                  |
| `POST /v1/admin/invite`              | Mint a scanner invite, with the QR payload to display.                                                                                                                                  |
| `GET /v1/admin/devices`              | The scanner roster.                                                                                                                                                                     |
| `POST /v1/admin/devices/{id}/revoke` | A scanner left in a taxi is a credential in a taxi.                                                                                                                                     |
| `POST /v1/admin/tickets/{id}/revoke` | A chargeback or a stolen ticket.                                                                                                                                                        |
| `POST /v1/admin/announce`            | Signed, and relayed into the mesh at priority.                                                                                                                                          |
| `POST /v1/admin/seal`                | Cut a Merkle checkpoint.                                                                                                                                                                |
| `GET /v1/admin/verify`               | Replay the chain and report.                                                                                                                                                            |
| `GET /v1/admin/attendance/{id}`      | The inclusion proof for one ticket.                                                                                                                                                     |
| `GET /v1/admin/export`               | The signed attendance report.                                                                                                                                                           |
| `GET /v1/admin/flags`                | Detected double uses, with both records.                                                                                                                                                |
| `GET /v1/admin/log`                  | Audit rows, paginated.                                                                                                                                                                  |

## Errors

```json
{ "code": "bad_token", "message": "Not signed in." }
```

A machine-readable `code` and a sentence somebody can act on. `message` is written for a
person reading it on a phone in a field, which is why none of them say "an error occurred".

## Rate limiting

The scan endpoint is limited per device. A scanner cannot be made to hammer the box faster
than a human can present tickets, and a rate limit is the difference between one
misconfigured phone and a box that stops answering the other eleven gates.

## Using it

[`gatecrash-client`](/reference/packages) is the typed client, and it is what the three
shipped apps use — so anything they can do, you can do.
