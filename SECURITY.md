# Security

## Reporting a vulnerability

**Do not open a public issue.** This software decides who gets into a building, so a
flaw in it has a physical consequence and a window where it can be used before it is
fixed.

Report it through [GitHub's private advisory
form](https://github.com/ManasMadan/gatecrash/security/advisories/new), or by email to
the address on [github.com/ManasMadan](https://github.com/ManasMadan).

What helps:

- what an attacker gets, in the terms of an actual event — "admits a used ticket at any
  gate" is more useful than "signature verification is weak"
- whether it needs to be on the venue network, hold an enrolled device, or be physically
  at the box
- a seed, if the simulator can reproduce it: `gatecrash-sim event -seed N -seeds 1`

This is a one-person project, so there is no committed response time. Expect an
acknowledgement within a few days and a fix or an explanation before any disclosure.

## What is in scope

Anything that breaks a promise in
[DELIVERY-GUARANTEES.md](DELIVERY-GUARANTEES.md). In particular:

- admitting a ticket twice at a once-only checkpoint in STRICT mode
- an undetected double use in DEGRADED mode
- forging a payload that a gate accepts
- an audit log that can be edited without the head changing
- an inclusion proof that verifies against a record that was not in the log
- reading a mesh channel or a direct message without its key
- forging an organizer announcement
- a scanner admitting outside its checkpoint allowlist
- reaching an admin endpoint without the admin token
- anything that lets a device on the venue Wi-Fi impersonate the box

## What is not in scope

These are documented properties rather than oversights, and each has a reason next to
it in the code:

- **Double admission in DEGRADED mode.** The mode exists to make that trade explicit.
  Detection is the guarantee; prevention under partition is impossible.
- **Traffic analysis of the mesh.** A BLE mesh broadcasts to everybody in range by
  construction. Contents are protected; the existence of traffic is not.
- **Rewriting a mesh hop count.** The TTL is outside the authenticated data because
  every relay decrements it. Raising it is bounded by the limit every receiver enforces;
  lowering it is indistinguishable from staying silent.
- **A browser warning before enrollment.** There is no public CA without internet. The
  ceremony turns the warning into a fingerprint comparison, which is the point.
- **Denial of service by radio.** Anybody with a 2.4GHz transmitter can jam Wi-Fi or BLE.
  The mitigation is that gates keep working offline, not that jamming is prevented.
- **A compromised box writing a consistent chain of fiction.** A hash chain proves the
  log has not been edited since it was written, not that it was true when written. The
  limits are device attribution and a box key whose fingerprint the organizer publishes.
- **Physical access to the box.** Somebody who can hold the SD card has the event master
  key. Seal the manifest, and treat the card as the credential it is.

## The threat model

The table in the [README](README.md#threat-model) is the summary. The reasoning behind
each row is in the code next to the thing that implements it, which is the only place it
cannot drift out of date.

## Cryptography

| What                 | Primitive                                      | Why there rather than the usual choice                              |
| -------------------- | ---------------------------------------------- | ------------------------------------------------------------------- |
| Ticket signatures    | Ed25519                                        | Small, fast, no parameter choices to get wrong                      |
| Rotating codes       | HMAC-SHA256, HKDF-derived per ticket           | No per-ticket secret is stored anywhere                             |
| Box certificates     | ECDSA P-256                                    | Ed25519 certificates are still rejected by some mobile browsers     |
| Mesh channels        | Argon2id → ChaCha20-Poly1305                   | A passphrase somebody says out loud needs a memory-hard KDF         |
| Mesh direct messages | X25519 → ChaCha20-Poly1305, split by direction | One key per direction so a message cannot be replayed at its sender |
| Mesh handshake       | Noise XX, hand-implemented                     | The same state machine has to exist in Go, Kotlin and Swift         |
| Audit log            | SHA-256 chain + RFC 6962 Merkle                | Tamper-evidence plus `O(log n)` proofs                              |

Every primitive comes from the standard library or `golang.org/x/crypto`. The only
hand-written protocol is the Noise handshake, and §11 of
[DECISIONS.md](DECISIONS.md) argues for it and states what it costs.

## Hardening a deployment

- Seal the manifest (`gatecrash-keys seal`) so the card is not the key.
- Set `organizer_fingerprint` in the config, so the box refuses a manifest signed by
  anybody else.
- Run `deploy/scripts/harden.sh` to make the root filesystem read-only.
- Use STRICT unless you have decided otherwise, deliberately, for a specific event.
- Revoke a lost scanner from the dashboard immediately; the client certificate stops
  working at once.
