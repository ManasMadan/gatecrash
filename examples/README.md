# Examples

Small, runnable programs that talk to a real box. Each one is a thing somebody actually asked
for at an event.

Start a box to point them at:

```sh
go run ./cmd/gatecrash-demo -keep /tmp/gcdemo   # builds an event and leaves the data behind
go run ./cmd/gatecrash serve --data /tmp/gcdemo
```

The boot log prints the addresses, the dashboard token and the CA fingerprint.

| Example                            | What it shows                                                                   |
| ---------------------------------- | ------------------------------------------------------------------------------- |
| [`turnstile`](./turnstile)         | A gate with no screen: scan, decide, pulse a relay. The smallest useful client. |
| [`door-sales`](./door-sales)       | Issuing a ticket at the door and admitting it in one breath.                    |
| [`foyer-display`](./foyer-display) | A read-only screen on the venue LAN, driven by the admin stream.                |

All three use [`gatecrash-client`](https://www.npmjs.com/package/gatecrash-client) and nothing
else.
