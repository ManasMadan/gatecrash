# turnstile

A gate with no screen. Sixty lines: read a payload, ask the box, pulse a relay.

```sh
pnpm install
node index.mjs --box https://10.11.0.1:8443 --token <device-token> --checkpoint gate-north
```

A barcode gun on a serial port behaves exactly like typing and pressing enter, which is why
this example reads from stdin — swap `createInterface` for a serial port and it is finished.

Get a device token by enrolling from the dashboard's Setup tab. A device that has not been
assigned to this checkpoint gets `SCANNER_NOT_AUTHORIZED`, deliberately.

## The two parts worth copying

**One scan id per presentation, reused on retry.** Generate it when the person presents the
ticket, not when you send the request. Resending the same id returns the verdict the box
already gave; generating a fresh one asks a new question, and the answer to that question is
`ALREADY_USED`.

**Holding when the box is unreachable.** A turnstile has no operator to ask, so it holds and
queues. That is STRICT behaviour and the right default for an unattended gate. A staffed gate
running DEGRADED would consult its local mirror instead — see
[when the box is unreachable](https://gatecrash.mmadan.in/guide/offline).
