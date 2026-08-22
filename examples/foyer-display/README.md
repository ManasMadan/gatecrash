# foyer-display

A read-only screen. "How many people are in?" is a question the box already answers, and a
television in the lobby answering it beats a dashboard nobody has open.

```sh
node index.mjs --box https://10.11.0.1:8443 --token <admin-token>
```

Occupancy against capacity per zone, and per-gate throughput as a **rate** rather than a total
— on a live screen the rate is what tells you something, because a gate doing forty a minute
and a gate that has stopped both have large totals.

## A warning about the token

This uses the admin token, which can also revoke devices and export the attendance report.
A public screen showing it is a credential on a wall. Run this on a machine nobody can walk up
to, or put a reverse proxy in front that only forwards `GET /v1/admin/stats`.

The box does not have a read-only token, and that is a real gap rather than a design decision
— it is in
[ROADMAP.md](https://github.com/ManasMadan/gatecrash/blob/master/ROADMAP.md).
