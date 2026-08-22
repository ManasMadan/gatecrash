# bench

The load rig. `go test -bench` gives a mean, and a mean is the wrong statistic for a queue.

```sh
go run ./cmd/gatecrash-demo -keep /tmp/gcdemo
go run ./cmd/gatecrash serve --data /tmp/gcdemo &
node bench.mjs --tokens t1,t2,...,t12 --rate 120 --seconds 10
```

One token per gate — enrol them from the dashboard's Setup tab, or with `POST
/v1/admin/invite` then `POST /v1/enroll`. A real run, on an M-series laptop:

```
gates      12
offering   120/s for 10s, 12 in flight

offered    1199 in 10.0s (120/s)
completed  1199

latency
  p50    2.59 ms
  p90    6.53 ms
  p99    19.71 ms
  p99.9  32.26 ms
  max    32.40 ms

verdicts
  UNKNOWN_TICKET           1199

p99 is 20ms. Twelve gates at forty scans a minute is eight a second; this run offered 120.
```

## Why it is built this way

**Percentiles, not a mean.** The p99 is the guard standing at a barrier wondering whether it
worked. A mean of 2ms with a p99 of two seconds is a gate that visibly stalls, and the mean does
not mention it.

**No coordinated omission.** Requests go out on a schedule; a slow response delays the
_measurement_, not the next request. A rig that waits for each response before sending the next
stops offering load exactly when the system slows down — the moment you were trying to observe —
and then reports beautiful numbers for a box that is falling over.

**An HDR-style histogram.** Log-linear buckets, so a million samples cost a few kilobytes and the
tail keeps its resolution. Storing every sample and sorting would be simpler, and would make the
rig's own memory growth part of what it measures.

**It says what it did not send.** If the concurrency bound is hit, that is printed. A rig that
silently drops what it could not offer is a rig reporting a load it never applied.

## What it scans

Well-formed GC1 payloads for ticket ids that do not exist, so every one comes back
`UNKNOWN_TICKET`. That is deliberate: a benchmark that admits tickets changes the state it is
measuring, and after the first pass every scan would be `ALREADY_USED` and take a different path.

A refusal is still a full trip — parse, device check, ticket lookup, audit row, hash chain — so
it measures real work. To time the admit path specifically, issue a large batch of tickets first
and feed their real payloads in, once each.

## Two things it got wrong first

Both worth knowing, because both produced a respectable-looking number for work that never
happened.

**One token.** The scan endpoint is rate limited **per device**, deliberately — a scanner cannot
be made to hammer the box faster than a human can present tickets. A rig driving one token at
150/s therefore measured the rate limiter: three quarters of the requests were rejected at the
door and the p99 looked fine. It now round-robins one token per gate and says so loudly if
rate limiting is still a significant share.

**The wrong alphabet.** Ticket ids and scan ids are RFC 4648 base32 — A–Z and 2–7. The first
version generated them from uppercased hex, whose `0` and `1` are not in that alphabet, so every
request came back `400` from the parser without the engine running at all. The scan id is not a
UUID either; `newScanId()` in `gatecrash-client` mints the right thing.
