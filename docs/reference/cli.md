# Command line

Two binaries. `gatecrash` runs on the box; `gatecrash-keys` runs on your machine and never
on the box, because a box that could sign its own manifest could invent tickets.

## gatecrash

```
gatecrash [serve] [flags]      run the box
gatecrash ingest <manifest>    load a signed manifest and exit
gatecrash verify               replay the audit chain and report
gatecrash seal                 cut a Merkle checkpoint and print the root to publish
gatecrash attendance <id>      prove one admission against that root
gatecrash export [file]        write the signed attendance report
gatecrash doctor               check the box's own state
gatecrash version              print the build
```

Everything has a working default. A box with no configuration at all boots, mints its own
certificate authority, serves on `:8443`, and waits for a manifest.

### serve

```
-config string    path to the configuration file (default "/etc/gatecrash/config.json")
-data string      override the data directory
-listen string    override the HTTPS listen address
-log string       log level: debug, info, warn, error
-manifest string  load this manifest at boot
-mode string      networking mode: router or ap
```

Flags override the config file, and `GATECRASH_*` environment variables sit between them —
see [Configuration](/reference/config).

### verify

```
-config string    path to the configuration file
-db string        verify this database file directly
```

The command an auditor runs against a database handed to them by somebody they have no
reason to trust. It needs no keys, no network, and no cooperation from the box.

```
database integrity: ok
audit chain: ok (29 rows)
checkpoint: ok
  rows 29
  root 7f30646169d83c6dda814f08b4ae9ef5c0a71bfebdc6163b2d4b1be97e39058e
  head ab2562d58285111302e1ac671daef92fe52c78081340689fc60d911890077bd1

admissions 19 of 29 recorded decisions
```

A broken chain is a non-zero exit, because this is the answer to a question somebody asked
and a script has to be able to act on it.

### seal

```
-config string    path to the configuration file
-db string        seal this database file directly
```

The box seals on a timer while it runs; this is the one an operator runs at the end of the
night, so the published root covers every row. Publishing it is a step somebody performs
deliberately rather than a side effect of a ticker.

### attendance

```
gatecrash attendance <ticket-id> [-db path] [-json]
```

```
PV725ZYDHUZ7627WG4PBOXATYU
  admitted at   gate-north
  by device     dev-VEje3BEs
  audit row     1
  proof         5 sibling hashes, 160 bytes
  against root  7f30646169d83c6dda814f08b4ae9ef5c0a71bfebdc6163b2d4b1be97e39058e
```

A ticket that was never admitted prints exactly that and exits zero — "no admission
recorded" is a perfectly good answer to the question, and often the one being checked for.

### doctor

Checks the box's own state without starting it: the database, the chain head, the
certificate expiry, the manifest digest, disk space, and whether the data directory has the
permissions it should. The first thing to run when something is wrong.

## gatecrash-keys

```
gatecrash-keys keygen   -out keys.json
gatecrash-keys venue    -out venue.json
gatecrash-keys issue    -keys k -venue v -n 500 -tier ga -section block-a -out ga.json
gatecrash-keys manifest -keys k -venue v -tickets a.json,b.json -event "Name" -out manifest.json
gatecrash-keys seal     -in manifest.json -out manifest.sealed.json
gatecrash-keys inspect  manifest.json
```

### issue

```
-keys string      the organizer key file
-venue string     the venue plan
-n int            how many tickets to issue (default 100)
-tier string      the tier to issue (default "ga")
-section string   seat tickets into this section, filling rows in order
-event string     an existing event id; a new one is generated when empty
-format string    gc1 (printed), gc2 (rotating), or either
-base-url string  the base URL for attendee ticket links
-out string       where to write the ticket list
```

Reuse `-event` for every batch of one event. Without it the second batch belongs to a
different event, and every one of those tickets is `WRONG_EVENT` at the door.

### manifest

```
-keys, -venue, -tickets, -out
-event string      the event name
-venue-name string the venue's human name
-tz string         IANA timezone, for display only (default "Asia/Kolkata")
-doors string       when doors open, RFC 3339
-curfew string      when gates close, RFC 3339
-mode string        consistency mode: strict or degraded (default "strict")
-support string     what an attendee should do when something goes wrong
-sequence int       manifest sequence; raise it for every re-issue (default 1)
```

`-mode` is inside the signed body on purpose: whether gates may admit during a partition is
the organizer's decision, not something anybody can change at the venue. See
[when the box is unreachable](/guide/offline).

### seal

```
-in string          the manifest to seal
-out string         where to write the sealed file
-passphrase string  read from GATECRASH_MANIFEST_PASSPHRASE when empty
```

An unsealed manifest carries the event master key, which can mint a rotating code for every
ticket at that event. Seal it before it travels.

## gatecrash-sim

```
gatecrash-sim event [flags]     seeded event-days against the real redemption engine
gatecrash-sim crowd [flags]     the mesh protocol against a model of a crowd
```

See [Correctness](/guide/correctness). The flags most worth knowing:

```
event  -seeds N        how many event-days (default 100)
       -seed N         the first seed; with -seeds 1, replays exactly one run
       -mode           strict, degraded, or both
       -retry, -reuse, -reorder, -offline, -skew, -power-cut, -write-fail
                       fault probabilities, so a failing seed can be narrowed down
                       by turning one off at a time

crowd  -nodes N        phones in the field
       -k F            the relay constant
       -boxes N        venue boxes acting as bridged super-nodes
       -sweep          sweep density and relay constant, and print the table
```
