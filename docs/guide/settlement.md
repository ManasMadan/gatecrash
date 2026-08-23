# After the event

The part that turns "we think 3,412 people came" into a number nobody has to take on trust.

## Seal, verify, export

```sh
gatecrash seal      # a Merkle checkpoint over the whole log
gatecrash verify    # every row still hashes to the head
gatecrash export    # attendance, with a proof per ticket
```

`seal` computes an RFC 6962 Merkle root over every audit row and records it. **Publish that
root.** It is 32 bytes, and it is what every proof below is checked against.

`verify` replays the hash chain. Every row carries the hash of the previous one, so changing,
inserting or deleting a row changes the head — and the head is what you published.

## Proving one admission

```sh
gatecrash attendance <ticket-id>
```

An inclusion proof: `O(log n)` sibling hashes against the published root. At fifty thousand
admissions that is sixteen hashes, 512 bytes, and it verifies **with the root alone** — no
log, no database, and no trust in the machine that produced it.

`go run ./cmd/gatecrash-demo` ends by doing exactly this and then tampering with one field to
show the proof fail. It is worth watching once.

## The attendance report

Signed by the box's own key, whose fingerprint the box printed on first boot. Publish that
fingerprint in advance and the report cannot be edited on the way to an artist or a promoter.

It carries turnout per tier, per gate and per section, the session window, the chain head, the
Merkle root, and the count of flagged double uses — including zero, which is itself a claim
worth signing.

## What a hash chain does not prove

It proves the log has not been edited since it was written. It cannot prove the box wrote down
what actually happened: a compromised box can write a perfectly consistent chain of fiction.

What limits that is device attribution — every admission is tied to an enrolled scanner with a
client certificate — and the box key whose fingerprint you published before the event. Stated
here because a guarantee section that only lists wins is marketing.

## Housekeeping

**The manifest is a credential.** Unsealed, it can mint a rotating code for every ticket at
that event. After the event, delete it or keep it sealed with the rest of your event records.

**Keep the data directory** until the settlement conversation is over. It is the only copy of
the audit log, and `gatecrash export` reads from it.

**Wipe before reuse.** A box going to a different organizer should not carry the last event's
audit log. Remove the data directory and let it mint a fresh CA and admin token on next boot.
