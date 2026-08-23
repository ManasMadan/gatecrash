# Decisions

Every choice here could have gone the other way. This is what was chosen, what it cost,
and what would have to change for the answer to be different.

The ones worth reading first are the mistakes: §15 onwards is a list of things that
were wrong in this repository and how they were found, because that is the part a
design document usually leaves out.

---

## 1. SQLite, not Postgres

**Chosen:** SQLite, embedded, one file, pure Go via `modernc.org/sqlite`.

The requirement that decides it is not performance. It is that the artefact has to be a
single static binary you copy onto a Raspberry Pi with `scp`. A Postgres dependency
means a second process, a second thing to configure, a second thing to back up, and a
second thing that can fail to start in a field.

SQLite's single-writer model is usually described as a limitation. Here it is the
feature: it is what makes the redemption CAS a serialisation point without a lock
manager, a leader election or a consensus protocol.

**Cost:** one writer, so ~2,300 scans/s through HTTP. Twelve gates at forty scans a
minute is eight a second. The ceiling is three hundred times the load.

**Would change if:** an event needed multiple boxes with a shared view. That is not a
bigger SQLite — it is Raft or a CRDT, and it is in [ROADMAP.md](ROADMAP.md) rather than
pretended at.

## 2. `CGO_ENABLED=0`, always

**Chosen:** pure Go everywhere, including SQLite.

With cgo, cross-compiling for `linux/arm64` needs a cross-toolchain on every machine
that builds a release, including CI. Without it, `GOOS=linux GOARCH=arm64 go build`
works from a laptop. The binary has no shared library dependencies at all, which means
it does not care what the Pi's userland looks like.

**Cost:** `modernc.org/sqlite` is a transpilation of the C library and is slower than
the real thing — roughly a factor of two on write-heavy work. See §1 for why that
ceiling is irrelevant.

## 3. Exactly-once by CAS, not by locking

**Chosen:** `INSERT ... ON CONFLICT (ticket_id, checkpoint, occurrence) DO NOTHING`,
and `changes()` is the verdict.

The alternatives all end up worse. `SELECT` then `INSERT` is a race. `SELECT FOR
UPDATE` does not exist in SQLite. An application-level mutex works within one process
and stops being a guarantee the moment there are two.

The insert _is_ the decision. There is no window between checking and acting, because
there is no checking.

**Cost:** the verdict is a side effect of a write, so the code has to be careful never
to treat a failed write as a refusal. That is why a rejected write returns an error
rather than a denial.

## 4. Hybrid logical clocks, not wall time

**Chosen:** 48 bits of milliseconds and 16 bits of counter, in one `uint64`.

Nobody's clock is right. A gate phone that has been off for a week is minutes out; a
box with no internet has never seen NTP. Ordering the audit log by wall time would mean
a log that goes backwards, and an attendance report that cannot be read in order.

An HLC is monotone regardless, merges a remote reading on every scan, and stays within
a few milliseconds of real time when real time is available.

**Cost:** two clocks to reason about. Wall time is recorded for humans and never
decides anything.

## 5. Two QR formats, not one

**Chosen:** GC1 static, Ed25519-signed, 134 characters. GC2 rotating, HMAC, 30-second
windows, ~53 characters.

A printed ticket has to work on paper, which means static. A screenshot of a printed
ticket also works, forever, which is the whole problem — so an in-app ticket rotates,
and a screenshot of it is worthless ninety seconds later.

Supporting both is not indecision: they are different products. A ticket is issued as
one or the other, and a ticket sold as rotating cannot be admitted from a static
payload — otherwise the anti-screenshot property is advisory rather than real.

**Cost:** two verification paths. Both are exercised by the simulator on every run.

**134 characters is not arbitrary:** it is a QR version 7 alphanumeric payload. One
character more needs a denser code, which measurably scans worse off paper in bad light.
There is a test asserting the number for exactly that reason.

## 6. HKDF-derived per-ticket secrets, not stored ones

**Chosen:** `ticket_secret = HKDF(event_master, ticket_id)`.

Fifty thousand tickets means either fifty thousand stored secrets or one master key and
a derivation. The derivation means the box stores no per-ticket secret at all, so
there is nothing to leak per ticket, and a manifest is small enough to fit on a boot
partition.

**Cost:** the event master key is a single point of compromise — it can mint a rotating
code for every ticket at that event. Which is why the manifest can be sealed with a
passphrase, and why the image builder warns that a card with a manifest on it _is_ the
key.

## 7. A Bloom filter on the scanner, written twice

**Chosen:** the box ships a Bloom filter of valid ticket ids; the scanner uses it to
reject unknown tickets with no network. Implemented in Go and again in TypeScript.

A scanner that cannot reach the box still needs to distinguish "a ticket I cannot
confirm" from "a QR somebody generated in a car park". The first is a hold; the second
is a refusal.

Two implementations of one format is two chances to disagree, and a disagreement here
does not look like a failing test — it looks like a gate refusing a valid ticket. So Go
generates a fixture, TypeScript reads it, and CI asserts the committed fixture is still
what the current Go code produces.

**Cost:** 175 KB at fifty thousand tickets, and a false positive rate of one in a
million — which lets through an unknown ticket once per million scans, into a hold
rather than an admission.

**Not maphash:** the first version used `hash/maphash`, whose seed is per-process. Two
boxes produced different filters for the same tickets. FNV-1a with a mixing step is
written out instead, so every platform agrees byte for byte.

## 8. A cuckoo filter for the mesh, not a Bloom filter

**Chosen:** cuckoo, 16-bit fingerprints, two generations rotated on a clock.

Mesh dedup entries have to expire — ten minutes on, nobody will relay a message again —
and a Bloom filter cannot forget. A filter that fills up and starts refusing to
remember new messages is worse than no filter.

**16 bits, not the usual 8:** a false positive here means a message this phone has
never seen is treated as already seen and never relayed. At eight bits that is 3% of
messages, which in a mesh whose delivery guarantee is "many paths, best effort" is a 3%
tax on every hop. Sixteen bits costs one byte per entry.

## 9. Relay probability `min(1, k/neighbours)`, with `k = 3`

**Chosen:** density-adaptive probabilistic flooding, with the density estimated from
distinct senders in a thirty-second window.

Naive flooding in a pit with five hundred phones spends the entire 2.4GHz band on
duplicates within seconds. The rule keeps roughly `k` relayers per neighbourhood
regardless of how many phones are in it.

`k = 3` comes from `gatecrash-sim crowd -sweep`, not from intuition — the first version
of this document quoted numbers that turned out to be wrong when measured, which is
recorded in §17.

**Cost:** in a sparse field the rule does nothing useful, because delivery there is
bounded by connectivity rather than by contention.

## 10. The mesh hop count is not authenticated

**Chosen:** the TTL is excluded from the AEAD's additional data. Everything else in the
header is included.

It has to be. Every relay decrements the TTL, so a TTL under the tag would mean a frame
failed to authenticate at the first hop — the message would travel exactly one hop and
the mesh would not work at all.

**Cost:** anybody can rewrite a TTL in flight. Raising it is bounded by the limit every
receiver enforces independently; lowering it is indistinguishable from staying silent,
which any node can do anyway. Neither is worth defending against, and both are written
down rather than glossed over.

## 11. Noise XX by hand

**Chosen:** implement `Noise_XX_25519_ChaChaPoly_SHA256` from the specification rather
than take a library.

The same handshake has to exist three times — Go for the box, Kotlin for Android, Swift
for iOS. Three ports of one 400-line state machine that agrees byte for byte is a more
tractable problem than three different libraries that each almost agree.

XX because neither phone knows the other's static key in advance, which is exactly two
strangers in a crowd with no directory and no CA. It also sends the responder's static
key encrypted, so somebody logging every frame in a field cannot build a list of which
devices were present.

**Cost:** hand-rolled crypto, which is normally the wrong answer. Mitigated by using
only vetted primitives from `x/crypto`, by pinning the two details that break ports —
the nonce layout and the direction of the split keys — with tests, and by a reproducible
transcript fixture the other two languages can be checked against.

## 12. ECDSA P-256 for the box's CA, not Ed25519

**Chosen:** P-256, despite Ed25519 being used everywhere else in the project.

Browser support. Ed25519 certificates are still not accepted by every mobile browser,
and a scanner that cannot open the gate page because its browser dislikes the curve is
a closed gate. Tickets are signed with Ed25519 because nothing but this software parses
those.

**Cost:** two signature schemes in one system, which is a real complexity cost and
worth it for the compatibility.

## 13. Three PWAs, and native only for the mesh

**Chosen:** scanner, wallet and dashboard as installable web apps. Native Android and
iOS only for Backstage.

A PWA needs no store review, no signing certificate and no install friction — a guard
opens a URL. Camera access needs HTTPS, which is why the enrollment ceremony installs
the CA.

The mesh cannot be a PWA. Web Bluetooth has no peripheral mode and does not exist on
iOS Safari at all, so a browser cannot advertise, and a mesh node that can only scan is
not a mesh node.

**Cost:** two more codebases, and App Store review for a Bluetooth mesh app is slow.
Which is why the ticket works entirely without them.

## 14. The verdict screen is a colour flood

**Chosen:** the whole viewport in one colour with one enormous glyph, plus a synthesised
sound and a distinct vibration pattern. Text is the third channel.

A guard at 22:00 is watching a queue, not a phone held at arm's length. Text is
unreadable in that situation, which was the first piece of feedback this project got and
the one that changed the most code.

Sound and haptics are synthesised with WebAudio rather than fetched, because at the
moment they are needed there may be no network.

**Cost:** a screen that ignores the platform's design language entirely.

---

# Things that were wrong

## 15. Tier grants leaked into backstage

Entitlements cascaded down the zone tree, so a general-admission ticket granted the
perimeter inherited every zone nested inside it — including backstage.

Found by writing the test that asserted the cascade worked, and reading what it
actually permitted. Fixed with a `Restricted` flag that stops the cascade, so nesting
fails closed rather than open.

**The lesson:** a hierarchy that inherits permissions downward is a security model that
grants everything by default, and it reads like a convenience feature.

## 16. The simulator was green and meant nothing

The first working version of the event simulator reported zero invariant violations
across every seed. Every scan was failing signature verification.

Every invariant is of the form "this bad thing never happened". Nothing happened, so
nothing bad happened, so everything passed. The cause was that the GC1 payload carries
only the ticket id and the signature — the claims it covers are reconstructed by the box
from its own stored record — and the simulator was signing with one issue time and
storing another.

**Fixed by** matching them, and by adding a test that asserts people are actually
admitted, so a vacuous pass can never look like a real one again.

## 17. The relay constant's justification was invented

The comment explaining why `k = 3` quoted delivery figures and airtime costs that had
never been measured. When the simulator was finally pointed at them, the sparse-crowd
claim was wrong by six percentage points.

**Fixed by** replacing the prose with the table the simulator produces, including the
seed. The correction that mattered was conceptual rather than numerical: the sparse case
is not a storm-control result at all.

## 18. The simulator found an idempotency violation that was its own fault

A retry of a refused scan returned a different refusal after a power cut. The engine
looked wrong.

It was not. The simulator was only flushing to durable storage after admissions, so a
power cut ate the stored refusal and the retry re-decided. The real box runs
`synchronous=FULL`, which commits a refusal as firmly as an admission.

**The lesson:** a simulator that models a weaker system than the real one reports bugs
the real one does not have, and they are indistinguishable from the real kind until you
look.

## 19. Store-and-forward was a broadcast storm

Offering the carry buffer to every newly met peer looked obviously good — it is how a
message crosses the gap between two groups who never hear each other. In a dense crowd
each node meets hundreds of peers, and four frames each turned into hundreds of
thousands of extra transmissions.

**Fixed by** gating the offer on the same sparseness test the relay rule uses. Carrying
only helps where flooding does not reach, which is exactly where the density estimate is
already low.

## 20. The dashboard's clock was the poll interval

Elapsed timers on open incidents counted 0s, 2s, 4s, because they were only recomputed
when the two-second poll landed. A stopwatch that skips is the number most likely to be
read out loud over a radio.

**Fixed by** giving the display its own one-second clock. A display clock has no
business being coupled to a network interval.

## 21. "Never picked up" counted alarms four seconds old

The incident board reported every unacknowledged incident as never-acknowledged,
including one raised moments ago. The number an operator watches never read zero, so it
meant nothing.

**Fixed by** splitting it: _unattended_ is the live signal — open, past a grace period,
still nobody — and _never acknowledged_ is the post-event judgement, counting only
incidents somebody closed without ever picking up.

## 22. The venue plan's ETag was the wrong hash

The plan's cache validator was the manifest digest. The plan the box serves comes from
the manifest file beside it, and the digest comes from whatever was last ingested. Move
a gate on the morning of an event and the two disagree: every phone held a stale plan
and then got a 304 forever, so the map went on pointing at a door that was not there.

Found by watching the browser show an old venue while `curl` showed the new one.

**Fixed by** hashing the response. A validator computed from the bytes being sent cannot
drift from the bytes being sent.

## 23. The seat label was a database row

The wallet's largest text read `block-a row A seat 1`. That is a code, not a seat.

**Fixed by** rendering labels through the venue, which knows the section's name. The
code form stays for the audit log, where codes are correct.
