# How a scan is decided

One statement decides it. Everything else exists to make that statement's answer meaningful.

```sql
INSERT INTO redemptions (ticket_id, checkpoint, occurrence, ...)
VALUES (?, ?, ?, ...) ON CONFLICT DO NOTHING;
```

`changes() == 1` and they are in. `changes() == 0` and somebody already came through on this
ticket, and the screen shows which gate and how long ago.

That insert **is** the decision. There is no window between checking and acting, because
there is no checking — which is why ten scanners hammering the same QR at the same instant
produce exactly one winner, decided by SQLite's single-writer serialisation rather than by
anything this project wrote.

## The order of checks

Before that insert, in this order:

1. **Idempotency** — has this exact `scan_id` been answered before? If so, return that
   answer. A scanner that lost the response and retried gets the original verdict, not
   `ALREADY_USED`. Bad Wi-Fi must not turn somebody away.
2. **Device** — is this scanner enrolled, unrevoked, and assigned to this checkpoint?
3. **Payload** — does it parse as GC1 or GC2 at all?
4. **Ticket** — does it exist, for this event, unrevoked?
5. **Crypto** — Ed25519 for a static code; the HMAC window for a rotating one.
6. **Entitlement** — does the tier reach this zone?
7. **Door** — does this checkpoint serve this ticket's section?
8. **Hours** — is the door open?
9. **Prerequisites** — have they been through what this door requires?
10. **Policy** — once, re-entry, or counted with passes left?
11. **The insert.**

The ordering is not arbitrary: the cheap and the certain come first, so a malformed QR does
not cost a signature verification, and every refusal that can be explained precisely is
reached before the one that cannot.

## The verdict

Fifteen of them, in three severities — `admit`, `deny`, `redirect`. The full list is in the
[verdict reference](/reference/verdicts), and every one carries a sentence written by the
box so that every gate at the event says the same thing.

A refusal carries its evidence. `ALREADY_USED` says which gate and when; `WRONG_DOOR` and
`PREREQUISITE_MISSING` carry a **redirect** — the door they should be at. That is the
difference between a guard who can help and a guard who can only say no.

## What the guard sees

A full-viewport colour flood with one enormous glyph, a synthesised tone, and a distinct
vibration pattern.

This is not a style choice. A guard at 22:00 is watching a queue, not a phone held at arm's
length, so text is unreadable in exactly the situation that matters. Colour and a glyph
carry across a queue; the sound and the buzz work when nobody is looking at all.

Above the glyph, three things somebody acts on: the **tier colour band** a guard matches
against a wristband, the **seat** an usher points at, and for a counted pass, how many are
left.

The screen clears itself — a verdict left up is a verdict the next person's scan gets
confused with, which at a busy gate is a real error. Admits clear fast because the queue is
moving; refusals hold longer because somebody is about to be told why.

## Every decision is recorded

Refusals are chained into the audit log too, not just admissions. A log that only records
successes cannot prove a gate was working, and "we never saw that ticket" is exactly the
claim a dispute turns on.

Next: [when the box is unreachable](/guide/offline).
