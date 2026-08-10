// Package store is the box's SQLite storage: the real implementation of the
// redemption engine's store contract, plus the manifest, incident and reporting
// queries the rest of the box runs.
//
// Three decisions shape everything here.
//
// SQLite is pure Go (modernc.org/sqlite), which is what keeps the promise that
// the artifact is one static binary you scp onto a Raspberry Pi. No CGO, no
// cross-compiler, no shared library that has to match the Pi's libc.
//
// There is exactly one writer. Not because SQLite forces it — it does — but
// because that single writer is the linearization point of the whole system. Ten
// scanners racing on one QR code are serialised by it, and the ON CONFLICT DO
// NOTHING insert in tx.go is where exactly-once actually happens.
//
// The SD card is treated as hostile media. Cheap cards acknowledge writes they
// have not committed and corrupt on power loss, so the database runs in WAL mode
// with synchronous=FULL, gets an integrity check at every boot, and has its WAL
// shipped off the card continuously. The hash chain in the audit log is the last
// line: corruption in the rows that matter is detected rather than served.
package store

// schema is the initial migration. Migrations are append-only and each is
// applied inside a transaction that also bumps user_version, so a power cut
// during an upgrade leaves the database at one version or the other and never
// half way.
const schema = `
-- Key-value box state: audit head, manifest digest, box identity, session
-- markers. Small enough that a single-row-per-key table beats a config file,
-- and transactional with the data it describes, which a config file is not.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

-- Monotonic counters. A table rather than AUTOINCREMENT because the redemption
-- stream's sequence has to be allocatable inside a transaction that may roll
-- back without leaving a gap: scanners resume the SSE delta stream from a
-- sequence, and a gap looks like lost admissions.
CREATE TABLE counters (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
) WITHOUT ROWID;

-- The manifest's ticket list. Note what is absent: no name, no email, no phone,
-- no order id. The box holds pseudonymous ids so that a stolen box is a list of
-- meaningless numbers, and personal data stays in the optional presale layer
-- where it can be deleted.
CREATE TABLE tickets (
    id        TEXT PRIMARY KEY,
    event_id  TEXT NOT NULL,
    tier      TEXT NOT NULL,
    section   TEXT NOT NULL DEFAULT '',
    row_label TEXT NOT NULL DEFAULT '',
    seat      TEXT NOT NULL DEFAULT '',
    issued_at INTEGER NOT NULL,
    revoked   INTEGER NOT NULL DEFAULT 0,
    signature BLOB,
    format    TEXT NOT NULL
) WITHOUT ROWID;

CREATE INDEX tickets_tier ON tickets (tier);
CREATE INDEX tickets_section ON tickets (section) WHERE section <> '';

-- Enrolled scanners and their checkpoint allowlists. checkpoints is a JSON
-- array: it is read once per scan into a small slice and never queried across
-- rows, so normalising it into a join table would buy nothing and cost a join
-- on the hot path.
CREATE TABLE devices (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    checkpoints TEXT NOT NULL DEFAULT '[]',
    revoked     INTEGER NOT NULL DEFAULT 0,
    last_seen   INTEGER NOT NULL DEFAULT 0,
    enrolled_at INTEGER NOT NULL DEFAULT 0,
    cert_sha256 BLOB
) WITHOUT ROWID;

-- The redemption table. This primary key is the entire exactly-once guarantee:
-- one row per (ticket, checkpoint, occurrence), enforced by SQLite, decided by
-- one insert. Everything else in this codebase is arrangements around it.
--
-- WITHOUT ROWID because the primary key IS the identity and a rowid would mean a
-- second B-tree, a second write per admission, and a second thing to corrupt.
CREATE TABLE redemptions (
    ticket_id  TEXT NOT NULL,
    checkpoint TEXT NOT NULL,
    occurrence INTEGER NOT NULL,
    scan_id    TEXT NOT NULL,
    device     TEXT NOT NULL,
    direction  TEXT NOT NULL,
    zone       TEXT NOT NULL,
    hlc        INTEGER NOT NULL,
    at         INTEGER NOT NULL,
    seq        INTEGER NOT NULL,
    offline    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ticket_id, checkpoint, occurrence)
) WITHOUT ROWID;

-- Scanners resume the delta stream from a sequence, so this has to be unique and
-- indexed for range scans.
CREATE UNIQUE INDEX redemptions_seq ON redemptions (seq);

-- Prerequisite checks and re-entry decisions read one ticket's whole history on
-- every scan, so that read must be an index seek rather than a table scan.
CREATE INDEX redemptions_ticket ON redemptions (ticket_id, seq);

-- Idempotency. A retry after a Wi-Fi blip re-sends the same scan id and gets the
-- original verdict back, which is what stops "the network duplicated my request"
-- from being reported to gate staff as "someone is reusing a ticket".
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    result  TEXT NOT NULL,
    at      INTEGER NOT NULL
) WITHOUT ROWID;

-- The tamper-evident log. Every decided scan is here, admitted or not: a log
-- that records only successes cannot prove a gate was working, and "we never saw
-- that ticket" is exactly the claim a dispute turns on.
--
-- There is no UPDATE or DELETE statement against this table anywhere in the
-- codebase. The hash chain is what proves that claim to somebody who does not
-- believe it.
CREATE TABLE audit_log (
    seq        INTEGER PRIMARY KEY,
    ticket_id  TEXT NOT NULL DEFAULT '',
    checkpoint TEXT NOT NULL DEFAULT '',
    occurrence INTEGER NOT NULL DEFAULT 0,
    scan_id    TEXT NOT NULL DEFAULT '',
    device     TEXT NOT NULL DEFAULT '',
    verdict    TEXT NOT NULL,
    direction  TEXT NOT NULL DEFAULT '',
    section    TEXT NOT NULL DEFAULT '',
    row_label  TEXT NOT NULL DEFAULT '',
    seat       TEXT NOT NULL DEFAULT '',
    hlc        INTEGER NOT NULL,
    offline    INTEGER NOT NULL DEFAULT 0,
    prev_hash  BLOB NOT NULL,
    row_hash   BLOB NOT NULL
);

CREATE INDEX audit_log_ticket ON audit_log (ticket_id, seq);
CREATE INDEX audit_log_verdict ON audit_log (verdict, seq);

-- Sealed Merkle checkpoints. The organizer publishes the latest root at close and
-- any admission in the event becomes provable against it with about twenty
-- hashes.
CREATE TABLE seals (
    seq  INTEGER PRIMARY KEY,
    rows INTEGER NOT NULL,
    root BLOB NOT NULL,
    head BLOB NOT NULL,
    hlc  INTEGER NOT NULL,
    at   INTEGER NOT NULL
);

-- Detected double uses. Under a partition these cannot be prevented, so they are
-- detected, flagged with both records as evidence, and published in the
-- post-event report rather than quietly rounded away.
CREATE TABLE flags (
    seq       INTEGER PRIMARY KEY,
    ticket_id TEXT NOT NULL,
    at        INTEGER NOT NULL,
    payload   TEXT NOT NULL
);

CREATE INDEX flags_ticket ON flags (ticket_id);

-- Staff signals. Stored as a JSON payload because an incident is read whole,
-- written whole, and never queried by field on the box; the columns that are
-- broken out are the ones the dashboard filters on.
CREATE TABLE incidents (
    id       TEXT PRIMARY KEY,
    seq      INTEGER NOT NULL,
    kind     TEXT NOT NULL,
    severity TEXT NOT NULL,
    status   TEXT NOT NULL,
    zone     TEXT NOT NULL DEFAULT '',
    raised   INTEGER NOT NULL,
    payload  TEXT NOT NULL
) WITHOUT ROWID;

CREATE UNIQUE INDEX incidents_seq ON incidents (seq);
CREATE INDEX incidents_status ON incidents (status, severity);

PRAGMA user_version = 1;
`

// migrations are applied in order for any database whose user_version is below
// their index. Index 0 is the initial schema above.
//
// Append only, never edit. A migration that has run on a box in the field is
// history, and editing it means two boxes with the same user_version have
// different schemas — which is discovered at a gate.
var migrations = []string{
	schema,
}

// schemaVersion is the version a freshly opened database ends at.
func schemaVersion() int { return len(migrations) }
