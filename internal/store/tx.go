package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/merkle"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// txn implements engine.Tx over a SQLite transaction.
type txn struct {
	ctx   context.Context
	tx    *sql.Tx
	write bool
	now   func() time.Time
}

// guard refuses writes in a read transaction. A read path that silently accepted
// writes would let a dashboard query mutate the log, which is the one thing the
// audit design promises cannot happen.
func (t *txn) guard() error {
	if !t.write {
		return ErrReadOnly
	}
	return nil
}

// metaAuditHead and metaAuditRows are the persisted chain position.
const (
	metaAuditHead = "audit_head"
	metaAuditRows = "audit_rows"
)

func (t *txn) StoredResult(scanID ticket.ID) (engine.Result, bool, error) {
	var encoded string
	err := t.tx.QueryRowContext(t.ctx, "SELECT result FROM scans WHERE scan_id = ?", scanID.Hex()).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return engine.Result{}, false, nil
	}
	if err != nil {
		return engine.Result{}, false, fmt.Errorf("store: reading stored result: %w", err)
	}

	var result engine.Result
	if err := json.Unmarshal([]byte(encoded), &result); err != nil {
		// A stored result that will not decode is a corrupt row. Reporting it
		// rather than treating it as absent matters: treating it as absent would
		// re-decide the scan and could admit a ticket a second time.
		return engine.Result{}, false, fmt.Errorf("store: stored result for scan %s is corrupt: %w", scanID, err)
	}
	return result, true, nil
}

func (t *txn) StoreResult(scanID ticket.ID, result engine.Result) error {
	if err := t.guard(); err != nil {
		return err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("store: encoding result: %w", err)
	}
	_, err = t.tx.ExecContext(t.ctx,
		"INSERT INTO scans (scan_id, result, at) VALUES (?, ?, ?)",
		scanID.Hex(), string(encoded), t.now().UnixMilli())
	if err != nil {
		return fmt.Errorf("store: storing result: %w", err)
	}
	return nil
}

func (t *txn) Ticket(id ticket.ID) (engine.Ticket, bool, error) {
	var (
		out       engine.Ticket
		idHex     string
		eventHex  string
		revoked   int
		signature []byte
	)
	err := t.tx.QueryRowContext(t.ctx, `
		SELECT id, event_id, tier, section, row_label, seat, issued_at, revoked, signature, format
		FROM tickets WHERE id = ?`, id.Hex()).Scan(
		&idHex, &eventHex, &out.Tier, &out.Seat.Section, &out.Seat.Row, &out.Seat.Seat,
		&out.IssuedAt, &revoked, &signature, &out.Format)
	if errors.Is(err, sql.ErrNoRows) {
		return engine.Ticket{}, false, nil
	}
	if err != nil {
		return engine.Ticket{}, false, fmt.Errorf("store: reading ticket: %w", err)
	}

	if out.ID, err = ticket.ParseID(idHex); err != nil {
		return engine.Ticket{}, false, fmt.Errorf("store: ticket id %q: %w", idHex, err)
	}
	if out.EventID, err = ticket.ParseID(eventHex); err != nil {
		return engine.Ticket{}, false, fmt.Errorf("store: ticket %s event id: %w", out.ID, err)
	}
	out.Revoked = revoked != 0
	out.Signature = signature
	return out, true, nil
}

func (t *txn) Device(id string) (engine.Device, bool, error) {
	var (
		out         engine.Device
		checkpoints string
		revoked     int
		lastSeen    int64
	)
	err := t.tx.QueryRowContext(t.ctx,
		"SELECT id, name, checkpoints, revoked, last_seen FROM devices WHERE id = ?", id).Scan(
		&out.ID, &out.Name, &checkpoints, &revoked, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return engine.Device{}, false, nil
	}
	if err != nil {
		return engine.Device{}, false, fmt.Errorf("store: reading device: %w", err)
	}

	if err := json.Unmarshal([]byte(checkpoints), &out.Checkpoints); err != nil {
		// Fail closed. A device whose allowlist will not parse must scan nothing,
		// because the alternative is a device that scans everything.
		return engine.Device{}, false, fmt.Errorf("store: device %s allowlist is corrupt: %w", id, err)
	}
	out.Revoked = revoked != 0
	if lastSeen != 0 {
		out.LastSeen = time.UnixMilli(lastSeen).UTC()
	}
	return out, true, nil
}

func (t *txn) TouchDevice(id string, at time.Time) error {
	if err := t.guard(); err != nil {
		return err
	}
	// Liveness is a monitoring signal, not part of the redemption decision. It
	// rides along in the same transaction because that is free, and a rollback
	// losing it costs nothing.
	if _, err := t.tx.ExecContext(t.ctx,
		"UPDATE devices SET last_seen = ? WHERE id = ?", at.UnixMilli(), id); err != nil {
		return fmt.Errorf("store: touching device: %w", err)
	}
	return nil
}

func (t *txn) Redemptions(id ticket.ID) ([]engine.Redemption, error) {
	rows, err := t.tx.QueryContext(t.ctx, `
		SELECT ticket_id, checkpoint, occurrence, scan_id, device, direction, zone, hlc, at, seq, offline
		FROM redemptions WHERE ticket_id = ? ORDER BY seq`, id.Hex())
	if err != nil {
		return nil, fmt.Errorf("store: reading redemptions: %w", err)
	}
	defer rows.Close()

	var out []engine.Redemption
	for rows.Next() {
		r, err := scanRedemption(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: reading redemptions: %w", err)
	}
	return out, nil
}

// scanner is the subset of *sql.Rows and *sql.Row that scanRedemption needs.
type scanner interface {
	Scan(dest ...any) error
}

func scanRedemption(row scanner) (engine.Redemption, error) {
	var (
		out       engine.Redemption
		ticketHex string
		scanHex   string
		stamp     uint64
		at        int64
		offline   int
	)
	if err := row.Scan(&ticketHex, &out.Checkpoint, &out.Occurrence, &scanHex,
		&out.Device, &out.Direction, &out.Zone, &stamp, &at, &out.Seq, &offline); err != nil {
		return engine.Redemption{}, fmt.Errorf("store: scanning redemption: %w", err)
	}
	var err error
	if out.TicketID, err = ticket.ParseID(ticketHex); err != nil {
		return engine.Redemption{}, fmt.Errorf("store: redemption ticket id %q: %w", ticketHex, err)
	}
	if out.ScanID, err = ticket.ParseID(scanHex); err != nil {
		return engine.Redemption{}, fmt.Errorf("store: redemption scan id %q: %w", scanHex, err)
	}
	out.HLC = hlc.Timestamp(stamp)
	out.At = time.UnixMilli(at).UTC()
	out.Offline = offline != 0
	return out, nil
}

// InsertRedemption is the linearization point of the entire system.
//
// One statement. ON CONFLICT DO NOTHING means the primary key decides, inside
// SQLite, under the single writer, with no read-then-write window for anything to
// slip through. Ten scanners hammering one QR code all run this; exactly one sees
// a row affected, and the losers are handed the winning row so the gate can show
// who got in, where, and when.
//
// The read that follows a conflict is inside the same transaction as the insert
// that lost, so the row it reports cannot have changed underneath it.
func (t *txn) InsertRedemption(r engine.Redemption) (bool, engine.Redemption, error) {
	if err := t.guard(); err != nil {
		return false, engine.Redemption{}, err
	}

	result, err := t.tx.ExecContext(t.ctx, `
		INSERT INTO redemptions
			(ticket_id, checkpoint, occurrence, scan_id, device, direction, zone, hlc, at, seq, offline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (ticket_id, checkpoint, occurrence) DO NOTHING`,
		r.TicketID.Hex(), r.Checkpoint, r.Occurrence, r.ScanID.Hex(), r.Device,
		r.Direction, r.Zone, uint64(r.HLC), r.At.UnixMilli(), r.Seq, boolToInt(r.Offline))
	if err != nil {
		return false, engine.Redemption{}, fmt.Errorf("store: inserting redemption: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, engine.Redemption{}, fmt.Errorf("store: counting inserted rows: %w", err)
	}
	if affected == 1 {
		return true, r, nil
	}

	winner, err := t.redemptionAt(r.TicketID, r.Checkpoint, r.Occurrence)
	if err != nil {
		return false, engine.Redemption{}, err
	}
	return false, winner, nil
}

func (t *txn) redemptionAt(id ticket.ID, checkpoint venue.CheckpointCode, occurrence uint32) (engine.Redemption, error) {
	row := t.tx.QueryRowContext(t.ctx, `
		SELECT ticket_id, checkpoint, occurrence, scan_id, device, direction, zone, hlc, at, seq, offline
		FROM redemptions WHERE ticket_id = ? AND checkpoint = ? AND occurrence = ?`,
		id.Hex(), checkpoint, occurrence)
	return scanRedemption(row)
}

func (t *txn) AppendRecord(r audit.Record) error {
	if err := t.guard(); err != nil {
		return err
	}
	_, err := t.tx.ExecContext(t.ctx, `
		INSERT INTO audit_log
			(seq, ticket_id, checkpoint, occurrence, scan_id, device, verdict, direction,
			 section, row_label, seat, hlc, offline, prev_hash, row_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Seq, hexOrEmpty(r.TicketID), r.Checkpoint, r.Occurrence, hexOrEmpty(r.ScanID),
		r.Device, r.Verdict, r.Direction, r.Seat.Section, r.Seat.Row, r.Seat.Seat,
		uint64(r.HLC), boolToInt(r.Offline), r.PrevHash[:], r.RowHash[:])
	if err != nil {
		return fmt.Errorf("store: appending audit row: %w", err)
	}
	return nil
}

func (t *txn) FlagDoubleUse(f engine.DoubleUse) error {
	if err := t.guard(); err != nil {
		return err
	}
	encoded, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("store: encoding double-use flag: %w", err)
	}
	if _, err := t.tx.ExecContext(t.ctx,
		"INSERT INTO flags (seq, ticket_id, at, payload) VALUES (?, ?, ?, ?)",
		f.Seq, f.TicketID.Hex(), f.At.UnixMilli(), string(encoded)); err != nil {
		return fmt.Errorf("store: flagging double use: %w", err)
	}
	return nil
}

// NextSeq allocates the next redemption-stream sequence.
//
// UPDATE ... RETURNING inside the transaction, so an allocation is rolled back
// with everything else. AUTOINCREMENT would leak a number on every rollback, and
// scanners resume the delta stream from a sequence: a gap looks exactly like lost
// admissions and would send a scanner back to a full manifest sync.
func (t *txn) NextSeq() (uint64, error) {
	if err := t.guard(); err != nil {
		return 0, err
	}
	var next uint64
	err := t.tx.QueryRowContext(t.ctx,
		"UPDATE counters SET value = value + 1 WHERE name = ? RETURNING value",
		counterRedemption).Scan(&next)
	if err != nil {
		return 0, fmt.Errorf("store: allocating sequence: %w", err)
	}
	return next, nil
}

func (t *txn) AuditHead() (merkle.Hash, uint64, error) {
	head, err := t.metaHash(metaAuditHead)
	if err != nil {
		return merkle.Hash{}, 0, err
	}
	rows, err := t.metaUint(metaAuditRows)
	if err != nil {
		return merkle.Hash{}, 0, err
	}
	return head, rows, nil
}

func (t *txn) SetAuditHead(head merkle.Hash, rows uint64) error {
	if err := t.guard(); err != nil {
		return err
	}
	if err := t.setMeta(metaAuditHead, hex.EncodeToString(head[:])); err != nil {
		return err
	}
	return t.setMeta(metaAuditRows, strconv.FormatUint(rows, 10))
}

// Meta helpers. The meta table is transactional with the data it describes,
// which a config file on the side is not: the audit head and the audit row it
// describes are written in one transaction and can never disagree.

func (t *txn) meta(key string) (string, bool, error) {
	var value string
	err := t.tx.QueryRowContext(t.ctx, "SELECT value FROM meta WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: reading meta %q: %w", key, err)
	}
	return value, true, nil
}

func (t *txn) setMeta(key, value string) error {
	if err := t.guard(); err != nil {
		return err
	}
	if _, err := t.tx.ExecContext(t.ctx,
		"INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
		key, value); err != nil {
		return fmt.Errorf("store: writing meta %q: %w", key, err)
	}
	return nil
}

func (t *txn) metaHash(key string) (merkle.Hash, error) {
	value, found, err := t.meta(key)
	if err != nil || !found || value == "" {
		return merkle.Hash{}, err
	}
	parsed, err := merkle.ParseHash(value)
	if err != nil {
		return merkle.Hash{}, fmt.Errorf("store: meta %q: %w", key, err)
	}
	return parsed, nil
}

func (t *txn) metaUint(key string) (uint64, error) {
	value, found, err := t.meta(key)
	if err != nil || !found || value == "" {
		return 0, err
	}
	var out uint64
	if _, err := fmt.Sscanf(value, "%d", &out); err != nil {
		return 0, fmt.Errorf("store: meta %q is not a number: %w", key, err)
	}
	return out, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// hexOrEmpty renders an id, mapping the zero id to the empty string so that a
// denial with no ticket (a malformed payload) does not store a row of zeroes
// that looks like a real identifier.
func hexOrEmpty(id ticket.ID) string {
	if id.IsZero() {
		return ""
	}
	return id.Hex()
}
