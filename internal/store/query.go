package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ManasMadan/gatecrash/internal/audit"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/incident"
	"github.com/ManasMadan/gatecrash/internal/merkle"
	"github.com/ManasMadan/gatecrash/internal/ticket"
)

// deltaBatchLimit caps how many redemptions one delta query returns.
//
// A scanner that has been offline for an hour asks for everything since its last
// sequence, and handing it fifty thousand rows in one response is how a cheap
// phone runs out of memory at a gate. It pages instead, and the SSE stream sends
// a resume marker so it knows to ask again.
const deltaBatchLimit = 2000

// Deltas returns redemptions after a sequence, which is what a reconnecting
// scanner catches up from.
func (s *Store) Deltas(ctx context.Context, since uint64, limit int) ([]engine.Redemption, error) {
	if limit <= 0 || limit > deltaBatchLimit {
		limit = deltaBatchLimit
	}
	rows, err := s.reader.QueryContext(ctx, `
		SELECT ticket_id, checkpoint, occurrence, scan_id, device, direction, zone, hlc, at, seq, offline
		FROM redemptions WHERE seq > ? ORDER BY seq LIMIT ?`, since, limit)
	if err != nil {
		return nil, fmt.Errorf("store: reading deltas: %w", err)
	}
	defer rows.Close()

	out := []engine.Redemption{}
	for rows.Next() {
		r, err := scanRedemption(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LatestSeq returns the highest allocated redemption sequence, which the manifest
// endpoint publishes so a scanner knows where its delta stream starts.
func (s *Store) LatestSeq(ctx context.Context) (uint64, error) {
	var seq uint64
	if err := s.reader.QueryRowContext(ctx,
		"SELECT value FROM counters WHERE name = ?", counterRedemption).Scan(&seq); err != nil {
		return 0, fmt.Errorf("store: reading latest sequence: %w", err)
	}
	return seq, nil
}

// RedeemedIDs returns the ticket ids currently admitted at once-only checkpoints,
// which is the redeemed snapshot a scanner loads alongside its Bloom filter.
//
// Only the mirror needs this and only for the checkpoint the scanner is bound to,
// so it takes a checkpoint rather than dumping the whole venue: a portal scanner
// does not need to know who came through the north gate, and sending it anyway
// costs a megabyte over venue Wi-Fi for nothing.
func (s *Store) RedeemedIDs(ctx context.Context, checkpoint string) ([]string, uint64, error) {
	seq, err := s.LatestSeq(ctx)
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.reader.QueryContext(ctx,
		"SELECT ticket_id FROM redemptions WHERE checkpoint = ? AND direction <> 'out' ORDER BY seq", checkpoint)
	if err != nil {
		return nil, 0, fmt.Errorf("store: reading redeemed snapshot: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, 0, fmt.Errorf("store: reading redeemed snapshot: %w", err)
		}
		out = append(out, id)
	}
	return out, seq, rows.Err()
}

// TicketIDs streams every loaded ticket id, which is what the scanner's Bloom
// filter is built from.
//
// A slice rather than a callback: fifty thousand 16-byte ids is 800 KB, which is
// nothing next to the box's 150 MB budget, and the filter build needs them all
// anyway. Returning ids rather than whole rows keeps the read off the signature
// blobs, which are the bulk of the table.
func (s *Store) TicketIDs(ctx context.Context) ([]ticket.ID, error) {
	rows, err := s.reader.QueryContext(ctx, "SELECT id FROM tickets")
	if err != nil {
		return nil, fmt.Errorf("store: listing ticket ids: %w", err)
	}
	defer rows.Close()

	var out []ticket.ID
	for rows.Next() {
		var idHex string
		if err := rows.Scan(&idHex); err != nil {
			return nil, fmt.Errorf("store: listing ticket ids: %w", err)
		}
		id, err := ticket.ParseID(idHex)
		if err != nil {
			return nil, fmt.Errorf("store: ticket id %q: %w", idHex, err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AuditRows returns audit log rows in sequence order.
//
// from and to are inclusive; a zero `to` means everything. Used by the verifier,
// by the attendance export and by the dashboard's log view.
func (s *Store) AuditRows(ctx context.Context, from, to uint64) ([]audit.Record, error) {
	query := `
		SELECT seq, ticket_id, checkpoint, occurrence, scan_id, device, verdict, direction,
		       section, row_label, seat, hlc, offline, prev_hash, row_hash
		FROM audit_log WHERE seq >= ?`
	args := []any{from}
	if to > 0 {
		query += " AND seq <= ?"
		args = append(args, to)
	}
	query += " ORDER BY seq"

	rows, err := s.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: reading audit log: %w", err)
	}
	defer rows.Close()

	var out []audit.Record
	for rows.Next() {
		var (
			r         audit.Record
			ticketHex string
			scanHex   string
			stamp     uint64
			offline   int
			prevHash  []byte
			rowHash   []byte
		)
		if err := rows.Scan(&r.Seq, &ticketHex, &r.Checkpoint, &r.Occurrence, &scanHex,
			&r.Device, &r.Verdict, &r.Direction, &r.Seat.Section, &r.Seat.Row, &r.Seat.Seat,
			&stamp, &offline, &prevHash, &rowHash); err != nil {
			return nil, fmt.Errorf("store: scanning audit row: %w", err)
		}
		if ticketHex != "" {
			if r.TicketID, err = ticket.ParseID(ticketHex); err != nil {
				return nil, fmt.Errorf("store: audit row %d ticket id: %w", r.Seq, err)
			}
		}
		if scanHex != "" {
			if r.ScanID, err = ticket.ParseID(scanHex); err != nil {
				return nil, fmt.Errorf("store: audit row %d scan id: %w", r.Seq, err)
			}
		}
		r.HLC = hlc.Timestamp(stamp)
		r.Offline = offline != 0
		copy(r.PrevHash[:], prevHash)
		copy(r.RowHash[:], rowHash)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AuditLeaves returns the Merkle leaf hash of every audit row, in order.
//
// Recomputed from the rows rather than cached, because a cached leaf that
// disagrees with its row would produce a checkpoint root that commits to
// something the log does not say — which is worse than no checkpoint at all. At
// fifty thousand admissions this is a 1.6 MB read and a few milliseconds of
// hashing, done between scans.
func (s *Store) AuditLeaves(ctx context.Context) ([]merkle.Hash, error) {
	rows, err := s.AuditRows(ctx, 1, 0)
	if err != nil {
		return nil, err
	}
	out := make([]merkle.Hash, 0, len(rows))
	for _, row := range rows {
		// Zero the chain fields: a leaf commits to the row's contents, and the
		// chain links are a separate mechanism over the top.
		row.PrevHash, row.RowHash = merkle.Hash{}, merkle.Hash{}
		out = append(out, row.Leaf())
	}
	return out, nil
}

// Seal computes and stores a Merkle checkpoint over the whole log.
func (s *Store) Seal(ctx context.Context, at hlc.Timestamp) (audit.Checkpoint, error) {
	leaves, err := s.AuditLeaves(ctx)
	if err != nil {
		return audit.Checkpoint{}, err
	}

	var head merkle.Hash
	if err := s.Read(ctx, func(tx engine.Tx) error {
		var err error
		head, _, err = tx.AuditHead()
		return err
	}); err != nil {
		return audit.Checkpoint{}, err
	}

	checkpoint := audit.Seal(leaves, head, at)
	if _, err := s.writer.ExecContext(ctx, `
		INSERT INTO seals (seq, rows, root, head, hlc, at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (seq) DO UPDATE SET
			rows = excluded.rows, root = excluded.root, head = excluded.head,
			hlc = excluded.hlc, at = excluded.at`,
		checkpoint.Seq, checkpoint.Rows, checkpoint.Root[:], checkpoint.Head[:],
		uint64(checkpoint.HLC), s.now().UnixMilli()); err != nil {
		return audit.Checkpoint{}, fmt.Errorf("store: storing seal: %w", err)
	}
	return checkpoint, nil
}

// LatestSeal returns the most recent sealed checkpoint.
func (s *Store) LatestSeal(ctx context.Context) (audit.Checkpoint, bool, error) {
	var (
		out  audit.Checkpoint
		root []byte
		head []byte
		hlcv uint64
	)
	err := s.reader.QueryRowContext(ctx,
		"SELECT seq, rows, root, head, hlc FROM seals ORDER BY seq DESC LIMIT 1").
		Scan(&out.Seq, &out.Rows, &root, &head, &hlcv)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return audit.Checkpoint{}, false, nil
		}
		return audit.Checkpoint{}, false, fmt.Errorf("store: reading latest seal: %w", err)
	}
	copy(out.Root[:], root)
	copy(out.Head[:], head)
	out.HLC = hlc.Timestamp(hlcv)
	return out, true, nil
}

// Attendance builds a provable statement that one ticket was admitted.
//
// This is the settlement workflow: given a ticket id, produce the audit row, an
// inclusion proof, and the checkpoint the proof is against. A recipient holding
// nothing but the published root can check it.
func (s *Store) Attendance(ctx context.Context, id ticket.ID) (audit.Attendance, bool, error) {
	leaves, err := s.AuditLeaves(ctx)
	if err != nil {
		return audit.Attendance{}, false, err
	}
	rows, err := s.AuditRows(ctx, 1, 0)
	if err != nil {
		return audit.Attendance{}, false, err
	}

	index := -1
	for i, row := range rows {
		if row.TicketID == id && row.Verdict == string(engine.Admit) {
			index = i
			break
		}
	}
	if index < 0 {
		return audit.Attendance{}, false, nil
	}

	proof, err := merkle.Prove(leaves, index)
	if err != nil {
		return audit.Attendance{}, false, fmt.Errorf("store: proving attendance: %w", err)
	}

	var head merkle.Hash
	if err := s.Read(ctx, func(tx engine.Tx) error {
		var err error
		head, _, err = tx.AuditHead()
		return err
	}); err != nil {
		return audit.Attendance{}, false, err
	}

	return audit.Attendance{
		Record:     rows[index],
		Proof:      proof,
		Checkpoint: audit.Seal(leaves, head, rows[len(rows)-1].HLC),
	}, true, nil
}

// Verify replays the whole chain and reports the first inconsistency. This is
// what an auditor runs against a database handed to them by somebody they have no
// reason to trust.
func (s *Store) Verify(ctx context.Context) error {
	rows, err := s.AuditRows(ctx, 1, 0)
	if err != nil {
		return err
	}
	return audit.Verify(rows)
}

// Flags returns every detected double use.
func (s *Store) Flags(ctx context.Context) ([]engine.DoubleUse, error) {
	rows, err := s.reader.QueryContext(ctx, "SELECT payload FROM flags ORDER BY seq")
	if err != nil {
		return nil, fmt.Errorf("store: reading flags: %w", err)
	}
	defer rows.Close()

	var out []engine.DoubleUse
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("store: reading flags: %w", err)
		}
		var flag engine.DoubleUse
		if err := json.Unmarshal([]byte(payload), &flag); err != nil {
			return nil, fmt.Errorf("store: flag payload is corrupt: %w", err)
		}
		out = append(out, flag)
	}
	return out, rows.Err()
}

// PutIncident inserts or replaces one incident. Called by the board's persist
// callback after every change.
func (s *Store) PutIncident(ctx context.Context, i incident.Incident) error {
	payload, err := json.Marshal(i)
	if err != nil {
		return fmt.Errorf("store: encoding incident: %w", err)
	}
	if _, err := s.writer.ExecContext(ctx, `
		INSERT INTO incidents (id, seq, kind, severity, status, zone, raised, payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			severity = excluded.severity, status = excluded.status, payload = excluded.payload`,
		string(i.ID), i.Seq, string(i.Kind), string(i.Severity), string(i.Status),
		string(i.Zone), i.RaisedAt.UnixMilli(), string(payload)); err != nil {
		return fmt.Errorf("store: putting incident %s: %w", i.ID, err)
	}
	return nil
}

// Incidents returns every incident, oldest first, for the board to restore on
// boot.
func (s *Store) Incidents(ctx context.Context) ([]incident.Incident, error) {
	rows, err := s.reader.QueryContext(ctx, "SELECT payload FROM incidents ORDER BY seq")
	if err != nil {
		return nil, fmt.Errorf("store: reading incidents: %w", err)
	}
	defer rows.Close()

	var out []incident.Incident
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("store: reading incidents: %w", err)
		}
		var i incident.Incident
		if err := json.Unmarshal([]byte(payload), &i); err != nil {
			return nil, fmt.Errorf("store: incident payload is corrupt: %w", err)
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// NextIncidentSeq allocates an incident sequence, so ids survive a reboot without
// the board having to scan the table.
func (s *Store) NextIncidentSeq(ctx context.Context) (uint64, error) {
	var next uint64
	if err := s.writer.QueryRowContext(ctx,
		"UPDATE counters SET value = value + 1 WHERE name = ? RETURNING value",
		counterIncident).Scan(&next); err != nil {
		return 0, fmt.Errorf("store: allocating incident sequence: %w", err)
	}
	return next, nil
}

// Session marks the box's open and close times, which bound the attendance
// report.
func (s *Store) OpenSession(ctx context.Context, at time.Time) error {
	if existing, found, err := s.Meta(ctx, MetaOpenedAt); err != nil {
		return err
	} else if found && existing != "" {
		// Already open. A reboot mid-event must not reset the session start, or
		// the attendance report claims doors opened whenever the box last
		// crashed.
		return nil
	}
	return s.SetMeta(ctx, MetaOpenedAt, fmt.Sprintf("%d", at.UnixMilli()))
}

// CloseSession records the session end.
func (s *Store) CloseSession(ctx context.Context, at time.Time) error {
	return s.SetMeta(ctx, MetaClosedAt, fmt.Sprintf("%d", at.UnixMilli()))
}

// SessionWindow returns the recorded open and close times.
func (s *Store) SessionWindow(ctx context.Context) (opened, closed time.Time, err error) {
	read := func(key string) (time.Time, error) {
		value, found, err := s.Meta(ctx, key)
		if err != nil || !found || value == "" {
			return time.Time{}, err
		}
		var millis int64
		if _, err := fmt.Sscanf(value, "%d", &millis); err != nil {
			return time.Time{}, fmt.Errorf("store: meta %q is not a timestamp: %w", key, err)
		}
		return time.UnixMilli(millis).UTC(), nil
	}
	if opened, err = read(MetaOpenedAt); err != nil {
		return time.Time{}, time.Time{}, err
	}
	closed, err = read(MetaClosedAt)
	return opened, closed, err
}
