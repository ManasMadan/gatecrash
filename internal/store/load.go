package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/manifest"
)

// Meta keys the box owns outside the engine's own chain position.
const (
	MetaManifestDigest   = "manifest_digest"
	MetaManifestSequence = "manifest_sequence"
	MetaEventID          = "event_id"
	MetaOpenedAt         = "opened_at"
	MetaClosedAt         = "closed_at"
	MetaBoxKey           = "box_key"
	MetaOrganizerKey     = "organizer_fingerprint"
)

// Ingest loads a verified manifest into the database.
//
// It is idempotent and it is a replace, not a merge: the ticket and device tables
// are made to match the manifest exactly. Merging would mean a ticket deleted
// upstream lingers on the box forever, and "we cancelled that ticket and it still
// got in" is the worst possible outcome for this table.
//
// Redemptions are never touched. A manifest can be re-ingested mid-event — which
// happens, because door sales and last-minute upgrades produce a new one — and
// everybody already inside stays inside.
func (s *Store) Ingest(ctx context.Context, body manifest.Body, digest string) error {
	previous, err := s.ManifestSequence(ctx)
	if err != nil {
		return err
	}
	// A stale file on a USB stick must not roll back a revocation.
	if body.Sequence < previous {
		return fmt.Errorf("%w: box holds sequence %d, file carries %d",
			manifest.ErrStale, previous, body.Sequence)
	}

	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: beginning ingest: %w", err)
	}
	defer tx.Rollback()

	// Replace wholesale. Both tables are small — fifty thousand rows is a few
	// megabytes — and a delete-then-insert inside one transaction is atomic, so
	// there is no window where the box has half a manifest.
	if _, err := tx.ExecContext(ctx, "DELETE FROM tickets"); err != nil {
		return fmt.Errorf("store: clearing tickets: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM devices"); err != nil {
		return fmt.Errorf("store: clearing devices: %w", err)
	}

	insertTicket, err := tx.PrepareContext(ctx, `
		INSERT INTO tickets (id, event_id, tier, section, row_label, seat, issued_at, revoked, signature, format)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("store: preparing ticket insert: %w", err)
	}
	defer insertTicket.Close()

	for _, t := range body.Tickets {
		if _, err := insertTicket.ExecContext(ctx,
			t.ID.Hex(), t.EventID.Hex(), t.Tier, t.Seat.Section, t.Seat.Row, t.Seat.Seat,
			t.IssuedAt, boolToInt(t.Revoked), t.Signature, t.Format); err != nil {
			return fmt.Errorf("store: inserting ticket %s: %w", t.ID, err)
		}
	}

	insertDevice, err := tx.PrepareContext(ctx, `
		INSERT INTO devices (id, name, checkpoints, revoked, enrolled_at)
		VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("store: preparing device insert: %w", err)
	}
	defer insertDevice.Close()

	enrolledAt := s.now().UnixMilli()
	for _, d := range body.Devices {
		allowlist, err := json.Marshal(d.Checkpoints)
		if err != nil {
			return fmt.Errorf("store: encoding allowlist for device %s: %w", d.ID, err)
		}
		if _, err := insertDevice.ExecContext(ctx,
			d.ID, d.Name, string(allowlist), boolToInt(d.Revoked), enrolledAt); err != nil {
			return fmt.Errorf("store: inserting device %s: %w", d.ID, err)
		}
	}

	for key, value := range map[string]string{
		MetaEventID:          body.Event.ID.Hex(),
		MetaManifestDigest:   digest,
		MetaManifestSequence: strconv.FormatUint(body.Sequence, 10),
		MetaOrganizerKey:     body.Verifying.Fingerprint(),
	} {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
			key, value); err != nil {
			return fmt.Errorf("store: writing meta %q: %w", key, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: committing ingest: %w", err)
	}
	return nil
}

// ManifestSequence returns the sequence of the manifest currently loaded.
func (s *Store) ManifestSequence(ctx context.Context) (uint64, error) {
	value, found, err := s.Meta(ctx, MetaManifestSequence)
	if err != nil || !found {
		return 0, err
	}
	var out uint64
	if _, err := fmt.Sscanf(value, "%d", &out); err != nil {
		return 0, fmt.Errorf("store: manifest sequence is not a number: %w", err)
	}
	return out, nil
}

// Meta reads one box-state value.
func (s *Store) Meta(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.reader.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?", key).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("store: reading meta %q: %w", key, err)
	}
	return value, true, nil
}

// SetMeta writes one box-state value.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	if _, err := s.writer.ExecContext(ctx,
		"INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
		key, value); err != nil {
		return fmt.Errorf("store: writing meta %q: %w", key, err)
	}
	return nil
}

// PutTicket inserts or replaces one ticket.
//
// Used by door sales and by the tests. Door sales are the reason this exists
// separately from Ingest: a ticket printed at the gate has to be admissible
// thirty seconds later, and regenerating and re-signing a whole manifest for one
// walk-up is not a thing that can happen in a queue.
func (s *Store) PutTicket(t engine.Ticket) {
	// The signature is deliberately swallowed rather than returned. This method
	// exists to satisfy the conformance harness's Loader interface, which cannot
	// return an error; PutTicketContext is the one production code calls.
	_ = s.PutTicketContext(context.Background(), t)
}

// PutTicketContext inserts or replaces one ticket, reporting failure.
func (s *Store) PutTicketContext(ctx context.Context, t engine.Ticket) error {
	_, err := s.writer.ExecContext(ctx, `
		INSERT INTO tickets (id, event_id, tier, section, row_label, seat, issued_at, revoked, signature, format)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			event_id = excluded.event_id, tier = excluded.tier, section = excluded.section,
			row_label = excluded.row_label, seat = excluded.seat, issued_at = excluded.issued_at,
			revoked = excluded.revoked, signature = excluded.signature, format = excluded.format`,
		t.ID.Hex(), t.EventID.Hex(), t.Tier, t.Seat.Section, t.Seat.Row, t.Seat.Seat,
		t.IssuedAt, boolToInt(t.Revoked), t.Signature, t.Format)
	if err != nil {
		return fmt.Errorf("store: putting ticket %s: %w", t.ID, err)
	}
	return nil
}

// PutDevice inserts or replaces one scanner. See PutTicket on the swallowed
// error.
func (s *Store) PutDevice(d engine.Device) {
	_ = s.PutDeviceContext(context.Background(), d)
}

// PutDeviceContext inserts or replaces one scanner, reporting failure.
func (s *Store) PutDeviceContext(ctx context.Context, d engine.Device) error {
	allowlist, err := json.Marshal(d.Checkpoints)
	if err != nil {
		return fmt.Errorf("store: encoding allowlist: %w", err)
	}
	if d.Checkpoints == nil {
		// json.Marshal renders a nil slice as "null", and a null allowlist would
		// decode to nil and be indistinguishable from a corrupt row. An
		// unassigned device has an empty list, which scans nothing.
		allowlist = []byte("[]")
	}
	_, err = s.writer.ExecContext(ctx, `
		INSERT INTO devices (id, name, checkpoints, revoked, enrolled_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			name = excluded.name, checkpoints = excluded.checkpoints, revoked = excluded.revoked`,
		d.ID, d.Name, string(allowlist), boolToInt(d.Revoked), s.now().UnixMilli())
	if err != nil {
		return fmt.Errorf("store: putting device %s: %w", d.ID, err)
	}
	return nil
}

// RevokeTicket marks a ticket revoked. One tap on the dashboard.
func (s *Store) RevokeTicket(ctx context.Context, idHex string, revoked bool) error {
	result, err := s.writer.ExecContext(ctx,
		"UPDATE tickets SET revoked = ? WHERE id = ?", boolToInt(revoked), idHex)
	if err != nil {
		return fmt.Errorf("store: revoking ticket: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: revoking ticket: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("store: no ticket %s", idHex)
	}
	return nil
}

// RevokeDeviceContext marks a scanner revoked, which is what happens when one is
// stolen. It takes effect on the very next scan because the engine reads the
// device row on every scan rather than caching it.
func (s *Store) RevokeDeviceContext(ctx context.Context, id string, revoked bool) error {
	result, err := s.writer.ExecContext(ctx,
		"UPDATE devices SET revoked = ? WHERE id = ?", boolToInt(revoked), id)
	if err != nil {
		return fmt.Errorf("store: revoking device: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: revoking device: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("store: no device %s", id)
	}
	return nil
}

// Devices lists the enrolled scanner roster.
func (s *Store) Devices(ctx context.Context) ([]engine.Device, error) {
	rows, err := s.reader.QueryContext(ctx,
		"SELECT id, name, checkpoints, revoked, last_seen FROM devices ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("store: listing devices: %w", err)
	}
	defer rows.Close()

	var out []engine.Device
	for rows.Next() {
		var (
			d           engine.Device
			checkpoints string
			revoked     int
			lastSeen    int64
		)
		if err := rows.Scan(&d.ID, &d.Name, &checkpoints, &revoked, &lastSeen); err != nil {
			return nil, fmt.Errorf("store: scanning device: %w", err)
		}
		if err := json.Unmarshal([]byte(checkpoints), &d.Checkpoints); err != nil {
			return nil, fmt.Errorf("store: device %s allowlist is corrupt: %w", d.ID, err)
		}
		d.Revoked = revoked != 0
		if lastSeen != 0 {
			d.LastSeen = time.UnixMilli(lastSeen).UTC()
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// TicketCount returns how many tickets are loaded, and how many per tier, which
// the dashboard shows as turnout against tickets sold.
func (s *Store) TicketCount(ctx context.Context) (int, map[string]int, error) {
	rows, err := s.reader.QueryContext(ctx, "SELECT tier, COUNT(*) FROM tickets GROUP BY tier")
	if err != nil {
		return 0, nil, fmt.Errorf("store: counting tickets: %w", err)
	}
	defer rows.Close()

	total := 0
	byTier := make(map[string]int)
	for rows.Next() {
		var tier string
		var count int
		if err := rows.Scan(&tier, &count); err != nil {
			return 0, nil, fmt.Errorf("store: counting tickets: %w", err)
		}
		byTier[tier] = count
		total += count
	}
	return total, byTier, rows.Err()
}
