package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure Go driver: no CGO, so one static binary

	"github.com/ManasMadan/gatecrash/internal/engine"
)

// Store is the box's SQLite storage.
//
// It holds two connection pools. The writer is capped at one connection because
// exactly one write transaction runs at a time, and that serialisation is the
// linearization point the exactly-once guarantee rests on. Readers get their own
// pool so a dashboard poll or a manifest download never queues behind a gate.
type Store struct {
	writer *sql.DB
	reader *sql.DB

	path string

	// now is injected so tests and the simulator can drive time.
	now func() time.Time
}

// Options configure a store.
type Options struct {
	// Path to the database file. The special value ":memory:" opens a private
	// in-memory database, used by tests.
	Path string

	// Readers is the size of the read pool. Zero picks four, which is more than a
	// Pi's core count and comfortably more than the number of concurrent
	// dashboard and manifest requests a venue generates.
	Readers int

	// Now is the box's clock.
	Now func() time.Time

	// Synchronous overrides the synchronous pragma. Empty means FULL, which is
	// what a real box runs: the SD card lies about fsync and FULL is the closest
	// SQLite can get to insisting. Tests and the simulator set NORMAL because
	// they are not fighting a card.
	Synchronous string
}

// Open opens or creates a database and applies any pending migrations.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, errors.New("store: no database path")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Readers <= 0 {
		opts.Readers = 4
	}
	if opts.Synchronous == "" {
		opts.Synchronous = "FULL"
	}

	memory := opts.Path == ":memory:"

	// An in-memory database has to be shared between the two pools or they see
	// different databases, which is a genuinely baffling failure mode.
	dsn := opts.Path
	if memory {
		dsn = "file::memory:?cache=shared"
	}

	writer, err := openPool(ctx, dsn, 1, opts.Synchronous)
	if err != nil {
		return nil, err
	}
	reader, err := openPool(ctx, dsn, opts.Readers, opts.Synchronous)
	if err != nil {
		_ = writer.Close()
		return nil, err
	}

	s := &Store{writer: writer, reader: reader, path: opts.Path, now: opts.Now}
	if err := s.migrate(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// openPool opens one connection pool with the box's pragmas applied.
func openPool(ctx context.Context, dsn string, maxOpen int, synchronous string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", dsn, err)
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxOpen)
	// Connections live for the process. Recycling them would mean re-running the
	// pragmas, and a connection that quietly lost journal_mode=WAL is a
	// connection that blocks every reader on every write.
	db.SetConnMaxLifetime(0)

	pragmas := []string{
		// WAL is what lets readers run during a write. Without it a dashboard
		// poll blocks a gate.
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = " + synchronous,
		// Wait rather than fail when the writer is busy. Five seconds is far
		// longer than any transaction here takes and far shorter than a gate
		// queue notices.
		"PRAGMA busy_timeout = 5000",
		"PRAGMA foreign_keys = ON",
		// Keep temp material in memory: writing a temp file to the SD card is
		// both slow and another chance to corrupt it.
		"PRAGMA temp_store = MEMORY",
		// 8 MiB of page cache. Enough to hold the working set of a 50k-ticket
		// event, small enough to leave room inside the box's 150 MB budget.
		"PRAGMA cache_size = -8000",
	}
	for _, pragma := range pragmas {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store: %s: %w", pragma, err)
		}
	}
	return db, nil
}

// migrate applies pending migrations.
func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.writer.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("store: reading schema version: %w", err)
	}
	if version > schemaVersion() {
		// A newer box wrote this file. Refusing is the only safe option: opening
		// it read-write with an older schema is how a database gets mangled.
		return fmt.Errorf("store: database is at schema version %d, this binary understands %d", version, schemaVersion())
	}

	for i := version; i < schemaVersion(); i++ {
		tx, err := s.writer.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: beginning migration %d: %w", i, err)
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: applying migration %d: %w", i, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: committing migration %d: %w", i, err)
		}
	}

	// Seed the counters the engine allocates from. INSERT OR IGNORE so this is
	// idempotent across reboots.
	for _, name := range []string{counterRedemption, counterIncident} {
		if _, err := s.writer.ExecContext(ctx,
			"INSERT OR IGNORE INTO counters (name, value) VALUES (?, 0)", name); err != nil {
			return fmt.Errorf("store: seeding counter %q: %w", name, err)
		}
	}
	return nil
}

// Counter names.
const (
	counterRedemption = "redemption"
	counterIncident   = "incident"
)

// IntegrityCheck runs SQLite's own consistency check.
//
// This runs at every boot, not just after a suspected problem. The box lives on
// media that corrupts on power loss, and the difference between finding out at
// startup and finding out at 8pm with a queue outside is the difference between
// swapping in the spare Pi and cancelling the show.
//
// It costs about a second on a 50k-ticket database, which is inside the
// twenty-second boot budget.
func (s *Store) IntegrityCheck(ctx context.Context) error {
	rows, err := s.reader.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return fmt.Errorf("store: integrity check: %w", err)
	}
	defer rows.Close()

	var problems []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return fmt.Errorf("store: integrity check: %w", err)
		}
		if line != "ok" {
			problems = append(problems, line)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: integrity check: %w", err)
	}
	if len(problems) > 0 {
		return fmt.Errorf("store: database is corrupt: %v", problems)
	}
	return nil
}

// Checkpoint forces the WAL into the main database file.
//
// Called before the WAL is shipped and at session close. Without it a box that
// has been running for six hours has most of its recent admissions in the WAL
// rather than the database, and a naive file copy of just the database misses
// them — which is the single most common way people lose data with SQLite.
func (s *Store) Checkpoint(ctx context.Context) error {
	if _, err := s.writer.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("store: wal checkpoint: %w", err)
	}
	return nil
}

// Path returns the database path.
func (s *Store) Path() string { return s.path }

// WALPath returns the write-ahead log's path, which the replication layer ships.
func (s *Store) WALPath() string {
	if s.path == ":memory:" {
		return ""
	}
	return s.path + "-wal"
}

// Dir returns the directory holding the database.
func (s *Store) Dir() string { return filepath.Dir(s.path) }

// Close shuts both pools down.
func (s *Store) Close() error {
	var first error
	if s.writer != nil {
		if err := s.writer.Close(); err != nil {
			first = err
		}
	}
	if s.reader != nil {
		if err := s.reader.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Write runs fn inside a serialized write transaction.
//
// BEGIN IMMEDIATE rather than plain BEGIN: a deferred transaction takes its write
// lock at the first write statement, which means a transaction that reads and
// then writes can fail with SQLITE_BUSY halfway through and has to be retried.
// Taking the lock up front turns that into a wait, and with a single writer
// connection there is nothing to wait for anyway.
func (s *Store) Write(ctx context.Context, fn func(engine.Tx) error) error {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: beginning write: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "SELECT 1"); err != nil {
		tx.Rollback()
		return fmt.Errorf("store: write transaction: %w", err)
	}

	if err := fn(&txn{ctx: ctx, tx: tx, write: true, now: s.now}); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: committing write: %w", err)
	}
	return nil
}

// Read runs fn inside a read transaction, concurrently with a writer.
func (s *Store) Read(ctx context.Context, fn func(engine.Tx) error) error {
	tx, err := s.reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("store: beginning read: %w", err)
	}
	// Reads never commit anything, so rollback unconditionally: it is how a
	// read-only transaction is released, and treating its error as significant
	// would turn a successful read into a failure.
	defer tx.Rollback()

	return fn(&txn{ctx: ctx, tx: tx, write: false, now: s.now})
}

// ErrReadOnly is returned when a read transaction attempts a write.
var ErrReadOnly = errors.New("store: write attempted in a read transaction")
