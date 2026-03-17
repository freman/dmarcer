// Package store provides SQLite persistence for dmarcer using modernc.org/sqlite.
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DB wraps a *sql.DB and exposes all dmarcer persistence operations.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path, applies the schema
// migration, and returns a ready-to-use DB.
func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}

	// SQLite performs best with a single writer connection.
	db.SetMaxOpenConns(1)

	if err := applySchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}

	return &DB{db: db}, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error { return d.db.Close() }

// SQL returns the raw *sql.DB for use by other store files.
func (d *DB) SQL() *sql.DB { return d.db }

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func applySchema(db *sql.DB) error {
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"); err != nil {
		return fmt.Errorf("pragmas: %w", err)
	}

	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}

	for i := version; i < len(migrations); i++ {
		if err := applyMigration(db, i); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}

	return nil
}

func applyMigration(db *sql.DB, idx int) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(migrations[idx]); err != nil {
		return err
	}

	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", idx+1)); err != nil {
		return err
	}

	return tx.Commit()
}

// migrations is an append-only list of schema changes. Each entry is applied
// exactly once; the SQLite user_version PRAGMA tracks how many have run.
// Never edit existing entries - add new ones for every schema change.
var migrations = []string{
	// 1: initial schema
	`CREATE TABLE IF NOT EXISTS aggregate_records (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at              TEXT NOT NULL DEFAULT (datetime('now')),
    xml_schema              TEXT,
    org_name                TEXT NOT NULL,
    org_email               TEXT,
    report_id               TEXT NOT NULL,
    report_begin            TEXT NOT NULL,
    report_end              TEXT NOT NULL,
    normalized_timespan     INTEGER NOT NULL DEFAULT 0,
    original_timespan_sec   INTEGER,
    policy_domain           TEXT NOT NULL,
    policy_adkim            TEXT,
    policy_aspf             TEXT,
    policy_p                TEXT,
    policy_sp               TEXT,
    policy_pct              INTEGER,
    policy_fo               TEXT,
    interval_begin          TEXT NOT NULL,
    interval_end            TEXT NOT NULL,
    source_ip               TEXT NOT NULL,
    source_country          TEXT,
    source_reverse_dns      TEXT,
    source_base_domain      TEXT,
    source_name             TEXT,
    source_type             TEXT,
    message_count           INTEGER NOT NULL DEFAULT 1,
    spf_aligned             INTEGER NOT NULL DEFAULT 0,
    dkim_aligned            INTEGER NOT NULL DEFAULT 0,
    dmarc_passed            INTEGER NOT NULL DEFAULT 0,
    disposition             TEXT,
    dkim_eval               TEXT,
    spf_eval                TEXT,
    header_from             TEXT,
    envelope_from           TEXT,
    envelope_to             TEXT,
    record_json             TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agg_report_id      ON aggregate_records(report_id, org_name, policy_domain);
CREATE INDEX IF NOT EXISTS idx_agg_interval_begin ON aggregate_records(interval_begin);
CREATE INDEX IF NOT EXISTS idx_agg_source_ip      ON aggregate_records(source_ip);
CREATE INDEX IF NOT EXISTS idx_agg_header_from    ON aggregate_records(header_from);
CREATE INDEX IF NOT EXISTS idx_agg_disposition    ON aggregate_records(disposition);
CREATE INDEX IF NOT EXISTS idx_agg_dmarc_passed   ON aggregate_records(dmarc_passed);
CREATE INDEX IF NOT EXISTS idx_agg_source_country ON aggregate_records(source_country);

CREATE TABLE IF NOT EXISTS forensic_reports (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    arrival_date_utc    TEXT,
    reported_domain     TEXT NOT NULL,
    source_ip           TEXT,
    source_country      TEXT,
    feedback_type       TEXT,
    delivery_result     TEXT,
    sample_subject      TEXT,
    report_json         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_for_arrival   ON forensic_reports(arrival_date_utc);
CREATE INDEX IF NOT EXISTS idx_for_domain    ON forensic_reports(reported_domain);
CREATE INDEX IF NOT EXISTS idx_for_source_ip ON forensic_reports(source_ip);

CREATE TABLE IF NOT EXISTS smtp_tls_records (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at                  TEXT NOT NULL DEFAULT (datetime('now')),
    org_name                    TEXT NOT NULL,
    report_id                   TEXT NOT NULL,
    begin_date                  TEXT NOT NULL,
    end_date                    TEXT NOT NULL,
    policy_domain               TEXT NOT NULL,
    policy_type                 TEXT,
    successful_session_count    INTEGER NOT NULL DEFAULT 0,
    failed_session_count        INTEGER NOT NULL DEFAULT 0,
    policy_json                 TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tls_report_id  ON smtp_tls_records(report_id, org_name);
CREATE INDEX IF NOT EXISTS idx_tls_begin_date ON smtp_tls_records(begin_date);
CREATE INDEX IF NOT EXISTS idx_tls_domain     ON smtp_tls_records(policy_domain);

CREATE TABLE IF NOT EXISTS ingest_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ingested_at         TEXT NOT NULL DEFAULT (datetime('now')),
    source              TEXT NOT NULL,
    filename            TEXT,
    report_type         TEXT,
    status              TEXT NOT NULL,
    message             TEXT,
    records_saved       INTEGER NOT NULL DEFAULT 0,
    duplicates_skipped  INTEGER NOT NULL DEFAULT 0
);
`,
}
