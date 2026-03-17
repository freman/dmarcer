package store

import (
	"fmt"
	"strings"

	"github.com/freman/dmarcer/internal/models"
)

// LogIngest writes one ingest result to the ingest_log table.
func (d *DB) LogIngest(r models.IngestResult) error {
	const ins = `
		INSERT INTO ingest_log (
			ingested_at, source, filename, report_type,
			status, message, records_saved, duplicates_skipped
		) VALUES (datetime(?), ?, ?, ?, ?, ?, ?, ?)`

	ts := r.IngestedAt.UTC().Format("2006-01-02 15:04:05")

	_, err := d.db.Exec(ins,
		ts,
		r.Source,
		nullString(r.Filename),
		nullString(string(r.Type)),
		string(r.Status),
		nullString(r.Message),
		r.RecordsSaved,
		r.DuplicatesSkipped,
	)
	if err != nil {
		return fmt.Errorf("store: LogIngest: %w", err)
	}

	return nil
}

// QueryIngestLogParams holds filter parameters for listing ingest log entries.
type QueryIngestLogParams struct {
	From    string
	To      string
	Status  string
	Source  string
	Page    int
	PerPage int
}

// IngestLogRow is one row from the ingest_log table.
type IngestLogRow struct {
	ID                int64  `json:"id"`
	IngestedAt        string `json:"ingested_at"`
	Source            string `json:"source"`
	Filename          string `json:"filename"`
	ReportType        string `json:"report_type"`
	Status            string `json:"status"`
	Message           string `json:"message"`
	RecordsSaved      int    `json:"records_saved"`
	DuplicatesSkipped int    `json:"duplicates_skipped"`
}

// ListIngestLog returns paginated ingest log rows with a total count.
func (d *DB) ListIngestLog(p QueryIngestLogParams) (rows []IngestLogRow, total int, err error) {
	perPage := p.PerPage
	if perPage <= 0 {
		perPage = 100
	}

	if perPage > 1000 {
		perPage = 1000
	}

	page := max(p.Page, 1)
	offset := (page - 1) * perPage

	where, args := ingestLogWhere(p)

	countQ := "SELECT COUNT(1) FROM ingest_log" + where
	if err = d.db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: ListIngestLog count: %w", err)
	}

	dataQ := `SELECT
		id, ingested_at,
		source, COALESCE(filename,''), COALESCE(report_type,''),
		status, COALESCE(message,''),
		records_saved, duplicates_skipped
	FROM ingest_log` + where + ` ORDER BY ingested_at DESC LIMIT ? OFFSET ?`

	dataArgs := append(args, perPage, offset)

	qRows, qErr := d.db.Query(dataQ, dataArgs...)
	if qErr != nil {
		return nil, 0, fmt.Errorf("store: ListIngestLog query: %w", qErr)
	}
	defer qRows.Close()

	for qRows.Next() {
		var r IngestLogRow
		if err = qRows.Scan(
			&r.ID, &r.IngestedAt,
			&r.Source, &r.Filename, &r.ReportType,
			&r.Status, &r.Message,
			&r.RecordsSaved, &r.DuplicatesSkipped,
		); err != nil {
			return nil, 0, fmt.Errorf("store: ListIngestLog scan: %w", err)
		}

		rows = append(rows, r)
	}

	if err = qRows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: ListIngestLog rows: %w", err)
	}

	return rows, total, nil
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

func ingestLogWhere(p QueryIngestLogParams) (string, []any) {
	var clauses []string

	var args []any

	if p.From != "" {
		clauses = append(clauses, "ingested_at >= ?")
		args = append(args, p.From)
	}

	if p.To != "" {
		clauses = append(clauses, "ingested_at <= ?")
		args = append(args, p.To)
	}

	if p.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, p.Status)
	}

	if p.Source != "" {
		clauses = append(clauses, "source = ?")
		args = append(args, p.Source)
	}

	if len(clauses) == 0 {
		return "", args
	}

	return " WHERE " + strings.Join(clauses, " AND "), args
}
