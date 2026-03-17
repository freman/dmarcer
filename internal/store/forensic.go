package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/freman/dmarcer/internal/models"
)

// IsDuplicateForensic returns true when the database already contains a report
// that matches arrival_date_utc + source_ip + sample_subject.
func (d *DB) IsDuplicateForensic(r *models.ForensicReport) (bool, error) {
	const q = `
		SELECT COUNT(1) FROM forensic_reports
		WHERE arrival_date_utc = ?
		  AND COALESCE(source_ip,'')     = ?
		  AND COALESCE(sample_subject,'') = ?
		LIMIT 1`

	ip := ""
	if r.Source.IPAddress != "" {
		ip = r.Source.IPAddress
	}

	subject := ""
	if r.ParsedSample != nil && r.ParsedSample.Subject != nil {
		subject = *r.ParsedSample.Subject
	}

	var n int

	err := d.db.QueryRow(q, r.ArrivalDateUTC, ip, subject).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: IsDuplicateForensic: %w", err)
	}

	return n > 0, nil
}

// SaveForensic persists a forensic report. Returns duplicate=true if skipped.
func (d *DB) SaveForensic(r *models.ForensicReport) (duplicate bool, err error) {
	dup, err := d.IsDuplicateForensic(r)
	if err != nil {
		return false, err
	}

	if dup {
		return true, nil
	}

	blob, err := json.Marshal(r)
	if err != nil {
		return false, fmt.Errorf("store: SaveForensic: marshal: %w", err)
	}

	subject := ""
	if r.ParsedSample != nil && r.ParsedSample.Subject != nil {
		subject = *r.ParsedSample.Subject
	}

	const ins = `
		INSERT INTO forensic_reports (
			arrival_date_utc, reported_domain,
			source_ip, source_country,
			feedback_type, delivery_result,
			sample_subject, report_json
		) VALUES (?,?,?,?,?,?,?,?)`

	_, err = d.db.Exec(ins,
		nullString(r.ArrivalDateUTC),
		r.ReportedDomain,
		nullString(r.Source.IPAddress),
		nullStringPtr(r.Source.Country),
		nullStringPtr(r.FeedbackType),
		nullStringPtr(r.DeliveryResult),
		nullString(subject),
		string(blob),
	)
	if err != nil {
		return false, fmt.Errorf("store: SaveForensic: insert: %w", err)
	}

	return false, nil
}

// QueryForensicParams holds filter parameters for listing forensic reports.
type QueryForensicParams struct {
	From          string
	To            string
	Domain        string
	SourceIP      string
	SourceCountry string
	Page          int
	PerPage       int
}

// ForensicRow is one flattened forensic report as returned by list/get queries.
type ForensicRow struct {
	ID             int64  `json:"id"`
	CreatedAt      string `json:"created_at"`
	ArrivalDateUTC string `json:"arrival_date_utc"`
	ReportedDomain string `json:"reported_domain"`
	SourceIP       string `json:"source_ip"`
	SourceCountry  string `json:"source_country"`
	FeedbackType   string `json:"feedback_type"`
	DeliveryResult string `json:"delivery_result"`
	SampleSubject  string `json:"sample_subject"`
	ReportJSON     string `json:"report_json"`
}

// ListForensic returns paginated forensic reports with a total count.
func (d *DB) ListForensic(p QueryForensicParams) (rows []ForensicRow, total int, err error) {
	perPage := p.PerPage
	if perPage <= 0 {
		perPage = 100
	}

	if perPage > 1000 {
		perPage = 1000
	}

	page := max(p.Page, 1)
	offset := (page - 1) * perPage

	where, args := forensicWhere(p)

	countQ := "SELECT COUNT(1) FROM forensic_reports" + where
	if err = d.db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: ListForensic count: %w", err)
	}

	dataQ := `SELECT
		id, created_at,
		COALESCE(arrival_date_utc,''),
		reported_domain,
		COALESCE(source_ip,''), COALESCE(source_country,''),
		COALESCE(feedback_type,''), COALESCE(delivery_result,''),
		COALESCE(sample_subject,''),
		report_json
	FROM forensic_reports` + where + ` ORDER BY arrival_date_utc DESC LIMIT ? OFFSET ?`

	dataArgs := append(args[:len(args):len(args)], perPage, offset)

	qRows, qErr := d.db.Query(dataQ, dataArgs...)
	if qErr != nil {
		return nil, 0, fmt.Errorf("store: ListForensic query: %w", qErr)
	}
	defer qRows.Close()

	for qRows.Next() {
		var r ForensicRow
		if err = qRows.Scan(
			&r.ID, &r.CreatedAt,
			&r.ArrivalDateUTC, &r.ReportedDomain,
			&r.SourceIP, &r.SourceCountry,
			&r.FeedbackType, &r.DeliveryResult,
			&r.SampleSubject,
			&r.ReportJSON,
		); err != nil {
			return nil, 0, fmt.Errorf("store: ListForensic scan: %w", err)
		}

		rows = append(rows, r)
	}

	if err = qRows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: ListForensic rows: %w", err)
	}

	return rows, total, nil
}

// GetForensic returns one forensic report by primary key.
func (d *DB) GetForensic(id int64) (*ForensicRow, error) {
	const q = `SELECT
		id, created_at,
		COALESCE(arrival_date_utc,''),
		reported_domain,
		COALESCE(source_ip,''), COALESCE(source_country,''),
		COALESCE(feedback_type,''), COALESCE(delivery_result,''),
		COALESCE(sample_subject,''),
		report_json
	FROM forensic_reports WHERE id = ?`

	var r ForensicRow

	err := d.db.QueryRow(q, id).Scan(
		&r.ID, &r.CreatedAt,
		&r.ArrivalDateUTC, &r.ReportedDomain,
		&r.SourceIP, &r.SourceCountry,
		&r.FeedbackType, &r.DeliveryResult,
		&r.SampleSubject,
		&r.ReportJSON,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("store: GetForensic: %w", err)
	}

	return &r, nil
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

func forensicWhere(p QueryForensicParams) (string, []any) {
	var clauses []string

	var args []any

	if p.From != "" {
		clauses = append(clauses, "arrival_date_utc >= ?")
		args = append(args, p.From)
	}

	if p.To != "" {
		clauses = append(clauses, "arrival_date_utc <= ?")
		args = append(args, p.To)
	}

	if p.Domain != "" {
		clauses = append(clauses, "reported_domain = ?")
		args = append(args, p.Domain)
	}

	if p.SourceIP != "" {
		clauses = append(clauses, "source_ip = ?")
		args = append(args, p.SourceIP)
	}

	if p.SourceCountry != "" {
		clauses = append(clauses, "source_country = ?")
		args = append(args, p.SourceCountry)
	}

	if len(clauses) == 0 {
		return "", args
	}

	return " WHERE " + strings.Join(clauses, " AND "), args
}
