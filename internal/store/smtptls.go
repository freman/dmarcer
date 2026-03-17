package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/freman/dmarcer/internal/models"
)

// IsDuplicateSMTPTLS returns true when a row already exists for the given
// report + policy combination (matched on org_name, report_id, and
// policy_domain).
func (d *DB) IsDuplicateSMTPTLS(report *models.SMTPTLSReport, policy *models.SMTPTLSPolicy) (bool, error) {
	const q = `
		SELECT COUNT(1) FROM smtp_tls_records
		WHERE org_name      = ?
		  AND report_id     = ?
		  AND policy_domain = ?
		LIMIT 1`

	var n int

	err := d.db.QueryRow(q,
		report.OrganizationName,
		report.ReportID,
		policy.PolicyDomain,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: IsDuplicateSMTPTLS: %w", err)
	}

	return n > 0, nil
}

// SaveSMTPTLS persists each policy within report as a separate row. Policies
// that are already present are skipped. Returns the count of rows inserted and
// whether every policy was a duplicate.
func (d *DB) SaveSMTPTLS(report *models.SMTPTLSReport) (saved int, duplicate bool, err error) {
	const ins = `
		INSERT INTO smtp_tls_records (
			org_name, report_id, begin_date, end_date,
			policy_domain, policy_type,
			successful_session_count, failed_session_count,
			policy_json
		) VALUES (?,?,?,?,?,?,?,?,?)`

	tx, err := d.db.Begin()
	if err != nil {
		return 0, false, fmt.Errorf("store: SaveSMTPTLS: begin tx: %w", err)
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	stmt, err := tx.Prepare(ins)
	if err != nil {
		return 0, false, fmt.Errorf("store: SaveSMTPTLS: prepare: %w", err)
	}
	defer stmt.Close()

	allDup := true

	for i := range report.Policies {
		pol := &report.Policies[i]

		dup, dupErr := d.IsDuplicateSMTPTLS(report, pol)
		if dupErr != nil {
			err = dupErr

			return 0, false, err
		}

		if dup {
			continue
		}

		allDup = false

		blob, marshalErr := json.Marshal(pol)
		if marshalErr != nil {
			err = fmt.Errorf("store: SaveSMTPTLS: marshal policy %d: %w", i, marshalErr)
			return 0, false, err
		}

		_, execErr := stmt.Exec(
			report.OrganizationName,
			report.ReportID,
			report.BeginDate,
			report.EndDate,
			pol.PolicyDomain,
			nullString(pol.PolicyType),
			pol.SuccessfulSessionCount,
			pol.FailedSessionCount,
			string(blob),
		)
		if execErr != nil {
			err = fmt.Errorf("store: SaveSMTPTLS: insert policy %d: %w", i, execErr)
			return 0, false, err
		}

		saved++
	}

	if err = tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("store: SaveSMTPTLS: commit: %w", err)
	}

	if saved == 0 && allDup {
		return 0, true, nil
	}

	return saved, false, nil
}

// QuerySMTPTLSParams holds filter parameters for listing SMTP TLS records.
type QuerySMTPTLSParams struct {
	From       string
	To         string
	Domain     string
	OrgName    string
	PolicyType string
	Page       int
	PerPage    int
}

// SMTPTLSRow is one flattened SMTP TLS record as returned by list/get queries.
type SMTPTLSRow struct {
	ID                     int64  `json:"id"`
	CreatedAt              string `json:"created_at"`
	OrgName                string `json:"org_name"`
	ReportID               string `json:"report_id"`
	BeginDate              string `json:"begin_date"`
	EndDate                string `json:"end_date"`
	PolicyDomain           string `json:"policy_domain"`
	PolicyType             string `json:"policy_type"`
	SuccessfulSessionCount int    `json:"successful_session_count"`
	FailedSessionCount     int    `json:"failed_session_count"`
	PolicyJSON             string `json:"policy_json"`
}

// SaveSMTPTLSPolicy inserts a single SMTP TLS policy record. Used by the Backend
// adapter when the fan-out writes policies individually after deduplication.
func (d *DB) SaveSMTPTLSPolicy(report *models.SMTPTLSReport, pol *models.SMTPTLSPolicy) error {
	const ins = `
		INSERT INTO smtp_tls_records (
			org_name, report_id, begin_date, end_date,
			policy_domain, policy_type,
			successful_session_count, failed_session_count,
			policy_json
		) VALUES (?,?,?,?,?,?,?,?,?)`

	blob, err := json.Marshal(pol)
	if err != nil {
		return fmt.Errorf("store: SaveSMTPTLSPolicy: marshal: %w", err)
	}

	_, err = d.db.Exec(ins,
		report.OrganizationName,
		report.ReportID,
		report.BeginDate,
		report.EndDate,
		pol.PolicyDomain,
		nullString(pol.PolicyType),
		pol.SuccessfulSessionCount,
		pol.FailedSessionCount,
		string(blob),
	)

	return err
}

// ListSMTPTLS returns paginated SMTP TLS records with a total count.
func (d *DB) ListSMTPTLS(p QuerySMTPTLSParams) (rows []SMTPTLSRow, total int, err error) {
	perPage := p.PerPage
	if perPage <= 0 {
		perPage = 100
	}

	if perPage > 1000 {
		perPage = 1000
	}

	page := max(p.Page, 1)
	offset := (page - 1) * perPage

	where, args := smtpTLSWhere(p)

	countQ := "SELECT COUNT(1) FROM smtp_tls_records" + where
	if err = d.db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: ListSMTPTLS count: %w", err)
	}

	dataQ := `SELECT
		id, created_at,
		org_name, report_id,
		begin_date, end_date,
		policy_domain, COALESCE(policy_type,''),
		successful_session_count, failed_session_count,
		policy_json
	FROM smtp_tls_records` + where + ` ORDER BY begin_date DESC LIMIT ? OFFSET ?`

	dataArgs := append(args[:len(args):len(args)], perPage, offset)

	qRows, qErr := d.db.Query(dataQ, dataArgs...)
	if qErr != nil {
		return nil, 0, fmt.Errorf("store: ListSMTPTLS query: %w", qErr)
	}
	defer qRows.Close()

	for qRows.Next() {
		var r SMTPTLSRow
		if err = qRows.Scan(
			&r.ID, &r.CreatedAt,
			&r.OrgName, &r.ReportID,
			&r.BeginDate, &r.EndDate,
			&r.PolicyDomain, &r.PolicyType,
			&r.SuccessfulSessionCount, &r.FailedSessionCount,
			&r.PolicyJSON,
		); err != nil {
			return nil, 0, fmt.Errorf("store: ListSMTPTLS scan: %w", err)
		}

		rows = append(rows, r)
	}

	if err = qRows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: ListSMTPTLS rows: %w", err)
	}

	return rows, total, nil
}

// GetSMTPTLS returns one SMTP TLS record by primary key.
func (d *DB) GetSMTPTLS(id int64) (*SMTPTLSRow, error) {
	const q = `SELECT
		id, created_at,
		org_name, report_id,
		begin_date, end_date,
		policy_domain, COALESCE(policy_type,''),
		successful_session_count, failed_session_count,
		policy_json
	FROM smtp_tls_records WHERE id = ?`

	var r SMTPTLSRow

	err := d.db.QueryRow(q, id).Scan(
		&r.ID, &r.CreatedAt,
		&r.OrgName, &r.ReportID,
		&r.BeginDate, &r.EndDate,
		&r.PolicyDomain, &r.PolicyType,
		&r.SuccessfulSessionCount, &r.FailedSessionCount,
		&r.PolicyJSON,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("store: GetSMTPTLS: %w", err)
	}

	return &r, nil
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

func smtpTLSWhere(p QuerySMTPTLSParams) (string, []any) {
	var clauses []string

	var args []any

	if p.From != "" {
		clauses = append(clauses, "begin_date >= ?")
		args = append(args, p.From)
	}

	if p.To != "" {
		clauses = append(clauses, "begin_date <= ?")
		args = append(args, p.To)
	}

	if p.Domain != "" {
		clauses = append(clauses, "policy_domain = ?")
		args = append(args, p.Domain)
	}

	if p.OrgName != "" {
		clauses = append(clauses, "org_name = ?")
		args = append(args, p.OrgName)
	}

	if p.PolicyType != "" {
		clauses = append(clauses, "policy_type = ?")
		args = append(args, p.PolicyType)
	}

	if len(clauses) == 0 {
		return "", args
	}

	return " WHERE " + strings.Join(clauses, " AND "), args
}
