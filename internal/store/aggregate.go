package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/freman/dmarcer/internal/models"
)

// IsDuplicateAggregate returns true when the database already contains at least
// one row with the same org_name, report_id, policy_domain, report_begin, and
// report_end.
func (d *DB) IsDuplicateAggregate(report *models.AggregateReport) (bool, error) {
	const q = `
		SELECT COUNT(1) FROM aggregate_records
		WHERE org_name      = ?
		  AND report_id     = ?
		  AND policy_domain = ?
		  AND report_begin  = ?
		  AND report_end    = ?
		LIMIT 1`

	var n int

	err := d.db.QueryRow(q,
		report.ReportMetadata.OrgName,
		report.ReportMetadata.ReportID,
		report.PolicyPublished.Domain,
		report.ReportMetadata.BeginDate,
		report.ReportMetadata.EndDate,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: IsDuplicateAggregate: %w", err)
	}

	return n > 0, nil
}

// SaveAggregate persists all records from report. It skips the whole report
// when IsDuplicateAggregate returns true. Returns the number of rows inserted
// and whether the report was a duplicate.
func (d *DB) SaveAggregate(report *models.AggregateReport) (saved int, duplicate bool, err error) {
	dup, err := d.IsDuplicateAggregate(report)
	if err != nil {
		return 0, false, err
	}

	if dup {
		return 0, true, nil
	}

	const ins = `
		INSERT INTO aggregate_records (
			xml_schema, org_name, org_email, report_id,
			report_begin, report_end,
			normalized_timespan, original_timespan_sec,
			policy_domain, policy_adkim, policy_aspf,
			policy_p, policy_sp, policy_pct, policy_fo,
			interval_begin, interval_end,
			source_ip, source_country, source_reverse_dns, source_base_domain,
			source_name, source_type,
			message_count, spf_aligned, dkim_aligned, dmarc_passed,
			disposition, dkim_eval, spf_eval,
			header_from, envelope_from, envelope_to,
			record_json
		) VALUES (
			?,?,?,?,
			?,?,
			?,?,
			?,?,?,
			?,?,?,?,
			?,?,
			?,?,?,?,
			?,?,
			?,?,?,?,
			?,?,?,
			?,?,?,
			?
		)`

	tx, err := d.db.Begin()
	if err != nil {
		return 0, false, fmt.Errorf("store: SaveAggregate: begin tx: %w", err)
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	stmt, err := tx.Prepare(ins)
	if err != nil {
		return 0, false, fmt.Errorf("store: SaveAggregate: prepare: %w", err)
	}
	defer stmt.Close()

	meta := report.ReportMetadata
	pol := report.PolicyPublished

	pctStr := pol.PCT

	var pctInt sql.NullInt64

	if pctStr != "" {
		var n int64
		if _, scanErr := fmt.Sscanf(pctStr, "%d", &n); scanErr == nil {
			pctInt = sql.NullInt64{Int64: n, Valid: true}
		}
	}

	for i := range report.Records {
		rec := &report.Records[i]

		blob, marshalErr := json.Marshal(rec)
		if marshalErr != nil {
			err = fmt.Errorf("store: SaveAggregate: marshal record %d: %w", i, marshalErr)
			return 0, false, err
		}

		normalizedInt := boolToInt(rec.NormalizedTimespan)

		_, execErr := stmt.Exec(
			report.XMLSchema,
			meta.OrgName,
			nullString(meta.OrgEmail),
			meta.ReportID,
			meta.BeginDate,
			meta.EndDate,
			normalizedInt,
			nullIntFromInt(meta.OriginalTimespanSeconds),
			pol.Domain,
			nullString(pol.ADKIM),
			nullString(pol.ASPF),
			nullString(pol.P),
			nullString(pol.SP),
			pctInt,
			nullString(pol.FO),
			rec.IntervalBegin,
			rec.IntervalEnd,
			rec.Source.IPAddress,
			nullStringPtr(rec.Source.Country),
			nullStringPtr(rec.Source.ReverseDNS),
			nullStringPtr(rec.Source.BaseDomain),
			nullStringPtr(rec.Source.Name),
			nullStringPtr(rec.Source.Type),
			rec.Count,
			boolToInt(rec.Alignment.SPF),
			boolToInt(rec.Alignment.DKIM),
			boolToInt(rec.Alignment.DMARC),
			nullString(rec.PolicyEvaluated.Disposition),
			nullString(rec.PolicyEvaluated.DKIM),
			nullString(rec.PolicyEvaluated.SPF),
			nullString(rec.Identifiers.HeaderFrom),
			nullStringPtr(rec.Identifiers.EnvelopeFrom),
			nullStringPtr(rec.Identifiers.EnvelopeTo),
			string(blob),
		)
		if execErr != nil {
			err = fmt.Errorf("store: SaveAggregate: insert record %d: %w", i, execErr)
			return 0, false, err
		}

		saved++
	}

	if err = tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("store: SaveAggregate: commit: %w", err)
	}

	return saved, false, nil
}

// SaveAggregateRecord inserts a single aggregate record. Used by the Backend
// adapter when the fan-out writes records individually after deduplication.
func (d *DB) SaveAggregateRecord(report *models.AggregateReport, rec *models.AggregateRecord) error {
	const ins = `
		INSERT INTO aggregate_records (
			xml_schema, org_name, org_email, report_id,
			report_begin, report_end,
			normalized_timespan, original_timespan_sec,
			policy_domain, policy_adkim, policy_aspf,
			policy_p, policy_sp, policy_pct, policy_fo,
			interval_begin, interval_end,
			source_ip, source_country, source_reverse_dns, source_base_domain,
			source_name, source_type,
			message_count, spf_aligned, dkim_aligned, dmarc_passed,
			disposition, dkim_eval, spf_eval,
			header_from, envelope_from, envelope_to,
			record_json
		) VALUES (
			?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
		)`

	meta := report.ReportMetadata
	pol := report.PolicyPublished

	var pctInt sql.NullInt64

	if pol.PCT != "" {
		var n int64
		if _, scanErr := fmt.Sscanf(pol.PCT, "%d", &n); scanErr == nil {
			pctInt = sql.NullInt64{Int64: n, Valid: true}
		}
	}

	blob, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("store: SaveAggregateRecord: marshal: %w", err)
	}

	_, err = d.db.Exec(ins,
		report.XMLSchema,
		meta.OrgName,
		nullString(meta.OrgEmail),
		meta.ReportID,
		meta.BeginDate,
		meta.EndDate,
		boolToInt(rec.NormalizedTimespan),
		nullIntFromInt(meta.OriginalTimespanSeconds),
		pol.Domain,
		nullString(pol.ADKIM),
		nullString(pol.ASPF),
		nullString(pol.P),
		nullString(pol.SP),
		pctInt,
		nullString(pol.FO),
		rec.IntervalBegin,
		rec.IntervalEnd,
		rec.Source.IPAddress,
		nullStringPtr(rec.Source.Country),
		nullStringPtr(rec.Source.ReverseDNS),
		nullStringPtr(rec.Source.BaseDomain),
		nullStringPtr(rec.Source.Name),
		nullStringPtr(rec.Source.Type),
		rec.Count,
		boolToInt(rec.Alignment.SPF),
		boolToInt(rec.Alignment.DKIM),
		boolToInt(rec.Alignment.DMARC),
		nullString(rec.PolicyEvaluated.Disposition),
		nullString(rec.PolicyEvaluated.DKIM),
		nullString(rec.PolicyEvaluated.SPF),
		nullString(rec.Identifiers.HeaderFrom),
		nullStringPtr(rec.Identifiers.EnvelopeFrom),
		nullStringPtr(rec.Identifiers.EnvelopeTo),
		string(blob),
	)

	return err
}

// QueryAggregateParams holds filter parameters for listing aggregate records.
type QueryAggregateParams struct {
	From             string
	To               string
	Domain           string
	HeaderFrom       string
	OrgName          string
	Disposition      string
	DMARCPassed      *bool
	SPFAligned       *bool
	DKIMAligned      *bool
	SourceCountry    string
	SourceType       string
	SourceName       string
	SourceIP         string
	SourceBaseDomain string
	Page             int
	PerPage          int
}

// AggregateRow is one flattened aggregate record as returned by list/get queries.
type AggregateRow struct {
	ID               int64  `json:"id"`
	CreatedAt        string `json:"created_at"`
	OrgName          string `json:"org_name"`
	OrgEmail         string `json:"org_email"`
	ReportID         string `json:"report_id"`
	ReportBegin      string `json:"report_begin"`
	ReportEnd        string `json:"report_end"`
	PolicyDomain     string `json:"policy_domain"`
	PolicyP          string `json:"policy_p"`
	PolicyPCT        int    `json:"policy_pct"`
	IntervalBegin    string `json:"interval_begin"`
	IntervalEnd      string `json:"interval_end"`
	SourceIP         string `json:"source_ip"`
	SourceCountry    string `json:"source_country"`
	SourceReverseDNS string `json:"source_reverse_dns"`
	SourceBaseDomain string `json:"source_base_domain"`
	SourceName       string `json:"source_name"`
	SourceType       string `json:"source_type"`
	MessageCount     int    `json:"message_count"`
	SPFAligned       bool   `json:"spf_aligned"`
	DKIMAligned      bool   `json:"dkim_aligned"`
	DMARCPassed      bool   `json:"dmarc_passed"`
	Disposition      string `json:"disposition"`
	HeaderFrom       string `json:"header_from"`
	EnvelopeFrom     string `json:"envelope_from"`
	RecordJSON       string `json:"record_json"`
}

// ListAggregate returns paginated aggregate records together with the total
// count that matches the filters.
func (d *DB) ListAggregate(p QueryAggregateParams) (rows []AggregateRow, total int, err error) {
	perPage := p.PerPage
	if perPage <= 0 {
		perPage = 100
	}

	if perPage > 1000 {
		perPage = 1000
	}

	page := max(p.Page, 1)
	offset := (page - 1) * perPage

	where, args := aggregateWhere(p)

	countQ := "SELECT COUNT(1) FROM aggregate_records" + where
	if err = d.db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: ListAggregate count: %w", err)
	}

	dataQ := `SELECT
		id, created_at,
		org_name, COALESCE(org_email,''), report_id,
		report_begin, report_end,
		COALESCE(policy_domain,''), COALESCE(policy_p,''), COALESCE(policy_pct,0),
		interval_begin, interval_end,
		source_ip,
		COALESCE(source_country,''), COALESCE(source_reverse_dns,''),
		COALESCE(source_base_domain,''), COALESCE(source_name,''), COALESCE(source_type,''),
		message_count,
		spf_aligned, dkim_aligned, dmarc_passed,
		COALESCE(disposition,''), COALESCE(header_from,''), COALESCE(envelope_from,''),
		record_json
	FROM aggregate_records` + where + ` ORDER BY interval_begin DESC LIMIT ? OFFSET ?`

	dataArgs := append(args[:len(args):len(args)], perPage, offset)

	qRows, qErr := d.db.Query(dataQ, dataArgs...)
	if qErr != nil {
		return nil, 0, fmt.Errorf("store: ListAggregate query: %w", qErr)
	}
	defer qRows.Close()

	for qRows.Next() {
		var r AggregateRow

		var spf, dkim, dmarc int

		if err = qRows.Scan(
			&r.ID, &r.CreatedAt,
			&r.OrgName, &r.OrgEmail, &r.ReportID,
			&r.ReportBegin, &r.ReportEnd,
			&r.PolicyDomain, &r.PolicyP, &r.PolicyPCT,
			&r.IntervalBegin, &r.IntervalEnd,
			&r.SourceIP,
			&r.SourceCountry, &r.SourceReverseDNS,
			&r.SourceBaseDomain, &r.SourceName, &r.SourceType,
			&r.MessageCount,
			&spf, &dkim, &dmarc,
			&r.Disposition, &r.HeaderFrom, &r.EnvelopeFrom,
			&r.RecordJSON,
		); err != nil {
			return nil, 0, fmt.Errorf("store: ListAggregate scan: %w", err)
		}

		r.SPFAligned = spf != 0
		r.DKIMAligned = dkim != 0
		r.DMARCPassed = dmarc != 0
		rows = append(rows, r)
	}

	if err = qRows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: ListAggregate rows: %w", err)
	}

	return rows, total, nil
}

// GetAggregate returns one aggregate record by primary key.
func (d *DB) GetAggregate(id int64) (*AggregateRow, error) {
	const q = `SELECT
		id, created_at,
		org_name, COALESCE(org_email,''), report_id,
		report_begin, report_end,
		COALESCE(policy_domain,''), COALESCE(policy_p,''), COALESCE(policy_pct,0),
		interval_begin, interval_end,
		source_ip,
		COALESCE(source_country,''), COALESCE(source_reverse_dns,''),
		COALESCE(source_base_domain,''), COALESCE(source_name,''), COALESCE(source_type,''),
		message_count,
		spf_aligned, dkim_aligned, dmarc_passed,
		COALESCE(disposition,''), COALESCE(header_from,''), COALESCE(envelope_from,''),
		record_json
	FROM aggregate_records WHERE id = ?`

	var r AggregateRow

	var spf, dkim, dmarc int

	err := d.db.QueryRow(q, id).Scan(
		&r.ID, &r.CreatedAt,
		&r.OrgName, &r.OrgEmail, &r.ReportID,
		&r.ReportBegin, &r.ReportEnd,
		&r.PolicyDomain, &r.PolicyP, &r.PolicyPCT,
		&r.IntervalBegin, &r.IntervalEnd,
		&r.SourceIP,
		&r.SourceCountry, &r.SourceReverseDNS,
		&r.SourceBaseDomain, &r.SourceName, &r.SourceType,
		&r.MessageCount,
		&spf, &dkim, &dmarc,
		&r.Disposition, &r.HeaderFrom, &r.EnvelopeFrom,
		&r.RecordJSON,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("store: GetAggregate: %w", err)
	}

	r.SPFAligned = spf != 0
	r.DKIMAligned = dkim != 0
	r.DMARCPassed = dmarc != 0

	return &r, nil
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// aggregateWhere builds the WHERE clause and argument slice from filter params.
// All user-supplied values are bound as parameters - no string interpolation.
func aggregateWhere(p QueryAggregateParams) (string, []any) {
	var clauses []string

	var args []any

	if p.From != "" {
		clauses = append(clauses, "interval_begin >= ?")
		args = append(args, p.From)
	}

	if p.To != "" {
		clauses = append(clauses, "interval_begin <= ?")
		args = append(args, p.To)
	}

	if p.Domain != "" {
		clauses = append(clauses, "policy_domain = ?")
		args = append(args, p.Domain)
	}

	if p.HeaderFrom != "" {
		clauses = append(clauses, "header_from = ?")
		args = append(args, p.HeaderFrom)
	}

	if p.OrgName != "" {
		clauses = append(clauses, "org_name = ?")
		args = append(args, p.OrgName)
	}

	if p.Disposition != "" {
		clauses = append(clauses, "disposition = ?")
		args = append(args, p.Disposition)
	}

	if p.DMARCPassed != nil {
		clauses = append(clauses, "dmarc_passed = ?")
		args = append(args, boolToInt(*p.DMARCPassed))
	}

	if p.SPFAligned != nil {
		clauses = append(clauses, "spf_aligned = ?")
		args = append(args, boolToInt(*p.SPFAligned))
	}

	if p.DKIMAligned != nil {
		clauses = append(clauses, "dkim_aligned = ?")
		args = append(args, boolToInt(*p.DKIMAligned))
	}

	if p.SourceCountry != "" {
		clauses = append(clauses, "source_country = ?")
		args = append(args, p.SourceCountry)
	}

	if p.SourceType != "" {
		clauses = append(clauses, "source_type = ?")
		args = append(args, p.SourceType)
	}

	if p.SourceName != "" {
		clauses = append(clauses, "source_name = ?")
		args = append(args, p.SourceName)
	}

	if p.SourceIP != "" {
		clauses = append(clauses, "source_ip = ?")
		args = append(args, p.SourceIP)
	}

	if p.SourceBaseDomain != "" {
		clauses = append(clauses, "source_base_domain = ?")
		args = append(args, p.SourceBaseDomain)
	}

	if len(clauses) == 0 {
		return "", args
	}

	return " WHERE " + strings.Join(clauses, " AND "), args
}

func boolToInt(b bool) int {
	if b {
		return 1
	}

	return 0
}

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func nullStringPtr(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}

	return sql.NullString{String: *s, Valid: true}
}

func nullIntFromInt(n int) sql.NullInt64 {
	return sql.NullInt64{Int64: int64(n), Valid: n != 0}
}
