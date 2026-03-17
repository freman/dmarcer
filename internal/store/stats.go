package store

import (
	"fmt"
	"strings"
)

// StatsFilter restricts aggregate stats queries by date range and/or domain.
type StatsFilter struct {
	From             string // ISO date (inclusive), e.g. "2024-01-01"
	To               string // ISO date (inclusive)
	Domain           string // policy_domain filter; empty = all domains
	SourceIP         string // filter by source_ip
	OrgName          string // filter by org_name (reporting organisation)
	SourceName       string // filter by source_name (sender ESP name)
	SourceBaseDomain string // filter by source_base_domain (when source_name is absent)
}

// SummaryStats holds high-level counts across all aggregate records.
type SummaryStats struct {
	TotalMessages int64            `json:"total_messages"`
	DMARCPassed   int64            `json:"dmarc_passed"`
	DMARCFailed   int64            `json:"dmarc_failed"`
	SPFAligned    int64            `json:"spf_aligned"`
	DKIMAligned   int64            `json:"dkim_aligned"`
	Dispositions  map[string]int64 `json:"dispositions"`
}

// TimelineBucket holds aggregated counts for one date bucket.
type TimelineBucket struct {
	Date          string           `json:"date"`
	TotalMessages int64            `json:"total_messages"`
	DMARCPassed   int64            `json:"dmarc_passed"`
	SPFAligned    int64            `json:"spf_aligned"`
	DKIMAligned   int64            `json:"dkim_aligned"`
	Dispositions  map[string]int64 `json:"dispositions"`
}

// TopSource aggregates message counts per sending IP/name.
type TopSource struct {
	SourceIP         string `json:"source_ip"`
	SourceReverseDNS string `json:"source_reverse_dns"`
	SourceBaseDomain string `json:"source_base_domain"`
	SourceCountry    string `json:"source_country"`
	SourceName       string `json:"source_name"`
	SourceType       string `json:"source_type"`
	TotalMessages    int64  `json:"total_messages"`
	DMARCPassed      int64  `json:"dmarc_passed"`
}

// CountryCount holds per-country message totals.
type CountryCount struct {
	Country       string `json:"country"`
	TotalMessages int64  `json:"total_messages"`
}

// OrgCount holds per-reporting-org message totals.
type OrgCount struct {
	OrgName       string `json:"org_name"`
	TotalMessages int64  `json:"total_messages"`
}

// SenderCount holds per-sender-name message and DMARC pass totals.
type SenderCount struct {
	SourceName       string `json:"source_name"`
	SourceType       string `json:"source_type"`
	SourceBaseDomain string `json:"source_base_domain"`
	TotalMessages    int64  `json:"total_messages"`
	DMARCPassed      int64  `json:"dmarc_passed"`
}

// SMTPTLSSummary holds aggregate session counts across SMTP TLS records.
type SMTPTLSSummary struct {
	TotalSuccessfulSessions int64            `json:"total_successful_sessions"`
	TotalFailedSessions     int64            `json:"total_failed_sessions"`
	ByPolicyType            map[string]int64 `json:"by_policy_type"`
}

// ---------------------------------------------------------------------------
// GetSummaryStats
// ---------------------------------------------------------------------------

// GetSummaryStats returns high-level message and alignment counts for the
// given filter.
func (d *DB) GetSummaryStats(f StatsFilter) (*SummaryStats, error) {
	where, args := statsWhere(f)

	// Main counts.
	countQ := `
		SELECT
			COALESCE(SUM(message_count),0),
			COALESCE(SUM(CASE WHEN dmarc_passed=1 THEN message_count ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN dmarc_passed=0 THEN message_count ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN spf_aligned=1  THEN message_count ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN dkim_aligned=1 THEN message_count ELSE 0 END),0)
		FROM aggregate_records` + where

	s := &SummaryStats{Dispositions: make(map[string]int64)}

	err := d.db.QueryRow(countQ, args...).Scan(
		&s.TotalMessages, &s.DMARCPassed, &s.DMARCFailed,
		&s.SPFAligned, &s.DKIMAligned,
	)
	if err != nil {
		return nil, fmt.Errorf("store: GetSummaryStats: %w", err)
	}

	// Per-disposition breakdown.
	dispQ := `
		SELECT COALESCE(disposition,'none'), COALESCE(SUM(message_count),0)
		FROM aggregate_records` + where + `
		GROUP BY disposition`

	rows, err := d.db.Query(dispQ, args...)
	if err != nil {
		return nil, fmt.Errorf("store: GetSummaryStats disposition: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var disp string

		var cnt int64
		if err = rows.Scan(&disp, &cnt); err != nil {
			return nil, fmt.Errorf("store: GetSummaryStats disposition scan: %w", err)
		}

		s.Dispositions[disp] = cnt
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("store: GetSummaryStats disposition rows: %w", err)
	}

	return s, nil
}

// ---------------------------------------------------------------------------
// GetTimeline
// ---------------------------------------------------------------------------

// GetTimeline returns per-bucket message counts. granularity may be "day",
// "week", or "month"; anything else defaults to "day".
func (d *DB) GetTimeline(f StatsFilter, granularity string) ([]TimelineBucket, error) {
	dateFmt := timelineFormat(granularity)
	where, args := statsWhere(f)

	mainQ := `
		SELECT
			strftime('` + dateFmt + `', interval_begin) AS bucket,
			COALESCE(SUM(message_count),0),
			COALESCE(SUM(CASE WHEN dmarc_passed=1 THEN message_count ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN spf_aligned=1  THEN message_count ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN dkim_aligned=1 THEN message_count ELSE 0 END),0)
		FROM aggregate_records` + where + `
		GROUP BY bucket ORDER BY bucket ASC`

	rows, err := d.db.Query(mainQ, args...)
	if err != nil {
		return nil, fmt.Errorf("store: GetTimeline: %w", err)
	}
	defer rows.Close()

	// Build a map of bucket -> bucket for disposition fill-in.
	bucketMap := map[string]*TimelineBucket{}

	var buckets []TimelineBucket

	for rows.Next() {
		var b TimelineBucket

		b.Dispositions = make(map[string]int64)
		if err = rows.Scan(&b.Date, &b.TotalMessages, &b.DMARCPassed, &b.SPFAligned, &b.DKIMAligned); err != nil {
			return nil, fmt.Errorf("store: GetTimeline scan: %w", err)
		}

		buckets = append(buckets, b)
		bucketMap[b.Date] = &buckets[len(buckets)-1]
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("store: GetTimeline rows: %w", err)
	}

	// Per-disposition per-bucket.
	dispQ := `
		SELECT
			strftime('` + dateFmt + `', interval_begin) AS bucket,
			COALESCE(disposition,'none'),
			COALESCE(SUM(message_count),0)
		FROM aggregate_records` + where + `
		GROUP BY bucket, disposition`

	dRows, err := d.db.Query(dispQ, args...)
	if err != nil {
		return nil, fmt.Errorf("store: GetTimeline disposition: %w", err)
	}
	defer dRows.Close()

	for dRows.Next() {
		var bucket, disp string

		var cnt int64
		if err = dRows.Scan(&bucket, &disp, &cnt); err != nil {
			return nil, fmt.Errorf("store: GetTimeline disposition scan: %w", err)
		}

		if b, ok := bucketMap[bucket]; ok {
			b.Dispositions[disp] = cnt
		}
	}

	if err = dRows.Err(); err != nil {
		return nil, fmt.Errorf("store: GetTimeline disposition rows: %w", err)
	}

	return buckets, nil
}

func timelineFormat(granularity string) string {
	switch granularity {
	case "month":
		return "%Y-%m"
	case "week":
		return "%Y-W%W"
	default:
		return "%Y-%m-%d"
	}
}

// ---------------------------------------------------------------------------
// GetTopSources
// ---------------------------------------------------------------------------

// GetTopSources returns the top N sending IPs ordered by total message count.
func (d *DB) GetTopSources(f StatsFilter, limit int) ([]TopSource, error) {
	if limit <= 0 {
		limit = 10
	}

	where, args := statsWhere(f)

	q := `
		SELECT
			source_ip,
			COALESCE(source_reverse_dns,''),
			COALESCE(source_base_domain,''),
			COALESCE(source_country,''),
			COALESCE(source_name,''),
			COALESCE(source_type,''),
			COALESCE(SUM(message_count),0)                                          AS total,
			COALESCE(SUM(CASE WHEN dmarc_passed=1 THEN message_count ELSE 0 END),0) AS passed
		FROM aggregate_records` + where + `
		GROUP BY source_ip
		ORDER BY total DESC
		LIMIT ?`

	rows, err := d.db.Query(q, append(args, limit)...)
	if err != nil {
		return nil, fmt.Errorf("store: GetTopSources: %w", err)
	}
	defer rows.Close()

	var out []TopSource

	for rows.Next() {
		var s TopSource
		if err = rows.Scan(
			&s.SourceIP, &s.SourceReverseDNS, &s.SourceBaseDomain,
			&s.SourceCountry, &s.SourceName, &s.SourceType,
			&s.TotalMessages, &s.DMARCPassed,
		); err != nil {
			return nil, fmt.Errorf("store: GetTopSources scan: %w", err)
		}

		out = append(out, s)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("store: GetTopSources rows: %w", err)
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// GetCountries
// ---------------------------------------------------------------------------

// GetCountries returns message counts grouped by source_country, ordered
// by total messages descending.
func (d *DB) GetCountries(f StatsFilter) ([]CountryCount, error) {
	where, args := statsWhere(f)

	q := `
		SELECT
			COALESCE(source_country,'unknown') AS country,
			COALESCE(SUM(message_count),0)    AS total
		FROM aggregate_records` + where + `
		GROUP BY source_country
		ORDER BY total DESC`

	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: GetCountries: %w", err)
	}
	defer rows.Close()

	var out []CountryCount

	for rows.Next() {
		var c CountryCount
		if err = rows.Scan(&c.Country, &c.TotalMessages); err != nil {
			return nil, fmt.Errorf("store: GetCountries scan: %w", err)
		}

		out = append(out, c)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("store: GetCountries rows: %w", err)
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// GetOrgs
// ---------------------------------------------------------------------------

// GetOrgs returns message counts grouped by org_name, ordered by total
// messages descending.
func (d *DB) GetOrgs(f StatsFilter) ([]OrgCount, error) {
	where, args := statsWhere(f)

	q := `
		SELECT
			org_name,
			COALESCE(SUM(message_count),0) AS total
		FROM aggregate_records` + where + `
		GROUP BY org_name
		ORDER BY total DESC`

	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: GetOrgs: %w", err)
	}
	defer rows.Close()

	var out []OrgCount

	for rows.Next() {
		var o OrgCount
		if err = rows.Scan(&o.OrgName, &o.TotalMessages); err != nil {
			return nil, fmt.Errorf("store: GetOrgs scan: %w", err)
		}

		out = append(out, o)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("store: GetOrgs rows: %w", err)
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// GetSenders
// ---------------------------------------------------------------------------

// GetSenders returns message counts grouped by (source_name, source_type),
// ordered by total messages descending.
func (d *DB) GetSenders(f StatsFilter) ([]SenderCount, error) {
	where, args := statsWhere(f)

	q := `
		SELECT
			COALESCE(source_name,''),
			COALESCE(source_type,''),
			COALESCE(source_base_domain,''),
			COALESCE(SUM(message_count),0)                                          AS total,
			COALESCE(SUM(CASE WHEN dmarc_passed=1 THEN message_count ELSE 0 END),0) AS passed
		FROM aggregate_records` + where + `
		GROUP BY source_name, source_type, source_base_domain
		ORDER BY total DESC`

	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: GetSenders: %w", err)
	}
	defer rows.Close()

	var out []SenderCount

	for rows.Next() {
		var s SenderCount
		if err = rows.Scan(&s.SourceName, &s.SourceType, &s.SourceBaseDomain, &s.TotalMessages, &s.DMARCPassed); err != nil {
			return nil, fmt.Errorf("store: GetSenders scan: %w", err)
		}

		out = append(out, s)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("store: GetSenders rows: %w", err)
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// GetSMTPTLSSummary
// ---------------------------------------------------------------------------

// GetSMTPTLSSummary returns aggregate session counts from smtp_tls_records.
func (d *DB) GetSMTPTLSSummary(f StatsFilter) (*SMTPTLSSummary, error) {
	where, args := smtpTLSStatsWhere(f)

	countQ := `
		SELECT
			COALESCE(SUM(successful_session_count),0),
			COALESCE(SUM(failed_session_count),0)
		FROM smtp_tls_records` + where

	s := &SMTPTLSSummary{ByPolicyType: make(map[string]int64)}

	err := d.db.QueryRow(countQ, args...).Scan(
		&s.TotalSuccessfulSessions,
		&s.TotalFailedSessions,
	)
	if err != nil {
		return nil, fmt.Errorf("store: GetSMTPTLSSummary: %w", err)
	}

	typeQ := `
		SELECT
			COALESCE(policy_type,'unknown'),
			COALESCE(SUM(successful_session_count),0)
		FROM smtp_tls_records` + where + `
		GROUP BY policy_type`

	rows, err := d.db.Query(typeQ, args...)
	if err != nil {
		return nil, fmt.Errorf("store: GetSMTPTLSSummary by type: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var pt string

		var cnt int64

		if err = rows.Scan(&pt, &cnt); err != nil {
			return nil, fmt.Errorf("store: GetSMTPTLSSummary by type scan: %w", err)
		}

		s.ByPolicyType[pt] = cnt
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("store: GetSMTPTLSSummary by type rows: %w", err)
	}

	return s, nil
}

// ---------------------------------------------------------------------------
// GetDistinctDomains
// ---------------------------------------------------------------------------

// GetDistinctDomains returns a sorted list of all distinct policy_domain
// values in aggregate_records.
func (d *DB) GetDistinctDomains() ([]string, error) {
	const q = `SELECT DISTINCT policy_domain FROM aggregate_records ORDER BY policy_domain ASC`

	rows, err := d.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("store: GetDistinctDomains: %w", err)
	}
	defer rows.Close()

	var out []string

	for rows.Next() {
		var domain string
		if err = rows.Scan(&domain); err != nil {
			return nil, fmt.Errorf("store: GetDistinctDomains scan: %w", err)
		}

		out = append(out, domain)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("store: GetDistinctDomains rows: %w", err)
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// WHERE clause builders
// ---------------------------------------------------------------------------

// statsWhere builds a WHERE clause for aggregate_records queries from a
// StatsFilter. All values are bound as parameters.
func statsWhere(f StatsFilter) (string, []any) {
	var clauses []string

	var args []any

	if f.From != "" {
		clauses = append(clauses, "interval_begin >= ?")
		args = append(args, f.From)
	}

	if f.To != "" {
		clauses = append(clauses, "interval_begin <= ?")
		args = append(args, f.To)
	}

	if f.Domain != "" {
		clauses = append(clauses, "policy_domain = ?")
		args = append(args, f.Domain)
	}

	if f.SourceIP != "" {
		clauses = append(clauses, "source_ip = ?")
		args = append(args, f.SourceIP)
	}

	if f.OrgName != "" {
		clauses = append(clauses, "org_name = ?")
		args = append(args, f.OrgName)
	}

	if f.SourceName != "" {
		clauses = append(clauses, "source_name = ?")
		args = append(args, f.SourceName)
	}

	if f.SourceBaseDomain != "" {
		clauses = append(clauses, "source_base_domain = ?")
		args = append(args, f.SourceBaseDomain)
	}

	if len(clauses) == 0 {
		return "", args
	}

	return " WHERE " + strings.Join(clauses, " AND "), args
}

// smtpTLSStatsWhere builds a WHERE clause for smtp_tls_records stats queries.
func smtpTLSStatsWhere(f StatsFilter) (string, []any) {
	var clauses []string

	var args []any

	if f.From != "" {
		clauses = append(clauses, "begin_date >= ?")
		args = append(args, f.From)
	}

	if f.To != "" {
		clauses = append(clauses, "begin_date <= ?")
		args = append(args, f.To)
	}

	if f.Domain != "" {
		clauses = append(clauses, "policy_domain = ?")
		args = append(args, f.Domain)
	}

	if len(clauses) == 0 {
		return "", args
	}

	return " WHERE " + strings.Join(clauses, " AND "), args
}
