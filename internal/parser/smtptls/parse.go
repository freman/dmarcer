// Package smtptls parses RFC 8460 SMTP TLS reports from JSON.
package smtptls

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/freman/dmarcer/internal/models"
)

// ── intermediate (raw) structs with hyphenated JSON tags ─────────────────────

type rawReport struct {
	OrganizationName string       `json:"organization-name"`
	DateRange        rawDateRange `json:"date-range"`
	ContactInfo      any          `json:"contact-info"` // string or []string
	ReportID         string       `json:"report-id"`
	Policies         []rawPolicy  `json:"policies"`
}

type rawDateRange struct {
	StartDatetime string `json:"start-datetime"`
	EndDatetime   string `json:"end-datetime"`
}

type rawPolicy struct {
	Policy         rawPolicyDetail    `json:"policy"`
	Summary        rawSummary         `json:"summary"`
	FailureDetails []rawFailureDetail `json:"failure-details"`
}

type rawPolicyDetail struct {
	PolicyDomain  string   `json:"policy-domain"`
	PolicyType    string   `json:"policy-type"`
	PolicyString  []string `json:"policy-string"`
	MXHostPattern []string `json:"mx-host-pattern"`
}

type rawSummary struct {
	TotalSuccessful int `json:"total-successful-session-count"`
	TotalFailed     int `json:"total-failure-session-count"`
}

type rawFailureDetail struct {
	ResultType          string `json:"result-type"`
	SendingMTAIP        string `json:"sending-mta-ip"`
	ReceivingIP         string `json:"receiving-ip"`
	ReceivingMXHostname string `json:"receiving-mx-hostname"`
	ReceivingMXHelo     string `json:"receiving-mx-helo"`
	FailedSessionCount  int    `json:"failed-session-count"`
	AdditionalInfoURI   string `json:"additional-info-uri"`
	FailureReasonCode   string `json:"failure-reason-code"`
}

// ── public API ────────────────────────────────────────────────────────────────

// Parse parses raw JSON bytes into an SMTPTLSReport.
func Parse(data []byte) (*models.SMTPTLSReport, error) {
	var raw rawReport
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("smtptls.Parse: json.Unmarshal: %w", err)
	}

	report := &models.SMTPTLSReport{
		OrganizationName: raw.OrganizationName,
		ReportID:         raw.ReportID,
		BeginDate:        parseRFC3339(raw.DateRange.StartDatetime),
		EndDate:          parseRFC3339(raw.DateRange.EndDatetime),
		ContactInfo:      normaliseContactInfo(raw.ContactInfo),
	}

	report.Policies = make([]models.SMTPTLSPolicy, 0, len(raw.Policies))
	for _, rp := range raw.Policies {
		policy := models.SMTPTLSPolicy{
			PolicyDomain:           rp.Policy.PolicyDomain,
			PolicyType:             rp.Policy.PolicyType,
			PolicyStrings:          nilSafeStringSlice(rp.Policy.PolicyString),
			MXHostPatterns:         nilSafeStringSlice(rp.Policy.MXHostPattern),
			SuccessfulSessionCount: rp.Summary.TotalSuccessful,
			FailedSessionCount:     rp.Summary.TotalFailed,
			FailureDetails:         make([]models.SMTPTLSFailureDetail, 0, len(rp.FailureDetails)),
		}

		for _, fd := range rp.FailureDetails {
			detail := models.SMTPTLSFailureDetail{
				ResultType:          fd.ResultType,
				SendingMTAIP:        fd.SendingMTAIP,
				FailedSessionCount:  fd.FailedSessionCount,
				ReceivingIP:         nullableString(fd.ReceivingIP),
				ReceivingMXHostname: nullableString(fd.ReceivingMXHostname),
				ReceivingMXHelo:     nullableString(fd.ReceivingMXHelo),
				AdditionalInfoURI:   nullableString(fd.AdditionalInfoURI),
				FailureReasonCode:   nullableString(fd.FailureReasonCode),
			}
			policy.FailureDetails = append(policy.FailureDetails, detail)
		}

		report.Policies = append(report.Policies, policy)
	}

	return report, nil
}

// ── normalisation helpers ─────────────────────────────────────────────────────

// parseRFC3339 parses an RFC 3339 timestamp and returns "YYYY-MM-DD HH:MM:SS" UTC.
// Returns the original string if parsing fails.
func parseRFC3339(s string) string {
	if s == "" {
		return s
	}

	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// Try without seconds.
		t, err = time.Parse("2006-01-02T15:04Z07:00", s)
		if err != nil {
			return s
		}
	}

	return t.UTC().Format("2006-01-02 15:04:05")
}

// normaliseContactInfo coerces the contact-info field (string or []string) to a string.
func normaliseContactInfo(v any) string {
	if v == nil {
		return ""
	}

	switch c := v.(type) {
	case string:
		return c
	case []any:
		parts := make([]string, 0, len(c))
		for _, item := range c {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
			}
		}

		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}

// nullableString returns a pointer to s if non-empty, otherwise nil.
func nullableString(s string) *string {
	if s == "" {
		return nil
	}

	return &s
}

// nilSafeStringSlice returns an empty (non-nil) slice if src is nil.
func nilSafeStringSlice(src []string) []string {
	if src == nil {
		return []string{}
	}

	return src
}
