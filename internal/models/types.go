// Package models defines all shared data types for dmarcer.
package models

import "time"

// ReportType identifies the category of a parsed DMARC-adjacent report.
type ReportType string

const (
	ReportTypeAggregate ReportType = "aggregate"
	ReportTypeForensic  ReportType = "forensic"
	ReportTypeSMTPTLS   ReportType = "smtp_tls"
	ReportTypeUnknown   ReportType = "unknown"
)

// IPSourceInfo is the enriched source IP record attached to all report records.
type IPSourceInfo struct {
	IPAddress  string  `json:"ip_address"`
	Country    *string `json:"country"`     // ISO 3166-1 alpha-2, nullable
	ReverseDNS *string `json:"reverse_dns"` // PTR record, nullable
	BaseDomain *string `json:"base_domain"` // TLD+1 of PTR, nullable
	Name       *string `json:"name"`        // e.g. "Google", from sender map
	Type       *string `json:"type"`        // e.g. "esp", "isp", from sender map
}

// ============================================================
// Aggregate Report
// ============================================================

// AggregateReport is a fully parsed and enriched DMARC aggregate (rua) report.
type AggregateReport struct {
	XMLSchema       string                  `json:"xml_schema"`
	ReportMetadata  AggregateMetadata       `json:"report_metadata"`
	PolicyPublished AggregatePolicyPublished `json:"policy_published"`
	Records         []AggregateRecord       `json:"records"`
}

// AggregateMetadata holds the report-level metadata from the XML <report_metadata> block.
type AggregateMetadata struct {
	OrgName                      string   `json:"org_name"`
	OrgEmail                     string   `json:"org_email"`
	OrgExtraContactInfo          *string  `json:"org_extra_contact_info"`
	ReportID                     string   `json:"report_id"`
	BeginDate                    string   `json:"begin_date"` // "YYYY-MM-DD HH:MM:SS" UTC
	EndDate                      string   `json:"end_date"`
	TimespanRequiresNormalization bool     `json:"timespan_requires_normalization"`
	OriginalTimespanSeconds       int      `json:"original_timespan_seconds"`
	Errors                        []string `json:"errors"`
}

// AggregatePolicyPublished holds the <policy_published> block from the aggregate XML.
type AggregatePolicyPublished struct {
	Domain string `json:"domain"`
	ADKIM  string `json:"adkim"` // "r" or "s"; default "r"
	ASPF   string `json:"aspf"`  // "r" or "s"; default "r"
	P      string `json:"p"`     // none/quarantine/reject
	SP     string `json:"sp"`
	PCT    string `json:"pct"` // default "100"
	FO     string `json:"fo"`  // default "0"
}

// AggregateRecord is one <record> block within an aggregate report, fully enriched.
type AggregateRecord struct {
	IntervalBegin      string               `json:"interval_begin"`
	IntervalEnd        string               `json:"interval_end"`
	Source             IPSourceInfo         `json:"source"`
	Count              int                  `json:"count"`
	Alignment          AggregateAlignment   `json:"alignment"`
	PolicyEvaluated    AggregatePolicyEval  `json:"policy_evaluated"`
	Identifiers        AggregateIdentifiers `json:"identifiers"`
	AuthResults        AggregateAuthResults `json:"auth_results"`
	NormalizedTimespan bool                 `json:"normalized_timespan"`
}

// AggregateAlignment holds computed DMARC alignment results for a record.
type AggregateAlignment struct {
	SPF   bool `json:"spf"`
	DKIM  bool `json:"dkim"`
	DMARC bool `json:"dmarc"` // spf OR dkim
}

// AggregatePolicyEval holds the <policy_evaluated> block from a record.
type AggregatePolicyEval struct {
	Disposition           string                 `json:"disposition"`
	DKIM                  string                 `json:"dkim"`
	SPF                   string                 `json:"spf"`
	PolicyOverrideReasons []PolicyOverrideReason `json:"policy_override_reasons"`
}

// PolicyOverrideReason is one entry in the <reason> list of a policy_evaluated block.
type PolicyOverrideReason struct {
	Type    string  `json:"type"`
	Comment *string `json:"comment"`
}

// AggregateIdentifiers holds the <identifiers> block from a record.
type AggregateIdentifiers struct {
	HeaderFrom   string  `json:"header_from"`
	EnvelopeFrom *string `json:"envelope_from"`
	EnvelopeTo   *string `json:"envelope_to"`
}

// AggregateAuthResults holds the <auth_results> block from a record.
type AggregateAuthResults struct {
	DKIM []DKIMResult `json:"dkim"`
	SPF  []SPFResult  `json:"spf"`
}

// DKIMResult is one DKIM authentication result within <auth_results>.
type DKIMResult struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector"` // default "none"
	Result   string `json:"result"`   // pass/fail/none/etc
}

// SPFResult is one SPF authentication result within <auth_results>.
type SPFResult struct {
	Domain string `json:"domain"`
	Scope  string `json:"scope"`  // "mfrom" or "helo"; default "mfrom"
	Result string `json:"result"` // pass/fail/neutral/etc
}

// ============================================================
// Forensic Report
// ============================================================

// ForensicReport is a fully parsed RFC 5965 ARF forensic (ruf) report.
type ForensicReport struct {
	FeedbackType             *string      `json:"feedback_type"`
	UserAgent                *string      `json:"user_agent"`
	Version                  *string      `json:"version"`
	OriginalEnvelopeID       *string      `json:"original_envelope_id"`
	OriginalMailFrom         *string      `json:"original_mail_from"`
	OriginalRcptTo           *string      `json:"original_rcpt_to"`
	ArrivalDate              string       `json:"arrival_date"`
	ArrivalDateUTC           string       `json:"arrival_date_utc"`
	AuthenticationResults    *string      `json:"authentication_results"`
	DeliveryResult           *string      `json:"delivery_result"`
	AuthFailure              []string     `json:"auth_failure"`
	AuthenticationMechanisms []string     `json:"authentication_mechanisms"`
	DKIMDomain               *string      `json:"dkim_domain"`
	ReportedDomain           string       `json:"reported_domain"`
	SampleHeadersOnly        bool         `json:"sample_headers_only"`
	Source                   IPSourceInfo `json:"source"`
	Sample                   string       `json:"sample"`
	ParsedSample             *ParsedEmail `json:"parsed_sample"`
}

// ParsedEmail is a parsed RFC 822 email message.
type ParsedEmail struct {
	From                *EmailAddress    `json:"from"`
	To                  []EmailAddress   `json:"to"`
	ReplyTo             []EmailAddress   `json:"reply_to"`
	CC                  []EmailAddress   `json:"cc"`
	BCC                 []EmailAddress   `json:"bcc"`
	Subject             *string          `json:"subject"`
	Date                *string          `json:"date"`
	Body                *string          `json:"body"`
	Headers             map[string]any   `json:"headers"`
	Attachments         []EmailAttachment `json:"attachments"`
	FilenameSafeSubject *string          `json:"filename_safe_subject"`
	HasDefects          bool             `json:"has_defects"`
	Received            []ReceivedHop    `json:"received"`
}

// EmailAddress is a parsed email address with display name components.
type EmailAddress struct {
	DisplayName *string `json:"display_name"`
	Address     string  `json:"address"`
	Local       string  `json:"local"`
	Domain      string  `json:"domain"`
}

// EmailAttachment represents a MIME attachment within a forensic email sample.
type EmailAttachment struct {
	Filename    *string `json:"filename"`
	ContentType string  `json:"content_type"`
	SHA256      string  `json:"sha256"`
	Payload     []byte  `json:"payload,omitempty"` // omitted when STRIP_ATTACHMENT_PAYLOADS=true
}

// ReceivedHop is one parsed Received: header hop.
type ReceivedHop struct {
	From    *string `json:"from"`
	By      *string `json:"by"`
	With    *string `json:"with"`
	Date    *string `json:"date"`
	DateUTC *string `json:"date_utc"`
	Hop     int     `json:"hop"`
	Delay   int     `json:"delay"` // seconds
}

// ============================================================
// SMTP TLS Report
// ============================================================

// SMTPTLSReport is a fully parsed RFC 8460 SMTP TLS report.
type SMTPTLSReport struct {
	OrganizationName string          `json:"organization_name"`
	BeginDate        string          `json:"begin_date"`
	EndDate          string          `json:"end_date"`
	ContactInfo      string          `json:"contact_info"`
	ReportID         string          `json:"report_id"`
	Policies         []SMTPTLSPolicy `json:"policies"`
}

// SMTPTLSPolicy is one policy entry within an SMTP TLS report.
type SMTPTLSPolicy struct {
	PolicyDomain           string                `json:"policy_domain"`
	PolicyType             string                `json:"policy_type"` // sts/tlsa/no-policy-found
	PolicyStrings          []string              `json:"policy_strings"`
	MXHostPatterns         []string              `json:"mx_host_patterns"`
	SuccessfulSessionCount int                   `json:"successful_session_count"`
	FailedSessionCount     int                   `json:"failed_session_count"`
	FailureDetails         []SMTPTLSFailureDetail `json:"failure_details"`
}

// SMTPTLSFailureDetail is one failure entry within an SMTP TLS policy.
type SMTPTLSFailureDetail struct {
	ResultType          string  `json:"result_type"`
	SendingMTAIP        string  `json:"sending_mta_ip"`
	ReceivingIP         *string `json:"receiving_ip"`
	ReceivingMXHostname *string `json:"receiving_mx_hostname"`
	ReceivingMXHelo     *string `json:"receiving_mx_helo"`
	FailedSessionCount  int     `json:"failed_session_count"`
	AdditionalInfoURI   *string `json:"additional_info_uri"`
	FailureReasonCode   *string `json:"failure_reason_code"`
}

// ============================================================
// Parse result container
// ============================================================

// ParseResult is the output of processing a single file or email message.
type ParseResult struct {
	Type      ReportType
	Aggregate *AggregateReport
	Forensic  *ForensicReport
	SMTPTLS   *SMTPTLSReport
}

// ============================================================
// Output backend interface
// ============================================================

// Backend is implemented by every output destination (SQLite, Elasticsearch, OpenObserve).
type Backend interface {
	// Name returns a human-readable identifier used in log messages.
	Name() string
	// WriteAggregate persists one aggregate record (already flattened from its parent report).
	WriteAggregate(report *AggregateReport, record *AggregateRecord) error
	// WriteForensic persists one forensic report.
	WriteForensic(report *ForensicReport) error
	// WriteSMTPTLS persists one SMTP TLS policy record (already split from its parent report).
	WriteSMTPTLS(report *SMTPTLSReport, policy *SMTPTLSPolicy) error
	// Close flushes pending buffers and releases resources.
	Close() error
}

// ============================================================
// Ingest result
// ============================================================

// IngestStatus describes the outcome of processing one file or message.
type IngestStatus string

const (
	IngestOK        IngestStatus = "ok"
	IngestDuplicate IngestStatus = "duplicate"
	IngestError     IngestStatus = "error"
)

// IngestResult is the outcome of ingesting one file or email.
type IngestResult struct {
	Source         string       // "imap", "upload", "file"
	Filename       string
	Type           ReportType
	Status         IngestStatus
	Message        string
	RecordsSaved   int
	DuplicatesSkipped int
	IngestedAt     time.Time
}
