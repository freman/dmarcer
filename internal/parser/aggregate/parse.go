// Package aggregate parses RFC 7489 DMARC aggregate XML reports.
package aggregate

import (
	"encoding/xml"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/freman/dmarcer/internal/enrichment"
	"github.com/freman/dmarcer/internal/models"
)

// xmlDeclRE matches an XML declaration so it can be replaced before parsing.
var xmlDeclRE = regexp.MustCompile(`<\?xml[^?]*\?>`)

// ── internal XML structs ──────────────────────────────────────────────────────

type xmlFeedback struct {
	XMLName         xml.Name           `xml:"feedback"`
	ReportMetadata  xmlReportMetadata  `xml:"report_metadata"`
	PolicyPublished xmlPolicyPublished `xml:"policy_published"`
	Records         []xmlRecord        `xml:"record"`
}

type xmlReportMetadata struct {
	OrgName          string       `xml:"org_name"`
	Email            string       `xml:"email"`
	ExtraContactInfo string       `xml:"extra_contact_info"`
	ReportID         string       `xml:"report_id"`
	DateRange        xmlDateRange `xml:"date_range"`
	Error            []string     `xml:"error"`
}

type xmlDateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

type xmlPolicyPublished struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim"`
	ASPF   string `xml:"aspf"`
	P      string `xml:"p"`
	SP     string `xml:"sp"`
	PCT    string `xml:"pct"`
	FO     string `xml:"fo"`
}

type xmlRecord struct {
	Row         xmlRow         `xml:"row"`
	Identifiers xmlIdentifiers `xml:"identifiers"`
	AuthResults xmlAuthResults `xml:"auth_results"`
}

type xmlRow struct {
	SourceIP        string             `xml:"source_ip"`
	Count           int                `xml:"count"`
	PolicyEvaluated xmlPolicyEvaluated `xml:"policy_evaluated"`
}

type xmlPolicyEvaluated struct {
	Disposition string      `xml:"disposition"`
	DKIM        string      `xml:"dkim"`
	SPF         string      `xml:"spf"`
	Reason      []xmlReason `xml:"reason"`
}

type xmlReason struct {
	Type    string `xml:"type"`
	Comment string `xml:"comment"`
}

type xmlIdentifiers struct {
	HeaderFrom   string `xml:"header_from"`
	EnvelopeFrom string `xml:"envelope_from"`
	EnvelopeTo   string `xml:"envelope_to"`
}

type xmlAuthResults struct {
	DKIM []xmlDKIM `xml:"dkim"`
	SPF  []xmlSPF  `xml:"spf"`
}

type xmlDKIM struct {
	Domain   string `xml:"domain"`
	Selector string `xml:"selector"`
	Result   string `xml:"result"`
}

type xmlSPF struct {
	Domain string `xml:"domain"`
	Scope  string `xml:"scope"`
	Result string `xml:"result"`
}

// ── public API ────────────────────────────────────────────────────────────────

// Parse parses raw XML bytes into an AggregateReport.
// enricher may be nil (skips IP enrichment).
// normalizeTimespanHours: split daily if span > this many hours (0 = disabled).
func Parse(data []byte, enricher enrichment.Enricher, normalizeTimespanHours float64) (*models.AggregateReport, error) {
	// 1. Replace XML declaration to avoid charset issues.
	clean := xmlDeclRE.ReplaceAll(data, []byte(`<?xml version="1.0"?>`))

	// 2. Strip xs: / xsi: namespace prefixes so standard Go XML can handle them.
	s := string(clean)
	s = strings.ReplaceAll(s, "xs:", "")
	s = strings.ReplaceAll(s, "xsi:", "")

	// 3. Unmarshal.
	var fb xmlFeedback
	if err := xml.Unmarshal([]byte(s), &fb); err != nil {
		return nil, fmt.Errorf("aggregate.Parse: xml.Unmarshal: %w", err)
	}

	// 4. Normalise policy_published.
	pp := normalisePolicyPublished(fb.PolicyPublished)

	// 5. Normalise metadata.
	meta := normaliseMetadata(fb.ReportMetadata)

	// 6. Build records.
	records := make([]models.AggregateRecord, 0, len(fb.Records))
	for _, xr := range fb.Records {
		rec := buildRecord(xr, meta.BeginDate, meta.EndDate)

		// IP enrichment.
		if enricher != nil && xr.Row.SourceIP != "" {
			info, err := enricher.Enrich(xr.Row.SourceIP)
			if err == nil && info != nil {
				rec.Source = *info
			} else {
				rec.Source.IPAddress = xr.Row.SourceIP
			}
		} else {
			rec.Source.IPAddress = xr.Row.SourceIP
		}

		records = append(records, rec)
	}

	// 7. Timespan normalisation.
	beginTS := time.Unix(fb.ReportMetadata.DateRange.Begin, 0).UTC()
	endTS := time.Unix(fb.ReportMetadata.DateRange.End, 0).UTC()
	spanHours := endTS.Sub(beginTS).Hours()

	if normalizeTimespanHours > 0 && spanHours > normalizeTimespanHours {
		meta.TimespanRequiresNormalization = true
		meta.OriginalTimespanSeconds = int(endTS.Sub(beginTS).Seconds())
		records = normalizeTimespan(records, beginTS, endTS)
	}

	return &models.AggregateReport{
		XMLSchema:       "feedback",
		ReportMetadata:  meta,
		PolicyPublished: pp,
		Records:         records,
	}, nil
}

// ── normalisation helpers ─────────────────────────────────────────────────────

const tsLayout = "2006-01-02 15:04:05"

func epochToString(epoch int64) string {
	return time.Unix(epoch, 0).UTC().Format(tsLayout)
}

func normalisePolicyPublished(xpp xmlPolicyPublished) models.AggregatePolicyPublished {
	pct := xpp.PCT
	if pct == "" {
		pct = "100"
	}

	fo := xpp.FO
	if fo == "" {
		fo = "0"
	}

	adkim := xpp.ADKIM
	if adkim == "" {
		adkim = "r"
	}

	aspf := xpp.ASPF
	if aspf == "" {
		aspf = "r"
	}

	return models.AggregatePolicyPublished{
		Domain: xpp.Domain,
		ADKIM:  adkim,
		ASPF:   aspf,
		P:      xpp.P,
		SP:     xpp.SP,
		PCT:    pct,
		FO:     fo,
	}
}

func normaliseMetadata(xm xmlReportMetadata) models.AggregateMetadata {
	orgName := xm.OrgName
	if orgName == "" && xm.Email != "" {
		parts := strings.SplitN(xm.Email, "@", 2)
		if len(parts) == 2 {
			orgName = parts[1]
		}
	}
	// If org name is a single word with no dot, it stays as-is (parsedmarc leaves it).
	// The spec says "try to extract base domain" but without a PSL we just use it verbatim.

	reportID := strings.Trim(xm.ReportID, "<>")
	// Strip @domain suffix: e.g. "<abc@example.com>" → "abc"
	if at := strings.LastIndex(reportID, "@"); at >= 0 {
		reportID = reportID[:at]
	}

	var extraContact *string

	if xm.ExtraContactInfo != "" {
		v := xm.ExtraContactInfo
		extraContact = &v
	}

	errors := xm.Error
	if errors == nil {
		errors = []string{}
	}

	return models.AggregateMetadata{
		OrgName:             orgName,
		OrgEmail:            xm.Email,
		OrgExtraContactInfo: extraContact,
		ReportID:            reportID,
		BeginDate:           epochToString(xm.DateRange.Begin),
		EndDate:             epochToString(xm.DateRange.End),
		Errors:              errors,
	}
}

func buildRecord(xr xmlRecord, intervalBegin, intervalEnd string) models.AggregateRecord {
	// Policy evaluated.
	disp := xr.Row.PolicyEvaluated.Disposition
	if disp == "pass" {
		disp = "none"
	}

	// Override reasons – always a list.
	reasons := make([]models.PolicyOverrideReason, 0, len(xr.Row.PolicyEvaluated.Reason))
	for _, xreason := range xr.Row.PolicyEvaluated.Reason {
		var comment *string

		if xreason.Comment != "" {
			c := xreason.Comment
			comment = &c
		}

		reasons = append(reasons, models.PolicyOverrideReason{
			Type:    xreason.Type,
			Comment: comment,
		})
	}

	// DKIM results.
	dkimResults := make([]models.DKIMResult, 0, len(xr.AuthResults.DKIM))
	for _, xd := range xr.AuthResults.DKIM {
		sel := xd.Selector
		if sel == "" {
			sel = "none"
		}

		dkimResults = append(dkimResults, models.DKIMResult{
			Domain:   xd.Domain,
			Selector: sel,
			Result:   xd.Result,
		})
	}

	// SPF results.
	spfResults := make([]models.SPFResult, 0, len(xr.AuthResults.SPF))
	for _, xs := range xr.AuthResults.SPF {
		scope := xs.Scope
		if scope == "" {
			scope = "mfrom"
		}

		result := xs.Result
		if result == "" {
			result = "none"
		}

		spfResults = append(spfResults, models.SPFResult{
			Domain: xs.Domain,
			Scope:  scope,
			Result: result,
		})
	}

	// envelope_from: if empty use domain of last SPF result with scope mfrom.
	var envelopeFrom *string

	if xr.Identifiers.EnvelopeFrom != "" {
		v := xr.Identifiers.EnvelopeFrom
		envelopeFrom = &v
	} else {
		for i := len(spfResults) - 1; i >= 0; i-- {
			if spfResults[i].Scope == "mfrom" && spfResults[i].Domain != "" {
				v := spfResults[i].Domain
				envelopeFrom = &v

				break
			}
		}
	}

	var envelopeTo *string

	if xr.Identifiers.EnvelopeTo != "" {
		v := xr.Identifiers.EnvelopeTo
		envelopeTo = &v
	}

	// Alignment.
	spfAligned := xr.Row.PolicyEvaluated.SPF == "pass"
	dkimAligned := xr.Row.PolicyEvaluated.DKIM == "pass"

	return models.AggregateRecord{
		IntervalBegin: intervalBegin,
		IntervalEnd:   intervalEnd,
		Count:         xr.Row.Count,
		Alignment: models.AggregateAlignment{
			SPF:   spfAligned,
			DKIM:  dkimAligned,
			DMARC: spfAligned || dkimAligned,
		},
		PolicyEvaluated: models.AggregatePolicyEval{
			Disposition:           disp,
			DKIM:                  xr.Row.PolicyEvaluated.DKIM,
			SPF:                   xr.Row.PolicyEvaluated.SPF,
			PolicyOverrideReasons: reasons,
		},
		Identifiers: models.AggregateIdentifiers{
			HeaderFrom:   xr.Identifiers.HeaderFrom,
			EnvelopeFrom: envelopeFrom,
			EnvelopeTo:   envelopeTo,
		},
		AuthResults: models.AggregateAuthResults{
			DKIM: dkimResults,
			SPF:  spfResults,
		},
	}
}

// ── timespan normalisation ────────────────────────────────────────────────────

// normalizeTimespan distributes each record's count across daily calendar buckets
// that overlap the [begin, end) window.  The largest-remainder method guarantees
// that the sum of distributed counts equals the original count.
func normalizeTimespan(records []models.AggregateRecord, begin, end time.Time) []models.AggregateRecord {
	days := calendarDays(begin, end)
	if len(days) == 0 {
		return records
	}

	totalSpan := end.Sub(begin).Seconds()

	var out []models.AggregateRecord

	for _, rec := range records {
		buckets := distributeRecord(rec, days, begin, end, totalSpan)
		out = append(out, buckets...)
	}

	return out
}

// calendarDay represents a UTC calendar day [midnight, midnight+24h).
type calendarDay struct {
	Start time.Time // 00:00:00 UTC
	End   time.Time // 23:59:59 UTC (inclusive for display)
}

func calendarDays(begin, end time.Time) []calendarDay {
	var days []calendarDay
	// Start of the first calendar day.
	day := time.Date(begin.Year(), begin.Month(), begin.Day(), 0, 0, 0, 0, time.UTC)
	for day.Before(end) {
		dayEnd := day.Add(24 * time.Hour)
		days = append(days, calendarDay{
			Start: day,
			End:   day.Add(24*time.Hour - time.Second), // 23:59:59
		})
		day = dayEnd
	}

	return days
}

// distributeRecord splits rec.Count across the provided days using the
// largest-remainder method (Hamilton method) to ensure integer counts sum exactly.
func distributeRecord(rec models.AggregateRecord, days []calendarDay, begin, end time.Time, totalSpanSecs float64) []models.AggregateRecord {
	n := len(days)
	fractions := make([]float64, n)

	for i, d := range days {
		// Overlap of this calendar day with [begin, end).
		overlapStart := maxTime(begin, d.Start)

		overlapEnd := minTime(end, d.End.Add(time.Second)) // use exclusive end for calculation
		if overlapEnd.After(overlapStart) {
			fractions[i] = overlapEnd.Sub(overlapStart).Seconds() / totalSpanSecs
		}
	}

	// Largest-remainder distribution.
	floatCounts := make([]float64, n)
	for i, f := range fractions {
		floatCounts[i] = f * float64(rec.Count)
	}

	intCounts := largestRemainder(floatCounts, rec.Count)

	var out []models.AggregateRecord

	for i, d := range days {
		if intCounts[i] == 0 {
			continue
		}

		bucket := rec // copy
		bucket.IntervalBegin = d.Start.Format(tsLayout)
		bucket.IntervalEnd = d.End.Format(tsLayout)
		bucket.Count = intCounts[i]
		bucket.NormalizedTimespan = true
		out = append(out, bucket)
	}

	return out
}

// largestRemainder distributes total integer units across floatCounts using the
// Hamilton / largest-remainder method.
func largestRemainder(floatCounts []float64, total int) []int {
	n := len(floatCounts)
	floors := make([]int, n)
	remainders := make([]float64, n)
	sum := 0

	for i, f := range floatCounts {
		floors[i] = int(math.Floor(f))
		remainders[i] = f - float64(floors[i])
		sum += floors[i]
	}
	// Distribute remaining units to those with the largest fractional parts.
	remaining := total - sum
	// Build index list sorted by remainder descending.
	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}
	// Simple insertion sort (n is typically small – ≤31 days).
	for i := 1; i < n; i++ {
		for j := i; j > 0 && remainders[indices[j]] > remainders[indices[j-1]]; j-- {
			indices[j], indices[j-1] = indices[j-1], indices[j]
		}
	}

	for i := 0; i < remaining && i < n; i++ {
		floors[indices[i]]++
	}

	return floors
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}

	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}

	return b
}
