// Package forensic parses RFC 5965 ARF forensic (ruf) email reports.
package forensic

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"

	gommessage "github.com/emersion/go-message"
	gomail "github.com/emersion/go-message/mail"

	"github.com/freman/dmarcer/internal/enrichment"
	"github.com/freman/dmarcer/internal/models"
)

// Parse parses a raw RFC 822 email (bytes) that contains an ARF forensic report.
// enricher may be nil.
// stripPayloads: if true, omit attachment payload bytes.
func Parse(data []byte, enricher enrichment.Enricher, stripPayloads bool) (*models.ForensicReport, error) {
	report := &models.ForensicReport{
		AuthFailure:              []string{},
		AuthenticationMechanisms: []string{},
	}

	// ── parse outer RFC 822 to capture the raw sample bytes & ARF fields ──────

	// We use net/mail for the outer envelope, then go-message for MIME walking.
	mr, err := gomail.CreateReader(bytes.NewReader(data))
	if err != nil {
		// If go-message fails, fall back to net/mail only.
		return parseWithNetMail(data, enricher, stripPayloads)
	}

	var (
		arfData    []byte
		sampleData []byte
		sampleType string // "message/rfc822" or "text/rfc822-headers"
	)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}

		if err != nil {
			// Non-fatal: skip unreadable parts.
			break
		}

		ct, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))

		body, readErr := io.ReadAll(part.Body)
		if readErr != nil {
			continue
		}

		ctLower := strings.ToLower(ct)
		switch {
		case ctLower == "message/feedback-report":
			arfData = body
		case ctLower == "message/rfc822":
			sampleData = body
			sampleType = "message/rfc822"
		case ctLower == "text/rfc822-headers":
			if sampleData == nil {
				sampleData = body
				sampleType = "text/rfc822-headers"
			}
		default:
			if ct != "" && ct != "multipart/mixed" && ct != "multipart/alternative" &&
				ct != "text/plain" && ct != "text/html" {
				// Treat as attachment on the outer email – skip for forensic report.
				_ = body
			}
		}
	}

	// ── require ARF feedback-report part ─────────────────────────────────────
	if len(arfData) == 0 {
		return nil, fmt.Errorf("forensic: no message/feedback-report part found")
	}

	parseARFFields(arfData, report)

	// ── store raw sample ──────────────────────────────────────────────────────
	if len(sampleData) > 0 {
		report.Sample = string(sampleData)
		report.SampleHeadersOnly = sampleType == "text/rfc822-headers"

		parsed, parseErr := parseInnerEmail(sampleData, stripPayloads)
		if parseErr == nil {
			report.ParsedSample = parsed
		}
	}

	// ── reported domain fallback ──────────────────────────────────────────────
	if report.ReportedDomain == "" {
		report.ReportedDomain = extractReportedDomain(report)
	}

	// ── source IP enrichment ──────────────────────────────────────────────────
	if enricher != nil && report.Source.IPAddress != "" {
		info, err := enricher.Enrich(report.Source.IPAddress)
		if err == nil && info != nil {
			report.Source = *info
		}
	}

	return report, nil
}

// parseARFFields reads line-by-line ARF headers and populates report fields.
var arfFieldRe = regexp.MustCompile(`(?i)^([\w\-]+):\s*(.+)$`)

func parseARFFields(data []byte, report *models.ForensicReport) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")

		m := arfFieldRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(m[1]))
		val := strings.TrimSpace(m[2])

		switch key {
		case "feedback-type":
			v := val
			report.FeedbackType = &v
		case "user-agent":
			v := val
			report.UserAgent = &v
		case "version":
			v := val
			report.Version = &v
		case "original-mail-from":
			v := val
			report.OriginalMailFrom = &v
		case "original-rcpt-to":
			v := val
			report.OriginalRcptTo = &v
		case "arrival-date":
			report.ArrivalDate = val
			report.ArrivalDateUTC = parseArrivalDateUTC(val)
		case "source-ip":
			report.Source.IPAddress = val
		case "authentication-results":
			v := val
			report.AuthenticationResults = &v
		case "delivery-result":
			v := val
			report.DeliveryResult = &v
		case "auth-failure":
			for _, p := range strings.Split(val, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					report.AuthFailure = append(report.AuthFailure, p)
				}
			}
		case "identity-alignment":
			for _, p := range strings.Split(val, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					report.AuthenticationMechanisms = append(report.AuthenticationMechanisms, p)
				}
			}
		case "reported-domain":
			report.ReportedDomain = val
		case "dkim-domain":
			v := val
			report.DKIMDomain = &v
		case "original-envelope-id":
			v := val
			report.OriginalEnvelopeID = &v
		}
	}
}

// parseArrivalDateUTC tries several common date formats and returns UTC string.
func parseArrivalDateUTC(s string) string {
	formats := []string{
		time.RFC1123Z,
		time.RFC1123,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 MST",
		"2 Jan 2006 15:04:05 -0700",
		"2 Jan 2006 15:04:05 MST",
		time.RFC822Z,
		time.RFC822,
	}
	for _, f := range formats {
		t, err := time.Parse(f, s)
		if err == nil {
			return t.UTC().Format("2006-01-02 15:04:05")
		}
	}

	return s
}

// parseInnerEmail parses a raw RFC 822 sample email.
func parseInnerEmail(data []byte, stripPayloads bool) (*models.ParsedEmail, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parseInnerEmail: %w", err)
	}

	pe := &models.ParsedEmail{
		Headers:     make(map[string]any),
		Attachments: []models.EmailAttachment{},
		Received:    []models.ReceivedHop{},
	}

	// ── headers ───────────────────────────────────────────────────────────────
	for k, vs := range msg.Header {
		if len(vs) == 1 {
			pe.Headers[k] = vs[0]
		} else {
			pe.Headers[k] = vs
		}
	}

	// From
	if fromStr := msg.Header.Get("From"); fromStr != "" {
		if addr, err := mail.ParseAddress(fromStr); err == nil {
			pe.From = parseEmailAddress(addr)
		}
	}

	// To
	if toStr := msg.Header.Get("To"); toStr != "" {
		if addrs, err := mail.ParseAddressList(toStr); err == nil {
			for _, a := range addrs {
				pe.To = append(pe.To, *parseEmailAddress(a))
			}
		}
	}

	// Reply-To
	if rtStr := msg.Header.Get("Reply-To"); rtStr != "" {
		if addrs, err := mail.ParseAddressList(rtStr); err == nil {
			for _, a := range addrs {
				pe.ReplyTo = append(pe.ReplyTo, *parseEmailAddress(a))
			}
		}
	}

	// CC
	if ccStr := msg.Header.Get("Cc"); ccStr != "" {
		if addrs, err := mail.ParseAddressList(ccStr); err == nil {
			for _, a := range addrs {
				pe.CC = append(pe.CC, *parseEmailAddress(a))
			}
		}
	}

	// BCC
	if bccStr := msg.Header.Get("Bcc"); bccStr != "" {
		if addrs, err := mail.ParseAddressList(bccStr); err == nil {
			for _, a := range addrs {
				pe.BCC = append(pe.BCC, *parseEmailAddress(a))
			}
		}
	}

	// Subject
	if subj := msg.Header.Get("Subject"); subj != "" {
		pe.Subject = &subj
		safe := filenameSafe(subj)
		pe.FilenameSafeSubject = &safe
	}

	// Date
	if dateStr := msg.Header.Get("Date"); dateStr != "" {
		pe.Date = &dateStr
	}

	// Received hops
	pe.Received = parseReceivedHeaders(msg.Header["Received"])

	// ── body & attachments via go-message ─────────────────────────────────────
	entity, err := gommessage.Read(bytes.NewReader(data))
	if err == nil {
		walkEntity(entity, pe, stripPayloads)
	} else {
		// Fallback: read body directly.
		body, _ := io.ReadAll(msg.Body)
		if len(body) > 0 {
			b := string(body)
			pe.Body = &b
		}
	}

	return pe, nil
}

// walkEntity recursively walks go-message entity tree to collect body and attachments.
func walkEntity(entity *gommessage.Entity, pe *models.ParsedEmail, stripPayloads bool) {
	ct, params, _ := entity.Header.ContentType()
	ctLower := strings.ToLower(ct)

	if strings.HasPrefix(ctLower, "multipart/") {
		mr := entity.MultipartReader()
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}

			walkEntity(part, pe, stripPayloads)
		}

		return
	}

	// Read part body.
	body, err := io.ReadAll(entity.Body)
	if err != nil {
		return
	}

	switch {
	case ctLower == "text/plain" && pe.Body == nil:
		b := string(body)
		pe.Body = &b
	default:
		// Treat as attachment if it has a filename or non-text content-type.
		filename := params["name"]
		if filename == "" {
			_, cdParams, _ := entity.Header.ContentDisposition()
			filename = cdParams["filename"]
		}

		if filename == "" && !strings.HasPrefix(ctLower, "text/") {
			filename = ""
		}
		// Only save as attachment if it has a filename or is clearly binary.
		if filename != "" || (!strings.HasPrefix(ctLower, "text/") && ct != "" && len(body) > 0) {
			hash := sha256.Sum256(body)

			att := models.EmailAttachment{
				ContentType: ct,
				SHA256:      fmt.Sprintf("%x", hash[:]),
			}
			if filename != "" {
				att.Filename = &filename
			}

			if !stripPayloads {
				att.Payload = body
			}

			pe.Attachments = append(pe.Attachments, att)
		}
	}
}

// ── Received header parsing ───────────────────────────────────────────────────

var (
	rcvFromRe = regexp.MustCompile(`(?i)\bfrom\s+(\S+)`)
	rcvByRe   = regexp.MustCompile(`(?i)\bby\s+(\S+)`)
	rcvWithRe = regexp.MustCompile(`(?i)\bwith\s+(\S+)`)
	// Match the date part after semicolon.
	rcvDateRe = regexp.MustCompile(`;\s*(.+)$`)
)

func parseReceivedHeaders(headers []string) []models.ReceivedHop {
	hops := make([]models.ReceivedHop, 0, len(headers))

	var prevTime *time.Time

	for i, h := range headers {
		hop := models.ReceivedHop{Hop: i + 1}

		if m := rcvFromRe.FindStringSubmatch(h); m != nil {
			v := m[1]
			hop.From = &v
		}

		if m := rcvByRe.FindStringSubmatch(h); m != nil {
			v := m[1]
			hop.By = &v
		}

		if m := rcvWithRe.FindStringSubmatch(h); m != nil {
			v := m[1]
			hop.With = &v
		}

		if m := rcvDateRe.FindStringSubmatch(h); m != nil {
			raw := strings.TrimSpace(m[1])
			hop.Date = &raw

			t := parseAnyDate(raw)
			if t != nil {
				utcStr := t.UTC().Format("2006-01-02 15:04:05")
				hop.DateUTC = &utcStr

				if prevTime != nil {
					diff := max(int(t.Sub(*prevTime).Seconds()), 0)
					hop.Delay = diff
				}

				prevTime = t
			}
		}

		hops = append(hops, hop)
	}

	return hops
}

func parseAnyDate(s string) *time.Time {
	formats := []string{
		time.RFC1123Z,
		time.RFC1123,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 MST",
		"2 Jan 2006 15:04:05 -0700",
		"2 Jan 2006 15:04:05 MST",
		time.RFC822Z,
		time.RFC822,
	}
	for _, f := range formats {
		t, err := time.Parse(f, s)
		if err == nil {
			return &t
		}
	}

	return nil
}

// ── helper functions ──────────────────────────────────────────────────────────

func parseEmailAddress(addr *mail.Address) *models.EmailAddress {
	ea := &models.EmailAddress{
		Address: addr.Address,
	}
	if addr.Name != "" {
		ea.DisplayName = &addr.Name
	}

	parts := strings.SplitN(addr.Address, "@", 2)

	ea.Local = parts[0]
	if len(parts) == 2 {
		ea.Domain = parts[1]
	}

	return ea
}

func filenameSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}

		return '_'
	}, s)
}

// extractReportedDomain tries to infer the reported domain from authentication_results
// or from the parsed sample's From header domain.
func extractReportedDomain(report *models.ForensicReport) string {
	if report.AuthenticationResults != nil {
		// e.g. "dmarc=fail header.from=example.com"
		re := regexp.MustCompile(`(?i)header\.from=([^\s;]+)`)
		if m := re.FindStringSubmatch(*report.AuthenticationResults); m != nil {
			return m[1]
		}
	}

	if report.ParsedSample != nil && report.ParsedSample.From != nil {
		return report.ParsedSample.From.Domain
	}

	return ""
}

// parseWithNetMail is the fallback parser using only net/mail.
func parseWithNetMail(data []byte, enricher enrichment.Enricher, stripPayloads bool) (*models.ForensicReport, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("forensic.Parse: %w", err)
	}

	report := &models.ForensicReport{
		AuthFailure:              []string{},
		AuthenticationMechanisms: []string{},
	}

	body, _ := io.ReadAll(msg.Body)
	report.Sample = string(body)

	parseARFFields(body, report)

	if report.ReportedDomain == "" {
		report.ReportedDomain = extractReportedDomain(report)
	}

	if enricher != nil && report.Source.IPAddress != "" {
		info, err := enricher.Enrich(report.Source.IPAddress)
		if err == nil && info != nil {
			report.Source = *info
		}
	}

	return report, nil
}
