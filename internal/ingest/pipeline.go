package ingest

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/freman/dmarcer/internal/enrichment"
	"github.com/freman/dmarcer/internal/models"
	"github.com/freman/dmarcer/internal/output"
	"github.com/freman/dmarcer/internal/parser"
	"github.com/freman/dmarcer/internal/parser/aggregate"
	"github.com/freman/dmarcer/internal/parser/forensic"
	"github.com/freman/dmarcer/internal/parser/smtptls"
	"github.com/freman/dmarcer/internal/store"
)

// Pipeline processes raw report bytes end-to-end: detection → parsing →
// enrichment → fan-out to all configured backends.
type Pipeline struct {
	db                     *store.DB
	fanout                 *output.Fanout
	enricher               enrichment.Enricher
	normalizeTimespan time.Duration
	stripAttachments       bool
	logger                 *slog.Logger
}

// NewPipeline constructs a Pipeline.
func NewPipeline(
	db *store.DB,
	fanout *output.Fanout,
	enricher enrichment.Enricher,
	normalizeTimespan time.Duration,
	stripAttachments bool,
	logger *slog.Logger,
) *Pipeline {
	return &Pipeline{
		db:                     db,
		fanout:                 fanout,
		enricher:               enricher,
		normalizeTimespan:      normalizeTimespan,
		stripAttachments:       stripAttachments,
		logger:                 logger,
	}
}

// Process parses raw bytes and writes to all configured backends.
// source should be "imap", "upload", or "file". filename is used for logging only.
func (p *Pipeline) Process(data []byte, source, filename string) models.IngestResult {
	result := models.IngestResult{
		Source:     source,
		Filename:   filename,
		Type:       models.ReportTypeUnknown,
		IngestedAt: time.Now().UTC(),
	}

	// Step 1: detect and decompress.
	detected, err := parser.Detect(data)
	if err != nil {
		result.Status = models.IngestError
		result.Message = fmt.Sprintf("detect: %v", err)
		p.logResult(result)

		return result
	}

	// Step 2: parse based on detected content type.
	var parseResult *models.ParseResult

	switch detected.ContentType {
	case parser.ContentXML:
		parseResult = p.tryAggregate(detected.Data)

	case parser.ContentJSON:
		parseResult = p.trySMTPTLS(detected.Data)
		if parseResult == nil {
			parseResult = p.tryAggregate(detected.Data)
		}

	case parser.ContentEmail:
		// Aggregate/SMTPTLS reports arrive as email attachments; try those first.
		parseResult = p.tryEmailAttachments(detected.Data)
		if parseResult == nil {
			parseResult = p.tryForensic(detected.Data)
		}

	case parser.ContentUnknown:
		parseResult = p.tryAggregate(detected.Data)
		if parseResult == nil {
			parseResult = p.trySMTPTLS(detected.Data)
		}

		if parseResult == nil {
			parseResult = p.tryForensic(detected.Data)
		}
	}

	if parseResult == nil {
		result.Status = models.IngestError
		result.Message = "unable to parse report: unrecognised format"
		p.logResult(result)

		return result
	}

	result.Type = parseResult.Type

	// Step 3: fan-out.
	switch parseResult.Type {
	case models.ReportTypeAggregate:
		result = p.handleAggregate(parseResult.Aggregate, result)
	case models.ReportTypeForensic:
		result = p.handleForensic(parseResult.Forensic, result)
	case models.ReportTypeSMTPTLS:
		result = p.handleSMTPTLS(parseResult.SMTPTLS, result)
	}

	// Step 4: log to DB.
	p.logResult(result)

	return result
}

// ---------------------------------------------------------------------------
// parse helpers – each returns nil on failure so the caller can try the next.
// ---------------------------------------------------------------------------

func (p *Pipeline) tryAggregate(data []byte) *models.ParseResult {
	report, err := aggregate.Parse(data, p.enricher, p.normalizeTimespan.Hours())
	if err != nil {
		return nil
	}

	return &models.ParseResult{
		Type:      models.ReportTypeAggregate,
		Aggregate: report,
	}
}

func (p *Pipeline) trySMTPTLS(data []byte) *models.ParseResult {
	report, err := smtptls.Parse(data)
	if err != nil {
		return nil
	}

	return &models.ParseResult{
		Type:    models.ReportTypeSMTPTLS,
		SMTPTLS: report,
	}
}

func (p *Pipeline) tryEmailAttachments(data []byte) *models.ParseResult {
	for _, att := range parser.ExtractEmailAttachments(data) {
		detected, err := parser.Detect(att)
		if err != nil {
			continue
		}

		switch detected.ContentType {
		case parser.ContentXML:
			if r := p.tryAggregate(detected.Data); r != nil {
				return r
			}
		case parser.ContentJSON:
			if r := p.trySMTPTLS(detected.Data); r != nil {
				return r
			}

			if r := p.tryAggregate(detected.Data); r != nil {
				return r
			}
		}
	}

	return nil
}

func (p *Pipeline) tryForensic(data []byte) *models.ParseResult {
	report, err := forensic.Parse(data, p.enricher, p.stripAttachments)
	if err != nil {
		return nil
	}

	return &models.ParseResult{
		Type:     models.ReportTypeForensic,
		Forensic: report,
	}
}

// ---------------------------------------------------------------------------
// fan-out handlers
// ---------------------------------------------------------------------------

func (p *Pipeline) handleAggregate(report *models.AggregateReport, result models.IngestResult) models.IngestResult {
	dup, err := p.db.IsDuplicateAggregate(report)
	if err != nil {
		result.Status = models.IngestError
		result.Message = fmt.Sprintf("duplicate check: %v", err)

		return result
	}

	if dup {
		result.Status = models.IngestDuplicate
		result.DuplicatesSkipped = len(report.Records)

		return result
	}

	var fanoutErr error

	for i := range report.Records {
		rec := &report.Records[i]
		if err := p.fanout.WriteAggregate(report, rec); err != nil {
			p.logger.Error("fanout WriteAggregate failed",
				slog.String("source", result.Source),
				slog.String("filename", result.Filename),
				slog.Any("error", err),
			)
			fanoutErr = err
		} else {
			result.RecordsSaved++
		}
	}

	if fanoutErr != nil && result.RecordsSaved == 0 {
		result.Status = models.IngestError
		result.Message = fmt.Sprintf("fanout: %v", fanoutErr)

		return result
	}

	result.Status = models.IngestOK

	return result
}

func (p *Pipeline) handleForensic(report *models.ForensicReport, result models.IngestResult) models.IngestResult {
	dup, err := p.db.IsDuplicateForensic(report)
	if err != nil {
		result.Status = models.IngestError
		result.Message = fmt.Sprintf("duplicate check: %v", err)

		return result
	}

	if dup {
		result.Status = models.IngestDuplicate
		result.DuplicatesSkipped = 1

		return result
	}

	if err := p.fanout.WriteForensic(report); err != nil {
		p.logger.Error("fanout WriteForensic failed",
			slog.String("source", result.Source),
			slog.String("filename", result.Filename),
			slog.Any("error", err),
		)
		result.Status = models.IngestError
		result.Message = fmt.Sprintf("fanout: %v", err)

		return result
	}

	result.RecordsSaved = 1
	result.Status = models.IngestOK

	return result
}

func (p *Pipeline) handleSMTPTLS(report *models.SMTPTLSReport, result models.IngestResult) models.IngestResult {
	allDup := true

	var fanoutErr error

	for i := range report.Policies {
		pol := &report.Policies[i]

		dup, err := p.db.IsDuplicateSMTPTLS(report, pol)
		if err != nil {
			result.Status = models.IngestError
			result.Message = fmt.Sprintf("duplicate check policy %d: %v", i, err)

			return result
		}

		if dup {
			result.DuplicatesSkipped++
			continue
		}

		allDup = false

		if err := p.fanout.WriteSMTPTLS(report, pol); err != nil {
			p.logger.Error("fanout WriteSMTPTLS failed",
				slog.String("source", result.Source),
				slog.String("filename", result.Filename),
				slog.Any("error", err),
			)
			fanoutErr = err
		} else {
			result.RecordsSaved++
		}
	}

	if allDup {
		result.Status = models.IngestDuplicate
		return result
	}

	if fanoutErr != nil && result.RecordsSaved == 0 {
		result.Status = models.IngestError
		result.Message = fmt.Sprintf("fanout: %v", fanoutErr)

		return result
	}

	result.Status = models.IngestOK

	return result
}

// ---------------------------------------------------------------------------
// logging
// ---------------------------------------------------------------------------

func (p *Pipeline) logResult(result models.IngestResult) {
	if err := p.db.LogIngest(result); err != nil {
		p.logger.Error("LogIngest failed", slog.Any("error", err))
	}
}
