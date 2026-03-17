package elastic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/freman/dmarcer/internal/models"
)

const (
	defaultIndexPrefix = "dmarcer_"
	maxBufSize         = 500
	flushInterval      = 5 * time.Second
	maxRetries         = 3
)

// Config holds Elasticsearch connection and index settings.
type Config struct {
	URLs          []string
	User          string
	Password      string
	APIKey        string
	TLSSkipVerify bool
	CACertPath    string
	IndexPrefix   string // default "dmarcer_"
	IndexSuffix   string
	MonthlyIndexes bool
	Timeout       time.Duration
	Shards        int
	Replicas      int
	FailOnError   bool
	Logger        *slog.Logger
}

// Backend is the Elasticsearch output backend.
type Backend struct {
	cfg    Config
	client *elasticsearch.Client
	buf    []docEntry
	mu     sync.Mutex
	done   chan struct{}
	logger *slog.Logger
}

type docEntry struct {
	index string
	doc   map[string]any
}

// New creates and returns a connected Elasticsearch backend.
// Starts a background flush goroutine (5-second interval).
func New(cfg Config) (*Backend, error) {
	if cfg.IndexPrefix == "" {
		cfg.IndexPrefix = defaultIndexPrefix
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec
	}

	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("elastic: read CA cert %q: %w", cfg.CACertPath, err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("elastic: no valid certs found in %q", cfg.CACertPath)
		}

		tlsCfg.RootCAs = pool
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	esCfg := elasticsearch.Config{
		Addresses: cfg.URLs,
		Username:  cfg.User,
		Password:  cfg.Password,
		APIKey:    cfg.APIKey,
		Transport: transport,
	}

	client, err := elasticsearch.NewClient(esCfg)
	if err != nil {
		return nil, fmt.Errorf("elastic: create client: %w", err)
	}

	b := &Backend{
		cfg:    cfg,
		client: client,
		buf:    make([]docEntry, 0, maxBufSize),
		done:   make(chan struct{}),
		logger: logger,
	}

	go b.flushLoop()

	return b, nil
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return "elasticsearch" }

// WriteAggregate buffers one aggregate record document.
func (b *Backend) WriteAggregate(report *models.AggregateReport, record *models.AggregateRecord) error {
	// Build a combined document with report metadata + record fields.
	type aggDoc struct {
		*models.AggregateReport
		Record *models.AggregateRecord `json:"record"`
	}

	combined := aggDoc{
		AggregateReport: report,
		Record:          record,
	}
	// Remove the Records slice from the embedded report to avoid duplication.
	doc, err := structToMap(combined)
	if err != nil {
		return fmt.Errorf("elastic: marshal aggregate doc: %w", err)
	}
	// Remove nested records array from the embedded report portion.
	delete(doc, "records")

	ts := parseTimestamp(record.IntervalBegin)
	doc["@timestamp"] = ts.UTC().Format(time.RFC3339)

	indexName := b.indexName("aggregate", ts)

	return b.buffer(indexName, doc)
}

// WriteForensic buffers one forensic report document.
func (b *Backend) WriteForensic(report *models.ForensicReport) error {
	doc, err := structToMap(report)
	if err != nil {
		return fmt.Errorf("elastic: marshal forensic doc: %w", err)
	}

	ts := parseTimestamp(report.ArrivalDateUTC)
	doc["@timestamp"] = ts.UTC().Format(time.RFC3339)

	indexName := b.indexName("forensic", ts)

	return b.buffer(indexName, doc)
}

// WriteSMTPTLS buffers one SMTP TLS policy document.
func (b *Backend) WriteSMTPTLS(report *models.SMTPTLSReport, policy *models.SMTPTLSPolicy) error {
	type tlsDoc struct {
		*models.SMTPTLSReport
		Policy *models.SMTPTLSPolicy `json:"policy"`
	}

	combined := tlsDoc{
		SMTPTLSReport: report,
		Policy:        policy,
	}

	doc, err := structToMap(combined)
	if err != nil {
		return fmt.Errorf("elastic: marshal smtp_tls doc: %w", err)
	}
	// Remove nested policies array from the embedded report portion.
	delete(doc, "policies")

	ts := parseTimestamp(report.BeginDate)
	doc["@timestamp"] = ts.UTC().Format(time.RFC3339)

	indexName := b.indexName("smtp_tls", ts)

	return b.buffer(indexName, doc)
}

// Close flushes remaining buffer and stops background goroutine.
func (b *Backend) Close() error {
	close(b.done)
	return b.flush()
}

// buffer adds a document to the internal buffer, flushing if capacity reached.
func (b *Backend) buffer(index string, doc map[string]any) error {
	b.mu.Lock()
	b.buf = append(b.buf, docEntry{index: index, doc: doc})
	shouldFlush := len(b.buf) >= maxBufSize
	b.mu.Unlock()

	if shouldFlush {
		return b.flush()
	}

	return nil
}

// flushLoop periodically flushes the buffer.
func (b *Backend) flushLoop() {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-b.done:
			return
		case <-ticker.C:
			if err := b.flush(); err != nil {
				b.logger.Error("elastic: periodic flush failed", slog.Any("error", err))
			}
		}
	}
}

// flush drains the buffer and sends to Elasticsearch via the bulk API.
func (b *Backend) flush() error {
	b.mu.Lock()
	if len(b.buf) == 0 {
		b.mu.Unlock()
		return nil
	}

	batch := b.buf
	b.buf = make([]docEntry, 0, maxBufSize)
	b.mu.Unlock()

	return b.sendBulk(batch)
}

// sendBulk sends a batch of documents using the ES _bulk API with retries.
func (b *Backend) sendBulk(batch []docEntry) error {
	body, err := buildBulkBody(batch)
	if err != nil {
		return fmt.Errorf("elastic: build bulk body: %w", err)
	}

	delays := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}

	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := delays[attempt-1]
			b.logger.Warn("elastic: retrying bulk request",
				slog.Int("attempt", attempt),
				slog.Duration("delay", delay),
				slog.Any("last_error", lastErr),
			)
			time.Sleep(delay)
		}

		ctx, cancel := context.WithTimeout(context.Background(), b.cfg.Timeout)
		res, err := b.client.Bulk(bytes.NewReader(body), b.client.Bulk.WithContext(ctx))

		cancel()

		if err != nil {
			// Network-level error – retry.
			lastErr = fmt.Errorf("elastic: bulk request: %w", err)
			continue
		}

		statusCode := res.StatusCode
		res.Body.Close()

		if statusCode >= 200 && statusCode < 300 {
			return nil
		}

		if statusCode >= 400 && statusCode < 500 {
			// 4xx – skip, log only.
			b.logger.Error("elastic: bulk request client error (skipping)",
				slog.Int("status", statusCode),
			)

			return nil
		}

		// 5xx – retry.
		lastErr = fmt.Errorf("elastic: bulk request returned status %d", statusCode)
	}

	if b.cfg.FailOnError {
		return lastErr
	}

	b.logger.Error("elastic: bulk request failed after retries",
		slog.Any("error", lastErr),
		slog.Int("docs", len(batch)),
	)

	return nil
}

// buildBulkBody constructs the NDJSON body for the _bulk API.
func buildBulkBody(batch []docEntry) ([]byte, error) {
	var buf bytes.Buffer

	for _, entry := range batch {
		// Action line.
		meta := map[string]any{
			"index": map[string]any{
				"_index": entry.index,
			},
		}

		metaBytes, err := json.Marshal(meta)
		if err != nil {
			return nil, err
		}

		buf.Write(metaBytes)
		buf.WriteByte('\n')

		// Document line.
		docBytes, err := json.Marshal(entry.doc)
		if err != nil {
			return nil, err
		}

		buf.Write(docBytes)
		buf.WriteByte('\n')
	}

	return buf.Bytes(), nil
}

// indexName returns the target index for a given report type and timestamp.
func (b *Backend) indexName(reportType string, ts time.Time) string {
	var dateSuffix string
	if b.cfg.MonthlyIndexes {
		dateSuffix = ts.UTC().Format("2006-01")
	} else {
		dateSuffix = ts.UTC().Format("2006-01-02")
	}

	return fmt.Sprintf("%s%s%s-%s", b.cfg.IndexPrefix, reportType, b.cfg.IndexSuffix, dateSuffix)
}

// structToMap converts a struct to map[string]any via JSON round-trip.
func structToMap(v any) (map[string]any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	return m, nil
}

// parseTimestamp parses the first 10 characters of a timestamp string as YYYY-MM-DD.
// Falls back to time.Now() on parse failure.
func parseTimestamp(s string) time.Time {
	s = strings.TrimSpace(s)
	if len(s) >= 10 {
		t, err := time.Parse("2006-01-02", s[:10])
		if err == nil {
			return t
		}
	}

	return time.Now().UTC()
}
