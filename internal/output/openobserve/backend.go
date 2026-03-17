package openobserve

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/freman/dmarcer/internal/models"
)

const (
	defaultOrg           = "default"
	defaultStreamAgg     = "dmarcer_aggregate"
	defaultStreamForensic = "dmarcer_forensic"
	defaultStreamSMTPTLS = "dmarcer_smtp_tls"
	defaultBatchSize     = 100
	defaultTimeout       = 60 * time.Second
	ooFlushInterval      = 5 * time.Second
	ooMaxRetries         = 3
)

// Config holds OpenObserve connection settings.
type Config struct {
	URL             string
	Org             string // default "default"
	User            string
	Password        string
	Token           string // bearer token; takes precedence over user/password
	TLSSkipVerify   bool
	StreamAggregate string // default "dmarcer_aggregate"
	StreamForensic  string // default "dmarcer_forensic"
	StreamSMTPTLS   string // default "dmarcer_smtp_tls"
	BatchSize       int    // default 100
	Timeout         time.Duration // default 60s
	FailOnError     bool
	Logger          *slog.Logger
}

// Backend is the OpenObserve output backend.
type Backend struct {
	cfg          Config
	client       *http.Client
	bufAggregate []map[string]any
	bufForensic  []map[string]any
	bufSMTPTLS   []map[string]any
	mu           sync.Mutex
	done         chan struct{}
	logger       *slog.Logger
}

// New creates and starts an OpenObserve backend.
// Starts a background flush goroutine (5-second interval).
func New(cfg Config) (*Backend, error) {
	// Apply defaults.
	if cfg.Org == "" {
		cfg.Org = defaultOrg
	}

	if cfg.StreamAggregate == "" {
		cfg.StreamAggregate = defaultStreamAgg
	}

	if cfg.StreamForensic == "" {
		cfg.StreamForensic = defaultStreamForensic
	}

	if cfg.StreamSMTPTLS == "" {
		cfg.StreamSMTPTLS = defaultStreamSMTPTLS
	}

	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	b := &Backend{
		cfg:          cfg,
		client:       client,
		bufAggregate: make([]map[string]any, 0, cfg.BatchSize),
		bufForensic:  make([]map[string]any, 0, cfg.BatchSize),
		bufSMTPTLS:   make([]map[string]any, 0, cfg.BatchSize),
		done:         make(chan struct{}),
		logger:       logger,
	}

	go b.flushLoop()

	return b, nil
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return "openobserve" }

// WriteAggregate buffers one aggregate record document.
func (b *Backend) WriteAggregate(report *models.AggregateReport, record *models.AggregateRecord) error {
	type aggDoc struct {
		*models.AggregateReport
		Record *models.AggregateRecord `json:"record"`
	}

	combined := aggDoc{
		AggregateReport: report,
		Record:          record,
	}

	doc, err := structToMap(combined)
	if err != nil {
		return fmt.Errorf("openobserve: marshal aggregate doc: %w", err)
	}
	// Remove nested records array to avoid duplication.
	delete(doc, "records")

	ts := parseTimestamp(record.IntervalBegin)
	doc["@timestamp"] = ts.UTC().Format(time.RFC3339)

	b.mu.Lock()
	b.bufAggregate = append(b.bufAggregate, doc)
	shouldFlush := len(b.bufAggregate) >= b.cfg.BatchSize
	b.mu.Unlock()

	if shouldFlush {
		return b.flushStream(b.cfg.StreamAggregate, func() []map[string]any {
			b.mu.Lock()
			batch := b.bufAggregate
			b.bufAggregate = make([]map[string]any, 0, b.cfg.BatchSize)
			b.mu.Unlock()

			return batch
		})
	}

	return nil
}

// WriteForensic buffers one forensic report document.
func (b *Backend) WriteForensic(report *models.ForensicReport) error {
	doc, err := structToMap(report)
	if err != nil {
		return fmt.Errorf("openobserve: marshal forensic doc: %w", err)
	}

	ts := parseTimestamp(report.ArrivalDateUTC)
	doc["@timestamp"] = ts.UTC().Format(time.RFC3339)

	b.mu.Lock()
	b.bufForensic = append(b.bufForensic, doc)
	shouldFlush := len(b.bufForensic) >= b.cfg.BatchSize
	b.mu.Unlock()

	if shouldFlush {
		return b.flushStream(b.cfg.StreamForensic, func() []map[string]any {
			b.mu.Lock()
			batch := b.bufForensic
			b.bufForensic = make([]map[string]any, 0, b.cfg.BatchSize)
			b.mu.Unlock()

			return batch
		})
	}

	return nil
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
		return fmt.Errorf("openobserve: marshal smtp_tls doc: %w", err)
	}
	// Remove nested policies array to avoid duplication.
	delete(doc, "policies")

	ts := parseTimestamp(report.BeginDate)
	doc["@timestamp"] = ts.UTC().Format(time.RFC3339)

	b.mu.Lock()
	b.bufSMTPTLS = append(b.bufSMTPTLS, doc)
	shouldFlush := len(b.bufSMTPTLS) >= b.cfg.BatchSize
	b.mu.Unlock()

	if shouldFlush {
		return b.flushStream(b.cfg.StreamSMTPTLS, func() []map[string]any {
			b.mu.Lock()
			batch := b.bufSMTPTLS
			b.bufSMTPTLS = make([]map[string]any, 0, b.cfg.BatchSize)
			b.mu.Unlock()

			return batch
		})
	}

	return nil
}

// Close flushes remaining buffers and stops background goroutine.
func (b *Backend) Close() error {
	close(b.done)

	var firstErr error

	// Flush each stream.
	for _, pair := range []struct {
		stream string
		drain  func() []map[string]any
	}{
		{b.cfg.StreamAggregate, func() []map[string]any {
			b.mu.Lock()
			defer b.mu.Unlock()

			batch := b.bufAggregate
			b.bufAggregate = nil

			return batch
		}},
		{b.cfg.StreamForensic, func() []map[string]any {
			b.mu.Lock()
			defer b.mu.Unlock()

			batch := b.bufForensic
			b.bufForensic = nil

			return batch
		}},
		{b.cfg.StreamSMTPTLS, func() []map[string]any {
			b.mu.Lock()
			defer b.mu.Unlock()

			batch := b.bufSMTPTLS
			b.bufSMTPTLS = nil

			return batch
		}},
	} {
		if err := b.flushStream(pair.stream, pair.drain); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// flushLoop periodically flushes all stream buffers.
func (b *Backend) flushLoop() {
	ticker := time.NewTicker(ooFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-b.done:
			return
		case <-ticker.C:
			b.flushAll()
		}
	}
}

// flushAll flushes all three stream buffers.
func (b *Backend) flushAll() {
	for _, pair := range []struct {
		stream string
		drain  func() []map[string]any
	}{
		{b.cfg.StreamAggregate, func() []map[string]any {
			b.mu.Lock()
			defer b.mu.Unlock()

			if len(b.bufAggregate) == 0 {
				return nil
			}

			batch := b.bufAggregate
			b.bufAggregate = make([]map[string]any, 0, b.cfg.BatchSize)

			return batch
		}},
		{b.cfg.StreamForensic, func() []map[string]any {
			b.mu.Lock()
			defer b.mu.Unlock()

			if len(b.bufForensic) == 0 {
				return nil
			}

			batch := b.bufForensic
			b.bufForensic = make([]map[string]any, 0, b.cfg.BatchSize)

			return batch
		}},
		{b.cfg.StreamSMTPTLS, func() []map[string]any {
			b.mu.Lock()
			defer b.mu.Unlock()

			if len(b.bufSMTPTLS) == 0 {
				return nil
			}

			batch := b.bufSMTPTLS
			b.bufSMTPTLS = make([]map[string]any, 0, b.cfg.BatchSize)

			return batch
		}},
	} {
		if err := b.flushStream(pair.stream, pair.drain); err != nil {
			b.logger.Error("openobserve: periodic flush failed",
				slog.String("stream", pair.stream),
				slog.Any("error", err),
			)
		}
	}
}

// flushStream drains one stream buffer and POSTs it to OpenObserve.
func (b *Backend) flushStream(stream string, drain func() []map[string]any) error {
	batch := drain()
	if len(batch) == 0 {
		return nil
	}

	return b.sendBatch(stream, batch)
}

// sendBatch POSTs a batch of documents to the OpenObserve ingest endpoint with retries.
func (b *Backend) sendBatch(stream string, batch []map[string]any) error {
	body, err := buildNDJSON(batch)
	if err != nil {
		return fmt.Errorf("openobserve: build ndjson: %w", err)
	}

	url := fmt.Sprintf("%s/api/%s/%s/_json",
		strings.TrimRight(b.cfg.URL, "/"),
		b.cfg.Org,
		stream,
	)

	delays := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}

	var lastErr error

	for attempt := 0; attempt <= ooMaxRetries; attempt++ {
		if attempt > 0 {
			delay := delays[attempt-1]
			b.logger.Warn("openobserve: retrying POST",
				slog.String("stream", stream),
				slog.Int("attempt", attempt),
				slog.Duration("delay", delay),
				slog.Any("last_error", lastErr),
			)
			time.Sleep(delay)
		}

		ctx, cancel := context.WithTimeout(context.Background(), b.cfg.Timeout)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			cancel()

			lastErr = fmt.Errorf("openobserve: create request: %w", err)

			continue
		}

		req.Header.Set("Content-Type", "application/json")

		if b.cfg.Token != "" {
			req.Header.Set("Authorization", "Bearer "+b.cfg.Token)
		} else if b.cfg.User != "" {
			req.SetBasicAuth(b.cfg.User, b.cfg.Password)
		}

		resp, err := b.client.Do(req)

		cancel()

		if err != nil {
			lastErr = fmt.Errorf("openobserve: POST %s: %w", url, err)
			continue
		}

		statusCode := resp.StatusCode
		resp.Body.Close()

		if statusCode >= 200 && statusCode < 300 {
			return nil
		}

		if statusCode >= 400 && statusCode < 500 {
			// 4xx – skip, log only.
			b.logger.Error("openobserve: client error (skipping)",
				slog.String("stream", stream),
				slog.Int("status", statusCode),
			)

			return nil
		}

		// 5xx – retry.
		lastErr = fmt.Errorf("openobserve: POST returned status %d", statusCode)
	}

	if b.cfg.FailOnError {
		return lastErr
	}

	b.logger.Error("openobserve: POST failed after retries",
		slog.String("stream", stream),
		slog.Any("error", lastErr),
		slog.Int("docs", len(batch)),
	)

	return nil
}

// buildNDJSON encodes a slice of documents as NDJSON (one JSON object per line).
func buildNDJSON(docs []map[string]any) ([]byte, error) {
	var buf bytes.Buffer

	for _, doc := range docs {
		line, err := json.Marshal(doc)
		if err != nil {
			return nil, err
		}

		buf.Write(line)
		buf.WriteByte('\n')
	}

	return buf.Bytes(), nil
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
