package output

import (
	"errors"
	"log/slog"
	"sync"

	"github.com/freman/dmarcer/internal/models"
)

// Fanout dispatches to multiple backends concurrently.
// A failure in one backend does not block others.
type Fanout struct {
	backends []models.Backend
	logger   *slog.Logger
}

// NewFanout creates a new Fanout that writes to all provided backends.
func NewFanout(logger *slog.Logger, backends ...models.Backend) *Fanout {
	return &Fanout{
		backends: backends,
		logger:   logger,
	}
}

// WriteAggregate writes to all backends concurrently, collecting errors.
// Returns the first non-nil error encountered, or nil if all succeeded.
func (f *Fanout) WriteAggregate(report *models.AggregateReport, record *models.AggregateRecord) error {
	errs := make([]error, len(f.backends))

	var wg sync.WaitGroup

	for i, b := range f.backends {
		wg.Add(1)

		go func(idx int, backend models.Backend) {
			defer wg.Done()

			if err := backend.WriteAggregate(report, record); err != nil {
				f.logger.Error("backend WriteAggregate failed",
					slog.String("backend", backend.Name()),
					slog.String("report_type", string(models.ReportTypeAggregate)),
					slog.Any("error", err),
				)
				errs[idx] = err
			}
		}(i, b)
	}

	wg.Wait()

	return firstError(errs)
}

// WriteForensic writes to all backends concurrently.
// Returns the first non-nil error encountered, or nil if all succeeded.
func (f *Fanout) WriteForensic(report *models.ForensicReport) error {
	errs := make([]error, len(f.backends))

	var wg sync.WaitGroup

	for i, b := range f.backends {
		wg.Add(1)

		go func(idx int, backend models.Backend) {
			defer wg.Done()

			if err := backend.WriteForensic(report); err != nil {
				f.logger.Error("backend WriteForensic failed",
					slog.String("backend", backend.Name()),
					slog.String("report_type", string(models.ReportTypeForensic)),
					slog.Any("error", err),
				)
				errs[idx] = err
			}
		}(i, b)
	}

	wg.Wait()

	return firstError(errs)
}

// WriteSMTPTLS writes to all backends concurrently.
// Returns the first non-nil error encountered, or nil if all succeeded.
func (f *Fanout) WriteSMTPTLS(report *models.SMTPTLSReport, policy *models.SMTPTLSPolicy) error {
	errs := make([]error, len(f.backends))

	var wg sync.WaitGroup

	for i, b := range f.backends {
		wg.Add(1)

		go func(idx int, backend models.Backend) {
			defer wg.Done()

			if err := backend.WriteSMTPTLS(report, policy); err != nil {
				f.logger.Error("backend WriteSMTPTLS failed",
					slog.String("backend", backend.Name()),
					slog.String("report_type", string(models.ReportTypeSMTPTLS)),
					slog.Any("error", err),
				)
				errs[idx] = err
			}
		}(i, b)
	}

	wg.Wait()

	return firstError(errs)
}

// Close closes all backends sequentially, collecting errors.
func (f *Fanout) Close() error {
	errs := make([]error, len(f.backends))

	for i, b := range f.backends {
		if err := b.Close(); err != nil {
			f.logger.Error("backend Close failed",
				slog.String("backend", b.Name()),
				slog.Any("error", err),
			)
			errs[i] = err
		}
	}

	return firstError(errs)
}

// firstError returns the first non-nil error from the slice, or nil.
func firstError(errs []error) error {
	return errors.Join(errs...)
}
