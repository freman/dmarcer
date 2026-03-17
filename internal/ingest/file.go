package ingest

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/freman/dmarcer/internal/models"
)

// supportedExtensions is the set of file extensions that are candidates for
// ingestion when walking a directory.
var supportedExtensions = map[string]struct{}{
	".xml":  {},
	".gz":   {},
	".zip":  {},
	".json": {},
	".eml":  {},
	".txt":  {},
}

// isSupportedFile returns true when name ends with a supported extension.
// It handles compound extensions like ".xml.gz" by checking suffixes.
func isSupportedFile(name string) bool {
	lower := strings.ToLower(name)
	// Check compound extension first.
	if strings.HasSuffix(lower, ".xml.gz") {
		return true
	}

	ext := filepath.Ext(lower)
	_, ok := supportedExtensions[ext]

	return ok
}

// FileIngester processes individual files or directories.
type FileIngester struct {
	pipeline *Pipeline
	logger   *slog.Logger
}

// NewFileIngester constructs a FileIngester.
func NewFileIngester(pipeline *Pipeline, logger *slog.Logger) *FileIngester {
	return &FileIngester{
		pipeline: pipeline,
		logger:   logger,
	}
}

// IngestPath processes a single file or all supported files in a directory.
// When recursive is true it walks subdirectories. It returns all individual
// results and a combined error if any file failed.
func (f *FileIngester) IngestPath(path string, recursive bool) ([]models.IngestResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("ingest: stat %q: %w", path, err)
	}

	if !info.IsDir() {
		r := f.IngestFile(path)

		var combined error

		if r.Status == models.IngestError {
			combined = errors.New(r.Message)
		}

		return []models.IngestResult{r}, combined
	}

	// Directory walk.
	var results []models.IngestResult

	var errs []error

	walkFn := func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			f.logger.Error("walk error", slog.String("path", p), slog.Any("error", walkErr))
			errs = append(errs, walkErr)

			return nil
		}

		if d.IsDir() {
			if p == path {
				return nil // root - always descend
			}

			if !recursive {
				return filepath.SkipDir
			}

			return nil
		}

		if !isSupportedFile(d.Name()) {
			return nil
		}

		r := f.IngestFile(p)

		results = append(results, r)

		if r.Status == models.IngestError {
			errs = append(errs, errors.New(r.Message))
		}

		return nil
	}

	if err := filepath.WalkDir(path, walkFn); err != nil {
		return results, fmt.Errorf("ingest: walk %q: %w", path, err)
	}

	return results, errors.Join(errs...)
}

// IngestFile reads and processes a single file through the pipeline.
func (f *FileIngester) IngestFile(path string) models.IngestResult {
	data, err := os.ReadFile(path)
	if err != nil {
		f.logger.Error("read file failed",
			slog.String("path", path),
			slog.Any("error", err),
		)

		return models.IngestResult{
			Source:     "file",
			Filename:   path,
			Type:       models.ReportTypeUnknown,
			Status:     models.IngestError,
			Message:    fmt.Sprintf("read file: %v", err),
			IngestedAt: time.Now().UTC(),
		}
	}

	f.logger.Info("ingesting file", slog.String("path", path))

	return f.pipeline.Process(data, "file", path)
}
