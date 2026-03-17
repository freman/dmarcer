package enrichment

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxmindDownloadURL = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"

// DownloadAndReload performs a single GeoIP download and hot-reloads the service.
// Returns an error if either step fails.
func DownloadAndReload(ctx context.Context, accountID, licenseKey, destPath string, svc *Service, logger *slog.Logger) error {
	logger.Info("geoip: downloading GeoLite2-Country database")

	if err := downloadGeoIP(ctx, accountID, licenseKey, destPath); err != nil {
		return fmt.Errorf("geoip: download: %w", err)
	}

	if err := svc.ReloadGeoIP(destPath); err != nil {
		return fmt.Errorf("geoip: reload: %w", err)
	}

	return nil
}

// StartGeoIPUpdater periodically re-downloads the GeoLite2-Country database.
// The first tick is scheduled based on the file's last modification time so
// that a recent file isn't re-downloaded immediately on restart.
// It does NOT perform an initial download - call DownloadAndReload first if needed.
// Blocks until ctx is cancelled.
func StartGeoIPUpdater(ctx context.Context, accountID, licenseKey, destPath string, interval time.Duration, svc *Service, logger *slog.Logger) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	// Work out how long until the next update is due.
	nextIn := interval

	if info, err := os.Stat(destPath); err == nil {
		age := time.Since(info.ModTime())
		if age < interval {
			nextIn = interval - age
		} else {
			nextIn = 0 // already overdue
		}
	}

	logger.Info("geoip: next update scheduled", slog.Duration("in", nextIn.Truncate(time.Second)))

	// Wait for the first tick, then switch to a regular interval.
	select {
	case <-ctx.Done():
		return
	case <-time.After(nextIn):
	}

	if err := DownloadAndReload(ctx, accountID, licenseKey, destPath, svc, logger); err != nil {
		logger.Error("geoip: update failed", slog.Any("error", err))
	}

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := DownloadAndReload(ctx, accountID, licenseKey, destPath, svc, logger); err != nil {
				logger.Error("geoip: periodic update failed", slog.Any("error", err))
			}
		}
	}
}

// downloadGeoIP fetches the GeoLite2-Country tar.gz from MaxMind, extracts the
// .mmdb file, and atomically writes it to destPath.
func downloadGeoIP(ctx context.Context, accountID, licenseKey, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, maxmindDownloadURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.SetBasicAuth(accountID, licenseKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	// Extract the .mmdb from the tar.gz stream.
	mmdbData, err := extractMMDB(resp.Body)
	if err != nil {
		return fmt.Errorf("extract mmdb: %w", err)
	}

	// Write atomically via a temp file in the same directory.
	dir := filepath.Dir(destPath)

	tmp, err := os.CreateTemp(dir, ".geoip-*.mmdb.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	tmpName := tmp.Name()

	if _, err := tmp.Write(mmdbData); err != nil {
		tmp.Close()
		os.Remove(tmpName)

		return fmt.Errorf("write temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpName, destPath); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename to dest: %w", err)
	}

	return nil
}

// extractMMDB reads a tar.gz stream and returns the contents of the first .mmdb file found.
func extractMMDB(r io.Reader) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("tar next: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		if strings.HasSuffix(hdr.Name, ".mmdb") {
			return io.ReadAll(tr)
		}
	}

	return nil, fmt.Errorf("no .mmdb file found in archive")
}
