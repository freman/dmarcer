package api

import (
	"io"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
)

// uploadResult is the per-file result returned in the upload response.
type uploadResult struct {
	Filename          string `json:"filename"`
	Type              string `json:"type"`
	Status            string `json:"status"`
	RecordsSaved      int    `json:"records_saved"`
	DuplicatesSkipped int    `json:"duplicates_skipped"`
	Message           string `json:"message"`
}

// handleUpload handles POST /api/upload.
//
// Accepts:
//   - multipart/form-data with one or more files in the "file" field.
//   - A raw body (application/octet-stream or similar); the filename is taken
//     from the Content-Disposition header if present, otherwise "upload".
func (s *Server) handleUpload(c echo.Context) error {
	maxBytes := s.cfg.UploadMaxSizeMB * 1024 * 1024

	ct := c.Request().Header.Get("Content-Type")

	var results []uploadResult

	if isMultipart(ct) {
		// Parse the multipart form with the configured size limit.
		if err := c.Request().ParseMultipartForm(maxBytes); err != nil {
			return errResp(c, http.StatusBadRequest, "failed to parse multipart form: "+err.Error())
		}

		mf := c.Request().MultipartForm
		if mf == nil || len(mf.File["file"]) == 0 {
			return errResp(c, http.StatusBadRequest, "no files found in 'file' field")
		}

		for _, fh := range mf.File["file"] {
			filename := fh.Filename
			if filename == "" {
				filename = "upload"
			}

			f, err := fh.Open()
			if err != nil {
				results = append(results, uploadResult{
					Filename: filename,
					Status:   "error",
					Message:  "failed to open file: " + err.Error(),
				})

				continue
			}

			data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
			f.Close()

			if err != nil {
				results = append(results, uploadResult{
					Filename: filename,
					Status:   "error",
					Message:  "failed to read file: " + err.Error(),
				})

				continue
			}

			if int64(len(data)) > maxBytes {
				results = append(results, uploadResult{
					Filename: filename,
					Status:   "error",
					Message:  "file exceeds maximum upload size",
				})

				continue
			}

			r := s.uploadPipeline.Process(data, "upload", filename)
			results = append(results, uploadResult{
				Filename:          filename,
				Type:              string(r.Type),
				Status:            string(r.Status),
				RecordsSaved:      r.RecordsSaved,
				DuplicatesSkipped: r.DuplicatesSkipped,
				Message:           r.Message,
			})
		}
	} else {
		// Raw body upload.
		filename := rawFilename(c)

		data, err := io.ReadAll(io.LimitReader(c.Request().Body, maxBytes+1))
		if err != nil {
			return errResp(c, http.StatusBadRequest, "failed to read body: "+err.Error())
		}

		if int64(len(data)) > maxBytes {
			return errResp(c, http.StatusRequestEntityTooLarge, "body exceeds maximum upload size")
		}

		r := s.uploadPipeline.Process(data, "upload", filename)
		results = append(results, uploadResult{
			Filename:          filename,
			Type:              string(r.Type),
			Status:            string(r.Status),
			RecordsSaved:      r.RecordsSaved,
			DuplicatesSkipped: r.DuplicatesSkipped,
			Message:           r.Message,
		})
	}

	if results == nil {
		results = []uploadResult{}
	}

	return c.JSON(http.StatusOK, map[string]any{
		"results": results,
	})
}

// isMultipart returns true when the Content-Type indicates a multipart/form-data body.
func isMultipart(ct string) bool {
	return strings.HasPrefix(ct, "multipart/form-data")
}

// rawFilename extracts a filename from the Content-Disposition header, or
// returns "upload" when none is present.
func rawFilename(c echo.Context) string {
	cd := c.Request().Header.Get("Content-Disposition")
	if cd == "" {
		return "upload"
	}

	const token = "filename="

	_, after, ok := strings.Cut(cd, token)
	if !ok {
		return "upload"
	}

	val := after
	// Strip optional surrounding quotes.
	if len(val) > 0 && val[0] == '"' {
		if end := strings.Index(val[1:], `"`); end >= 0 {
			return val[1 : end+1]
		}
	}
	// Unquoted - take up to the next semicolon or end.
	if before, _, ok := strings.Cut(val, ";"); ok {
		return strings.TrimSpace(before)
	}

	return strings.TrimSpace(val)
}
