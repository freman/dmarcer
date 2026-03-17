package api

import (
	"net/http"
	"strconv"

	"github.com/freman/dmarcer/internal/store"
	"github.com/labstack/echo/v5"
)

// handleIngestLog handles GET /api/ingest-log.
// Supported query params: from, to, status, source, page, per_page.
func (s *Server) handleIngestLog(c echo.Context) error {
	p := store.QueryIngestLogParams{
		From:   c.QueryParam("from"),
		To:     c.QueryParam("to"),
		Status: c.QueryParam("status"),
		Source: c.QueryParam("source"),
	}

	p.Page, _ = strconv.Atoi(c.QueryParam("page"))
	p.PerPage, _ = strconv.Atoi(c.QueryParam("per_page"))

	rows, total, err := s.db.ListIngestLog(p)
	if err != nil {
		s.logger.Error("ListIngestLog failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if rows == nil {
		rows = []store.IngestLogRow{}
	}

	page := max(p.Page, 1)

	perPage := p.PerPage
	if perPage <= 0 {
		perPage = 100
	}

	return c.JSON(http.StatusOK, map[string]any{
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"records":  rows,
	})
}
