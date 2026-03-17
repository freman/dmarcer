package api

import (
	"net/http"
	"strconv"

	"github.com/freman/dmarcer/internal/store"
	"github.com/labstack/echo/v5"
)

// handleListForensic handles GET /api/forensic.
// Supported query params: from, to, domain, source_ip, source_country,
// page, per_page.
func (s *Server) handleListForensic(c echo.Context) error {
	p := store.QueryForensicParams{
		From:          c.QueryParam("from"),
		To:            c.QueryParam("to"),
		Domain:        c.QueryParam("domain"),
		SourceIP:      c.QueryParam("source_ip"),
		SourceCountry: c.QueryParam("source_country"),
	}

	p.Page, _ = strconv.Atoi(c.QueryParam("page"))
	p.PerPage, _ = strconv.Atoi(c.QueryParam("per_page"))

	rows, total, err := s.db.ListForensic(p)
	if err != nil {
		s.logger.Error("ListForensic failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if rows == nil {
		rows = []store.ForensicRow{}
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

// handleGetForensic handles GET /api/forensic/:id.
func (s *Server) handleGetForensic(c echo.Context) error {
	id, err := strconv.ParseInt(c.PathParam("id"), 10, 64)
	if err != nil {
		return errResp(c, http.StatusBadRequest, "invalid id")
	}

	row, err := s.db.GetForensic(id)
	if err != nil {
		s.logger.Error("GetForensic failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if row == nil {
		return errResp(c, http.StatusNotFound, "not found")
	}

	return c.JSON(http.StatusOK, row)
}
