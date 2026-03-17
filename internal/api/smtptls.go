package api

import (
	"net/http"
	"strconv"

	"github.com/freman/dmarcer/internal/store"
	"github.com/labstack/echo/v5"
)

// handleListSMTPTLS handles GET /api/smtp-tls.
// Supported query params: from, to, domain, org_name, policy_type,
// page, per_page.
func (s *Server) handleListSMTPTLS(c echo.Context) error {
	p := store.QuerySMTPTLSParams{
		From:       c.QueryParam("from"),
		To:         c.QueryParam("to"),
		Domain:     c.QueryParam("domain"),
		OrgName:    c.QueryParam("org_name"),
		PolicyType: c.QueryParam("policy_type"),
	}

	p.Page, _ = strconv.Atoi(c.QueryParam("page"))
	p.PerPage, _ = strconv.Atoi(c.QueryParam("per_page"))

	rows, total, err := s.db.ListSMTPTLS(p)
	if err != nil {
		s.logger.Error("ListSMTPTLS failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if rows == nil {
		rows = []store.SMTPTLSRow{}
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

// handleGetSMTPTLS handles GET /api/smtp-tls/:id.
func (s *Server) handleGetSMTPTLS(c echo.Context) error {
	id, err := strconv.ParseInt(c.PathParam("id"), 10, 64)
	if err != nil {
		return errResp(c, http.StatusBadRequest, "invalid id")
	}

	row, err := s.db.GetSMTPTLS(id)
	if err != nil {
		s.logger.Error("GetSMTPTLS failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if row == nil {
		return errResp(c, http.StatusNotFound, "not found")
	}

	return c.JSON(http.StatusOK, row)
}
