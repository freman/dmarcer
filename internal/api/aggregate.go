package api

import (
	"net/http"
	"strconv"

	"github.com/freman/dmarcer/internal/store"
	"github.com/labstack/echo/v5"
)

// handleListAggregate handles GET /api/aggregate.
// Supported query params: from, to, domain, header_from, org_name, disposition,
// dmarc_passed, spf_aligned, dkim_aligned, source_country, source_type,
// source_name, page, per_page.
func (s *Server) handleListAggregate(c echo.Context) error {
	p := store.QueryAggregateParams{
		From:             c.QueryParam("from"),
		To:               c.QueryParam("to"),
		Domain:           c.QueryParam("domain"),
		HeaderFrom:       c.QueryParam("header_from"),
		OrgName:          c.QueryParam("org_name"),
		Disposition:      c.QueryParam("disposition"),
		SourceCountry:    c.QueryParam("source_country"),
		SourceType:       c.QueryParam("source_type"),
		SourceName:       c.QueryParam("source_name"),
		SourceIP:         c.QueryParam("source_ip"),
		SourceBaseDomain: c.QueryParam("source_base_domain"),
	}

	if v := c.QueryParam("dmarc_passed"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return errResp(c, http.StatusBadRequest, "invalid dmarc_passed value")
		}

		p.DMARCPassed = &b
	}

	if v := c.QueryParam("spf_aligned"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return errResp(c, http.StatusBadRequest, "invalid spf_aligned value")
		}

		p.SPFAligned = &b
	}

	if v := c.QueryParam("dkim_aligned"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return errResp(c, http.StatusBadRequest, "invalid dkim_aligned value")
		}

		p.DKIMAligned = &b
	}

	p.Page, _ = strconv.Atoi(c.QueryParam("page"))
	p.PerPage, _ = strconv.Atoi(c.QueryParam("per_page"))

	rows, total, err := s.db.ListAggregate(p)
	if err != nil {
		s.logger.Error("ListAggregate failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if rows == nil {
		rows = []store.AggregateRow{}
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

// handleGetAggregate handles GET /api/aggregate/:id.
func (s *Server) handleGetAggregate(c echo.Context) error {
	id, err := strconv.ParseInt(c.PathParam("id"), 10, 64)
	if err != nil {
		return errResp(c, http.StatusBadRequest, "invalid id")
	}

	row, err := s.db.GetAggregate(id)
	if err != nil {
		s.logger.Error("GetAggregate failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if row == nil {
		return errResp(c, http.StatusNotFound, "not found")
	}

	return c.JSON(http.StatusOK, row)
}
