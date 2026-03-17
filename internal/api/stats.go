package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/freman/dmarcer/internal/store"
	"github.com/labstack/echo/v5"
)

const dateFmt = "2006-01-02"

// statsFilter builds a StatsFilter from the common from/to/domain query params,
// applying a default 30-day window when from/to are absent.
func statsFilter(c echo.Context) store.StatsFilter {
	from := c.QueryParam("from")
	to := c.QueryParam("to")

	if from == "" {
		from = time.Now().UTC().AddDate(0, 0, -30).Format(dateFmt)
	}

	if to == "" {
		to = time.Now().UTC().Format(dateFmt)
	}

	return store.StatsFilter{
		From:             from,
		To:               to,
		Domain:           c.QueryParam("domain"),
		SourceIP:         c.QueryParam("source_ip"),
		OrgName:          c.QueryParam("org_name"),
		SourceName:       c.QueryParam("source_name"),
		SourceBaseDomain: c.QueryParam("source_base_domain"),
	}
}

// handleSummary handles GET /api/stats/summary.
func (s *Server) handleSummary(c echo.Context) error {
	f := statsFilter(c)

	stats, err := s.db.GetSummaryStats(f)
	if err != nil {
		s.logger.Error("GetSummaryStats failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	return c.JSON(http.StatusOK, stats)
}

// handleTimeline handles GET /api/stats/timeline.
// Additional query param: granularity (day|week|month, default day).
func (s *Server) handleTimeline(c echo.Context) error {
	f := statsFilter(c)

	granularity := c.QueryParam("granularity")
	if granularity == "" {
		granularity = "day"
	}

	buckets, err := s.db.GetTimeline(f, granularity)
	if err != nil {
		s.logger.Error("GetTimeline failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if buckets == nil {
		buckets = []store.TimelineBucket{}
	}

	return c.JSON(http.StatusOK, buckets)
}

// handleTopSources handles GET /api/stats/top-sources.
// Additional query param: limit (default 10).
func (s *Server) handleTopSources(c echo.Context) error {
	f := statsFilter(c)

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit <= 0 {
		limit = 10
	}

	sources, err := s.db.GetTopSources(f, limit)
	if err != nil {
		s.logger.Error("GetTopSources failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if sources == nil {
		sources = []store.TopSource{}
	}

	return c.JSON(http.StatusOK, sources)
}

// handleCountries handles GET /api/stats/countries.
func (s *Server) handleCountries(c echo.Context) error {
	f := statsFilter(c)

	countries, err := s.db.GetCountries(f)
	if err != nil {
		s.logger.Error("GetCountries failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if countries == nil {
		countries = []store.CountryCount{}
	}

	return c.JSON(http.StatusOK, countries)
}

// handleOrgs handles GET /api/stats/orgs.
func (s *Server) handleOrgs(c echo.Context) error {
	f := statsFilter(c)

	orgs, err := s.db.GetOrgs(f)
	if err != nil {
		s.logger.Error("GetOrgs failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if orgs == nil {
		orgs = []store.OrgCount{}
	}

	return c.JSON(http.StatusOK, orgs)
}

// handleSenders handles GET /api/stats/senders.
func (s *Server) handleSenders(c echo.Context) error {
	f := statsFilter(c)

	senders, err := s.db.GetSenders(f)
	if err != nil {
		s.logger.Error("GetSenders failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if senders == nil {
		senders = []store.SenderCount{}
	}

	return c.JSON(http.StatusOK, senders)
}

// handleSMTPTLSSummary handles GET /api/stats/smtp-tls-summary.
func (s *Server) handleSMTPTLSSummary(c echo.Context) error {
	f := statsFilter(c)

	summary, err := s.db.GetSMTPTLSSummary(f)
	if err != nil {
		s.logger.Error("GetSMTPTLSSummary failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	return c.JSON(http.StatusOK, summary)
}

// handleDomains handles GET /api/stats/domains.
// Returns the sorted list of distinct policy domains in the database.
func (s *Server) handleDomains(c echo.Context) error {
	domains, err := s.db.GetDistinctDomains()
	if err != nil {
		s.logger.Error("GetDistinctDomains failed", "error", err)
		return errResp(c, http.StatusInternalServerError, "database error")
	}

	if domains == nil {
		domains = []string{}
	}

	return c.JSON(http.StatusOK, domains)
}

// handleHealth handles GET /api/health.
// Pings the database and returns status ok (200) or degraded (503).
func (s *Server) handleHealth(c echo.Context) error {
	var one int

	err := s.db.SQL().QueryRow("SELECT 1").Scan(&one)
	if err != nil {
		s.logger.Error("health check DB ping failed", "error", err)

		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"status": "degraded",
			"db":     "error",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status": "ok",
		"db":     "ok",
	})
}
