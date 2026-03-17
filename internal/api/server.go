// Package api implements the HTTP API server for dmarcer.
package api

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/freman/dmarcer/internal/config"
	"github.com/freman/dmarcer/internal/models"
	"github.com/freman/dmarcer/internal/store"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// UploadPipeline is implemented by the ingest pipeline to process uploaded bytes.
type UploadPipeline interface {
	Process(data []byte, source, filename string) models.IngestResult
}

// Server holds the Echo instance and all dependencies.
type Server struct {
	echo           *echo.Echo
	db             *store.DB
	cfg            *config.Config
	logger         *slog.Logger
	uploadPipeline UploadPipeline
	shutdownCancel context.CancelFunc
}

// New creates the Echo server, registers all routes and middleware, and
// configures static asset serving from the provided fs.FS.
func New(cfg *config.Config, db *store.DB, pipeline UploadPipeline, logger *slog.Logger, webFS fs.FS) *Server {
	e := echo.New()

	s := &Server{
		echo:           e,
		db:             db,
		cfg:            cfg,
		logger:         logger,
		uploadPipeline: pipeline,
	}

	// Global middleware.
	e.Use(middleware.Recover())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogMethod:  true,
		LogURI:     true,
		LogStatus:  true,
		LogLatency: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			logger.Info("request",
				"method", v.Method,
				"uri", v.URI,
				"status", v.Status,
				"latency_ms", v.Latency.Milliseconds(),
			)

			return nil
		},
	}))

	// API route group - optionally protected by a Bearer token.
	apiGroup := e.Group("/api")
	if cfg.APIKey != "" {
		apiGroup.Use(s.bearerAuthMiddleware())
	}

	// Register API routes.
	apiGroup.GET("/health", s.handleHealth)

	apiGroup.GET("/aggregate", s.handleListAggregate)
	apiGroup.GET("/aggregate/:id", s.handleGetAggregate)

	apiGroup.GET("/forensic", s.handleListForensic)
	apiGroup.GET("/forensic/:id", s.handleGetForensic)

	apiGroup.GET("/smtp-tls", s.handleListSMTPTLS)
	apiGroup.GET("/smtp-tls/:id", s.handleGetSMTPTLS)

	apiGroup.GET("/stats/summary", s.handleSummary)
	apiGroup.GET("/stats/timeline", s.handleTimeline)
	apiGroup.GET("/stats/top-sources", s.handleTopSources)
	apiGroup.GET("/stats/countries", s.handleCountries)
	apiGroup.GET("/stats/orgs", s.handleOrgs)
	apiGroup.GET("/stats/senders", s.handleSenders)
	apiGroup.GET("/stats/smtp-tls-summary", s.handleSMTPTLSSummary)
	apiGroup.GET("/stats/domains", s.handleDomains)

	apiGroup.GET("/ingest-log", s.handleIngestLog)

	if cfg.UploadEnabled {
		apiGroup.POST("/upload", s.handleUpload)
	}

	// Serve embedded web UI as a catch-all. Any path that does not match an
	// API route falls through to the SPA index or a static asset.
	if webFS != nil {
		e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
			Root:       ".",
			Index:      "index.html",
			HTML5:      true,
			Browse:     false,
			Filesystem: webFS,
		}))
	}

	return s
}

// bearerAuthMiddleware returns a middleware that validates Authorization: Bearer <key>.
func (s *Server) bearerAuthMiddleware() echo.MiddlewareFunc {
	expected := "Bearer " + s.cfg.APIKey

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auth := c.Request().Header.Get("Authorization")
			if auth != expected {
				return errResp(c, http.StatusUnauthorized, "unauthorized")
			}

			return next(c)
		}
	}
}

// Start starts the HTTP server on cfg.HTTPAddr. It blocks until the server
// stops (either by error or graceful shutdown via Shutdown).
func (s *Server) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	s.shutdownCancel = cancel

	return echo.StartConfig{
		Address:         s.cfg.HTTPAddr,
		HideBanner:      true,
		GracefulContext: ctx,
	}.Start(s.echo)
}

// Shutdown signals the server to stop accepting new connections and waits for
// in-flight requests to finish within the given context deadline.
func (s *Server) Shutdown(_ context.Context) error {
	if s.shutdownCancel != nil {
		s.shutdownCancel()
	}

	return nil
}

// errResp writes a JSON error response.
func errResp(c echo.Context, status int, msg string) error {
	return c.JSON(status, map[string]string{"error": msg})
}
