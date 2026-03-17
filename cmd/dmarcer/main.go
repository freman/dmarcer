package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	dmarcer "github.com/freman/dmarcer"
	"github.com/freman/dmarcer/internal/api"
	"github.com/freman/dmarcer/internal/config"
	"github.com/freman/dmarcer/internal/enrichment"
	"github.com/freman/dmarcer/internal/ingest"
	"github.com/freman/dmarcer/internal/models"
	"github.com/freman/dmarcer/internal/output"
	"github.com/freman/dmarcer/internal/output/elastic"
	"github.com/freman/dmarcer/internal/output/openobserve"
	"github.com/freman/dmarcer/internal/store"
)

func main() {
	args := os.Args[1:]

	// File ingest mode: dmarcer ingest [--recursive] <path>...
	fileIngestMode := len(args) > 0 && args[0] == "ingest"

	var ingestPaths []string

	recursive := false

	if fileIngestMode {
		for _, a := range args[1:] {
			switch a {
			case "--recursive", "-r":
				recursive = true
			default:
				ingestPaths = append(ingestPaths, a)
			}
		}

		if len(ingestPaths) == 0 {
			fmt.Fprintln(os.Stderr, "usage: dmarcer ingest [--recursive] <path>...")
			os.Exit(1)
		}
	}

	// Load configuration.
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	// Build slog logger.
	var level slog.Level

	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Open SQLite database.
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		logger.Error("open database", slog.String("path", cfg.DBPath), slog.Any("error", err))
		os.Exit(1)
	}
	defer db.Close()

	// Build enrichment service.
	// Use SafeGeoIPData so an empty/stub MMDB file is treated as no GeoIP.
	var geoIPBytes []byte
	if cfg.GeoIPDBPath == "" {
		geoIPBytes = dmarcer.SafeGeoIPData()
	}

	var senderMapBytes []byte
	if cfg.SenderMapPath == "" {
		senderMapBytes = dmarcer.SenderMapData
	}

	enrichCfg := enrichment.Config{
		GeoIPPath:     cfg.GeoIPDBPath,
		SenderMapPath: cfg.SenderMapPath,
		Nameservers:   cfg.Nameservers,
		DNSTimeout:    cfg.DNSTimeout,
		CacheTTL:      cfg.DNSCacheTTL,
		CacheMax:      cfg.DNSCacheMax,
		Offline:       cfg.Offline,
		Logger:        logger,
	}

	enrichSvc, err := enrichment.New(enrichCfg, geoIPBytes, senderMapBytes)
	if err != nil {
		logger.Error("build enrichment service", slog.Any("error", err))
		os.Exit(1)
	}

	// Build output backends.
	sqliteBackend := store.NewBackend(db, cfg.SaveAggregate, cfg.SaveForensic, cfg.SaveSMTPTLS)
	fanout := buildFanout(cfg, logger, sqliteBackend)

	// Build the ingest pipeline.
	pipeline := ingest.NewPipeline(
		db,
		fanout,
		enrichSvc,
		cfg.NormalizeTimespan,
		cfg.StripAttachmentPayloads,
		logger,
	)

	// File ingest mode: process files and exit.
	if fileIngestMode {
		fileIngester := ingest.NewFileIngester(pipeline, logger)
		exitCode := 0

		for _, path := range ingestPaths {
			results, err := fileIngester.IngestPath(path, recursive)
			for _, r := range results {
				fmt.Printf("%s\t%s\t%s\t%s\tsaved=%d duplicates=%d\n",
					string(r.Status), r.Source, string(r.Type), r.Filename,
					r.RecordsSaved, r.DuplicatesSkipped,
				)

				if r.Message != "" {
					fmt.Printf("  message: %s\n", r.Message)
				}
			}

			if err != nil {
				fmt.Fprintf(os.Stderr, "ingest %q: %v\n", path, err)

				exitCode = 1
			}
		}

		_ = fanout.Close()

		os.Exit(exitCode)
	}

	// Server mode.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Build web sub-FS from the embedded web/dist directory.
	webSubFS, err := dmarcer.SubWebFS()
	if err != nil {
		logger.Error("build web sub-FS", slog.Any("error", err))
		os.Exit(1)
	}

	// Build API server.
	srv := api.New(cfg, db, pipeline, logger, webSubFS)

	// Start GeoIP auto-updater if MaxMind credentials are configured.
	if cfg.GeoIPAccountID != "" && cfg.GeoIPLicenseKey != "" {
		destPath := cfg.GeoIPDBPath
		if destPath == "" {
			destPath = "geoip.mmdb"
		}
		// If the DB file doesn't exist yet, download it now before starting
		// the IMAP ingester so the first batch of messages gets country data.
		if _, statErr := os.Stat(destPath); os.IsNotExist(statErr) {
			if dlErr := enrichment.DownloadAndReload(ctx, cfg.GeoIPAccountID, cfg.GeoIPLicenseKey, destPath, enrichSvc, logger); dlErr != nil {
				logger.Warn("geoip: initial download failed, starting without GeoIP", slog.Any("error", dlErr))
			}
		}

		interval := cfg.GeoIPUpdateInterval
		go enrichment.StartGeoIPUpdater(ctx, cfg.GeoIPAccountID, cfg.GeoIPLicenseKey, destPath, interval, enrichSvc, logger)
	}

	// Start IMAP ingester if configured.
	if cfg.IMAPEnabled() {
		imapIngester := ingest.NewIMAPIngester(cfg, pipeline, logger)

		go func() {
			if err := imapIngester.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("IMAP ingester stopped", slog.Any("error", err))
			}
		}()
	}

	// Start HTTP server in background.
	srvErr := make(chan error, 1)

	go func() {
		logger.Info("starting HTTP server", slog.String("addr", cfg.HTTPAddr))

		srvErr <- srv.Start()
	}()

	// Wait for termination signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		logger.Info("shutting down", slog.String("signal", sig.String()))
	case err := <-srvErr:
		if err != nil {
			logger.Error("HTTP server error", slog.Any("error", err))
		}
	}

	// Graceful shutdown.
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown", slog.Any("error", err))
	}

	if err := fanout.Close(); err != nil {
		logger.Error("fanout close", slog.Any("error", err))
	}

	if err := db.Close(); err != nil {
		logger.Error("db close", slog.Any("error", err))
	}

	logger.Info("shutdown complete")
}

// buildFanout constructs the output fanout with all configured backends.
func buildFanout(cfg *config.Config, logger *slog.Logger, sqliteBackend *store.Backend) *output.Fanout {
	backends := []models.Backend{sqliteBackend}

	// Build Elasticsearch backend if enabled.
	if cfg.ESEnabled {
		b, err := elastic.New(elastic.Config{
			URLs:           cfg.ESURLs,
			User:           cfg.ESUser,
			Password:       cfg.ESPassword,
			APIKey:         cfg.ESAPIKey,
			TLSSkipVerify:  cfg.ESTLSSkipVerify,
			CACertPath:     cfg.ESCACertPath,
			IndexPrefix:    cfg.ESIndexPrefix,
			IndexSuffix:    cfg.ESIndexSuffix,
			MonthlyIndexes: cfg.ESMonthlyIndexes,
			Timeout:        cfg.ESTimeout,
			Shards:         cfg.ESShards,
			Replicas:       cfg.ESReplicas,
			FailOnError:    cfg.ESFailOnError,
			Logger:         logger,
		})
		if err != nil {
			logger.Error("create elasticsearch backend", slog.Any("error", err))
		} else {
			backends = append(backends, b)
		}
	}

	// Build OpenObserve backend if enabled.
	if cfg.OOEnabled {
		b, err := openobserve.New(openobserve.Config{
			URL:             cfg.OOURL,
			Org:             cfg.OOOrg,
			User:            cfg.OOUser,
			Password:        cfg.OOPassword,
			Token:           cfg.OOToken,
			TLSSkipVerify:   cfg.OOTLSSkipVerify,
			StreamAggregate: cfg.OOStreamAggregate,
			StreamForensic:  cfg.OOStreamForensic,
			StreamSMTPTLS:   cfg.OOStreamSMTPTLS,
			BatchSize:       cfg.OOBatchSize,
			Timeout:         cfg.OOTimeout,
			FailOnError:     cfg.OOFailOnError,
			Logger:          logger,
		})
		if err != nil {
			logger.Error("create openobserve backend", slog.Any("error", err))
		} else {
			backends = append(backends, b)
		}
	}

	return output.NewFanout(logger, backends...)
}
