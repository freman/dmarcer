// Package config loads dmarcer configuration from environment variables,
// optionally seeded from a .env file in the current working directory.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all runtime configuration for dmarcer. Every field maps to an
// environment variable with the DMARCER_ prefix. Actual environment variables
// always take precedence over values read from .env.
type Config struct {
	// General
	DBPath                  string        // DMARCER_DB_PATH, default "./dmarcer.db"
	HTTPAddr                string        // DMARCER_HTTP_ADDR, default ":8080"
	BaseURL                 string        // DMARCER_BASE_URL, default ""
	LogLevel                string        // DMARCER_LOG_LEVEL, default "info"
	Offline                 bool          // DMARCER_OFFLINE, default false
	GeoIPDBPath             string        // DMARCER_GEOIP_DB_PATH, default ""
	GeoIPAccountID          string        // DMARCER_GEOIP_ACCOUNT_ID, MaxMind account ID for auto-update
	GeoIPLicenseKey         string        // DMARCER_GEOIP_LICENSE_KEY, MaxMind license key for auto-update
	GeoIPUpdateInterval     time.Duration // DMARCER_GEOIP_UPDATE_INTERVAL, default 24h
	SenderMapPath           string        // DMARCER_SENDER_MAP_PATH, default ""
	NormalizeTimespan       time.Duration // DMARCER_NORMALIZE_TIMESPAN, default 24h
	SaveAggregate           bool          // DMARCER_SAVE_AGGREGATE, default true
	SaveForensic            bool          // DMARCER_SAVE_FORENSIC, default true
	SaveSMTPTLS             bool          // DMARCER_SAVE_SMTP_TLS, default true
	StripAttachmentPayloads bool          // DMARCER_STRIP_ATTACHMENT_PAYLOADS, default false
	UploadEnabled           bool          // DMARCER_UPLOAD_ENABLED, default true
	UploadMaxSizeMB         int64         // DMARCER_UPLOAD_MAX_SIZE_MB, default 25
	APIKey                  string        // DMARCER_API_KEY, default ""

	// DNS
	Nameservers []string      // DMARCER_NAMESERVERS, default ["1.1.1.1","1.0.0.1"]
	DNSTimeout  time.Duration // DMARCER_DNS_TIMEOUT, default 2s
	DNSCacheTTL time.Duration // DMARCER_DNS_CACHE_TTL, default 4h
	DNSCacheMax int           // DMARCER_DNS_CACHE_MAX, default 10000

	// IMAP - enabled implicitly when IMAPHost is non-empty.
	IMAPHost          string        // DMARCER_IMAP_HOST
	IMAPPort          int           // DMARCER_IMAP_PORT, default 993
	IMAPTLS           bool          // DMARCER_IMAP_TLS, default true
	IMAPTLSSkipVerify bool          // DMARCER_IMAP_TLS_SKIP_VERIFY, default false
	IMAPUser          string        // DMARCER_IMAP_USER
	IMAPPassword      string        // DMARCER_IMAP_PASSWORD
	IMAPInbox         string        // DMARCER_IMAP_INBOX, default "INBOX"
	IMAPArchiveFolder string        // DMARCER_IMAP_ARCHIVE_FOLDER, default "Archive"
	IMAPDelete        bool          // DMARCER_IMAP_DELETE, default false
	IMAPWatch         bool          // DMARCER_IMAP_WATCH, default false
	IMAPPollInterval  time.Duration // DMARCER_IMAP_POLL_INTERVAL, default 5m
	IMAPBatchSize     int           // DMARCER_IMAP_BATCH_SIZE, default 10
	IMAPTimeout       time.Duration // DMARCER_IMAP_TIMEOUT, default 28m
	IMAPMaxRetries    int           // DMARCER_IMAP_MAX_RETRIES, default 4

	// Elasticsearch
	ESEnabled        bool          // DMARCER_ES_ENABLED, default false (forced true when ES_URL set)
	ESURLs           []string      // DMARCER_ES_URL, comma-separated
	ESUser           string        // DMARCER_ES_USER
	ESPassword       string        // DMARCER_ES_PASSWORD
	ESAPIKey         string        // DMARCER_ES_API_KEY
	ESTLSSkipVerify  bool          // DMARCER_ES_TLS_SKIP_VERIFY, default false
	ESCACertPath     string        // DMARCER_ES_CA_CERT_PATH
	ESIndexPrefix    string        // DMARCER_ES_INDEX_PREFIX, default "dmarcer_"
	ESIndexSuffix    string        // DMARCER_ES_INDEX_SUFFIX, default ""
	ESMonthlyIndexes bool          // DMARCER_ES_MONTHLY_INDEXES, default false
	ESTimeout        time.Duration // DMARCER_ES_TIMEOUT, default 60s
	ESShards         int           // DMARCER_ES_SHARDS, default 1
	ESReplicas       int           // DMARCER_ES_REPLICAS, default 0
	ESFailOnError    bool          // DMARCER_ES_FAIL_ON_ERROR, default false

	// OpenObserve
	OOEnabled         bool          // DMARCER_OO_ENABLED, default false (forced true when OO_URL set)
	OOURL             string        // DMARCER_OO_URL
	OOOrg             string        // DMARCER_OO_ORG, default "default"
	OOUser            string        // DMARCER_OO_USER
	OOPassword        string        // DMARCER_OO_PASSWORD
	OOToken           string        // DMARCER_OO_TOKEN
	OOTLSSkipVerify   bool          // DMARCER_OO_TLS_SKIP_VERIFY, default false
	OOStreamAggregate string        // DMARCER_OO_STREAM_AGGREGATE, default "dmarcer_aggregate"
	OOStreamForensic  string        // DMARCER_OO_STREAM_FORENSIC, default "dmarcer_forensic"
	OOStreamSMTPTLS   string        // DMARCER_OO_STREAM_SMTP_TLS, default "dmarcer_smtp_tls"
	OOBatchSize       int           // DMARCER_OO_BATCH_SIZE, default 100
	OOTimeout         time.Duration // DMARCER_OO_TIMEOUT, default 60s
	OOFailOnError     bool          // DMARCER_OO_FAIL_ON_ERROR, default false
}

// IMAPEnabled returns true when IMAP is configured (IMAPHost is set).
func (c *Config) IMAPEnabled() bool { return c.IMAPHost != "" }

// Load reads .env from the current working directory (if present) and then
// overlays the real process environment. It returns a fully populated Config
// with all defaults applied.
func Load() (*Config, error) {
	// Seed from .env if it exists; real env vars are overlaid below so they
	// always win regardless of godotenv.Read vs. godotenv.Overload semantics.
	dotenv := map[string]string{}

	if _, err := os.Stat(".env"); err == nil {
		var readErr error

		dotenv, readErr = godotenv.Read(".env")
		if readErr != nil {
			return nil, readErr
		}
	}

	// lookup returns the value for key, preferring the real environment over .env.
	lookup := func(key string) string {
		if v, ok := os.LookupEnv(key); ok {
			return v
		}

		return dotenv[key]
	}

	cfg := &Config{}

	// ---- General ----
	cfg.DBPath = str(lookup, "DMARCER_DB_PATH", "./dmarcer.db")
	cfg.HTTPAddr = str(lookup, "DMARCER_HTTP_ADDR", ":8080")
	cfg.BaseURL = str(lookup, "DMARCER_BASE_URL", "")
	cfg.LogLevel = str(lookup, "DMARCER_LOG_LEVEL", "info")
	cfg.Offline = boolean(lookup, "DMARCER_OFFLINE", false)
	cfg.GeoIPDBPath = str(lookup, "DMARCER_GEOIP_DB_PATH", "")
	cfg.GeoIPAccountID = str(lookup, "DMARCER_GEOIP_ACCOUNT_ID", "")
	cfg.GeoIPLicenseKey = str(lookup, "DMARCER_GEOIP_LICENSE_KEY", "")
	cfg.GeoIPUpdateInterval = duration(lookup, "DMARCER_GEOIP_UPDATE_INTERVAL", 24*time.Hour)
	cfg.SenderMapPath = str(lookup, "DMARCER_SENDER_MAP_PATH", "")
	cfg.NormalizeTimespan = duration(lookup, "DMARCER_NORMALIZE_TIMESPAN", 24*time.Hour)
	cfg.SaveAggregate = boolean(lookup, "DMARCER_SAVE_AGGREGATE", true)
	cfg.SaveForensic = boolean(lookup, "DMARCER_SAVE_FORENSIC", true)
	cfg.SaveSMTPTLS = boolean(lookup, "DMARCER_SAVE_SMTP_TLS", true)
	cfg.StripAttachmentPayloads = boolean(lookup, "DMARCER_STRIP_ATTACHMENT_PAYLOADS", false)
	cfg.UploadEnabled = boolean(lookup, "DMARCER_UPLOAD_ENABLED", true)
	cfg.UploadMaxSizeMB = int64Val(lookup, "DMARCER_UPLOAD_MAX_SIZE_MB", 25)
	cfg.APIKey = str(lookup, "DMARCER_API_KEY", "")

	// ---- DNS ----
	cfg.Nameservers = strList(lookup, "DMARCER_NAMESERVERS", []string{"1.1.1.1", "1.0.0.1"})
	cfg.DNSTimeout = duration(lookup, "DMARCER_DNS_TIMEOUT", 2*time.Second)
	cfg.DNSCacheTTL = duration(lookup, "DMARCER_DNS_CACHE_TTL", 4*time.Hour)
	cfg.DNSCacheMax = integer(lookup, "DMARCER_DNS_CACHE_MAX", 10000)

	// ---- IMAP ----
	cfg.IMAPHost = str(lookup, "DMARCER_IMAP_HOST", "")
	cfg.IMAPPort = integer(lookup, "DMARCER_IMAP_PORT", 993)
	cfg.IMAPTLS = boolean(lookup, "DMARCER_IMAP_TLS", true)
	cfg.IMAPTLSSkipVerify = boolean(lookup, "DMARCER_IMAP_TLS_SKIP_VERIFY", false)
	cfg.IMAPUser = str(lookup, "DMARCER_IMAP_USER", "")
	cfg.IMAPPassword = str(lookup, "DMARCER_IMAP_PASSWORD", "")
	cfg.IMAPInbox = str(lookup, "DMARCER_IMAP_INBOX", "INBOX")
	cfg.IMAPArchiveFolder = str(lookup, "DMARCER_IMAP_ARCHIVE_FOLDER", "Archive")
	cfg.IMAPDelete = boolean(lookup, "DMARCER_IMAP_DELETE", false)
	cfg.IMAPWatch = boolean(lookup, "DMARCER_IMAP_WATCH", false)
	cfg.IMAPPollInterval = duration(lookup, "DMARCER_IMAP_POLL_INTERVAL", 5*time.Minute)
	cfg.IMAPBatchSize = integer(lookup, "DMARCER_IMAP_BATCH_SIZE", 10)
	cfg.IMAPTimeout = duration(lookup, "DMARCER_IMAP_TIMEOUT", 28*time.Minute)
	cfg.IMAPMaxRetries = integer(lookup, "DMARCER_IMAP_MAX_RETRIES", 4)

	// ---- Elasticsearch ----
	cfg.ESURLs = strList(lookup, "DMARCER_ES_URL", nil)
	cfg.ESEnabled = boolean(lookup, "DMARCER_ES_ENABLED", false) || len(cfg.ESURLs) > 0
	cfg.ESUser = str(lookup, "DMARCER_ES_USER", "")
	cfg.ESPassword = str(lookup, "DMARCER_ES_PASSWORD", "")
	cfg.ESAPIKey = str(lookup, "DMARCER_ES_API_KEY", "")
	cfg.ESTLSSkipVerify = boolean(lookup, "DMARCER_ES_TLS_SKIP_VERIFY", false)
	cfg.ESCACertPath = str(lookup, "DMARCER_ES_CA_CERT_PATH", "")
	cfg.ESIndexPrefix = str(lookup, "DMARCER_ES_INDEX_PREFIX", "dmarcer_")
	cfg.ESIndexSuffix = str(lookup, "DMARCER_ES_INDEX_SUFFIX", "")
	cfg.ESMonthlyIndexes = boolean(lookup, "DMARCER_ES_MONTHLY_INDEXES", false)
	cfg.ESTimeout = duration(lookup, "DMARCER_ES_TIMEOUT", 60*time.Second)
	cfg.ESShards = integer(lookup, "DMARCER_ES_SHARDS", 1)
	cfg.ESReplicas = integer(lookup, "DMARCER_ES_REPLICAS", 0)
	cfg.ESFailOnError = boolean(lookup, "DMARCER_ES_FAIL_ON_ERROR", false)

	// ---- OpenObserve ----
	cfg.OOURL = str(lookup, "DMARCER_OO_URL", "")
	cfg.OOEnabled = boolean(lookup, "DMARCER_OO_ENABLED", false) || cfg.OOURL != ""
	cfg.OOOrg = str(lookup, "DMARCER_OO_ORG", "default")
	cfg.OOUser = str(lookup, "DMARCER_OO_USER", "")
	cfg.OOPassword = str(lookup, "DMARCER_OO_PASSWORD", "")
	cfg.OOToken = str(lookup, "DMARCER_OO_TOKEN", "")
	cfg.OOTLSSkipVerify = boolean(lookup, "DMARCER_OO_TLS_SKIP_VERIFY", false)
	cfg.OOStreamAggregate = str(lookup, "DMARCER_OO_STREAM_AGGREGATE", "dmarcer_aggregate")
	cfg.OOStreamForensic = str(lookup, "DMARCER_OO_STREAM_FORENSIC", "dmarcer_forensic")
	cfg.OOStreamSMTPTLS = str(lookup, "DMARCER_OO_STREAM_SMTP_TLS", "dmarcer_smtp_tls")
	cfg.OOBatchSize = integer(lookup, "DMARCER_OO_BATCH_SIZE", 100)
	cfg.OOTimeout = duration(lookup, "DMARCER_OO_TIMEOUT", 60*time.Second)
	cfg.OOFailOnError = boolean(lookup, "DMARCER_OO_FAIL_ON_ERROR", false)

	return cfg, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type lookupFn func(string) string

func str(fn lookupFn, key, def string) string {
	if v := fn(key); v != "" {
		return v
	}

	return def
}

func boolean(fn lookupFn, key string, def bool) bool {
	v := fn(key)
	if v == "" {
		return def
	}

	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}

	return b
}

func integer(fn lookupFn, key string, def int) int {
	v := fn(key)
	if v == "" {
		return def
	}

	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}

	return n
}

func int64Val(fn lookupFn, key string, def int64) int64 {
	v := fn(key)
	if v == "" {
		return def
	}

	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}

	return n
}

func duration(fn lookupFn, key string, def time.Duration) time.Duration {
	v := fn(key)
	if v == "" {
		return def
	}

	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}

	return d
}

// strList parses a comma-separated environment variable into a string slice.
// Returns def when the variable is unset or empty.
func strList(fn lookupFn, key string, def []string) []string {
	v := fn(key)
	if v == "" {
		return def
	}

	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}

	if len(out) == 0 {
		return def
	}

	return out
}
