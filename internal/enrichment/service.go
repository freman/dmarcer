package enrichment

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/freman/dmarcer/internal/models"
)

// Service implements Enricher.
type Service struct {
	mu      sync.RWMutex
	geo     *geoIPDB
	dns     *dnsResolver
	senders *senderMap
	cache   *ipCache
	offline bool
	logger  *slog.Logger
}

// Config holds the settings needed to construct a Service.
type Config struct {
	GeoIPPath     string
	SenderMapPath string        // path to CSV; if empty uses embedded
	Nameservers   []string      // bare IPs, port 53 appended automatically
	DNSTimeout    time.Duration
	CacheTTL      time.Duration
	CacheMax      int
	Offline       bool
	Logger        *slog.Logger
}

// New constructs an enrichment Service.
// If GeoIPPath is non-empty, GeoIP is loaded from disk.
// If GeoIPPath is empty and geoIPData is non-nil, GeoIP is loaded from the provided bytes.
// If SenderMapPath is non-empty, the sender map is loaded from disk.
// If SenderMapPath is empty and senderMapData is non-nil, it is loaded from the provided bytes.
func New(cfg Config, geoIPData []byte, senderMapData []byte) (*Service, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// --- GeoIP ---
	var geo *geoIPDB

	var err error

	if cfg.GeoIPPath != "" {
		geo, err = openGeoIP(cfg.GeoIPPath)
		if err != nil {
			return nil, fmt.Errorf("enrichment: open geoip from disk: %w", err)
		}
	} else if len(geoIPData) > 0 {
		geo, err = openGeoIPFromBytes(geoIPData)
		if err != nil {
			return nil, fmt.Errorf("enrichment: open geoip from bytes: %w", err)
		}
	}

	if geo == nil {
		logger.Warn("enrichment: GeoIP database unavailable; country lookups disabled")
	}

	// --- Sender map ---
	var sm *senderMap

	if cfg.SenderMapPath != "" {
		f, err := os.Open(cfg.SenderMapPath)
		if err != nil {
			return nil, fmt.Errorf("enrichment: open sender map: %w", err)
		}
		defer f.Close()

		sm, err = loadSenderMap(f)
		if err != nil {
			return nil, fmt.Errorf("enrichment: load sender map from file: %w", err)
		}
	} else if len(senderMapData) > 0 {
		sm, err = loadSenderMap(bytes.NewReader(senderMapData))
		if err != nil {
			return nil, fmt.Errorf("enrichment: load sender map from bytes: %w", err)
		}
	}

	if sm == nil {
		sm = &senderMap{entries: make(map[string]senderEntry)}
	}

	// --- DNS nameservers ---
	nameservers := make([]string, 0, len(cfg.Nameservers))
	for _, ns := range cfg.Nameservers {
		if ns == "" {
			continue
		}
		// Append :53 if no port is present. Use net.SplitHostPort to detect an existing port.
		if _, _, err := net.SplitHostPort(ns); err != nil {
			ns = ns + ":53"
		}

		nameservers = append(nameservers, ns)
	}

	dnsTimeout := cfg.DNSTimeout
	if dnsTimeout == 0 {
		dnsTimeout = 5 * time.Second
	}

	cacheMax := cfg.CacheMax
	if cacheMax <= 0 {
		cacheMax = 4096
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 24 * time.Hour
	}

	return &Service{
		geo:     geo,
		dns:     newDNSResolver(nameservers, dnsTimeout),
		senders: sm,
		cache:   newIPCache(cacheMax, cacheTTL),
		offline: cfg.Offline,
		logger:  logger,
	}, nil
}

// ReloadGeoIP hot-swaps the GeoIP database from the given path.
// Safe to call from any goroutine.
func (s *Service) ReloadGeoIP(path string) error {
	geo, err := openGeoIP(path)
	if err != nil {
		return fmt.Errorf("enrichment: reload geoip: %w", err)
	}

	s.mu.Lock()
	s.geo = geo
	s.mu.Unlock()
	s.cache.flush()
	s.logger.Info("enrichment: GeoIP database reloaded", slog.String("path", path))

	return nil
}

// Enrich implements Enricher. Returns IPSourceInfo for the given IP.
// Results are cached. If offline=true, skips DNS and returns GeoIP-only enrichment.
// Errors are logged internally; the returned value is always usable.
func (s *Service) Enrich(ip string) (*models.IPSourceInfo, error) {
	// 1. Check cache.
	if cached, ok := s.cache.get(ip); ok {
		return &cached, nil
	}

	// 2. Start with base info.
	info := models.IPSourceInfo{IPAddress: ip}

	// 3. GeoIP lookup.
	s.mu.RLock()
	geo := s.geo
	s.mu.RUnlock()

	if geo != nil {
		if code := geo.country(ip); code != "" {
			c := code
			info.Country = &c
		}
	}

	// 4. DNS enrichment (skipped when offline).
	if !s.offline {
		// 4a. PTR lookup.
		ptr := s.dns.reverseDNS(ip)
		if ptr != "" {
			p := ptr
			info.ReverseDNS = &p

			// 4b. Extract base domain.
			baseDomain, bdErr := publicsuffix.EffectiveTLDPlusOne(ptr)
			if bdErr == nil && baseDomain != "" {
				bd := strings.ToLower(baseDomain)
				info.BaseDomain = &bd

				// 4c. Sender map lookup.
				if entry, ok := s.senders.lookup(bd); ok {
					if entry.Name != "" {
						n := entry.Name
						info.Name = &n
					}

					if entry.Type != "" {
						t := entry.Type
						info.Type = &t
					}
				}
			}
		}
	}

	// 5. Store in cache.
	s.cache.set(ip, info)

	return &info, nil
}
