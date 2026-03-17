// Package enrichment provides IP address enrichment with GeoIP country lookup,
// reverse DNS resolution, base domain extraction, and sender identity mapping.
// The primary entry point is [Service], constructed via [New].
// Callers should use the [Enricher] interface to decouple from the concrete type.
package enrichment

import "github.com/freman/dmarcer/internal/models"

// Enricher enriches a source IP with GeoIP country, reverse DNS, base domain,
// and sender identity. Errors are non-fatal; the returned IPSourceInfo is always
// usable even if some fields could not be populated.
type Enricher interface {
	Enrich(ip string) (*models.IPSourceInfo, error)
}
