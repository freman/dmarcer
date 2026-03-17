// Package dmarcer provides embedded static assets for the dmarcer binary.
// These are accessed by cmd/dmarcer/main.go via this package.
package dmarcer

import (
	"embed"
	"io/fs"
)

//go:embed web/dist
var WebFS embed.FS

//go:embed assets/dbip-country-lite.mmdb
var GeoIPData []byte

//go:embed assets/base_reverse_dns_map.csv
var SenderMapData []byte

// SubWebFS returns an fs.FS rooted at web/dist for serving the embedded UI.
func SubWebFS() (fs.FS, error) {
	return fs.Sub(WebFS, "web/dist")
}

// SafeGeoIPData returns GeoIPData if it looks like a valid MMDB file (>= 100 bytes),
// otherwise nil so the enrichment service gracefully disables country lookups.
func SafeGeoIPData() []byte {
	if len(GeoIPData) < 100 {
		return nil
	}

	return GeoIPData
}
