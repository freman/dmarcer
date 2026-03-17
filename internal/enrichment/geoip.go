package enrichment

import (
	"net"

	"github.com/oschwald/maxminddb-golang"
)

// mmdbRecord is the struct used to decode country records from a MaxMind / DB-IP MMDB file.
type mmdbRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// geoIPDB wraps a maxminddb reader.
type geoIPDB struct {
	reader *maxminddb.Reader
}

// openGeoIP opens an MMDB file from disk.
// Returns nil, nil if path is empty (GeoIP disabled).
func openGeoIP(path string) (*geoIPDB, error) {
	if path == "" {
		return nil, nil
	}

	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}

	return &geoIPDB{reader: reader}, nil
}

// openGeoIPFromBytes opens an MMDB database from in-memory bytes.
// Returns nil, nil if data is nil or empty.
func openGeoIPFromBytes(data []byte) (*geoIPDB, error) {
	if len(data) == 0 {
		return nil, nil
	}

	reader, err := maxminddb.FromBytes(data)
	if err != nil {
		return nil, err
	}

	return &geoIPDB{reader: reader}, nil
}

// country returns the ISO 3166-1 alpha-2 country code for an IP, or "" if not found.
func (g *geoIPDB) country(ip string) string {
	if g == nil || g.reader == nil {
		return ""
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	var record mmdbRecord
	if err := g.reader.Lookup(parsed, &record); err != nil {
		return ""
	}

	return record.Country.ISOCode
}
