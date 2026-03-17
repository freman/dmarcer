package enrichment

import (
	"encoding/csv"
	"io"
)

// senderEntry holds the name and type for a known sending organisation.
type senderEntry struct {
	Name string
	Type string
}

// senderMap maps base_reverse_dns domain → {name, type}.
type senderMap struct {
	entries map[string]senderEntry
}

// loadSenderMap reads a CSV (columns: base_reverse_dns, name, type) from r.
// Skips the header row. Returns empty map on empty reader.
func loadSenderMap(r io.Reader) (*senderMap, error) {
	sm := &senderMap{entries: make(map[string]senderEntry)}

	reader := csv.NewReader(r)
	reader.Comment = '#'
	reader.TrimLeadingSpace = true

	// Skip header row.
	if _, err := reader.Read(); err != nil {
		if err == io.EOF {
			return sm, nil
		}

		return nil, err
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		// Expect at least 3 columns: base_reverse_dns, name, type.
		if len(record) < 3 {
			continue
		}

		domain := record[0]
		if domain == "" {
			continue
		}

		sm.entries[domain] = senderEntry{
			Name: record[1],
			Type: record[2],
		}
	}

	return sm, nil
}

// lookup returns the sender entry for a base domain, or zero value if not found.
func (s *senderMap) lookup(baseDomain string) (senderEntry, bool) {
	if s == nil {
		return senderEntry{}, false
	}

	entry, ok := s.entries[baseDomain]

	return entry, ok
}
