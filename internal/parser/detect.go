// Package parser provides detection and decompression of DMARC-adjacent report files.
package parser

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
)

// ContentType identifies the high-level format of a report's raw content.
type ContentType int

const (
	ContentXML     ContentType = iota
	ContentJSON    ContentType = iota
	ContentEmail   ContentType = iota // RFC 822
	ContentUnknown ContentType = iota
)

// DetectResult contains the decompressed/decoded payload and a content-type hint.
type DetectResult struct {
	Data        []byte
	ContentType ContentType
}

// magic byte sequences
var (
	magicZIP  = []byte{0x50, 0x4b, 0x03, 0x04}
	magicGZIP = []byte{0x1f, 0x8b}
)

// Detect takes raw bytes and returns decompressed content with a content-type hint.
//
// Detection order:
//  1. ZIP  (magic \x50\x4b\x03\x04) → decompress first entry, then classify inner bytes
//  2. GZIP (magic \x1f\x8b)         → decompress fully, then classify inner bytes
//  3. XML  (starts with '<')
//  4. JSON (starts with '{')
//  5. Base64                         → strip whitespace, decode, re-detect recursively
//  6. Email fallback
func Detect(data []byte) (*DetectResult, error) {
	return detect(data, false)
}

// detect is the internal recursive implementation. reDetect prevents infinite recursion
// after a base64 decode step.
func detect(data []byte, reDetect bool) (*DetectResult, error) {
	if len(data) == 0 {
		return &DetectResult{Data: data, ContentType: ContentUnknown}, nil
	}

	// 1. ZIP
	if bytes.HasPrefix(data, magicZIP) {
		inner, err := unzip(data)
		if err != nil {
			return nil, fmt.Errorf("detect: unzip: %w", err)
		}

		return detect(inner, false)
	}

	// 2. GZIP
	if bytes.HasPrefix(data, magicGZIP) {
		inner, err := ungzip(data)
		if err != nil {
			return nil, fmt.Errorf("detect: ungzip: %w", err)
		}

		return detect(inner, false)
	}

	// classify uncompressed content
	trimmed := bytes.TrimLeftFunc(data, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})

	// 3. XML
	if len(trimmed) > 0 && trimmed[0] == '<' {
		return &DetectResult{Data: data, ContentType: ContentXML}, nil
	}

	// 4. JSON
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return &DetectResult{Data: data, ContentType: ContentJSON}, nil
	}

	// 5. Base64 (only on first pass – prevents infinite recursion)
	if !reDetect {
		// strip all whitespace before attempting decode
		stripped := bytes.Map(func(r rune) rune {
			switch r {
			case ' ', '\t', '\r', '\n':
				return -1
			default:
				return r
			}
		}, data)

		decoded, err := base64.StdEncoding.DecodeString(string(stripped))
		if err == nil && len(decoded) > 0 {
			inner, err := detect(decoded, true)
			if err == nil {
				return inner, nil
			}
		}
		// also try RawStdEncoding (no padding)
		decoded, err = base64.RawStdEncoding.DecodeString(string(stripped))
		if err == nil && len(decoded) > 0 {
			inner, err := detect(decoded, true)
			if err == nil {
				return inner, nil
			}
		}
	}

	// 6. Email fallback
	return &DetectResult{Data: data, ContentType: ContentEmail}, nil
}

// unzip reads a ZIP archive from p and returns the contents of the first entry.
func unzip(p []byte) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(p), int64(len(p)))
	if err != nil {
		return nil, err
	}

	if len(r.File) == 0 {
		return nil, fmt.Errorf("zip archive contains no entries")
	}

	f := r.File[0]

	rc, err := f.Open()
	if err != nil {
		return nil, err
	}

	defer rc.Close()

	return io.ReadAll(rc)
}

// ungzip decompresses a GZIP stream from p and returns the full payload.
func ungzip(p []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(p))
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	return io.ReadAll(gr)
}
