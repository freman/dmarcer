package parser

import (
	"bytes"
	"errors"
	"io"
	"strings"

	gomail "github.com/emersion/go-message/mail"
)

// ExtractEmailAttachments parses a raw RFC 822 email and returns the raw bytes
// of any non-text MIME parts (i.e. attachments). These are the candidates that
// may contain embedded DMARC aggregate or SMTP TLS reports.
func ExtractEmailAttachments(data []byte) [][]byte {
	mr, err := gomail.CreateReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}

	var out [][]byte

	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			break
		}

		ct := strings.ToLower(part.Header.Get("Content-Type"))
		// Skip text/plain, text/html, multipart/*, message/feedback-report, message/rfc822.
		if strings.HasPrefix(ct, "text/") ||
			strings.HasPrefix(ct, "multipart/") ||
			strings.HasPrefix(ct, "message/") ||
			ct == "" {
			continue
		}

		body, err := io.ReadAll(part.Body)
		if err != nil || len(body) == 0 {
			continue
		}

		out = append(out, body)
	}

	return out
}
