package ingest

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/freman/dmarcer/internal/config"
	"github.com/freman/dmarcer/internal/models"
)

// imapClient wraps an imapclient.Client with server-specific metadata.
type imapClient struct {
	*imapclient.Client
	delim string // hierarchy separator, e.g. "." or "/"
}

// IMAPIngester polls or watches an IMAP mailbox for DMARC reports.
type IMAPIngester struct {
	cfg      *config.Config
	pipeline *Pipeline
	logger   *slog.Logger
}

// NewIMAPIngester constructs an IMAPIngester.
func NewIMAPIngester(cfg *config.Config, pipeline *Pipeline, logger *slog.Logger) *IMAPIngester {
	return &IMAPIngester{
		cfg:      cfg,
		pipeline: pipeline,
		logger:   logger,
	}
}

// Run starts the ingestion loop. Blocks until ctx is cancelled.
func (i *IMAPIngester) Run(ctx context.Context) error {
	if i.cfg.IMAPWatch {
		return i.runWatch(ctx)
	}

	return i.runPoll(ctx)
}

// ---------------------------------------------------------------------------
// Poll mode
// ---------------------------------------------------------------------------

func (i *IMAPIngester) runPoll(ctx context.Context) error {
	pollInterval := i.cfg.IMAPPollInterval
	if pollInterval <= 0 {
		pollInterval = 5 * time.Minute
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		client, err := i.connectWithRetry(ctx)
		if err != nil {
			return err
		}

		// Inner loop: keep the connection alive across polls.
		for {
			if ctx.Err() != nil {
				client.Close()
				return ctx.Err()
			}

			n, batchErr := i.processBatch(ctx, client)
			if batchErr != nil {
				i.logger.Error("imap: processBatch error", slog.Any("error", batchErr))
				client.Close()

				break // reconnect
			}

			if n > 0 {
				i.logger.Info("imap: batch complete", slog.Int("messages", n))
			}

			select {
			case <-ctx.Done():
				client.Close()
				return ctx.Err()
			case <-time.After(pollInterval):
			}
		}

		// Brief pause before reconnect.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// ---------------------------------------------------------------------------
// Watch (IDLE) mode
// ---------------------------------------------------------------------------

func (i *IMAPIngester) runWatch(ctx context.Context) error {
	idleTimeout := i.cfg.IMAPTimeout
	if idleTimeout <= 0 {
		idleTimeout = 28 * time.Minute
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		client, err := i.connectWithRetry(ctx)
		if err != nil {
			return err
		}

		watchErr := i.watchLoop(ctx, client, idleTimeout)
		client.Close()

		if ctx.Err() != nil {
			return ctx.Err()
		}

		if watchErr != nil {
			i.logger.Error("imap: watch loop ended", slog.Any("error", watchErr))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (i *IMAPIngester) watchLoop(ctx context.Context, client *imapClient, idleTimeout time.Duration) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Always process any waiting messages before entering IDLE.
		if _, err := i.processBatch(ctx, client); err != nil {
			return fmt.Errorf("processBatch: %w", err)
		}

		idleCmd, err := client.Idle()
		if err != nil {
			return fmt.Errorf("IDLE: %w", err)
		}

		idleDone := make(chan error, 1)

		go func() {
			idleDone <- idleCmd.Wait()
		}()

		select {
		case <-ctx.Done():
			_ = idleCmd.Close()

			<-idleDone

			return ctx.Err()

		case <-time.After(idleTimeout):
			// Timeout: exit IDLE, check mailbox, re-enter.
			if err := idleCmd.Close(); err != nil {
				return fmt.Errorf("IDLE close on timeout: %w", err)
			}

			<-idleDone

		case err := <-idleDone:
			// Server sent an unilateral response (EXISTS, etc.).
			if err != nil {
				return fmt.Errorf("IDLE wait: %w", err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Connect helpers
// ---------------------------------------------------------------------------

func (i *IMAPIngester) connectWithRetry(ctx context.Context) (*imapClient, error) {
	backoff := 5 * time.Second

	const maxBackoff = 5 * time.Minute

	maxRetries := i.cfg.IMAPMaxRetries
	if maxRetries <= 0 {
		maxRetries = 4
	}

	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		ic, err := i.connect()
		if err == nil {
			return ic, nil
		}

		lastErr = err
		i.logger.Error("imap: connect failed",
			slog.Int("attempt", attempt+1),
			slog.Int("max", maxRetries),
			slog.Any("error", err),
		)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}

		backoff = min(backoff*2, maxBackoff)
	}

	return nil, fmt.Errorf("imap: connect failed after %d attempts: %w", maxRetries, lastErr)
}

func (i *IMAPIngester) connect() (*imapClient, error) {
	addr := fmt.Sprintf("%s:%d", i.cfg.IMAPHost, i.cfg.IMAPPort)

	opts := &imapclient.Options{}
	if i.cfg.IMAPTLS {
		opts.TLSConfig = &tls.Config{
			InsecureSkipVerify: i.cfg.IMAPTLSSkipVerify, //nolint:gosec
			ServerName:         i.cfg.IMAPHost,
		}
	}

	var (
		client *imapclient.Client
		err    error
	)
	if i.cfg.IMAPTLS {
		client, err = imapclient.DialTLS(addr, opts)
	} else {
		client, err = imapclient.DialInsecure(addr, opts)
	}

	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	if err := client.Login(i.cfg.IMAPUser, i.cfg.IMAPPassword).Wait(); err != nil {
		client.Close()
		return nil, fmt.Errorf("login: %w", err)
	}

	delim := fetchDelimiter(client, i.logger)

	if _, err := client.Select(i.cfg.IMAPInbox, nil).Wait(); err != nil {
		client.Close()
		return nil, fmt.Errorf("select %q: %w", i.cfg.IMAPInbox, err)
	}

	return &imapClient{Client: client, delim: delim}, nil
}

// fetchDelimiter issues a LIST "" "" to discover the server's hierarchy separator.
// Falls back to "." on any error.
func fetchDelimiter(client *imapclient.Client, logger *slog.Logger) string {
	data, err := client.List("", "", nil).Collect()
	if err != nil || len(data) == 0 || data[0].Delim == 0 {
		if err != nil {
			logger.Warn("imap: could not fetch hierarchy delimiter, defaulting to '.'", slog.Any("error", err))
		}

		return "."
	}

	return string(data[0].Delim)
}

// ---------------------------------------------------------------------------
// Batch processing
// ---------------------------------------------------------------------------

// processBatch fetches up to cfg.IMAPBatchSize unseen messages, processes them,
// and then moves or deletes as configured. Returns the count of messages handled.
func (i *IMAPIngester) processBatch(ctx context.Context, client *imapClient) (int, error) {
	batchSize := i.cfg.IMAPBatchSize
	if batchSize <= 0 {
		batchSize = 10
	}

	// Search for all messages not yet moved out of the inbox (seen or unseen),
	// excluding messages already flagged for deletion.
	criteria := &imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagDeleted},
	}

	searchData, err := client.UIDSearch(criteria, nil).Wait()
	if err != nil {
		return 0, fmt.Errorf("UID SEARCH: %w", err)
	}

	// searchData.All is imap.NumSet; for a UID search it is imap.UIDSet.
	var allUIDs []imap.UID

	if uidSet, ok := searchData.All.(imap.UIDSet); ok {
		for _, r := range uidSet {
			for uid := r.Start; uid <= r.Stop; uid++ {
				allUIDs = append(allUIDs, uid)
			}
		}
	}

	if len(allUIDs) == 0 {
		return 0, nil
	}

	// Limit to batch size.
	if len(allUIDs) > batchSize {
		allUIDs = allUIDs[:batchSize]
	}

	// Build a UID set for fetching.
	uidSet := imap.UIDSetNum(allUIDs...)

	// Fetch full message bodies.
	bodySectionItem := &imap.FetchItemBodySection{}
	fetchCmd := client.Fetch(uidSet, &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{bodySectionItem},
	})

	type pendingMsg struct {
		uid  imap.UID
		data []byte
	}

	var pending []pendingMsg

	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}

		buf, collectErr := msg.Collect()
		if collectErr != nil {
			i.logger.Error("imap: collect message data failed", slog.Any("error", collectErr))
			continue
		}

		if buf.UID != 0 && len(buf.BodySection) > 0 {
			pending = append(pending, pendingMsg{uid: buf.UID, data: buf.BodySection[0].Bytes})
		}
	}

	if err := fetchCmd.Close(); err != nil {
		return 0, fmt.Errorf("fetch close: %w", err)
	}

	// Process each fetched message.
	var processed int

	for _, m := range pending {
		if ctx.Err() != nil {
			return processed, ctx.Err()
		}

		filename := fmt.Sprintf("imap-uid-%d", m.uid)
		result := i.pipeline.Process(m.data, "imap", filename)

		i.logger.Info("imap: message ingested",
			slog.Any("uid", m.uid),
			slog.String("status", string(result.Status)),
			slog.String("type", string(result.Type)),
		)

		singleUID := imap.UIDSetNum(m.uid)

		if i.cfg.IMAPDelete {
			i.flagDeleted(client, singleUID, m.uid)
			i.expunge(client)
		} else {
			folder := i.archiveFolder(result, client.delim)
			i.ensureFolder(client, folder)

			if _, err := client.Copy(singleUID, folder).Wait(); err != nil {
				i.logger.Error("imap: copy to archive failed",
					slog.String("folder", folder),
					slog.Any("uid", m.uid),
					slog.Any("error", err),
				)
			} else {
				i.flagDeleted(client, singleUID, m.uid)
				i.expunge(client)
			}
		}

		processed++
	}

	return processed, nil
}

func (i *IMAPIngester) flagDeleted(client *imapClient, uidSet imap.UIDSet, uid imap.UID) {
	if err := client.Store(uidSet, &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		i.logger.Error("imap: mark \\Deleted failed", slog.Any("uid", uid), slog.Any("error", err))
	}
}

func (i *IMAPIngester) expunge(client *imapClient) {
	if err := client.Expunge().Close(); err != nil {
		i.logger.Error("imap: expunge failed", slog.Any("error", err))
	}
}

// archiveFolder returns the destination mailbox path based on report type,
// using the server's hierarchy delimiter.
func (i *IMAPIngester) archiveFolder(result models.IngestResult, delim string) string {
	base := i.cfg.IMAPArchiveFolder

	switch result.Type {
	case models.ReportTypeAggregate:
		return base + delim + "Aggregate"
	case models.ReportTypeForensic:
		return base + delim + "Forensic"
	case models.ReportTypeSMTPTLS:
		return base + delim + "SMTP-TLS"
	default:
		return base + delim + "Invalid"
	}
}

// ensureFolder issues a CREATE command and silently ignores "already exists" errors.
func (i *IMAPIngester) ensureFolder(client *imapClient, folder string) {
	if err := client.Create(folder, nil).Wait(); err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "already exist") ||
			strings.Contains(lower, "alreadyexists") ||
			strings.Contains(lower, "[alreadyexists]") {
			return
		}

		i.logger.Warn("imap: create folder failed",
			slog.String("folder", folder),
			slog.Any("error", err),
		)
	}
}

