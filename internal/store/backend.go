package store

import (
	"github.com/freman/dmarcer/internal/models"
)

// Backend wraps DB so it satisfies models.Backend.
// It honours the SaveAggregate/SaveForensic/SaveSMTPTLS flags from the caller.
type Backend struct {
	db            *DB
	saveAggregate bool
	saveForensic  bool
	saveSMTPTLS   bool
}

// NewBackend wraps a DB as a models.Backend.
func NewBackend(db *DB, saveAggregate, saveForensic, saveSMTPTLS bool) *Backend {
	return &Backend{
		db:            db,
		saveAggregate: saveAggregate,
		saveForensic:  saveForensic,
		saveSMTPTLS:   saveSMTPTLS,
	}
}

func (b *Backend) Name() string { return "sqlite" }

func (b *Backend) WriteAggregate(report *models.AggregateReport, record *models.AggregateRecord) error {
	if !b.saveAggregate {
		return nil
	}

	return b.db.SaveAggregateRecord(report, record)
}

func (b *Backend) WriteForensic(report *models.ForensicReport) error {
	if !b.saveForensic {
		return nil
	}

	_, err := b.db.SaveForensic(report)

	return err
}

func (b *Backend) WriteSMTPTLS(report *models.SMTPTLSReport, policy *models.SMTPTLSPolicy) error {
	if !b.saveSMTPTLS {
		return nil
	}

	return b.db.SaveSMTPTLSPolicy(report, policy)
}

func (b *Backend) Close() error { return nil }
