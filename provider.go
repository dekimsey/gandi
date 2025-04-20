package gandi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider implements the libdns interfaces for Gandi.
type Provider struct {
	BearerToken string `json:"bearer_token,omitempty"`

	domains map[string]gandiDomain
	mutex   sync.Mutex
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	domain, err := p.getDomain(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("cannot get records, unable to get zone details: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", domain.DomainRecordsHref, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %w", err)
	}

	var gandiRecords []gandiRecord
	_, err = p.doRequest(req, &gandiRecords)
	if err != nil {
		return nil, fmt.Errorf("unable to get zone records from %v: %w", domain.DomainRecordsHref, err)
	}

	var libRecords []libdns.Record
	var merr error
	for _, rec := range gandiRecords {
		for _, val := range rec.RRSetValues {
			// Convert the raw record to a libdns resource record
			rawRR := libdns.RR{
				Type: rec.RRSetType,
				Name: rec.RRSetName,
				TTL:  time.Duration(rec.RRSetTTL) * time.Second,
				Data: val,
			}
			// If possible, parse the raw resource record to a resource-typed struct for returning
			rr, err := rawRR.Parse()
			if err != nil {
				merr = errors.Join(merr, fmt.Errorf("failed to parse RR type=%v, name=%v: %w", rec.RRSetType, rec.RRSetName, err))
			}

			libRecords = append(libRecords, rr)
		}
	}

	return libRecords, merr
}

// AppendRecords adds records to the zone and returns the records that were created.
// Due to technical limitations of the LiveDNS API, it may affect the TTL of similar records
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	domain, err := p.getDomain(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("cannot append records, unable to get zone details: %w", err)
	}

	for _, rec := range records {
		err := p.setRecord(ctx, zone, rec.RR(), domain)
		if err != nil {
			return nil, fmt.Errorf("failed to append record %v: %w", rec.RR().Name, err)
		}
	}

	return records, nil
}

// DeleteRecords deletes records from the zone and returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	domain, err := p.getDomain(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("unable to get zone details: %w", err)
	}

	for _, rec := range records {
		err := p.deleteRecord(ctx, zone, rec.RR(), domain)
		if err != nil {
			return nil, fmt.Errorf("failed to delete record %v: %w", rec.RR().Name, err)
		}
	}

	return records, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones, and returns the recordsthat were updated.
// Due to technical limitations of the LiveDNS API, it may affect the TTL of similar records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	domain, err := p.getDomain(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("cannot set records, unable to get zone details: %w", err)
	}

	for _, rec := range records {
		err := p.setRecord(ctx, zone, rec.RR(), domain)
		if err != nil {
			return nil, fmt.Errorf("failed to set record %v: %w", rec.RR().Name, err)
		}
	}

	return records, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
