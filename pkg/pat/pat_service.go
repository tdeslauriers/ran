package pat

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	exo "github.com/tdeslauriers/carapace/pkg/pat"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/ran/internal/util"
	"github.com/tdeslauriers/ran/pkg/clients"
)

// Service is an interface for personal access token services
type Service interface {

	// GeneratePat generates a new personal access token (PAT) for a given client slug
	GeneratePat(slug string) (*Pat, error)
}

// NewService creates a new personal access token (PAT) service interface abstracting a concrete implementation
func NewService(sql data.SqlRepository, p exo.PatTokener) Service {
	return &service{
		sql: sql,
		pat: p,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceKey)).
			With(slog.String(util.PackageKey, util.PackagePAT)).
			With(slog.String(util.ComponentKey, util.ComponentPatService)),
	}
}

var _ Service = (*service)(nil)

// service is a concrete implementation of the Service interface
type service struct {
	sql data.SqlRepository
	pat exo.PatTokener

	logger *slog.Logger
}

// GeneratePat is the concrete implentation of the Service interface method which
// generates a new personal access token (PAT) for a given client slug
func (s *service) GeneratePat(slug string) (*Pat, error) {

	// validate the slug is a valid uuid
	// redundant validation, but good practice
	if !validate.IsValidUuid(slug) {
		return nil, fmt.Errorf("invalid client slug format")
	}

	// lookup the client uuid for xref record creation
	qry := `
		SELECT
			uuid,
			name,
			owner,
			created_at,
			enabled,
			account_expired,
			account_locked,
			slug
		FROM client WHERE slug = ?
			AND enabled = true
			AND account_expired = false
			AND account_locked = false`
	var client clients.Client
	if err := s.sql.SelectRecord(qry, &client, slug); err != nil {
		if err == sql.ErrNoRows {
			// check if client exists but disabled
			disabled, err := s.sql.SelectExists(clientDisabledQry, slug)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve client record for slug %s: %v", slug, err)
			}
			if disabled {
				return nil, fmt.Errorf("client (slug '%s') is disabled", slug)
			}

			// check if client exists but locked
			locked, err := s.sql.SelectExists(clientAccountLockedQry, slug)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve client record for slug %s: %v", slug, err)
			}
			if locked {
				return nil, fmt.Errorf("client (slug '%s') is locked", slug)
			}

			// check if client exists but expired
			expired, err := s.sql.SelectExists(clientAccountExpiredQry, slug)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve client record for slug %s: %v", slug, err)
			}
			if expired {
				return nil, fmt.Errorf("client (slug '%s') account has expired", slug)
			}

			return nil, fmt.Errorf("client (slug '%s') not found", slug)
		} else {
			return nil, fmt.Errorf("failed to retrieve client record for slug %s: %v", slug, err)
		}
	}

	// generate a new pat uuid
	patId, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate pat uuid: %v", err)
	}

	// generate a new pat token (64 byte random byte slice -> base64 url encoded)
	raw, token, err := s.pat.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate pat token: %v", err)
	}

	// create lookup index from the raw token to persist in the db
	index, err := s.pat.ObtainIndex(raw)

	// persist the pat record
	record := PatRecord{
		Id:        patId.String(),
		PatIndex:  index,
		CreatedAt: data.CustomTime{Time: time.Now().UTC()},
		Active:    true,
		Revoked:   false,
		Expired:   false,
	}
	qry = `
		INSERT INTO pat (
			uuid,
			pat_index,
			created_at,
			active,
			revoked,
			expired
		) VALUES (?, ?, ?, ?, ?, ?)`
	if err := s.sql.InsertRecord(qry, record); err != nil {
		return nil, fmt.Errorf("failed to persist pat record: %v", err)
	}

	// persist the xref record
	xref := PatClientXref{
		Id:        0, // autoincrement
		PatID:     patId.String(),
		ClientID:  client.Id,
		CreatedAt: data.CustomTime{Time: time.Now().UTC()},
	}
	qry = `
		INSERT INTO pat_client (
			id,
			pat_uuid,
			client_uuid,
			created_at
		) VALUES (?, ?, ?, ?)`
	if err := s.sql.InsertRecord(qry, xref); err != nil {
		return nil, fmt.Errorf("failed to persist pat client xref record: %v", err)
	}

	// return the pat model (with token)
	return &Pat{
		Client:    client.Name,
		Token:     token,
		CreatedAt: record.CreatedAt.Format(time.RFC3339),
		Active:    record.Active,
		Revoked:   record.Revoked,
		Expired:   record.Expired,
	}, nil
}
