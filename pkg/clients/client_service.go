package clients

import (
	"database/sql"
	"fmt"
	"log/slog"
	"ran/internal/util"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Service provides clients service operations
type Service interface {

	// GetClients returns all clients, active or inactive
	GetClients() ([]Client, error)

	// GetClient returns a single client from a slug
	GetClient(slug string) (*Client, error)
}

// NewService creates a new clients service interface abstracting a concrete implementation
func NewService(sql data.SqlRepository) Service {
	return &service{
		sql: sql,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceKey)).
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClients)),
	}
}

var _ Service = (*service)(nil)

// service is a concrete implementation of the Service interface
type service struct {
	sql data.SqlRepository

	logger *slog.Logger
}

// GetClients is a concrete impl of the Service interface method: returns all clients, active or inactive
func (s *service) GetClients() ([]Client, error) {

	var clients []Client
	query := `
			SELECT
				uuid,
				name,
				owner,
				created_at,
				enabled,
				account_expired,
				account_locked,
				slug
			FROM client`
	err := s.sql.SelectRecords(query, &clients)
	if err != nil {
		return nil, fmt.Errorf("failed to get clients from db: %v", err)
	}

	return clients, nil
}

// GetClient is a concrete impl of the Service interface method: returns a single client from a slug
func (s *service) GetClient(slug string) (*Client, error) {

	// validate input
	if slug == "" {
		return nil, fmt.Errorf("service client slug is required")
	}

	if !validate.IsValidUuid(slug) {
		return nil, fmt.Errorf("invalid or not well formatted service client slug")
	}

	var client Client
	query := `
			SELECT
				uuid,
				name,
				owner,
				created_at,
				enabled,
				account_expired,
				account_locked,
				slug
			FROM client
			WHERE slug = ?`
	if err := s.sql.SelectRecord(query, &client, slug); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("service client not found for slug: %s", slug)
		}
		return nil, fmt.Errorf("failed to get service client from db: %v", err)
	}

	return &client, nil
}
