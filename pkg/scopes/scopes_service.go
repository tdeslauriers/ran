package scopes

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"ran/internal/util"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Service provides scopes service operations
type Service interface {

	// GetScopes returns all scopes, active or inactive
	GetScopes() ([]types.Scope, error)

	// GetActiveScopes returns all active scopes
	GetActiveScopes() ([]types.Scope, error)

	// GetScope returns a single scope by slug uuid
	GetScope(slug string) (*types.Scope, error)
}

// NewSerivce creates a new scopes service interface abstracting a concrete implementation
func NewSerivce(sql data.SqlRepository) Service {
	return &service{
		sql: sql,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceKey)).
			With(slog.String(util.PackageKey, util.PackageScopes)).
			With(slog.String(util.ComponentKey, util.ComponentScopes)),
	}
}

var _ Service = (*service)(nil)

// service is a concrete implementation of the Service interface
type service struct {
	sql data.SqlRepository

	logger *slog.Logger
}

// GetScopes is a concrete impl of the Service interface method: returns all scopes, active or inactive
func (s *service) GetScopes() ([]types.Scope, error) {

	var scopes []types.Scope
	query := `
			SELECT 
				uuid, 
				service_name, 
				scope, 
				name, 
				description, 
				created_at, 
				active,
				slug
			FROM scope`
	err := s.sql.SelectRecords(query, &scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to get scopes records from db: %v", err)
	}

	return scopes, nil
}

// GetActiveScopes is a concrete impl of the Service interface method: returns all active scopes
func (a *service) GetActiveScopes() ([]types.Scope, error) {

	var scopes []types.Scope
	query := `
			SELECT 
				uuid, 
				service_name, 
				scope, 
				name, 
				description, 
				created_at, 
				active,
				slug
			FROM scope 
			WHERE active = true`
	err := a.sql.SelectRecords(query, &scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to get scopes records from db: %v", err)
	}

	return scopes, nil
}

// GetScope is a concrete impl of the Service interface method: returns a single scope by slug uuid
func (s *service) GetScope(slug string) (*types.Scope, error) {

	// validate slug is well formed uuid
	if !validate.IsValidUuid(slug) {
		errMsg := fmt.Sprintf("%s: '%s' not well-formed uuid", ErrInvalidSlug, slug)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	// get scope record from db
	var scope types.Scope
	query := `SELECT
				uuid,
				service_name,
				scope,
				name,
				description,
				created_at,
				active,
				slug
			FROM scope
			WHERE slug = ?`
	if err := s.sql.SelectRecord(query, &scope, slug); err != nil {
		if err == sql.ErrNoRows {
			errMsg := fmt.Sprintf("no scope found for slug %s", slug)
			s.logger.Error(errMsg)
			return nil, errors.New(errMsg)
		}
		errMsg := fmt.Sprintf("failed to retrieve scope '%s' record from db: %v", slug, err)
		s.logger.Error(errMsg)
		return nil, errors.New(errMsg)
	}

	return &scope, nil
}
