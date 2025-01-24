package scopes

import (
	"fmt"
	"log/slog"
	"ran/internal/util"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// Service provides scopes service operations
type Service interface {

	// GetScopes returns all scopes, active or inactive
	GetScopes() ([]types.Scope, error)

	// GetActiveScopes returns all active scopes
	GetActiveScopes() ([]types.Scope, error)
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
