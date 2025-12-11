package scopes

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/ran/internal/definitions"
	"github.com/tdeslauriers/ran/pkg/api/scopes"
)

// Service provides scopes service operations
type Service interface {

	// GetScopes returns all scopes, active or inactive
	GetScopes() ([]scopes.Scope, error)

	// GetActiveScopes returns all active scopes
	GetActiveScopes() ([]scopes.Scope, error)

	// GetScope returns a single scope by slug uuid
	GetScope(slug string) (*scopes.Scope, error)

	// AddScope adds a new scope record
	AddScope(scope *scopes.Scope) (*scopes.Scope, error)

	// UpdateScope updates a scope record
	UpdateScope(scope *scopes.Scope) error
}

// NewSerivce creates a new scopes service interface abstracting a concrete implementation
func NewSerivce(sql *sql.DB) Service {
	return &service{
		sql: NewScopesRepository(sql),

		logger: slog.Default().
			With(slog.String(definitions.PackageKey, definitions.PackageScopes)).
			With(slog.String(definitions.ComponentKey, definitions.ComponentScopes)),
	}
}

var _ Service = (*service)(nil)

// service is a concrete implementation of the Service interface
type service struct {
	sql ScopesRepository

	logger *slog.Logger
}

// GetScopes is a concrete impl of the Service interface method: returns all scopes, active or inactive
func (s *service) GetScopes() ([]scopes.Scope, error) {
	return s.sql.FindScopes()
}

// GetActiveScopes is a concrete impl of the Service interface method: returns all active scopes
func (a *service) GetActiveScopes() ([]scopes.Scope, error) {
	return a.sql.FindActiveScopes()
}

// GetScope is a concrete impl of the Service interface method: returns a single scope by slug uuid
func (s *service) GetScope(slug string) (*scopes.Scope, error) {

	// validate slug is well formed uuid
	// redundant check (should be checked in handler), but good pratice
	if !validate.IsValidUuid(slug) {
		return nil, errors.New("invalid slug")
	}

	return s.sql.FindScopeBySlug(slug)
}

// AddScope is a concrete impl of the Service interface method: adds a new scope record
func (s *service) AddScope(scope *scopes.Scope) (*scopes.Scope, error) {

	// validate scope is not nil and is well formed
	if scope == nil {
		return nil, errors.New("scope is nil")
	}

	// redundant check (should be checked in handler), but good pratice
	if err := scope.ValidateCmd(); err != nil {
		return nil, err
	}

	// generate uuid for scope
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate uuid for scope id: %v", err)
	}
	scope.Uuid = id.String()

	// generate slug for scope
	slug, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate slug for scope: %v", err)
	}
	scope.Slug = slug.String()

	// set created_at timestamp
	now := time.Now().UTC()
	scope.CreatedAt = now.Format("2006-01-02 15:04:05")

	// add scope record to db
	if err := s.sql.InsertScope(scope); err != nil {
		return nil, err
	}

	return scope, nil
}

// UpdateScope is a concrete impl of the Service interface method: updates a scope record
func (s *service) UpdateScope(scope *scopes.Scope) error {

	// vadiate scope is not nil and is well formed
	if scope == nil {
		return errors.New("scope is nil")
	}

	// redundant check, but good pratice
	if err := scope.ValidateCmd(); err != nil {
		return err
	}

	// update scope record in db
	return s.sql.UpdateScope(scope)
}
