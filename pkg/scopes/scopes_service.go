package scopes

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/ran/internal/util"
)

// Service provides scopes service operations
type Service interface {

	// GetScopes returns all scopes, active or inactive
	GetScopes() ([]types.Scope, error)

	// GetActiveScopes returns all active scopes
	GetActiveScopes() ([]types.Scope, error)

	// GetScope returns a single scope by slug uuid
	GetScope(slug string) (*types.Scope, error)

	// AddScope adds a new scope record
	AddScope(scope *types.Scope) (*types.Scope, error)

	// UpdateScope updates a scope record
	UpdateScope(scope *types.Scope) error
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
			FROM scope
			ORDER BY service_name, name ASC`
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
		return nil, err
	}

	return scopes, nil
}

// GetScope is a concrete impl of the Service interface method: returns a single scope by slug uuid
func (s *service) GetScope(slug string) (*types.Scope, error) {

	// validate slug is well formed uuid
	if !validate.IsValidUuid(slug) {
		return nil, errors.New(ErrInvalidSlug)
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
			return nil, fmt.Errorf("no scope found for slug %s", slug)
		}
		return nil, err
	}

	return &scope, nil
}

// AddScope is a concrete impl of the Service interface method: adds a new scope record
func (s *service) AddScope(scope *types.Scope) (*types.Scope, error) {

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
	query := `INSERT INTO 
				scope (
					uuid, 
					service_name, 
					scope, 
					name, 
					description, 
					created_at,
					active,
					slug
				) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if err := s.sql.InsertRecord(query, *scope); err != nil {
		return nil, fmt.Errorf("failed to insert new scope record into db: %v", err)
	}

	return scope, nil
}

// UpdateScope is a concrete impl of the Service interface method: updates a scope record
func (s *service) UpdateScope(scope *types.Scope) error {

	// vadiate scope is not nil and is well formed
	if scope == nil {
		return errors.New("scope is nil")
	}

	// redundant check, but good pratice
	if err := scope.ValidateCmd(); err != nil {
		return err
	}

	// update scope record in db
	query := `
			UPDATE 
				scope SET
					service_name = ?,
					scope = ?,
					name = ?,
					description = ?,
					active = ?
			WHERE slug = ?`
	if err := s.sql.UpdateRecord(query, scope.ServiceName, scope.Scope, scope.Name, scope.Description, scope.Active, scope.Slug); err != nil {
		return err
	}

	return nil
}
