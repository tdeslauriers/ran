package scopes

import (
	"database/sql"
	"errors"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/ran/pkg/api/scopes"
)

// ScopesRepository defines the interface for scopes-related data operations.
type ScopesRepository interface {

	// FindScopes retrieves all scopes from the database.
	FindScopes() ([]scopes.Scope, error)

	// FindActiveScopes retrieves all active scopes from the database.
	FindActiveScopes() ([]scopes.Scope, error)

	// FindScopeBySlug retrieves a scope by its slug uuid from the database.
	FindScopeBySlug(slug string) (*scopes.Scope, error)

	// InsertScope inserts a new scope record into the database.
	InsertScope(s *scopes.Scope) error

	// UpdateScope updates a scope record in the database.
	UpdateScope(s *scopes.Scope) error
}

// NewScopesRepository creates a new instance of ScopesRepository and returns and underlying concrete implementation.
func NewScopesRepository(sql *sql.DB) ScopesRepository {
	return &scopesRepository{
		sql: sql,
	}
}

var _ ScopesRepository = (*scopesRepository)(nil)

// scopesRepository is the concrete implementation of ScopesRepository interface.
type scopesRepository struct {
	sql *sql.DB
}

// FindScopes retrieves all scopes from the database.
func (r *scopesRepository) FindScopes() ([]scopes.Scope, error) {

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
	scopes, err := data.SelectRecords[scopes.Scope](r.sql, query)
	if err != nil {
		return nil, errors.New("failed to retrieve scopes from database")

	}

	return scopes, nil
}

// FindActiveScopes retrieves all active scopes from the database.
func (r *scopesRepository) FindActiveScopes() ([]scopes.Scope, error) {

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
	scopes, err := data.SelectRecords[scopes.Scope](r.sql, query)
	if err != nil {
		return nil, errors.New("failed to retrieve active scopes from database")

	}

	return scopes, nil
}

// FindScopeBySlug retrieves a scope by its slug uuid from the database.
func (r *scopesRepository) FindScopeBySlug(slug string) (*scopes.Scope, error) {

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
	scope, err := data.SelectOneRecord[scopes.Scope](r.sql, query, slug)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("scope for provided slug not found")
		}
		return nil, errors.New("failed to retrieve scope from database")
	}

	return &scope, nil
}

// InsertScope inserts a new scope record into the database.
func (r *scopesRepository) InsertScope(s *scopes.Scope) error {

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
	if err := data.InsertRecord[scopes.Scope](r.sql, query, *s); err != nil {
		return errors.New("failed to insert new scope record into db")
	}

	return nil
}

// UpdateScope updates a scope record in the database.
func (r *scopesRepository) UpdateScope(s *scopes.Scope) error {

	query := `
			UPDATE 
				scope SET
					service_name = ?,
					scope = ?,
					name = ?,
					description = ?,
					active = ?
			WHERE slug = ?`
	if err := data.UpdateRecord(
		r.sql,
		query,
		s.ServiceName,
		s.Scope,
		s.Name,
		s.Description,
		s.Active,
		s.Slug, // WHERE condition
	); err != nil {
		return errors.New("failed to update scope record in db")
	}

	return nil
}
