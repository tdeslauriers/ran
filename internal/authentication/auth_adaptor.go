package authentication

import (
	"database/sql"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/ran/internal/clients"
	"github.com/tdeslauriers/ran/pkg/scopes"
)

// AuthRepository defines the interface for authentication-related data operations.
type AuthRepository interface {

	// RefreshExists checks if a refresh token exists in the database.
	RefreshExists(index string) (bool, error)

	// FindClientById retrieves a client by its id from database.
	FindClientById(id string) (*clients.ClientRecord, error)

	// FindScopes retrieves the scopes associated with a client id and serivce name.
	FindScopes(clientId string, service string) ([]scopes.Scope, error)

	// FindRefreshToken retrieves a refresh token record by its index.
	FindRefreshToken(index string) (*types.S2sRefresh, error)

	// InsertRefreshToken inserts a new refresh token record into the database.
	InsertRefreshToken(token types.S2sRefresh) error

	// UpdateRefreshToken updates an existing refresh token record in the database.
	UpdateRefreshToken(token types.S2sRefresh) error

	// DeleteRefreshById deletes a refresh token record by its db id
	DeleteRefreshById(id string) error

	// DeleteRefreshByIndex deletes a refresh token record by its index
	DeleteRefreshByIndex(index string) error
}

// NewAuthRepository creates a new instance of AuthRepository and returns and underlying concrete implementation.
func NewAuthRepository(sql *sql.DB) AuthRepository {
	return &authRepository{
		sql: sql,
	}
}

var _ AuthRepository = (*authRepository)(nil)

// authRepository is the concrete implementation of AuthRepository interface.
type authRepository struct {
	sql *sql.DB
}

// RefreshExists checks if a refresh token exists in the database.
func (r *authRepository) RefreshExists(index string) (bool, error) {

	qry := `SELECT EXISTS (SELECT 1 FROM refresh WHERE refresh_index = ?)`
	exists, err := data.SelectExists(r.sql, qry, index)
	if err != nil {
		return false, fmt.Errorf("failed to check refresh token existence in db: %v", err)
	}

	return exists, nil
}

// FindClientById retrieves a client by its id from database.
func (r *authRepository) FindClientById(id string) (*clients.ClientRecord, error) {

	qry := `
		SELECT 
			uuid, 
			password, 
			name, 
			owner, 
			created_at, 
			enabled, 
			account_expired, 
			account_locked, 
			slug
		FROM client 
		WHERE uuid = ?`
	c, err := data.SelectOneRecord[clients.ClientRecord](r.sql, qry, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("s2s client with id %s does not exist", id)
		} else {
			return nil, fmt.Errorf("failed to retrieve s2s client id %s: %v", id, err)
		}
	}

	return &c, nil
}

// FindScopes retrieves the scopes associated with a client id and serivce name.
func (r *authRepository) FindScopes(clientId string, service string) ([]scopes.Scope, error) {

	qry := `
		SELECT 
			s.uuid,
			s.service_name,
			s.scope,
			s.name,
			s.description,
			s.created_at,
			s.active,
			slug
		FROM scope s 
			LEFT JOIN client_scope cs ON s.uuid = cs.scope_uuid
		WHERE cs.client_uuid = ?
			AND s.service_name = ?`
	scps, err := data.SelectRecords[scopes.Scope](r.sql, qry, clientId, service)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve scopes for client id %s and service %s: %v", clientId, service, err)
	}

	return scps, nil
}

// FindRefreshToken retrieves a refresh token record by its index.
func (r *authRepository) FindRefreshToken(index string) (*types.S2sRefresh, error) {

	qry := `
		SELECT 
			uuid, 
			refresh_index,
			service_name,
			refresh_token, 
			client_uuid, 
			client_index,
			created_at, 
			revoked 
		FROM refresh
		WHERE refresh_index = ?`
	rt, err := data.SelectOneRecord[types.S2sRefresh](r.sql, qry, index)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("refresh token with index %s does not exist", index)
		} else {
			return nil, fmt.Errorf("failed to retrieve refresh token with index %s: %v", index, err)
		}
	}

	return &rt, nil
}

// InsertRefreshToken inserts a new refresh token record into the database.
func (r *authRepository) InsertRefreshToken(token types.S2sRefresh) error {

	qry := `
		INSERT INTO refresh (
			uuid, 
			refresh_index, 
			service_name, 
			refresh_token, 
			client_uuid, 
			client_index, 
			created_at, 
			revoked
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if err := data.InsertRecord(r.sql, qry, token); err != nil {
		return err
	}

	return nil
}

// UpdateRefreshToken updates an existing refresh token record in the database.
// This impl only updates the revoked status because there would never be a need to update other fields.
func (r *authRepository) UpdateRefreshToken(token types.S2sRefresh) error {

	qry := `
		UPDATE refresh 
		SET 
			 revoked = ?
		WHERE uuid = ?`
	if err := data.UpdateRecord(r.sql, qry, token.Revoked, token.Uuid); err != nil {
		return err
	}

	return nil
}

// DeleteRefreshById deletes a refresh token record by its db id
func (r *authRepository) DeleteRefreshById(id string) error {

	qry := `DELETE FROM refresh WHERE uuid = ?`
	if err := data.DeleteRecord(r.sql, qry, id); err != nil {
		return err
	}

	return nil
}

// DeleteRefreshByIndex deletes a refresh token record by its index
func (r *authRepository) DeleteRefreshByIndex(index string) error {

	qry := `DELETE FROM refresh WHERE refresh_index = ?`
	if err := data.DeleteRecord(r.sql, qry, index); err != nil {
		return err
	}

	return nil
}
