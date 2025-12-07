package clients

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/ran/pkg/api/clients"
)

// ClientRepository provides client repository/persistance operations
type ClientRepository interface {

	// FindAll gets all client records from the database
	FindAll() ([]ClientAccount, error)

	// FindClientScopes gets a client record by slug from the database
	FindClientScopes(slug string) ([]ClientScope, error)

	// Update takes a client record and updates it in the database
	Update(client *clients.Client) error

	// AddScope assigns a scope to a client in the database via xref table record
	AddScope(clientId string, scopeId string) error

	// RemoveScope disassociates a scope from a client by removing the xref table record
	RemoveScope(clientId, scopeId string) error
}

// NewClientRepository creates a new client repository interface abstracting a concrete implementation
func NewClientRepository(sql *sql.DB) ClientRepository {
	return &mariaClientRepository{
		sql: sql,
	}
}

var _ ClientRepository = (*mariaClientRepository)(nil)

// mariaClientRepository is a concrete implementation of the ClientRepository interface
type mariaClientRepository struct {
	sql *sql.DB
}

// FindAll is a concrete impl of the ClientRepository interface method: gets all client records from the database
func (r *mariaClientRepository) FindAll() ([]ClientAccount, error) {

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
	clients, err := data.SelectRecords[ClientAccount](r.sql, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get clients from db: %v", err)
	}

	return clients, nil
}

// FindClientScopes is a concrete impl of the ClientRepository interface method: gets a
// client record by slug from the database
func (r *mariaClientRepository) FindClientScopes(slug string) ([]ClientScope, error) {

	query := `
			SELECT
				c.uuid AS client_id,
				c.name AS client_name,
				c.owner,
				c.created_at AS client_created_at,
				c.enabled,
				c.account_expired,
				c.account_locked,
				c.slug AS client_slug,
				COALESCE(s.uuid, '') AS scope_id,
				COALESCE(s.service_name, '') AS service_name,
				COALESCE(s.scope, '') AS scope,
				COALESCE(s.name, '') AS scope_name,
				COALESCE(s.description, '') AS description,
				COALESCE(s.created_at, '') AS scope_created_at,
				COALESCE(s.active, FALSE) AS active,
				COALESCE(s.slug, '') AS scope_slug
			FROM client c
				LEFT OUTER JOIN client_scope cs ON c.uuid = cs.client_uuid
				LEFT OUTER JOIN scope s ON cs.scope_uuid = s.uuid
			WHERE c.slug = ?`
	clientScopes, err := data.SelectRecords[ClientScope](r.sql, query, slug)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("service client not found")
		}
		return nil, fmt.Errorf("failed to look up client and scopes in database, %v", err)
	}

	return clientScopes, nil
}

// Update is a concrete impl of the ClientRepository interface method: takes a
// client record and updates it in the database
func (r *mariaClientRepository) Update(client *clients.Client) error {

	// update client record
	query := `
			UPDATE 
				client SET
					name = ?,
					owner = ?,
					enabled = ?,
					account_expired = ?,
					account_locked = ?
			WHERE slug = ?`
	if err := data.UpdateRecord(
		r.sql,
		query,
		client.Name,
		client.Owner,
		client.Enabled,
		client.AccountExpired,
		client.AccountLocked,
		client.Slug,
	); err != nil {

		return err
	}

	return nil
}

// AddScope is a concrete impl of the ClientRepository interface method: assigns a scope to a client in
// the database via xref table record
func (r *mariaClientRepository) AddScope(clientId string, scopeId string) error {

	xref := ClientScopeXref{
		ClientId:  clientId,
		ScopeId:   scopeId,
		CreatedAt: data.CustomTime{Time: time.Now().UTC()},
	}

	query := `
			INSERT INTO client_scope (
				client_uuid, 
				scope_uuid, 
				created_at
			)
			VALUES (?, ?, ?)`
	if err := data.InsertRecord(r.sql, query, xref); err != nil {
		return err
	}

	return nil
}

// RemoveScope is a concrete impl of the ClientRepository interface method: disassociates a scope from a
// client by removing the xref table record
func (r *mariaClientRepository) RemoveScope(clientId, scopeId string) error {

	query := `
			DELETE 
			FROM client_scope
			WHERE client_uuid = ? AND scope_uuid = ?`
	if err := data.DeleteRecord(
		r.sql,
		query,
		clientId,
		scopeId,
	); err != nil {
		return err
	}

	return nil
}
