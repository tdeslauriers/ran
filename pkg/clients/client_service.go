package clients

import (
	"database/sql"
	"fmt"
	"log/slog"
	"ran/internal/util"
	"strings"
	"sync"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// ClientService provides clients service operations
type ClientService interface {

	// GetClients returns all service clients, active or inactive
	GetClients() ([]Client, error)

	// GetClient returns a single service client (and it's assigned scopes) from a slug
	GetClient(slug string) (*profile.Client, error)

	// UpdateClient updates a service client record (doesn not include password updates/resets)
	UpdateClient(client *Client) error

	UpdateScopes(client *profile.Client, updated []types.Scope) error
}

// NewClientService creates a new clients service interface abstracting a concrete implementation
func NewClientService(sql data.SqlRepository) ClientService {
	return &clientService{
		sql: sql,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceKey)).
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClients)),
	}
}

var _ ClientService = (*clientService)(nil)

// clientService is a concrete implementation of the Service interface
type clientService struct {
	sql data.SqlRepository

	logger *slog.Logger
}

// GetClients is a concrete impl of the Service interface method: returns all clients, active or inactive
func (s *clientService) GetClients() ([]Client, error) {

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
func (s *clientService) GetClient(slug string) (*profile.Client, error) {

	// validate input
	if slug == "" {
		return nil, fmt.Errorf("service client slug is required")
	}

	if !validate.IsValidUuid(slug) {
		return nil, fmt.Errorf("invalid or not well formatted service client slug")
	}

	var clientScope []ClientScope
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
	if err := s.sql.SelectRecords(query, &clientScope, slug); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("service client not found for slug: %s", slug)
		}
		return nil, fmt.Errorf("failed to get service client from db: %v", err)
	}

	// build client from db records slice
	client := profile.Client{
		Id:             clientScope[0].ClientId,
		Name:           clientScope[0].ClientName,
		Owner:          clientScope[0].Owner,
		CreatedAt:      clientScope[0].ClientCreatedAt,
		Enabled:        clientScope[0].Enabled,
		AccountExpired: clientScope[0].AccountExpired,
		AccountLocked:  clientScope[0].AccountLocked,
		Slug:           clientScope[0].CLientSlug,
	}

	// build scopes from db records slice
	for _, cs := range clientScope {
		// emtpy scope id means no scope(s) assigned to service client
		// id will be empty (instead of null: null causes reflection err)
		// because of the coalesce syntax in the query
		if cs.ScopeId == "" {
			continue
		}

		client.Scopes = append(client.Scopes, types.Scope{
			Uuid:        cs.ScopeId,
			ServiceName: cs.ServiceName,
			Scope:       cs.Scope,
			Name:        cs.ScopeName,
			Description: cs.Description,
			CreatedAt:   cs.ScopeCreatedAt,
			Active:      cs.Active,
			Slug:        cs.ScopeSlug,
		})
	}

	return &client, nil
}

// UpdateClient is a concrete impl of the Service interface method: updates a service client record
func (s *clientService) UpdateClient(client *Client) error {

	// validate client is not nil
	if client == nil {
		return fmt.Errorf("service client is required")
	}

	// validate client fields
	// redundant, but good practice
	if err := client.Validate(); err != nil {
		return fmt.Errorf("invalid service client: %v", err)
	}

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
	if err := s.sql.UpdateRecord(query, client.Name, client.Owner, client.Enabled, client.AccountExpired, client.AccountLocked, client.Slug); err != nil {
		errMsg := fmt.Sprintf("failed to update service client record for slug %s: %v", client.Slug, err)
		s.logger.Error(errMsg)
		return fmt.Errorf(errMsg)
	}

	return nil
}

// UpdateScopes is a concrete impl of the Service interface method: updates a service client's assigned scopes
func (s *clientService) UpdateScopes(client *profile.Client, updated []types.Scope) error {

	// validate client is not nil
	if client == nil {
		return fmt.Errorf(ErrClientMissing)
	}

	// if client scopes and updated scopes are both empty, return
	if len(client.Scopes) < 1 && len(updated) < 1 {
		s.logger.Info("both client scopes and updated scopes are empty: no scopes to update")
		return nil
	}

	// if both client and updated scopes are not empty, reconcile
	if len(updated) > 0 || len(client.Scopes) > 0 {

		// idendify scopes to remove, if any
		var (
			toRemove  = make(map[types.Scope]bool)
			isRemoved bool
		)

		for _, scope := range client.Scopes {
			isRemoved = true
			// if updated is empty this will remove all scopes
			for _, u := range updated {
				if scope.Uuid == u.Uuid {
					isRemoved = false
					break
				}
			}
			if isRemoved {
				toRemove[scope] = true
			}
		}

		// identify scopes to add, if any
		var (
			toAdd   = make(map[types.Scope]bool)
			isAdded bool
		)
		for _, u := range updated {
			isAdded = true
			// if client scopes is empty this will add all scopes in updated
			for _, scope := range client.Scopes {
				if u.Uuid == scope.Uuid {
					isAdded = false
					break
				}
			}
			if isAdded {
				toAdd[u] = true
			}
		}

		// add-to and remove-from client_scopes xref table
		if len(toRemove) > 0 || len(toAdd) > 0 {

			var (
				wg      sync.WaitGroup
				errChan = make(chan error, len(toRemove)+len(toAdd))
			)

			// remove scopes
			if len(toRemove) > 0 {
				for scope := range toRemove {
					wg.Add(1)
					go func(scope types.Scope) {
						defer wg.Done()

						query := `
								DELETE 
								FROM client_scope
								WHERE client_uuid = ? AND scope_uuid = ?`
						if err := s.sql.DeleteRecord(query, client.Id, scope.Uuid); err != nil {
							errChan <- fmt.Errorf("%s for scope %s from client %s: %v", ErrRemoveXref, scope.Name, client.Name, err)
						}

						s.logger.Info(fmt.Sprintf("successfully removed xref record for scope %s from client %s", scope.Name, client.Name))
					}(scope)
				}
			}

			// add scopes
			if len(toAdd) > 0 {
				for scope := range toAdd {
					wg.Add(1)
					go func(scope types.Scope) {
						defer wg.Done()

						xref := ClientScopeXref{
							ClientId:  client.Id,
							ScopeId:   scope.Uuid,
							CreatedAt: data.CustomTime{Time: time.Now().UTC()},
						}

						query := `
								INSERT INTO client_scope (
									client_uuid, 
									scope_uuid, 
									created_at
								)
								VALUES (?, ?, ?)`
						if err := s.sql.InsertRecord(query, xref); err != nil {
							errChan <- fmt.Errorf("%s for scope %s to client %s: %v", ErrAddXref, scope.Name, client.Name, err)
						}

						s.logger.Info(fmt.Sprintf("successfully added xref record for scope %s to client %s", scope.Name, client.Name))
					}(scope)
				}
			}

			// wait for all go routines to finish
			wg.Wait()
			close(errChan)

			// check for errors
			errCount := len(errChan)
			if errCount > 0 {
				var sb strings.Builder
				counter := 0
				for i := 0; i < errCount; i++ {
					for err := range errChan {
						sb.WriteString(err.Error())
						if counter+1 < errCount {
							sb.WriteString("; ")
						}
						counter++
					}
				}
				return fmt.Errorf(sb.String())
			}
		}
	}

	return nil
}
