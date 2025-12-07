package clients

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/ran/internal/definitions"
	"github.com/tdeslauriers/ran/pkg/api/clients"
	"github.com/tdeslauriers/ran/pkg/scopes"
)

// ClientService provides clients service operations
type ClientService interface {

	// GetClients returns all service clients, active or inactive
	GetClients() ([]ClientAccount, error)

	// GetClient returns a single service client (and it's assigned scopes) from a slug
	GetClient(slug string) (*clients.Client, error)

	// UpdateClient updates a service client record (doesn not include password updates/resets)
	UpdateClient(client *clients.Client) error

	UpdateScopes(ctx context.Context, client *clients.Client, updated []scopes.Scope) error
}

// NewClientService creates a new clients service interface abstracting a concrete implementation
func NewClientService(sql *sql.DB) ClientService {

	return &clientService{
		sql: NewClientRepository(sql),

		logger: slog.Default().
			With(slog.String(definitions.PackageKey, definitions.PackageClients)).
			With(slog.String(definitions.ComponentKey, definitions.ComponentClients)),
	}
}

var _ ClientService = (*clientService)(nil)

// clientService is a concrete implementation of the Service interface
type clientService struct {
	sql ClientRepository

	logger *slog.Logger
}

// GetClients is a concrete impl of the Service interface method: returns all clients, active or inactive
func (s *clientService) GetClients() ([]ClientAccount, error) {

	return s.sql.FindAll()
}

// GetClient is a concrete impl of the Service interface method: returns a single client from a slug
func (s *clientService) GetClient(slug string) (*clients.Client, error) {

	// validate input
	if slug == "" {
		return nil, errors.New("service client slug is required")
	}

	if !validate.IsValidUuid(slug) {
		return nil, errors.New("invalid or not well formatted service client slug")
	}

	// get clientscopes records slice from the database
	clientScopes, err := s.sql.FindClientScopes(slug)
	if err != nil {
		return nil, err
	}

	// build client from db records slice
	client := clients.Client{
		Id:             clientScopes[0].ClientId,
		Name:           clientScopes[0].ClientName,
		Owner:          clientScopes[0].Owner,
		CreatedAt:      clientScopes[0].ClientCreatedAt,
		Enabled:        clientScopes[0].Enabled,
		AccountExpired: clientScopes[0].AccountExpired,
		AccountLocked:  clientScopes[0].AccountLocked,
		Slug:           clientScopes[0].CLientSlug,
	}

	// build scopes from db records slice
	for _, cs := range clientScopes {
		// emtpy scope id means no scope(s) assigned to service client
		// id will be empty (instead of null: null causes reflection err)
		// because of the coalesce syntax in the query
		if cs.ScopeId == "" {
			continue
		}

		client.Scopes = append(client.Scopes, scopes.Scope{
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
func (s *clientService) UpdateClient(client *clients.Client) error {

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
	if err := s.sql.Update(client); err != nil {
		return fmt.Errorf("failed to update service client %s: %v", client.Name, err)
	}

	return nil
}

// UpdateScopes is a concrete impl of the Service interface method: updates a service client's assigned scopes
func (s *clientService) UpdateScopes(ctx context.Context, client *clients.Client, updated []scopes.Scope) error {

	// create local logger
	log := s.logger

	// get telemetry from context
	tel, ok := ctx.Value(connect.TelemetryKey).(*connect.Telemetry)
	if ok && tel != nil {
		log = log.With(tel.TelemetryFields()...)
	} else {
		log.Warn("telemetry not found in context: using default logger")
	}

	// validate client is not nil
	if client == nil {
		return fmt.Errorf("service client is missing")
	}

	// if client scopes and updated scopes are both empty, return
	if len(client.Scopes) < 1 && len(updated) < 1 {
		log.Warn("both client scopes and updated scopes are empty: no scopes to update")
		return nil
	}

	// if both client and updated scopes are not empty, reconcile
	if len(updated) > 0 || len(client.Scopes) > 0 {

		// idendify scopes to remove, if any
		var (
			toRemove  = make(map[scopes.Scope]bool)
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
			toAdd   = make(map[scopes.Scope]bool)
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
					go func(scope scopes.Scope) {
						defer wg.Done()

						if err := s.sql.RemoveScope(client.Id, scope.Uuid); err != nil {

							errChan <- fmt.Errorf("failed to delete xref for scope %s - client %s: %v", scope.Name, client.Name, err)
						}

						log.Info(fmt.Sprintf("successfully deleted xref for scope %s - client %s", scope.Name, client.Name))
					}(scope)
				}
			}

			// add scopes
			if len(toAdd) > 0 {
				for scope := range toAdd {
					wg.Add(1)
					go func(scope scopes.Scope) {
						defer wg.Done()

						if err := s.sql.AddScope(client.Id, scope.Uuid); err != nil {
							errChan <- fmt.Errorf("failed to add xref record beteween scope %s and client %s: %v",
								scope.Name, client.Name, err)
						}

						log.Info(fmt.Sprintf("successfully added xref between scope %s and client %s",
							scope.Name, client.Name))
					}(scope)
				}
			}

			// wait for all go routines to finish
			wg.Wait()
			close(errChan)

			// check for errors
			if len(errChan) > 0 {
				var errs []error
				for err := range errChan {
					errs = append(errs, err)
				}
				return fmt.Errorf("error(s) occurred updating client %s's scopes: %v", client.Name, errors.Join(errs...))
			}
		}
	}

	return nil
}
