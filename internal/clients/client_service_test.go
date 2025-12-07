package clients

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/ran/pkg/api/clients"
	"github.com/tdeslauriers/ran/pkg/scopes"
)

// mockClientRepository implements ClientRepository for testing
type mockClientRepository struct {
	findAllFunc          func() ([]ClientAccount, error)
	findClientScopesFunc func(slug string) ([]ClientScope, error)
	updateFunc           func(client *clients.Client) error
	addScopeFunc         func(clientId, scopeId string) error
	removeScopeFunc      func(clientId, scopeId string) error
}

// implement ClientRepository interface methods
func (m *mockClientRepository) FindAll() ([]ClientAccount, error) {
	if m.findAllFunc != nil {
		return m.findAllFunc()
	}
	return nil, errors.New("findAllFunc not set")
}

func (m *mockClientRepository) FindClientScopes(slug string) ([]ClientScope, error) {
	if m.findClientScopesFunc != nil {
		return m.findClientScopesFunc(slug)
	}
	return nil, errors.New("findClientScopesFunc not set")
}

func (m *mockClientRepository) Update(client *clients.Client) error {
	if m.updateFunc != nil {
		return m.updateFunc(client)
	}
	return errors.New("updateFunc not set")
}

func (m *mockClientRepository) AddScope(clientId, scopeId string) error {
	if m.addScopeFunc != nil {
		return m.addScopeFunc(clientId, scopeId)
	}
	return errors.New("addScopeFunc not set")
}

func (m *mockClientRepository) RemoveScope(clientId, scopeId string) error {
	if m.removeScopeFunc != nil {
		return m.removeScopeFunc(clientId, scopeId)
	}
	return errors.New("removeScopeFunc not set")
}

var _ ClientRepository = (*mockClientRepository)(nil)

// TestGetClients tests the GetClients service method
func TestGetClients(t *testing.T) {

	tests := []struct {
		name           string
		mockRepo       *mockClientRepository
		expectError    bool
		validateError  func(*testing.T, error)
		validateResult func(*testing.T, []ClientAccount)
	}{
		{
			name: "successfully retrieves all clients",
			mockRepo: &mockClientRepository{
				findAllFunc: func() ([]ClientAccount, error) {
					return []ClientAccount{
						{
							Id:             "client-uuid-1",
							Name:           "Test Client 1",
							Owner:          "owner1@example.com",
							CreatedAt:      data.CustomTime{Time: time.Now().UTC()},
							Enabled:        true,
							AccountExpired: false,
							AccountLocked:  false,
							Slug:           "550e8400-e29b-41d4-a716-446655440001",
						},
						{
							Id:             "client-uuid-2",
							Name:           "Test Client 2",
							Owner:          "owner2@example.com",
							CreatedAt:      data.CustomTime{Time: time.Now().UTC()},
							Enabled:        false,
							AccountExpired: true,
							AccountLocked:  false,
							Slug:           "550e8400-e29b-41d4-a716-446655440002",
						},
					}, nil
				},
			},
			expectError: false,
			validateResult: func(t *testing.T, clients []ClientAccount) {
				if len(clients) != 2 {
					t.Errorf("expected 2 clients, got %d", len(clients))
				}
				if clients[0].Name != "Test Client 1" {
					t.Errorf("expected first client name 'Test Client 1', got %q", clients[0].Name)
				}
				if clients[1].AccountExpired != true {
					t.Errorf("expected second client to have expired account")
				}
			},
		},
		{
			name: "returns empty slice when no clients exist",
			mockRepo: &mockClientRepository{
				findAllFunc: func() ([]ClientAccount, error) {
					return []ClientAccount{}, nil
				},
			},
			expectError: false,
			validateResult: func(t *testing.T, clients []ClientAccount) {
				if len(clients) != 0 {
					t.Errorf("expected 0 clients, got %d", len(clients))
				}
			},
		},
		{
			name: "repository error is propagated",
			mockRepo: &mockClientRepository{
				findAllFunc: func() ([]ClientAccount, error) {
					return nil, errors.New("database connection failed")
				},
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "database connection failed") {
					t.Errorf("expected error to contain 'database connection failed', got %q", err.Error())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create service with mock repository
			service := &clientService{
				sql: tt.mockRepo,
			}

			// Call the service method
			result, err := service.GetClients()

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.validateError != nil {
					tt.validateError(t, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
}

// TestGetClient tests the GetClient service method
func TestGetClient(t *testing.T) {
	validSlug := "550e8400-e29b-41d4-a716-446655440000"

	tests := []struct {
		name           string
		slug           string
		mockRepo       *mockClientRepository
		expectError    bool
		validateError  func(*testing.T, error)
		validateResult func(*testing.T, *clients.Client)
	}{
		{
			name: "successfully retrieves client with scopes",
			slug: validSlug,
			mockRepo: &mockClientRepository{
				findClientScopesFunc: func(slug string) ([]ClientScope, error) {
					if slug != validSlug {
						t.Errorf("expected slug %q, got %q", validSlug, slug)
					}

					return []ClientScope{
						{
							ClientId:        "client-uuid-1",
							ClientName:      "Test Client",
							Owner:           "owner@example.com",
							ClientCreatedAt: data.CustomTime{Time: time.Now().UTC()},
							Enabled:         true,
							AccountExpired:  false,
							AccountLocked:   false,
							CLientSlug:      validSlug,
							ScopeId:         "scope-uuid-1",
							ServiceName:     "test-service",
							Scope:           "read",
							ScopeName:       "Read Access",
							Description:     "Read access to test service",
							ScopeCreatedAt:  data.CustomTime{Time: time.Now().UTC()}.String(),
							Active:          true,
							ScopeSlug:       "scope-slug-1",
						},
						{
							ClientId:        "client-uuid-1",
							ClientName:      "Test Client",
							Owner:           "owner@example.com",
							ClientCreatedAt: data.CustomTime{Time: time.Now().UTC()},
							Enabled:         true,
							AccountExpired:  false,
							AccountLocked:   false,
							CLientSlug:      validSlug,
							ScopeId:         "scope-uuid-2",
							ServiceName:     "test-service",
							Scope:           "write",
							ScopeName:       "Write Access",
							Description:     "Write access to test service",
							ScopeCreatedAt:  data.CustomTime{Time: time.Now().UTC()}.String(),
							Active:          true,
							ScopeSlug:       "scope-slug-2",
						},
					}, nil
				},
			},
			expectError: false,
			validateResult: func(t *testing.T, client *clients.Client) {
				if client == nil {
					t.Fatal("expected client, got nil")
				}
				if client.Name != "Test Client" {
					t.Errorf("expected client name 'Test Client', got %q", client.Name)
				}
				if len(client.Scopes) != 2 {
					t.Errorf("expected 2 scopes, got %d", len(client.Scopes))
				}
				if client.Scopes[0].Scope != "read" {
					t.Errorf("expected first scope 'read', got %q", client.Scopes[0].Scope)
				}
				if client.Scopes[1].Scope != "write" {
					t.Errorf("expected second scope 'write', got %q", client.Scopes[1].Scope)
				}
			},
		},
		{
			name: "successfully retrieves client without scopes",
			slug: validSlug,
			mockRepo: &mockClientRepository{
				findClientScopesFunc: func(slug string) ([]ClientScope, error) {
					return []ClientScope{
						{
							ClientId:        "client-uuid-1",
							ClientName:      "Test Client",
							Owner:           "owner@example.com",
							ClientCreatedAt: data.CustomTime{Time: time.Now().UTC()},
							Enabled:         true,
							AccountExpired:  false,
							AccountLocked:   false,
							CLientSlug:      validSlug,
							ScopeId:         "", // Empty = no scopes
						},
					}, nil
				},
			},
			expectError: false,
			validateResult: func(t *testing.T, client *clients.Client) {
				if client == nil {
					t.Fatal("expected client, got nil")
				}
				if len(client.Scopes) != 0 {
					t.Errorf("expected 0 scopes, got %d", len(client.Scopes))
				}
			},
		},
		{
			name:        "empty slug returns validation error",
			slug:        "",
			mockRepo:    &mockClientRepository{},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "slug is required") {
					t.Errorf("expected 'slug is required' error, got %q", err.Error())
				}
			},
		},
		{
			name:        "invalid uuid format returns validation error",
			slug:        "not-a-valid-uuid",
			mockRepo:    &mockClientRepository{},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "invalid or not well formatted") {
					t.Errorf("expected 'invalid or not well formatted' error, got %q", err.Error())
				}
			},
		},
		{
			name: "repository error is wrapped and returned",
			slug: validSlug,
			mockRepo: &mockClientRepository{
				findClientScopesFunc: func(slug string) ([]ClientScope, error) {
					return nil, errors.New("database connection failed")
				},
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "failed to get service client and its scopes from db") {
					t.Errorf("expected wrapped error, got %q", err.Error())
				}
				if !strings.Contains(err.Error(), "database connection failed") {
					t.Errorf("expected underlying error, got %q", err.Error())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create service with mock repository
			service := &clientService{
				sql: tt.mockRepo,
			}

			// Call the service method
			result, err := service.GetClient(tt.slug)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.validateError != nil {
					tt.validateError(t, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
}

// TestUpdateScopes tests the UpdateScopes service method
func TestUpdateScopes(t *testing.T) {
	tests := []struct {
		name          string
		client        *clients.Client
		updated       []scopes.Scope
		mockRepo      *mockClientRepository
		expectError   bool
		validateError func(*testing.T, error)
		validateCalls func(*testing.T, *callTracker)
	}{
		{
			name: "adds new scopes when client has none",
			client: &clients.Client{
				Id:     "client-uuid-1",
				Name:   "Test Client",
				Scopes: []scopes.Scope{},
			},
			updated: []scopes.Scope{
				{Uuid: "scope-uuid-1", Name: "Scope 1"},
				{Uuid: "scope-uuid-2", Name: "Scope 2"},
			},
			mockRepo: &mockClientRepository{
				addScopeFunc: func(clientId, scopeId string) error {
					if clientId != "client-uuid-1" {
						t.Errorf("expected client ID 'client-uuid-1', got %q", clientId)
					}
					return nil
				},
			},
			expectError: false,
			validateCalls: func(t *testing.T, tracker *callTracker) {
				if tracker.addScopeCalls != 2 {
					t.Errorf("expected 2 AddScope calls, got %d", tracker.addScopeCalls)
				}
				if tracker.removeScopeCalls != 0 {
					t.Errorf("expected 0 RemoveScope calls, got %d", tracker.removeScopeCalls)
				}
			},
		},
		{
			name: "removes scopes when updated is empty",
			client: &clients.Client{
				Id:   "client-uuid-1",
				Name: "Test Client",
				Scopes: []scopes.Scope{
					{Uuid: "scope-uuid-1", Name: "Scope 1"},
					{Uuid: "scope-uuid-2", Name: "Scope 2"},
				},
			},
			updated: []scopes.Scope{},
			mockRepo: &mockClientRepository{
				removeScopeFunc: func(clientId, scopeId string) error {
					if clientId != "client-uuid-1" {
						t.Errorf("expected client ID 'client-uuid-1', got %q", clientId)
					}
					return nil
				},
			},
			expectError: false,
			validateCalls: func(t *testing.T, tracker *callTracker) {
				if tracker.removeScopeCalls != 2 {
					t.Errorf("expected 2 RemoveScope calls, got %d", tracker.removeScopeCalls)
				}
				if tracker.addScopeCalls != 0 {
					t.Errorf("expected 0 AddScope calls, got %d", tracker.addScopeCalls)
				}
			},
		},
		{
			name: "adds and removes scopes simultaneously",
			client: &clients.Client{
				Id:   "client-uuid-1",
				Name: "Test Client",
				Scopes: []scopes.Scope{
					{Uuid: "scope-uuid-1", Name: "Scope 1"},
					{Uuid: "scope-uuid-2", Name: "Scope 2"},
				},
			},
			updated: []scopes.Scope{
				{Uuid: "scope-uuid-2", Name: "Scope 2"}, // Keep
				{Uuid: "scope-uuid-3", Name: "Scope 3"}, // Add
			},
			mockRepo: &mockClientRepository{
				addScopeFunc: func(clientId, scopeId string) error {
					if scopeId != "scope-uuid-3" {
						t.Errorf("expected to add scope-uuid-3, got %q", scopeId)
					}
					return nil
				},
				removeScopeFunc: func(clientId, scopeId string) error {
					if scopeId != "scope-uuid-1" {
						t.Errorf("expected to remove scope-uuid-1, got %q", scopeId)
					}
					return nil
				},
			},
			expectError: false,
			validateCalls: func(t *testing.T, tracker *callTracker) {
				if tracker.addScopeCalls != 1 {
					t.Errorf("expected 1 AddScope call, got %d", tracker.addScopeCalls)
				}
				if tracker.removeScopeCalls != 1 {
					t.Errorf("expected 1 RemoveScope call, got %d", tracker.removeScopeCalls)
				}
			},
		},
		{
			name: "no changes when scopes are identical",
			client: &clients.Client{
				Id:   "client-uuid-1",
				Name: "Test Client",
				Scopes: []scopes.Scope{
					{Uuid: "scope-uuid-1", Name: "Scope 1"},
				},
			},
			updated: []scopes.Scope{
				{Uuid: "scope-uuid-1", Name: "Scope 1"},
			},
			mockRepo: &mockClientRepository{
				addScopeFunc: func(clientId, scopeId string) error {
					t.Error("AddScope should not be called")
					return nil
				},
				removeScopeFunc: func(clientId, scopeId string) error {
					t.Error("RemoveScope should not be called")
					return nil
				},
			},
			expectError: false,
			validateCalls: func(t *testing.T, tracker *callTracker) {
				if tracker.addScopeCalls != 0 {
					t.Errorf("expected 0 AddScope calls, got %d", tracker.addScopeCalls)
				}
				if tracker.removeScopeCalls != 0 {
					t.Errorf("expected 0 RemoveScope calls, got %d", tracker.removeScopeCalls)
				}
			},
		},
		{
			name:        "nil client returns error",
			client:      nil,
			updated:     []scopes.Scope{},
			mockRepo:    &mockClientRepository{},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !errors.Is(err, errors.New("service client is missing")) {
					t.Errorf("expected ErrClientMissing, got %q", err.Error())
				}
			},
		},
		{
			name: "both empty scopes returns nil without repository calls",
			client: &clients.Client{
				Id:     "client-uuid-1",
				Name:   "Test Client",
				Scopes: []scopes.Scope{},
			},
			updated: []scopes.Scope{},
			mockRepo: &mockClientRepository{
				addScopeFunc: func(clientId, scopeId string) error {
					t.Error("AddScope should not be called")
					return nil
				},
				removeScopeFunc: func(clientId, scopeId string) error {
					t.Error("RemoveScope should not be called")
					return nil
				},
			},
			expectError: false,
		},
		{
			name: "add scope error is collected and returned",
			client: &clients.Client{
				Id:     "client-uuid-1",
				Name:   "Test Client",
				Scopes: []scopes.Scope{},
			},
			updated: []scopes.Scope{
				{Uuid: "scope-uuid-1", Name: "Scope 1"},
			},
			mockRepo: &mockClientRepository{
				addScopeFunc: func(clientId, scopeId string) error {
					return errors.New("database insert failed")
				},
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "error(s) occurred updating") {
					t.Errorf("expected wrapped errors, got %q", err.Error())
				}
				if !strings.Contains(err.Error(), "database insert failed") {
					t.Errorf("expected underlying error, got %q", err.Error())
				}
			},
		},
		{
			name: "remove scope error is collected and returned",
			client: &clients.Client{
				Id:   "client-uuid-1",
				Name: "Test Client",
				Scopes: []scopes.Scope{
					{Uuid: "scope-uuid-1", Name: "Scope 1"},
				},
			},
			updated: []scopes.Scope{},
			mockRepo: &mockClientRepository{
				removeScopeFunc: func(clientId, scopeId string) error {
					return errors.New("database delete failed")
				},
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "error(s) occurred updating") {
					t.Errorf("expected wrapped errors, got %q", err.Error())
				}
				if !strings.Contains(err.Error(), "database delete failed") {
					t.Errorf("expected underlying error, got %q", err.Error())
				}
			},
		},
		{
			name: "multiple errors are collected and joined",
			client: &clients.Client{
				Id:   "client-uuid-1",
				Name: "Test Client",
				Scopes: []scopes.Scope{
					{Uuid: "scope-uuid-1", Name: "Scope 1"},
				},
			},
			updated: []scopes.Scope{
				{Uuid: "scope-uuid-2", Name: "Scope 2"},
			},
			mockRepo: &mockClientRepository{
				addScopeFunc: func(clientId, scopeId string) error {
					return errors.New("insert failed")
				},
				removeScopeFunc: func(clientId, scopeId string) error {
					return errors.New("delete failed")
				},
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "insert failed") {
					t.Errorf("expected 'insert failed' in error, got %q", err.Error())
				}
				if !strings.Contains(err.Error(), "delete failed") {
					t.Errorf("expected 'delete failed' in error, got %q", err.Error())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create call tracker if validation needed
			var tracker *callTracker
			if tt.validateCalls != nil {
				tracker = &callTracker{}

				// Wrap mock functions to track calls
				if tt.mockRepo.addScopeFunc != nil {
					originalAdd := tt.mockRepo.addScopeFunc
					tt.mockRepo.addScopeFunc = func(clientId, scopeId string) error {
						tracker.addScopeCalls++
						return originalAdd(clientId, scopeId)
					}
				}

				if tt.mockRepo.removeScopeFunc != nil {
					originalRemove := tt.mockRepo.removeScopeFunc
					tt.mockRepo.removeScopeFunc = func(clientId, scopeId string) error {
						tracker.removeScopeCalls++
						return originalRemove(clientId, scopeId)
					}
				}
			}

			// Create service with mock repository
			service := &clientService{
				sql:    tt.mockRepo,
				logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
			}

			// Create context with telemetry
			ctx := context.Background()
			tel := &connect.Telemetry{}
			ctx = context.WithValue(ctx, connect.TelemetryKey, tel)

			// Call the service method
			err := service.UpdateScopes(ctx, tt.client, tt.updated)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.validateError != nil {
					tt.validateError(t, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validateCalls != nil && tracker != nil {
				tt.validateCalls(t, tracker)
			}
		})
	}
}

// callTracker tracks method calls for validation
type callTracker struct {
	addScopeCalls    int
	removeScopeCalls int
}
