package scopes

import (
	"errors"
	"fmt"
	"testing"

	"github.com/tdeslauriers/ran/pkg/api/scopes"
)

// Mock implementation of ScopesRepository
type mockScopesRepository struct {
	findScopesFunc       func() ([]scopes.Scope, error)
	findActiveScopesFunc func() ([]scopes.Scope, error)
	findScopeBySlugFunc  func(slug string) (*scopes.Scope, error)
	insertScopeFunc      func(s *scopes.Scope) error
	updateScopeFunc      func(s *scopes.Scope) error
}

func (m *mockScopesRepository) FindScopes() ([]scopes.Scope, error) {
	if m.findScopesFunc != nil {
		return m.findScopesFunc()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockScopesRepository) FindActiveScopes() ([]scopes.Scope, error) {
	if m.findActiveScopesFunc != nil {
		return m.findActiveScopesFunc()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockScopesRepository) FindScopeBySlug(slug string) (*scopes.Scope, error) {
	if m.findScopeBySlugFunc != nil {
		return m.findScopeBySlugFunc(slug)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockScopesRepository) InsertScope(s *scopes.Scope) error {
	if m.insertScopeFunc != nil {
		return m.insertScopeFunc(s)
	}
	return fmt.Errorf("not implemented")
}

func (m *mockScopesRepository) UpdateScope(s *scopes.Scope) error {
	if m.updateScopeFunc != nil {
		return m.updateScopeFunc(s)
	}
	return fmt.Errorf("not implemented")
}

// TestGetScopes tests the GetScopes service method using table-driven tests
func TestGetScopes(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func() *mockScopesRepository
		expectError    bool
		errorContains  string
		validateResult func(t *testing.T, result []scopes.Scope)
	}{
		{
			name: "success with multiple scopes",
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					findScopesFunc: func() ([]scopes.Scope, error) {
						return []scopes.Scope{
							{
								Uuid:        "803efa7a-7901-4fad-86ba-4879df1f41a9",
								ServiceName: "service",
								Scope:       "r:service:data:*",
								Name:        "Read Data",
								Description: "Read access",
								CreatedAt:   "2024-01-01 00:00:00",
								Active:      true,
								Slug:        "slug-1",
							},
							{
								Uuid:        "uuid-2",
								ServiceName: "service",
								Scope:       "write:data",
								Name:        "Write Data",
								Description: "Write access",
								CreatedAt:   "2024-01-02 00:00:00",
								Active:      false,
								Slug:        "slug-2",
							},
						}, nil
					},
				}
			},
			expectError: false,
			validateResult: func(t *testing.T, result []scopes.Scope) {
				if len(result) != 2 {
					t.Errorf("expected 2 scopes, got %d", len(result))
				}
				if result[0].ServiceName != "service" {
					t.Errorf("expected service name 'service', got '%s'", result[0].ServiceName)
				}
			},
		},
		{
			name: "success with empty list",
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					findScopesFunc: func() ([]scopes.Scope, error) {
						return []scopes.Scope{}, nil
					},
				}
			},
			expectError: false,
			validateResult: func(t *testing.T, result []scopes.Scope) {
				if len(result) != 0 {
					t.Errorf("expected empty list, got %d scopes", len(result))
				}
			},
		},
		{
			name: "database error",
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					findScopesFunc: func() ([]scopes.Scope, error) {
						return nil, errors.New("database connection failed")
					},
				}
			},
			expectError:   true,
			errorContains: "database connection failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			repo := tt.setupMock()
			svc := &service{
				sql: repo,
			}

			// Execute
			result, err := svc.GetScopes()

			// Assert
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain '%s', got '%v'", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

// TestGetActiveScopes tests the GetActiveScopes service method using table-driven tests
func TestGetActiveScopes(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func() *mockScopesRepository
		expectError    bool
		errorContains  string
		validateResult func(t *testing.T, result []scopes.Scope)
	}{
		{
			name: "success with multiple active scopes",
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					findActiveScopesFunc: func() ([]scopes.Scope, error) {
						return []scopes.Scope{
							{
								Uuid:        "803efa7a-7901-4fad-86ba-4879df1f41a9",
								ServiceName: "service",
								Scope:       "r:service:data:*",
								Name:        "Read Data",
								Description: "Read access",
								CreatedAt:   "2024-01-01 00:00:00",
								Active:      true,
								Slug:        "slug-1",
							},
							{
								Uuid:        "uuid-2",
								ServiceName: "service-b",
								Scope:       "write:data",
								Name:        "Write Data",
								Description: "Write access",
								CreatedAt:   "2024-01-02 00:00:00",
								Active:      true,
								Slug:        "slug-2",
							},
						}, nil
					},
				}
			},
			expectError: false,
			validateResult: func(t *testing.T, result []scopes.Scope) {
				if len(result) != 2 {
					t.Errorf("expected 2 active scopes, got %d", len(result))
				}
				for i, scope := range result {
					if !scope.Active {
						t.Errorf("scope at index %d should be active", i)
					}
				}
			},
		},
		{
			name: "success with no active scopes",
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					findActiveScopesFunc: func() ([]scopes.Scope, error) {
						return []scopes.Scope{}, nil
					},
				}
			},
			expectError: false,
			validateResult: func(t *testing.T, result []scopes.Scope) {
				if len(result) != 0 {
					t.Errorf("expected empty list, got %d scopes", len(result))
				}
			},
		},
		{
			name: "database error",
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					findActiveScopesFunc: func() ([]scopes.Scope, error) {
						return nil, errors.New("database query failed")
					},
				}
			},
			expectError:   true,
			errorContains: "database query failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			repo := tt.setupMock()
			svc := &service{
				sql: repo,
			}

			// Execute
			result, err := svc.GetActiveScopes()

			// Assert
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain '%s', got '%v'", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

// TestGetScope tests the GetScope service method using table-driven tests
func TestGetScope(t *testing.T) {
	validSlug := "550e8400-e29b-41d4-a716-446655440000"

	tests := []struct {
		name           string
		slug           string
		setupMock      func() *mockScopesRepository
		expectError    bool
		errorContains  string
		validateResult func(t *testing.T, result *scopes.Scope)
	}{
		{
			name: "success",
			slug: validSlug,
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					findScopeBySlugFunc: func(slug string) (*scopes.Scope, error) {
						if slug != validSlug {
							t.Errorf("expected slug %s, got %s", validSlug, slug)
						}
						return &scopes.Scope{
							Uuid:        "803efa7a-7901-4fad-86ba-4879df1f41a9",
							ServiceName: "service",
							Scope:       "r:service:data:*",
							Name:        "Read Data",
							Description: "Read access",
							CreatedAt:   "2024-01-01 00:00:00",
							Active:      true,
							Slug:        validSlug,
						}, nil
					},
				}
			},
			expectError: false,
			validateResult: func(t *testing.T, result *scopes.Scope) {
				if result == nil {
					t.Fatal("expected result to not be nil")
				}
				if result.Slug != validSlug {
					t.Errorf("expected slug %s, got %s", validSlug, result.Slug)
				}
				if result.Scope != "r:service:data:*" {
					t.Errorf("expected scope 'r:service:data:*', got '%s'", result.Scope)
				}
			},
		},
		{
			name: "invalid slug format",
			slug: "not-a-uuid",
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{}
			},
			expectError:   true,
			errorContains: "invalid slug",
		},
		{
			name: "scope not found",
			slug: validSlug,
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					findScopeBySlugFunc: func(slug string) (*scopes.Scope, error) {
						return nil, errors.New("scope for provided slug not found")
					},
				}
			},
			expectError:   true,
			errorContains: "not found",
		},
		{
			name: "database error",
			slug: validSlug,
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					findScopeBySlugFunc: func(slug string) (*scopes.Scope, error) {
						return nil, errors.New("database connection lost")
					},
				}
			},
			expectError:   true,
			errorContains: "database connection lost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			repo := tt.setupMock()
			svc := &service{
				sql: repo,
			}

			// Execute
			result, err := svc.GetScope(tt.slug)

			// Assert
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain '%s', got '%v'", tt.errorContains, err)
				}
				if result != nil {
					t.Error("expected result to be nil on error")
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

// TestAddScope tests the AddScope service method using table-driven tests
func TestAddScope(t *testing.T) {
	tests := []struct {
		name           string
		inputScope     *scopes.Scope
		setupMock      func() *mockScopesRepository
		expectError    bool
		errorContains  string
		validateResult func(t *testing.T, result *scopes.Scope)
	}{
		{
			name: "success",
			inputScope: &scopes.Scope{
				ServiceName: "service",
				Scope:       "r:service:data:*",
				Name:        "Read Data",
				Description: "Read access to data",
				Active:      true,
			},
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					insertScopeFunc: func(s *scopes.Scope) error {
						// Validate that UUID and slug were generated
						if s.Uuid == "" {
							t.Error("expected UUID to be generated")
						}
						if s.Slug == "" {
							t.Error("expected slug to be generated")
						}
						if s.CreatedAt == "" {
							t.Error("expected CreatedAt to be set")
						}
						return nil
					},
				}
			},
			expectError: false,
			validateResult: func(t *testing.T, result *scopes.Scope) {
				if result == nil {
					t.Fatal("expected result to not be nil")
				}
				if result.Uuid == "" {
					t.Error("expected UUID to be generated")
				}
				if result.Slug == "" {
					t.Error("expected slug to be generated")
				}
				if result.CreatedAt == "" {
					t.Error("expected CreatedAt to be set")
				}
				if result.ServiceName != "service" {
					t.Errorf("expected service name 'service', got '%s'", result.ServiceName)
				}
			},
		},
		{
			name:       "nil scope",
			inputScope: nil,
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{}
			},
			expectError:   true,
			errorContains: "scope is nil",
		},
		{
			name: "validation error - empty service name",
			inputScope: &scopes.Scope{
				ServiceName: "", // Invalid - empty
				Scope:       "r:service:data:*",
				Name:        "Read Data",
				Description: "Read access",
				Active:      true,
			},
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{}
			},
			expectError:   true,
			errorContains: "", // Will contain validation error from ValidateCmd
		},
		{
			name: "validation error - empty scope",
			inputScope: &scopes.Scope{
				ServiceName: "service",
				Scope:       "", // Invalid - empty
				Name:        "Read Data",
				Description: "Read access",
				Active:      true,
			},
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{}
			},
			expectError:   true,
			errorContains: "", // Will contain validation error from ValidateCmd
		},
		{
			name: "validation error - empty name",
			inputScope: &scopes.Scope{
				ServiceName: "service",
				Scope:       "r:service:data:*",
				Name:        "", // Invalid - empty
				Description: "Read access",
				Active:      true,
			},
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{}
			},
			expectError:   true,
			errorContains: "", // Will contain validation error from ValidateCmd
		},
		{
			name: "database insert error",
			inputScope: &scopes.Scope{
				ServiceName: "service",
				Scope:       "r:service:data:*",
				Name:        "Read Data",
				Description: "Read access",
				Active:      true,
			},
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					insertScopeFunc: func(s *scopes.Scope) error {
						return errors.New("failed to insert new scope record into db")
					},
				}
			},
			expectError:   true,
			errorContains: "failed to insert new scope record into db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			repo := tt.setupMock()
			svc := &service{
				sql: repo,
			}

			// Execute
			result, err := svc.AddScope(tt.inputScope)

			// Assert
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain '%s', got '%v'", tt.errorContains, err)
				}
				if result != nil {
					t.Error("expected result to be nil on error")
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

// TestUpdateScope tests the UpdateScope service method using table-driven tests
func TestUpdateScope(t *testing.T) {
	validSlug := "550e8400-e29b-41d4-a716-446655440000"

	tests := []struct {
		name          string
		inputScope    *scopes.Scope
		setupMock     func() *mockScopesRepository
		expectError   bool
		errorContains string
	}{
		{
			name: "success",
			inputScope: &scopes.Scope{
				Uuid:        "803efa7a-7901-4fad-86ba-4879df1f41a9",
				ServiceName: "service",
				Scope:       "r:service:data:*",
				Name:        "Read Data Updated",
				Description: "Updated description",
				Active:      true,
				Slug:        validSlug,
			},
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					updateScopeFunc: func(s *scopes.Scope) error {
						if s.Slug != validSlug {
							t.Errorf("expected slug %s, got %s", validSlug, s.Slug)
						}
						if s.Name != "Read Data Updated" {
							t.Errorf("expected name 'Read Data Updated', got '%s'", s.Name)
						}
						return nil
					},
				}
			},
			expectError: false,
		},
		{
			name:       "nil scope",
			inputScope: nil,
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{}
			},
			expectError:   true,
			errorContains: "scope is nil",
		},
		{
			name: "validation error - empty service name",
			inputScope: &scopes.Scope{
				Uuid:        "803efa7a-7901-4fad-86ba-4879df1f41a9",
				ServiceName: "", // Invalid - empty
				Scope:       "r:service:data:*",
				Name:        "Read Data",
				Description: "Description",
				Active:      true,
				Slug:        validSlug,
			},
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{}
			},
			expectError:   true,
			errorContains: "", // Will contain validation error from ValidateCmd
		},
		{
			name: "validation error - empty scope",
			inputScope: &scopes.Scope{
				Uuid:        "803efa7a-7901-4fad-86ba-4879df1f41a9",
				ServiceName: "service",
				Scope:       "", // Invalid - empty
				Name:        "Read Data",
				Description: "Description",
				Active:      true,
				Slug:        validSlug,
			},
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{}
			},
			expectError:   true,
			errorContains: "", // Will contain validation error from ValidateCmd
		},
		{
			name: "validation error - empty name",
			inputScope: &scopes.Scope{
				Uuid:        "803efa7a-7901-4fad-86ba-4879df1f41a9",
				ServiceName: "service",
				Scope:       "r:service:data:*",
				Name:        "", // Invalid - empty
				Description: "Description",
				Active:      true,
				Slug:        validSlug,
			},
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{}
			},
			expectError:   true,
			errorContains: "", // Will contain validation error from ValidateCmd
		},
		{
			name: "database update error",
			inputScope: &scopes.Scope{
				Uuid:        "803efa7a-7901-4fad-86ba-4879df1f41a9",
				ServiceName: "service",
				Scope:       "r:service:data:*",
				Name:        "Read Data",
				Description: "Description",
				Active:      true,
				Slug:        validSlug,
			},
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					updateScopeFunc: func(s *scopes.Scope) error {
						return errors.New("failed to update scope record in db")
					},
				}
			},
			expectError:   true,
			errorContains: "failed to update scope record in db",
		},
		{
			name: "scope not found in database",
			inputScope: &scopes.Scope{
				Uuid:        "803efa7a-7901-4fad-86ba-4879df1f41a9",
				ServiceName: "service",
				Scope:       "r:service:data:*",
				Name:        "Read Data",
				Description: "Description",
				Active:      true,
				Slug:        validSlug,
			},
			setupMock: func() *mockScopesRepository {
				return &mockScopesRepository{
					updateScopeFunc: func(s *scopes.Scope) error {
						return errors.New("scope not found")
					},
				}
			},
			expectError:   true,
			errorContains: "scope not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			repo := tt.setupMock()
			svc := &service{
				sql: repo,
			}

			// Execute
			err := svc.UpdateScope(tt.inputScope)

			// Assert
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain '%s', got '%v'", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}
		})
	}
}

// contains is a helper function to check if a string contains a substring
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
