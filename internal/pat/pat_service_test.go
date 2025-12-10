package pat

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	exo "github.com/tdeslauriers/carapace/pkg/pat"
	"github.com/tdeslauriers/ran/internal/clients"
)

// Mock implementation of PatRepository
type mockPatRepository struct {
	findClientBySlugFunc    func(slug string) (*clients.ClientRecord, error)
	findPatByIndexFunc      func(patIndex string) (*PatRecord, error)
	findPatScopesFunc       func(patIndex string) ([]ScopePatRecord, error)
	findClientByPatFunc     func(patIndex string) (*ClientStatus, error)
	insertPatFunc           func(pat PatRecord) error
	insertPatClientXrefFunc func(xref PatClientXref) error
}

func (m *mockPatRepository) FindClientBySlug(slug string) (*clients.ClientRecord, error) {
	if m.findClientBySlugFunc != nil {
		return m.findClientBySlugFunc(slug)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockPatRepository) FindPatByIndex(patIndex string) (*PatRecord, error) {
	if m.findPatByIndexFunc != nil {
		return m.findPatByIndexFunc(patIndex)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockPatRepository) FindPatScopes(patIndex string) ([]ScopePatRecord, error) {
	if m.findPatScopesFunc != nil {
		return m.findPatScopesFunc(patIndex)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockPatRepository) FindClientByPat(patIndex string) (*ClientStatus, error) {
	if m.findClientByPatFunc != nil {
		return m.findClientByPatFunc(patIndex)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockPatRepository) InsertPat(pat PatRecord) error {
	if m.insertPatFunc != nil {
		return m.insertPatFunc(pat)
	}
	return fmt.Errorf("not implemented")
}

func (m *mockPatRepository) InsertPatClientXref(xref PatClientXref) error {
	if m.insertPatClientXrefFunc != nil {
		return m.insertPatClientXrefFunc(xref)
	}
	return fmt.Errorf("not implemented")
}

// Mock implementation of PatTokener
type mockPatTokener struct {
	generateFunc       func() ([]byte, string, error)
	obtainIndexFunc    func(raw []byte) (string, error)
	hashAndCompareFunc func(token []byte, blindIndex string) (bool, error)
}

func (m *mockPatTokener) Generate() ([]byte, string, error) {
	if m.generateFunc != nil {
		return m.generateFunc()
	}
	return nil, "", fmt.Errorf("not implemented")
}

func (m *mockPatTokener) ObtainIndex(raw []byte) (string, error) {
	if m.obtainIndexFunc != nil {
		return m.obtainIndexFunc(raw)
	}
	return "", fmt.Errorf("not implemented")
}

func (m *mockPatTokener) HashAndCompare(token []byte, blindIndex string) (bool, error) {
	if m.hashAndCompareFunc != nil {
		return m.hashAndCompareFunc(token, blindIndex)
	}
	return false, fmt.Errorf("not implemented")
}

// TestGeneratePat tests the GeneratePat service method using table-driven tests
func TestGeneratePat(t *testing.T) {
	testSlug := "550e8400-e29b-41d4-a716-446655440000"
	testClientID := "client-uuid-123"
	testClientName := "test-client"
	testRawToken := []byte("test-raw-token-bytes-64-characters-long-enough-for-validation")
	testToken := base64.StdEncoding.EncodeToString(testRawToken)
	testIndex := "test-index-hash"

	tests := []struct {
		name           string
		slug           string
		setupMocks     func() (*mockPatRepository, *mockPatTokener)
		expectError    bool
		errorContains  string
		validateResult func(t *testing.T, result *Pat)
	}{
		{
			name: "success",
			slug: testSlug,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findClientBySlugFunc: func(slug string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             testClientID,
							Name:           testClientName,
							Enabled:        true,
							AccountExpired: false,
							AccountLocked:  false,
						}, nil
					},
					insertPatFunc: func(pat PatRecord) error {
						if pat.PatIndex != testIndex {
							t.Errorf("expected pat index %s, got %s", testIndex, pat.PatIndex)
						}
						if !pat.Active || pat.Revoked || pat.Expired {
							t.Error("expected pat to be active, not revoked, and not expired")
						}
						return nil
					},
					insertPatClientXrefFunc: func(xref PatClientXref) error {
						if xref.ClientID != testClientID {
							t.Errorf("expected client ID %s, got %s", testClientID, xref.ClientID)
						}
						return nil
					},
				}
				tokener := &mockPatTokener{
					generateFunc: func() ([]byte, string, error) {
						return testRawToken, testToken, nil
					},
					obtainIndexFunc: func(raw []byte) (string, error) {
						return testIndex, nil
					},
				}
				return repo, tokener
			},
			expectError: false,
			validateResult: func(t *testing.T, result *Pat) {
				if result.Client != testClientName {
					t.Errorf("expected client name %s, got %s", testClientName, result.Client)
				}
				if result.Token != testToken {
					t.Errorf("expected token %s, got %s", testToken, result.Token)
				}
				if !result.Active || result.Revoked || result.Expired {
					t.Error("expected pat to be active, not revoked, and not expired")
				}
			},
		},
		{
			name: "invalid slug format",
			slug: "invalid-slug",
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				return &mockPatRepository{}, &mockPatTokener{}
			},
			expectError:   true,
			errorContains: "invalid client slug format",
		},
		{
			name: "client not found",
			slug: testSlug,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findClientBySlugFunc: func(slug string) (*clients.ClientRecord, error) {
						return nil, fmt.Errorf("client with slug %s does not exist", slug)
					},
				}
				return repo, &mockPatTokener{}
			},
			expectError:   true,
			errorContains: "does not exist",
		},
		{
			name: "client disabled",
			slug: testSlug,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findClientBySlugFunc: func(slug string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             "client-123",
							Name:           "test-client",
							Enabled:        false,
							AccountExpired: false,
							AccountLocked:  false,
						}, nil
					},
				}
				return repo, &mockPatTokener{}
			},
			expectError:   true,
			errorContains: "is disabled",
		},
		{
			name: "client locked",
			slug: testSlug,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findClientBySlugFunc: func(slug string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             "client-123",
							Name:           "test-client",
							Enabled:        true,
							AccountExpired: false,
							AccountLocked:  true,
						}, nil
					},
				}
				return repo, &mockPatTokener{}
			},
			expectError:   true,
			errorContains: "is locked",
		},
		{
			name: "client expired",
			slug: testSlug,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findClientBySlugFunc: func(slug string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             "client-123",
							Name:           "test-client",
							Enabled:        true,
							AccountExpired: true,
							AccountLocked:  false,
						}, nil
					},
				}
				return repo, &mockPatTokener{}
			},
			expectError:   true,
			errorContains: "has expired",
		},
		{
			name: "token generation failure",
			slug: testSlug,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findClientBySlugFunc: func(slug string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             "client-123",
							Name:           "test-client",
							Enabled:        true,
							AccountExpired: false,
							AccountLocked:  false,
						}, nil
					},
				}
				tokener := &mockPatTokener{
					generateFunc: func() ([]byte, string, error) {
						return nil, "", fmt.Errorf("random generation failed")
					},
				}
				return repo, tokener
			},
			expectError:   true,
			errorContains: "failed to generate pat token",
		},
		{
			name: "index generation failure",
			slug: testSlug,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findClientBySlugFunc: func(slug string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             "client-123",
							Name:           "test-client",
							Enabled:        true,
							AccountExpired: false,
							AccountLocked:  false,
						}, nil
					},
				}
				tokener := &mockPatTokener{
					generateFunc: func() ([]byte, string, error) {
						return []byte("test-raw-token"), "test-token", nil
					},
					obtainIndexFunc: func(raw []byte) (string, error) {
						return "", fmt.Errorf("hashing failed")
					},
				}
				return repo, tokener
			},
			expectError:   true,
			errorContains: "failed to obtain pat index",
		},
		{
			name: "database insert failure",
			slug: testSlug,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findClientBySlugFunc: func(slug string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             "client-123",
							Name:           "test-client",
							Enabled:        true,
							AccountExpired: false,
							AccountLocked:  false,
						}, nil
					},
					insertPatFunc: func(pat PatRecord) error {
						return fmt.Errorf("database constraint violation")
					},
				}
				tokener := &mockPatTokener{
					generateFunc: func() ([]byte, string, error) {
						return []byte("test-raw-token"), "test-token", nil
					},
					obtainIndexFunc: func(raw []byte) (string, error) {
						return "test-index", nil
					},
				}
				return repo, tokener
			},
			expectError:   true,
			errorContains: "failed to persist pat record",
		},
		{
			name: "xref insert failure",
			slug: testSlug,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findClientBySlugFunc: func(slug string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             "client-123",
							Name:           "test-client",
							Enabled:        true,
							AccountExpired: false,
							AccountLocked:  false,
						}, nil
					},
					insertPatFunc: func(pat PatRecord) error {
						return nil
					},
					insertPatClientXrefFunc: func(xref PatClientXref) error {
						return fmt.Errorf("xref insert failed")
					},
				}
				tokener := &mockPatTokener{
					generateFunc: func() ([]byte, string, error) {
						return []byte("test-raw-token"), "test-token", nil
					},
					obtainIndexFunc: func(raw []byte) (string, error) {
						return "test-index", nil
					},
				}
				return repo, tokener
			},
			expectError:   true,
			errorContains: "failed to persist pat-client xref",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			repo, tokener := tt.setupMocks()
			svc := &service{
				sql: repo,
				pat: tokener,
			}

			// Execute
			result, err := svc.GeneratePat(tt.slug)

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
				if result == nil {
					t.Fatal("expected result to not be nil")
				}
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

// contains is a helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && 
		(s == substr || len(s) > len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestIntrospectPat tests the IntrospectPat service method using table-driven tests
func TestIntrospectPat(t *testing.T) {
	testRawToken := []byte("test-raw-token-bytes-64-characters-long-enough-for-validation")
	testToken := base64.StdEncoding.EncodeToString(testRawToken)
	testIndex := "test-index-hash"
	testClientID := "client-uuid-123"
	testServiceName := "test-service"

	tests := []struct {
		name           string
		token          string
		setupMocks     func() (*mockPatRepository, *mockPatTokener)
		expectError    bool
		errorContains  string
		validateResult func(t *testing.T, result *exo.IntrospectResponse)
	}{
		{
			name:  "success with multiple scopes",
			token: testToken,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findPatScopesFunc: func(patIndex string) ([]ScopePatRecord, error) {
						return []ScopePatRecord{
							{
								ScopeId:          "scope-1",
								ServiceName:      testServiceName,
								Scope:            "read:data",
								ScopeName:        "Read Data",
								ScopeDescription: "Read access to data",
								ScopeActive:      true,
								ClientId:         testClientID,
							},
							{
								ScopeId:          "scope-2",
								ServiceName:      testServiceName,
								Scope:            "write:data",
								ScopeName:        "Write Data",
								ScopeDescription: "Write access to data",
								ScopeActive:      true,
								ClientId:         testClientID,
							},
						}, nil
					},
				}
				tokener := &mockPatTokener{
					obtainIndexFunc: func(raw []byte) (string, error) {
						return testIndex, nil
					},
				}
				return repo, tokener
			},
			expectError: false,
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				if !result.Active {
					t.Error("expected token to be active")
				}
				expectedScope := "read:data write:data"
				if result.Scope != expectedScope {
					t.Errorf("expected scope '%s', got '%s'", expectedScope, result.Scope)
				}
				if result.Sub != testClientID {
					t.Errorf("expected subject %s, got %s", testClientID, result.Sub)
				}
				if result.ServiceName != testServiceName {
					t.Errorf("expected service name %s, got %s", testServiceName, result.ServiceName)
				}
			},
		},
		{
			name:  "success with single scope",
			token: testToken,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findPatScopesFunc: func(patIndex string) ([]ScopePatRecord, error) {
						return []ScopePatRecord{
							{
								ScopeId:          "scope-1",
								ServiceName:      testServiceName,
								Scope:            "read:data",
								ScopeName:        "Read Data",
								ScopeDescription: "Read access to data",
								ScopeActive:      true,
								ClientId:         testClientID,
							},
						}, nil
					},
				}
				tokener := &mockPatTokener{
					obtainIndexFunc: func(raw []byte) (string, error) {
						return testIndex, nil
					},
				}
				return repo, tokener
			},
			expectError: false,
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				expectedScope := "read:data"
				if result.Scope != expectedScope {
					t.Errorf("expected scope '%s', got '%s'", expectedScope, result.Scope)
				}
			},
		},
		{
			name:  "invalid token format - too short",
			token: "short",
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				return &mockPatRepository{}, &mockPatTokener{}
			},
			expectError:   true,
			errorContains: "invalid pat token format",
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				// Early validation failures return nil result
				if result != nil {
					t.Error("expected result to be nil for early validation failure")
				}
			},
		},
		{
			name:  "invalid token format - too long",
			token: string(make([]byte, 129)),
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				return &mockPatRepository{}, &mockPatTokener{}
			},
			expectError:   true,
			errorContains: "invalid pat token format",
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				// Early validation failures return nil result
				if result != nil {
					t.Error("expected result to be nil for early validation failure")
				}
			},
		},
		{
			name:  "invalid base64 encoding",
			token: "!!!invalid-base64-that-is-64-characters-long-enough-validation",
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				return &mockPatRepository{}, &mockPatTokener{}
			},
			expectError:   true,
			errorContains: "invalid pat token format",
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				// Early validation failures return nil result
				if result != nil {
					t.Error("expected result to be nil for early validation failure")
				}
			},
		},
		{
			name:  "index generation failure",
			token: testToken,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				tokener := &mockPatTokener{
					obtainIndexFunc: func(raw []byte) (string, error) {
						return "", fmt.Errorf("hashing failed")
					},
				}
				return &mockPatRepository{}, tokener
			},
			expectError:   true,
			errorContains: "failed to obtain lookup index",
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				// Early validation failures return nil result
				if result != nil {
					t.Error("expected result to be nil for early validation failure")
				}
			},
		},
		{
			name:  "pat inactive",
			token: testToken,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findPatScopesFunc: func(patIndex string) ([]ScopePatRecord, error) {
						return []ScopePatRecord{}, nil
					},
					findPatByIndexFunc: func(patIndex string) (*PatRecord, error) {
						return &PatRecord{
							Id:        "pat-uuid",
							PatIndex:  patIndex,
							CreatedAt: data.CustomTime{Time: time.Now()},
							Active:    false,
							Revoked:   false,
							Expired:   false,
						}, nil
					},
				}
				tokener := &mockPatTokener{
					obtainIndexFunc: func(raw []byte) (string, error) {
						return testIndex, nil
					},
				}
				return repo, tokener
			},
			expectError:   true,
			errorContains: "pat token is inactive",
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				if result == nil {
					t.Fatal("expected result to not be nil for buildPatFailResponse cases")
				}
				if result.Active {
					t.Error("expected token to be inactive")
				}
			},
		},
		{
			name:  "pat revoked",
			token: testToken,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findPatScopesFunc: func(patIndex string) ([]ScopePatRecord, error) {
						return []ScopePatRecord{}, nil
					},
					findPatByIndexFunc: func(patIndex string) (*PatRecord, error) {
						return &PatRecord{
							Id:        "pat-uuid",
							PatIndex:  patIndex,
							CreatedAt: data.CustomTime{Time: time.Now()},
							Active:    true,
							Revoked:   true,
							Expired:   false,
						}, nil
					},
				}
				tokener := &mockPatTokener{
					obtainIndexFunc: func(raw []byte) (string, error) {
						return testIndex, nil
					},
				}
				return repo, tokener
			},
			expectError:   true,
			errorContains: "pat token has been revoked",
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				if result == nil {
					t.Fatal("expected result to not be nil for buildPatFailResponse cases")
				}
				if result.Active {
					t.Error("expected token to be inactive")
				}
			},
		},
		{
			name:  "pat expired",
			token: testToken,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findPatScopesFunc: func(patIndex string) ([]ScopePatRecord, error) {
						return []ScopePatRecord{}, nil
					},
					findPatByIndexFunc: func(patIndex string) (*PatRecord, error) {
						return &PatRecord{
							Id:        "pat-uuid",
							PatIndex:  patIndex,
							CreatedAt: data.CustomTime{Time: time.Now()},
							Active:    true,
							Revoked:   false,
							Expired:   true,
						}, nil
					},
				}
				tokener := &mockPatTokener{
					obtainIndexFunc: func(raw []byte) (string, error) {
						return testIndex, nil
					},
				}
				return repo, tokener
			},
			expectError:   true,
			errorContains: "pat token has expired",
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				if result == nil {
					t.Fatal("expected result to not be nil for buildPatFailResponse cases")
				}
				if result.Active {
					t.Error("expected token to be inactive")
				}
			},
		},
		{
			name:  "client disabled",
			token: testToken,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findPatScopesFunc: func(patIndex string) ([]ScopePatRecord, error) {
						return []ScopePatRecord{}, nil
					},
					findPatByIndexFunc: func(patIndex string) (*PatRecord, error) {
						return &PatRecord{
							Id:        "pat-uuid",
							PatIndex:  patIndex,
							CreatedAt: data.CustomTime{Time: time.Now()},
							Active:    true,
							Revoked:   false,
							Expired:   false,
						}, nil
					},
					findClientByPatFunc: func(patIndex string) (*ClientStatus, error) {
						return &ClientStatus{
							Id:             "client-123",
							Name:           "test-client",
							Enabled:        false,
							AccountExpired: false,
							AccountLocked:  false,
						}, nil
					},
				}
				tokener := &mockPatTokener{
					obtainIndexFunc: func(raw []byte) (string, error) {
						return testIndex, nil
					},
				}
				return repo, tokener
			},
			expectError:   true,
			errorContains: "client associated with this pat token is disabled",
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				if result == nil {
					t.Fatal("expected result to not be nil for buildPatFailResponse cases")
				}
				if result.Active {
					t.Error("expected token to be inactive")
				}
			},
		},
		{
			name:  "client locked",
			token: testToken,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findPatScopesFunc: func(patIndex string) ([]ScopePatRecord, error) {
						return []ScopePatRecord{}, nil
					},
					findPatByIndexFunc: func(patIndex string) (*PatRecord, error) {
						return &PatRecord{
							Id:        "pat-uuid",
							PatIndex:  patIndex,
							CreatedAt: data.CustomTime{Time: time.Now()},
							Active:    true,
							Revoked:   false,
							Expired:   false,
						}, nil
					},
					findClientByPatFunc: func(patIndex string) (*ClientStatus, error) {
						return &ClientStatus{
							Id:             "client-123",
							Name:           "test-client",
							Enabled:        true,
							AccountExpired: false,
							AccountLocked:  true,
						}, nil
					},
				}
				tokener := &mockPatTokener{
					obtainIndexFunc: func(raw []byte) (string, error) {
						return testIndex, nil
					},
				}
				return repo, tokener
			},
			expectError:   true,
			errorContains: "client associated with this pat token is locked",
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				if result == nil {
					t.Fatal("expected result to not be nil for buildPatFailResponse cases")
				}
				if result.Active {
					t.Error("expected token to be inactive")
				}
			},
		},
		{
			name:  "client expired",
			token: testToken,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findPatScopesFunc: func(patIndex string) ([]ScopePatRecord, error) {
						return []ScopePatRecord{}, nil
					},
					findPatByIndexFunc: func(patIndex string) (*PatRecord, error) {
						return &PatRecord{
							Id:        "pat-uuid",
							PatIndex:  patIndex,
							CreatedAt: data.CustomTime{Time: time.Now()},
							Active:    true,
							Revoked:   false,
							Expired:   false,
						}, nil
					},
					findClientByPatFunc: func(patIndex string) (*ClientStatus, error) {
						return &ClientStatus{
							Id:             "client-123",
							Name:           "test-client",
							Enabled:        true,
							AccountExpired: true,
							AccountLocked:  false,
						}, nil
					},
				}
				tokener := &mockPatTokener{
					obtainIndexFunc: func(raw []byte) (string, error) {
						return testIndex, nil
					},
				}
				return repo, tokener
			},
			expectError:   true,
			errorContains: "client associated with this pat token has expired",
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				if result == nil {
					t.Fatal("expected result to not be nil for buildPatFailResponse cases")
				}
				if result.Active {
					t.Error("expected token to be inactive")
				}
			},
		},
		{
			name:  "no active scopes found",
			token: testToken,
			setupMocks: func() (*mockPatRepository, *mockPatTokener) {
				repo := &mockPatRepository{
					findPatScopesFunc: func(patIndex string) ([]ScopePatRecord, error) {
						return []ScopePatRecord{}, nil
					},
					findPatByIndexFunc: func(patIndex string) (*PatRecord, error) {
						return &PatRecord{
							Id:        "pat-uuid",
							PatIndex:  patIndex,
							CreatedAt: data.CustomTime{Time: time.Now()},
							Active:    true,
							Revoked:   false,
							Expired:   false,
						}, nil
					},
					findClientByPatFunc: func(patIndex string) (*ClientStatus, error) {
						return &ClientStatus{
							Id:             "client-123",
							Name:           "test-client",
							Enabled:        true,
							AccountExpired: false,
							AccountLocked:  false,
						}, nil
					},
				}
				tokener := &mockPatTokener{
					obtainIndexFunc: func(raw []byte) (string, error) {
						return testIndex, nil
					},
				}
				return repo, tokener
			},
			expectError:   true,
			errorContains: "no active scopes found",
			validateResult: func(t *testing.T, result *exo.IntrospectResponse) {
				if result == nil {
					t.Fatal("expected result to not be nil for buildPatFailResponse cases")
				}
				if result.Active {
					t.Error("expected token to be inactive")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			repo, tokener := tt.setupMocks()
			svc := &service{
				sql: repo,
				pat: tokener,
			}

			// Execute
			result, err := svc.IntrospectPat(tt.token)

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
				if result == nil {
					t.Fatal("expected result to not be nil")
				}
			}

			// Additional validation if provided
			if tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
}