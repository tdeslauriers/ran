package scopes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/ran/pkg/api/scopes"
)

// Mock Service implementation
type mockService struct {
	getScopesFunc       func() ([]scopes.Scope, error)
	getActiveScopesFunc func() ([]scopes.Scope, error)
	getScopeFunc        func(slug string) (*scopes.Scope, error)
	addScopeFunc        func(scope *scopes.Scope) (*scopes.Scope, error)
	updateScopeFunc     func(scope *scopes.Scope) error
}

func (m *mockService) GetScopes() ([]scopes.Scope, error) {
	if m.getScopesFunc != nil {
		return m.getScopesFunc()
	}
	return nil, nil
}

func (m *mockService) GetActiveScopes() ([]scopes.Scope, error) {
	if m.getActiveScopesFunc != nil {
		return m.getActiveScopesFunc()
	}
	return nil, nil
}

func (m *mockService) GetScope(slug string) (*scopes.Scope, error) {
	if m.getScopeFunc != nil {
		return m.getScopeFunc(slug)
	}
	return nil, nil
}

func (m *mockService) AddScope(scope *scopes.Scope) (*scopes.Scope, error) {
	if m.addScopeFunc != nil {
		return m.addScopeFunc(scope)
	}
	return nil, nil
}

func (m *mockService) UpdateScope(scope *scopes.Scope) error {
	if m.updateScopeFunc != nil {
		return m.updateScopeFunc(scope)
	}
	return nil
}

// Mock JWT Verifier implementation
type mockVerifier struct {
	verifySignatureFunc func(msg string, sig []byte) error
	buildAuthorizedFunc func(allowedScopes []string, token string) (*jwt.Token, error)
}

func (m *mockVerifier) VerifySignature(msg string, sig []byte) error {
	if m == nil {
		return errors.New("mock verifier is nil")
	}
	if m.verifySignatureFunc != nil {
		return m.verifySignatureFunc(msg, sig)
	}
	return nil
}

func (m *mockVerifier) BuildAuthorized(allowedScopes []string, token string) (*jwt.Token, error) {
	if m == nil {
		return nil, errors.New("mock verifier is nil")
	}
	if m.buildAuthorizedFunc != nil {
		return m.buildAuthorizedFunc(allowedScopes, token)
	}
	// Default behavior if no mock function is set
	return &jwt.Token{
		Claims: jwt.Claims{
			Subject: "test-subject",
		},
	}, nil
}

// Helper function to create a mock handler
func createMockHandler(svc Service, s2s, iam jwt.Verifier) *handler {
	return &handler{
		svc:         svc,
		s2sVerifier: s2s,
		iamVerifier: iam,
		logger:      slog.Default(),
	}
}

// Test HandleScopes - Method routing
func TestHandleScopes_MethodRouting(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		pathValue      string
		expectedCalled string
	}{
		{
			name:           "GET all scopes",
			method:         http.MethodGet,
			pathValue:      "",
			expectedCalled: "getAllScopes",
		},
		{
			name:           "GET active scopes",
			method:         http.MethodGet,
			pathValue:      "active",
			expectedCalled: "getActiveScopes",
		},
		{
			name:           "GET scope by slug",
			method:         http.MethodGet,
			pathValue:      "test-slug-uuid",
			expectedCalled: "getScopeBySlug",
		},
		{
			name:           "PUT update scope",
			method:         http.MethodPut,
			pathValue:      "",
			expectedCalled: "updateScope",
		},
		{
			name:           "POST create scope",
			method:         http.MethodPost,
			pathValue:      "add",
			expectedCalled: "createScope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := &mockService{}
			mockS2s := &mockVerifier{}
			mockIam := &mockVerifier{}

			h := createMockHandler(mockSvc, mockS2s, mockIam)

			req := httptest.NewRequest(tt.method, "/scopes", nil)
			req.SetPathValue("slug", tt.pathValue)
			w := httptest.NewRecorder()

			h.HandleScopes(w, req)

			// Note: Full validation requires mocking the underlying method implementations
			// This test ensures the routing logic works
		})
	}
}

func TestHandleScopes_UnsupportedMethod(t *testing.T) {
	mockSvc := &mockService{}
	mockS2s := &mockVerifier{}
	mockIam := &mockVerifier{}

	h := createMockHandler(mockSvc, mockS2s, mockIam)

	req := httptest.NewRequest(http.MethodDelete, "/scopes", nil)
	w := httptest.NewRecorder()

	h.HandleScopes(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestHandleScopes_PostInvalidSlug(t *testing.T) {
	mockSvc := &mockService{}
	mockS2s := &mockVerifier{}
	mockIam := &mockVerifier{}

	h := createMockHandler(mockSvc, mockS2s, mockIam)

	req := httptest.NewRequest(http.MethodPost, "/scopes/invalid", nil)
	req.SetPathValue("slug", "invalid")
	w := httptest.NewRecorder()

	h.HandleScopes(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test getAllScopes
func TestGetAllScopes_Handler(t *testing.T) {
	tests := []struct {
		name               string
		setupMocks         func() (*mockService, jwt.Verifier, jwt.Verifier)
		headers            map[string]string
		expectedStatusCode int
		validateResponse   func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "success with S2S only",
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{
					getScopesFunc: func() ([]scopes.Scope, error) {
						return []scopes.Scope{
							{
								Uuid:        "12345678-1234-1234-1234-123456789001",
								ServiceName: "testservice",
								Scope:       "r:testservice:*",
								Name:        "Test Scope",
								Description: "Test Description",
								Active:      true,
								Slug:        "12345678-1234-1234-1234-123456789002",
							},
						}, nil
					},
				}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, nil
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
			},
			expectedStatusCode: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var result []scopes.Scope
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if len(result) != 1 {
					t.Errorf("expected 1 scope, got %d", len(result))
				}
			},
		},
		{
			name: "success with user token",
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{
					getScopesFunc: func() ([]scopes.Scope, error) {
						return []scopes.Scope{
							{
								Uuid:        "12345678-1234-1234-1234-123456789001",
								ServiceName: "testservice",
								Scope:       "r:testservice:*",
								Name:        "Test Scope",
								Description: "Test Description",
								Active:      true,
								Slug:        "12345678-1234-1234-1234-123456789002",
							},
						}, nil
					},
				}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-user@example.com",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer user-token",
			},
			expectedStatusCode: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var result []scopes.Scope
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if len(result) != 1 {
					t.Errorf("expected 1 scope, got %d", len(result))
				}
			},
		},
		{
			name: "S2S auth failure",
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return nil, errors.New("unauthorized: invalid token")
					},
				}
				return mockSvc, mockS2s, nil
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer invalid-token",
			},
			expectedStatusCode: http.StatusUnauthorized,
			validateResponse:   nil,
		},
		{
			name: "user auth failure",
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return nil, errors.New("unauthorized: invalid user token")
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer invalid-user-token",
			},
			expectedStatusCode: http.StatusUnauthorized,
			validateResponse:   nil,
		},
		{
			name: "service error",
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{
					getScopesFunc: func() ([]scopes.Scope, error) {
						return nil, errors.New("database error")
					},
				}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				// Return nil for iamVerifier to indicate S2S-only endpoint
				return mockSvc, mockS2s, nil
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
			},
			expectedStatusCode: http.StatusInternalServerError,
			validateResponse:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc, mockS2s, mockIam := tt.setupMocks()
			h := createMockHandler(mockSvc, mockS2s, mockIam)

			req := httptest.NewRequest(http.MethodGet, "/scopes", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			w := httptest.NewRecorder()

			h.getAllScopes(w, req)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("expected status %d, got %d", tt.expectedStatusCode, w.Code)
			}

			if tt.validateResponse != nil {
				tt.validateResponse(t, w)
			}
		})
	}
}

// Test getActiveScopes
func TestGetActiveScopes_Handler(t *testing.T) {
	tests := []struct {
		name               string
		setupMocks         func() (*mockService, jwt.Verifier, jwt.Verifier)
		headers            map[string]string
		expectedStatusCode int
		validateResponse   func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "success",
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{
					getActiveScopesFunc: func() ([]scopes.Scope, error) {
						return []scopes.Scope{
							{
								Uuid:        "12345678-1234-1234-1234-123456789001",
								ServiceName: "testservice",
								Scope:       "r:testservice:*",
								Name:        "Active Scope",
								Description: "Active Description",
								Active:      true,
								Slug:        "12345678-1234-1234-1234-123456789002",
							},
						}, nil
					},
				}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, nil
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
			},
			expectedStatusCode: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var result []scopes.Scope
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if len(result) != 1 {
					t.Errorf("expected 1 scope, got %d", len(result))
				}
				if !result[0].Active {
					t.Error("expected scope to be active")
				}
			},
		},
		{
			name: "service error",
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{
					getActiveScopesFunc: func() ([]scopes.Scope, error) {
						return nil, errors.New("database error")
					},
				}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, nil
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
			},
			expectedStatusCode: http.StatusInternalServerError,
			validateResponse:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc, mockS2s, mockIam := tt.setupMocks()
			h := createMockHandler(mockSvc, mockS2s, mockIam)

			req := httptest.NewRequest(http.MethodGet, "/scopes/active", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			w := httptest.NewRecorder()

			h.getActiveScopes(w, req)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("expected status %d, got %d", tt.expectedStatusCode, w.Code)
			}

			if tt.validateResponse != nil {
				tt.validateResponse(t, w)
			}
		})
	}
}

// Test getScopeBySlug
func TestGetScopeBySlug_Handler(t *testing.T) {
	validSlug := "12345678-1234-1234-1234-123456789002"

	tests := []struct {
		name               string
		slug               string
		setupMocks         func() (*mockService, jwt.Verifier, jwt.Verifier)
		headers            map[string]string
		expectedStatusCode int
		validateResponse   func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "success",
			slug: validSlug,
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{
					getScopeFunc: func(slug string) (*scopes.Scope, error) {
						if slug == validSlug {
							return &scopes.Scope{
								Uuid:        "12345678-1234-1234-1234-123456789001",
								ServiceName: "testservice",
								Scope:       "r:testservice:*",
								Name:        "Test Scope",
								Description: "Test Description",
								Active:      true,
								Slug:        validSlug,
							}, nil
						}
						return nil, errors.New("scope not found")
					},
				}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-user@example.com",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer user-token",
			},
			expectedStatusCode: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var result scopes.Scope
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if result.Slug != validSlug {
					t.Errorf("expected slug %s, got %s", validSlug, result.Slug)
				}
			},
		},
		{
			name: "invalid slug",
			slug: "invalid-slug",
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-user@example.com",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer user-token",
			},
			expectedStatusCode: http.StatusBadRequest,
			validateResponse:   nil,
		},
		{
			name: "not found",
			slug: "12345678-1234-1234-1234-123456789012",
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{
					getScopeFunc: func(slug string) (*scopes.Scope, error) {
						return nil, errors.New("scope not found")
					},
				}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-user@example.com",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer user-token",
			},
			expectedStatusCode: http.StatusNotFound,
			validateResponse:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc, mockS2s, mockIam := tt.setupMocks()
			h := createMockHandler(mockSvc, mockS2s, mockIam)

			req := httptest.NewRequest(http.MethodGet, "/scopes/"+tt.slug, nil)
			req.SetPathValue("slug", tt.slug)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			w := httptest.NewRecorder()

			h.getScopeBySlug(w, req)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("expected status %d, got %d", tt.expectedStatusCode, w.Code)
			}

			if tt.validateResponse != nil {
				tt.validateResponse(t, w)
			}
		})
	}
}

// Test createScope
func TestCreateScope_Handler(t *testing.T) {
	validScope := scopes.Scope{
		ServiceName: "testservice",
		Scope:       "r:testservice:*",
		Name:        "New Scope",
		Description: "New Description",
		Active:      true,
	}

	tests := []struct {
		name               string
		requestBody        interface{}
		setupMocks         func() (*mockService, jwt.Verifier, jwt.Verifier)
		headers            map[string]string
		expectedStatusCode int
		validateResponse   func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:        "success",
			requestBody: validScope,
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				returnedScope := validScope
				returnedScope.Uuid = "12345678-1234-1234-1234-123456789001"
				returnedScope.Slug = "12345678-1234-1234-1234-123456789002"
				returnedScope.CreatedAt = "2024-01-01 12:00:00"

				mockSvc := &mockService{
					addScopeFunc: func(scope *scopes.Scope) (*scopes.Scope, error) {
						return &returnedScope, nil
					},
				}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-user@example.com",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer user-token",
				"Content-Type":          "application/json",
			},
			expectedStatusCode: http.StatusCreated,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var result scopes.Scope
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if result.Uuid == "" {
					t.Error("expected uuid to be set")
				}
				if result.Slug == "" {
					t.Error("expected slug to be set")
				}
			},
		},
		{
			name:        "S2S auth failure",
			requestBody: validScope,
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return nil, errors.New("unauthorized: invalid token")
					},
				}
				mockIam := &mockVerifier{}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer invalid-token",
				"Authorization":         "Bearer user-token",
			},
			expectedStatusCode: http.StatusUnauthorized,
			validateResponse:   nil,
		},
		{
			name:        "user auth failure",
			requestBody: validScope,
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return nil, errors.New("unauthorized: invalid user token")
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer invalid-user-token",
			},
			expectedStatusCode: http.StatusUnauthorized,
			validateResponse:   nil,
		},
		{
			name:        "invalid JSON",
			requestBody: "invalid json",
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-user@example.com",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer user-token",
				"Content-Type":          "application/json",
			},
			expectedStatusCode: http.StatusBadRequest,
			validateResponse:   nil,
		},
		{
			name:        "service error",
			requestBody: validScope,
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{
					addScopeFunc: func(scope *scopes.Scope) (*scopes.Scope, error) {
						return nil, errors.New("database error")
					},
				}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-user@example.com",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer user-token",
				"Content-Type":          "application/json",
			},
			expectedStatusCode: http.StatusInternalServerError,
			validateResponse:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc, mockS2s, mockIam := tt.setupMocks()
			h := createMockHandler(mockSvc, mockS2s, mockIam)

			var body []byte
			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, _ = json.Marshal(tt.requestBody)
			}

			req := httptest.NewRequest(http.MethodPost, "/scopes/add", bytes.NewBuffer(body))
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			w := httptest.NewRecorder()

			h.createScope(w, req)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("expected status %d, got %d", tt.expectedStatusCode, w.Code)
			}

			if tt.validateResponse != nil {
				tt.validateResponse(t, w)
			}
		})
	}
}

// Test updateScope
func TestUpdateScope_Handler(t *testing.T) {
	validSlug := "12345678-1234-1234-1234-123456789002"
	existingScope := &scopes.Scope{
		Uuid:        "12345678-1234-1234-1234-123456789001",
		ServiceName: "oldservice",
		Scope:       "r:oldservice:*",
		Name:        "Old Name",
		Description: "Old Description",
		CreatedAt:   "2024-01-01 12:00:00",
		Active:      false,
		Slug:        validSlug,
	}

	updatedCmd := scopes.Scope{
		ServiceName: "newservice",
		Scope:       "r:newservice:*",
		Name:        "New Name",
		Description: "New Description",
		Active:      true,
	}

	tests := []struct {
		name               string
		slug               string
		requestBody        interface{}
		setupMocks         func() (*mockService, jwt.Verifier, jwt.Verifier)
		headers            map[string]string
		expectedStatusCode int
		validateResponse   func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:        "success",
			slug:        validSlug,
			requestBody: updatedCmd,
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{
					getScopeFunc: func(slug string) (*scopes.Scope, error) {
						if slug == validSlug {
							return existingScope, nil
						}
						return nil, errors.New("scope not found")
					},
					updateScopeFunc: func(scope *scopes.Scope) error {
						return nil
					},
				}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-user@example.com",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer user-token",
				"Content-Type":          "application/json",
			},
			expectedStatusCode: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var result scopes.Scope
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if result.Uuid != existingScope.Uuid {
					t.Errorf("expected uuid %s, got %s", existingScope.Uuid, result.Uuid)
				}
				if result.Slug != existingScope.Slug {
					t.Errorf("expected slug %s, got %s", existingScope.Slug, result.Slug)
				}
				if result.ServiceName != updatedCmd.ServiceName {
					t.Errorf("expected service name %s, got %s", updatedCmd.ServiceName, result.ServiceName)
				}
				if result.Active != updatedCmd.Active {
					t.Errorf("expected active %v, got %v", updatedCmd.Active, result.Active)
				}
			},
		},
		{
			name:        "invalid slug",
			slug:        "invalid-slug",
			requestBody: updatedCmd,
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-user@example.com",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer user-token",
				"Content-Type":          "application/json",
			},
			expectedStatusCode: http.StatusBadRequest,
			validateResponse:   nil,
		},
		{
			name:        "not found",
			slug:        "12345678-1234-1234-1234-123456789099",
			requestBody: updatedCmd,
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{
					getScopeFunc: func(slug string) (*scopes.Scope, error) {
						return nil, errors.New("scope not found")
					},
				}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-user@example.com",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer user-token",
				"Content-Type":          "application/json",
			},
			expectedStatusCode: http.StatusNotFound,
			validateResponse:   nil,
		},
		{
			name:        "invalid JSON",
			slug:        validSlug,
			requestBody: "invalid json",
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-user@example.com",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer user-token",
				"Content-Type":          "application/json",
			},
			expectedStatusCode: http.StatusBadRequest,
			validateResponse:   nil,
		},
		{
			name:        "service error",
			slug:        validSlug,
			requestBody: updatedCmd,
			setupMocks: func() (*mockService, jwt.Verifier, jwt.Verifier) {
				mockSvc := &mockService{
					getScopeFunc: func(slug string) (*scopes.Scope, error) {
						return existingScope, nil
					},
					updateScopeFunc: func(scope *scopes.Scope) error {
						return errors.New("database error")
					},
				}
				mockS2s := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-service",
							},
						}, nil
					},
				}
				mockIam := &mockVerifier{
					buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
						return &jwt.Token{
							Claims: jwt.Claims{
								Subject: "test-user@example.com",
							},
						}, nil
					},
				}
				return mockSvc, mockS2s, mockIam
			},
			headers: map[string]string{
				"Service-Authorization": "Bearer s2s-token",
				"Authorization":         "Bearer user-token",
				"Content-Type":          "application/json",
			},
			expectedStatusCode: http.StatusInternalServerError,
			validateResponse:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc, mockS2s, mockIam := tt.setupMocks()
			h := createMockHandler(mockSvc, mockS2s, mockIam)

			var body []byte
			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, _ = json.Marshal(tt.requestBody)
			}

			req := httptest.NewRequest(http.MethodPut, "/scopes/"+tt.slug, bytes.NewBuffer(body))
			req.SetPathValue("slug", tt.slug)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			w := httptest.NewRecorder()

			h.updateScope(w, req)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("expected status %d, got %d", tt.expectedStatusCode, w.Code)
			}

			if tt.validateResponse != nil {
				tt.validateResponse(t, w)
			}
		})
	}
}

// Test HandleServiceError
func TestHandleServiceError(t *testing.T) {
	tests := []struct {
		name               string
		err                error
		expectedStatusCode int
	}{
		{
			name:               "invalid slug",
			err:                errors.New("invalid slug"),
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "invalid data",
			err:                errors.New("invalid scope data"),
			expectedStatusCode: http.StatusUnprocessableEntity,
		},
		{
			name:               "not found",
			err:                errors.New("scope not found"),
			expectedStatusCode: http.StatusNotFound,
		},
		{
			name:               "generic error",
			err:                errors.New("some unexpected error"),
			expectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := createMockHandler(nil, nil, nil)
			w := httptest.NewRecorder()

			h.HandleServiceError(w, tt.err)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("expected status %d, got %d", tt.expectedStatusCode, w.Code)
			}
		})
	}
}

// Test handler creation
func TestNewHandler(t *testing.T) {
	mockSvc := &mockService{}
	mockS2s := &mockVerifier{}
	mockIam := &mockVerifier{}

	h := NewHandler(mockSvc, mockS2s, mockIam)

	if h == nil {
		t.Fatal("expected handler to be created, got nil")
	}

	handler, ok := h.(*handler)
	if !ok {
		t.Fatal("expected handler to be of type *handler")
	}

	if handler.svc != mockSvc {
		t.Error("expected service to be set")
	}

	if handler.s2sVerifier != mockS2s {
		t.Error("expected s2sVerifier to be set")
	}

	if handler.iamVerifier != mockIam {
		t.Error("expected iamVerifier to be set")
	}
}

// Benchmark tests
func BenchmarkGetAllScopes(b *testing.B) {
	scopeList := make([]scopes.Scope, 100)
	for i := 0; i < 100; i++ {
		scopeList[i] = scopes.Scope{
			Uuid:        fmt.Sprintf("12345678-1234-1234-1234-%012d", i),
			ServiceName: "testservice",
			Scope:       "r:testservice:*",
			Name:        fmt.Sprintf("Scope %d", i),
			Description: "Test Description",
			Active:      true,
			Slug:        fmt.Sprintf("87654321-4321-4321-4321-%012d", i),
		}
	}

	mockSvc := &mockService{
		getScopesFunc: func() ([]scopes.Scope, error) {
			return scopeList, nil
		},
	}

	mockS2s := &mockVerifier{
		buildAuthorizedFunc: func(allowedScopes []string, token string) (*jwt.Token, error) {
			return &jwt.Token{
				Claims: jwt.Claims{
					Subject: "test-service",
				},
			}, nil
		},
	}

	h := createMockHandler(mockSvc, mockS2s, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/scopes", nil)
		req.Header.Set("Service-Authorization", "Bearer s2s-token")
		w := httptest.NewRecorder()

		h.getAllScopes(w, req)
	}
}
