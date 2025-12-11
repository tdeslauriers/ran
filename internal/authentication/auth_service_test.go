package authentication

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/ran/internal/clients"
	"github.com/tdeslauriers/ran/pkg/api/scopes"
)

// MockAuthRepository is a mock implementation of the AuthRepository interface for testing
type MockAuthRepository struct {
	RefreshExistsFunc        func(index string) (bool, error)
	GetClientByIdFunc        func(id string) (*clients.ClientRecord, error)
	GetScopesFunc            func(clientId string, service string) ([]scopes.Scope, error)
	FindRefreshTokenFunc     func(index string) (*types.S2sRefresh, error)
	InsertRefreshTokenFunc   func(token types.S2sRefresh) error
	UpdateRefreshTokenFunc   func(token types.S2sRefresh) error
	DeleteRefreshByIdFunc    func(id string) error
	DeleteRefreshByIndexFunc func(index string) error
}

var _ AuthRepository = (*MockAuthRepository)(nil)

func (m *MockAuthRepository) RefreshExists(index string) (bool, error) {
	if m.RefreshExistsFunc != nil {
		return m.RefreshExistsFunc(index)
	}
	return false, nil
}

func (m *MockAuthRepository) FindClientById(id string) (*clients.ClientRecord, error) {
	if m.GetClientByIdFunc != nil {
		return m.GetClientByIdFunc(id)
	}
	return nil, nil
}

func (m *MockAuthRepository) FindScopes(clientId string, service string) ([]scopes.Scope, error) {
	if m.GetScopesFunc != nil {
		return m.GetScopesFunc(clientId, service)
	}
	return nil, nil
}

func (m *MockAuthRepository) FindRefreshToken(index string) (*types.S2sRefresh, error) {
	if m.FindRefreshTokenFunc != nil {
		return m.FindRefreshTokenFunc(index)
	}
	return nil, nil
}

func (m *MockAuthRepository) InsertRefreshToken(token types.S2sRefresh) error {
	if m.InsertRefreshTokenFunc != nil {
		return m.InsertRefreshTokenFunc(token)
	}
	return nil
}

func (m *MockAuthRepository) UpdateRefreshToken(token types.S2sRefresh) error {
	if m.UpdateRefreshTokenFunc != nil {
		return m.UpdateRefreshTokenFunc(token)
	}
	return nil
}

func (m *MockAuthRepository) DeleteRefreshById(id string) error {
	if m.DeleteRefreshByIdFunc != nil {
		return m.DeleteRefreshByIdFunc(id)
	}
	return nil
}

func (m *MockAuthRepository) DeleteRefreshByIndex(index string) error {
	if m.DeleteRefreshByIndexFunc != nil {
		return m.DeleteRefreshByIndexFunc(index)
	}
	return nil
}

// MockSigner is a mock implementation of the jwt.Signer interface for testing
type MockSigner struct {
	MintFunc func(*jwt.Token) error
}

var _ jwt.Signer = (*MockSigner)(nil)

func (m *MockSigner) Mint(token *jwt.Token) error {
	if m.MintFunc != nil {
		return m.MintFunc(token)
	}
	// Default behavior: set signature and token string
	token.Signature = []byte("mock-signature")
	token.Token = token.BaseString + ".mock-signature"
	return nil
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsHelper(s, substr)))
}

// MockIndexer is a mock implementation of the data.Indexer interface for testing
type MockIndexer struct {
	ObtainBlindIndexFunc func(string) (string, error)
}

var _ data.Indexer = (*MockIndexer)(nil)

func (m *MockIndexer) ObtainBlindIndex(s string) (string, error) {
	if m.ObtainBlindIndexFunc != nil {
		return m.ObtainBlindIndexFunc(s)
	}
	// Default behavior: return a predictable mock index
	return "mock-index-" + s, nil
}

// MockCryptor is a mock implementation of the data.Cryptor interface for testing
type MockCryptor struct {
	EncryptServiceDataFunc func([]byte) (string, error)
	DecryptServiceDataFunc func(string) ([]byte, error)
}

var _ data.Cryptor = (*MockCryptor)(nil)

func (m *MockCryptor) EncryptServiceData(clear []byte) (string, error) {
	if m.EncryptServiceDataFunc != nil {
		return m.EncryptServiceDataFunc(clear)
	}
	// Default behavior: simple base64 encoding for predictable testing
	return base64.StdEncoding.EncodeToString(clear), nil
}

func (m *MockCryptor) DecryptServiceData(ciphertext string) ([]byte, error) {
	if m.DecryptServiceDataFunc != nil {
		return m.DecryptServiceDataFunc(ciphertext)
	}
	// Default behavior: simple base64 decoding for predictable testing
	return base64.StdEncoding.DecodeString(ciphertext)
}

// MockCredService is a mock implementation of the CredService interface for testing
type MockCredService struct {
	GenerateAccessTokenFunc      func() (string, error)
	GenerateHashFromPasswordFunc func(password string) (string, error)
	CompareHashAndPasswordFunc   func(hash, password string) error
}

var _ CredService = (*MockCredService)(nil)

func (m *MockCredService) GenerateAccessToken() (string, error) {
	if m.GenerateAccessTokenFunc != nil {
		return m.GenerateAccessTokenFunc()
	}
	return "dws_mock-access-token-42-characters-long", nil
}

func (m *MockCredService) GenerateHashFromPassword(password string) (string, error) {
	if m.GenerateHashFromPasswordFunc != nil {
		return m.GenerateHashFromPasswordFunc(password)
	}
	return "mock-hash-" + password, nil
}

func (m *MockCredService) CompareHashAndPassword(hash, password string) error {
	if m.CompareHashAndPasswordFunc != nil {
		return m.CompareHashAndPasswordFunc(hash, password)
	}
	// Default behavior: simple string comparison for testing
	expectedHash := "mock-hash-" + password
	if hash != expectedHash {
		return fmt.Errorf("hash and password do not match")
	}
	return nil
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// ValidateCredentials Tests
// =============================================================================

func TestValidateCredentials(t *testing.T) {
	testCases := []struct {
		name          string
		clientId      string
		clientSecret  string
		setupRepo     func() *MockAuthRepository
		setupCreds    func() *MockCredService
		expectError   bool
		errorContains string
	}{
		{
			name:         "successful validation",
			clientId:     "test-client-id",
			clientSecret: "test-secret",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					GetClientByIdFunc: func(id string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             "test-client-id",
							Password:       "mock-hash-test-secret",
							Name:           "Test Client",
							Owner:          "test-owner",
							CreatedAt:      data.CustomTime{Time: time.Now()},
							Enabled:        true,
							AccountExpired: false,
							AccountLocked:  false,
							Slug:           "test-client",
						}, nil
					},
				}
			},
			setupCreds: func() *MockCredService {
				return &MockCredService{
					CompareHashAndPasswordFunc: func(hash, password string) error {
						if hash == "mock-hash-test-secret" && password == "test-secret" {
							return nil
						}
						return fmt.Errorf("hash and password do not match")
					},
				}
			},
			expectError: false,
		},
		{
			name:         "client not found",
			clientId:     "nonexistent-client",
			clientSecret: "test-secret",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					GetClientByIdFunc: func(id string) (*clients.ClientRecord, error) {
						return nil, fmt.Errorf("s2s client with id %s does not exist", id)
					},
				}
			},
			setupCreds: func() *MockCredService {
				return &MockCredService{}
			},
			expectError:   true,
			errorContains: "does not exist",
		},
		{
			name:         "client not enabled",
			clientId:     "disabled-client",
			clientSecret: "test-secret",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					GetClientByIdFunc: func(id string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             "disabled-client",
							Password:       "mock-hash-test-secret",
							Name:           "Disabled Client",
							Owner:          "test-owner",
							CreatedAt:      data.CustomTime{Time: time.Now()},
							Enabled:        false,
							AccountExpired: false,
							AccountLocked:  false,
							Slug:           "disabled-client",
						}, nil
					},
				}
			},
			setupCreds: func() *MockCredService {
				return &MockCredService{}
			},
			expectError:   true,
			errorContains: "is not enabled",
		},
		{
			name:         "client account locked",
			clientId:     "locked-client",
			clientSecret: "test-secret",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					GetClientByIdFunc: func(id string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             "locked-client",
							Password:       "mock-hash-test-secret",
							Name:           "Locked Client",
							Owner:          "test-owner",
							CreatedAt:      data.CustomTime{Time: time.Now()},
							Enabled:        true,
							AccountExpired: false,
							AccountLocked:  true,
							Slug:           "locked-client",
						}, nil
					},
				}
			},
			setupCreds: func() *MockCredService {
				return &MockCredService{}
			},
			expectError:   true,
			errorContains: "is locked",
		},
		{
			name:         "client account expired",
			clientId:     "expired-client",
			clientSecret: "test-secret",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					GetClientByIdFunc: func(id string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             "expired-client",
							Password:       "mock-hash-test-secret",
							Name:           "Expired Client",
							Owner:          "test-owner",
							CreatedAt:      data.CustomTime{Time: time.Now()},
							Enabled:        true,
							AccountExpired: true,
							AccountLocked:  false,
							Slug:           "expired-client",
						}, nil
					},
				}
			},
			setupCreds: func() *MockCredService {
				return &MockCredService{}
			},
			expectError:   true,
			errorContains: "has expired",
		},
		{
			name:         "invalid password",
			clientId:     "test-client",
			clientSecret: "wrong-password",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					GetClientByIdFunc: func(id string) (*clients.ClientRecord, error) {
						return &clients.ClientRecord{
							Id:             "test-client",
							Password:       "mock-hash-correct-password",
							Name:           "Test Client",
							Owner:          "test-owner",
							CreatedAt:      data.CustomTime{Time: time.Now()},
							Enabled:        true,
							AccountExpired: false,
							AccountLocked:  false,
							Slug:           "test-client",
						}, nil
					},
				}
			},
			setupCreds: func() *MockCredService {
				return &MockCredService{
					CompareHashAndPasswordFunc: func(hash, password string) error {
						return fmt.Errorf("hash and password do not match")
					},
				}
			},
			expectError:   true,
			errorContains: "failed to validate credentials",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service := &s2sAuthService{
				sql:         tc.setupRepo(),
				credService: tc.setupCreds(),
			}

			err := service.ValidateCredentials(tc.clientId, tc.clientSecret)

			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tc.errorContains != "" && !contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain '%s', got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// =============================================================================
// GetScopes Tests
// =============================================================================

func TestGetScopes(t *testing.T) {
	testCases := []struct {
		name          string
		clientId      string
		service       string
		setupRepo     func() *MockAuthRepository
		expectedCount int
		expectError   bool
		errorContains string
	}{
		{
			name:     "successful scope retrieval",
			clientId: "test-client-id",
			service:  "test-service",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					GetScopesFunc: func(clientId string, service string) ([]scopes.Scope, error) {
						return []scopes.Scope{
							{
								Uuid:        "scope-1",
								ServiceName: "test-service",
								Scope:       "read:data",
								Name:        "Read Data",
								Description: "Allows reading data",
								CreatedAt:   time.Now().String(),
								Active:      true,
								Slug:        "read-data",
							},
							{
								Uuid:        "scope-2",
								ServiceName: "test-service",
								Scope:       "write:data",
								Name:        "Write Data",
								Description: "Allows writing data",
								CreatedAt:   time.Now().String(),
								Active:      true,
								Slug:        "write-data",
							},
						}, nil
					},
				}
			},
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:     "no scopes found",
			clientId: "test-client-id",
			service:  "unknown-service",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					GetScopesFunc: func(clientId string, service string) ([]scopes.Scope, error) {
						return []scopes.Scope{}, nil
					},
				}
			},
			expectedCount: 0,
			expectError:   false,
		},
		{
			name:     "database error",
			clientId: "test-client-id",
			service:  "test-service",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					GetScopesFunc: func(clientId string, service string) ([]scopes.Scope, error) {
						return nil, fmt.Errorf("failed to retrieve scopes for client id %s and service %s: database error", clientId, service)
					},
				}
			},
			expectedCount: 0,
			expectError:   true,
			errorContains: "failed to retrieve scopes",
		},
		{
			name:     "single scope",
			clientId: "limited-client",
			service:  "test-service",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					GetScopesFunc: func(clientId string, service string) ([]scopes.Scope, error) {
						return []scopes.Scope{
							{
								Uuid:        "scope-1",
								ServiceName: "test-service",
								Scope:       "read:data",
								Name:        "Read Data",
								Description: "Allows reading data",
								CreatedAt:   time.Now().String(),
								Active:      true,
								Slug:        "read-data",
							},
						}, nil
					},
				}
			},
			expectedCount: 1,
			expectError:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service := &s2sAuthService{
				sql: tc.setupRepo(),
			}

			result, err := service.GetScopes(tc.clientId, tc.service)

			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tc.errorContains != "" && !contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain '%s', got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(result) != tc.expectedCount {
					t.Errorf("expected %d scopes, got %d", tc.expectedCount, len(result))
				}
			}
		})
	}
}

// =============================================================================
// MintToken Tests
// =============================================================================

func TestMintToken(t *testing.T) {
	testCases := []struct {
		name          string
		claims        jwt.Claims
		setupSigner   func() *MockSigner
		expectError   bool
		errorContains string
		validateToken func(*testing.T, *jwt.Token)
	}{
		{
			name: "successful token minting",
			claims: jwt.Claims{
				Jti:      "test-jti",
				Issuer:   "test-issuer",
				Subject:  "test-subject",
				Audience: []string{"test-audience"},
				IssuedAt: time.Now().Unix(),
				Expires:  time.Now().Add(5 * time.Minute).Unix(),
				Scopes:   "read:data write:data",
			},
			setupSigner: func() *MockSigner {
				return &MockSigner{
					MintFunc: func(token *jwt.Token) error {
						token.Signature = []byte("test-signature")
						token.Token = token.BaseString + ".dGVzdC1zaWduYXR1cmU"
						return nil
					},
				}
			},
			expectError: false,
			validateToken: func(t *testing.T, token *jwt.Token) {
				if token == nil {
					t.Error("expected token but got nil")
					return
				}
				if token.Header.Alg != jwt.ES512 {
					t.Errorf("expected algorithm %s, got %s", jwt.ES512, token.Header.Alg)
				}
				if token.Header.Typ != jwt.TokenType {
					t.Errorf("expected type %s, got %s", jwt.TokenType, token.Header.Typ)
				}
				if len(token.Signature) == 0 {
					t.Error("expected signature but got empty")
				}
				if len(token.Token) == 0 {
					t.Error("expected token string but got empty")
				}
			},
		},
		{
			name: "signer error",
			claims: jwt.Claims{
				Jti:      "test-jti",
				Issuer:   "test-issuer",
				Subject:  "test-subject",
				Audience: []string{"test-audience"},
				IssuedAt: time.Now().Unix(),
				Expires:  time.Now().Add(5 * time.Minute).Unix(),
			},
			setupSigner: func() *MockSigner {
				return &MockSigner{
					MintFunc: func(token *jwt.Token) error {
						return fmt.Errorf("signing error: failed to sign token")
					},
				}
			},
			expectError:   true,
			errorContains: "failed to mint jwt",
		},
		{
			name: "token with multiple audiences",
			claims: jwt.Claims{
				Jti:      "test-jti",
				Issuer:   "test-issuer",
				Subject:  "test-subject",
				Audience: []string{"audience-1", "audience-2", "audience-3"},
				IssuedAt: time.Now().Unix(),
				Expires:  time.Now().Add(5 * time.Minute).Unix(),
				Scopes:   "read:data write:data admin:all",
			},
			setupSigner: func() *MockSigner {
				return &MockSigner{}
			},
			expectError: false,
			validateToken: func(t *testing.T, token *jwt.Token) {
				if token == nil {
					t.Error("expected token but got nil")
					return
				}
				if len(token.Claims.Audience) != 3 {
					t.Errorf("expected 3 audiences, got %d", len(token.Claims.Audience))
				}
			},
		},
		{
			name: "token with optional fields",
			claims: jwt.Claims{
				Jti:        "test-jti",
				Issuer:     "test-issuer",
				Subject:    "test-subject",
				Audience:   []string{"test-audience"},
				IssuedAt:   time.Now().Unix(),
				NotBefore:  time.Now().Unix(),
				Expires:    time.Now().Add(5 * time.Minute).Unix(),
				Scopes:     "read:data",
				Nonce:      "test-nonce",
				Email:      "test@example.com",
				Name:       "Test User",
				GivenName:  "Test",
				FamilyName: "User",
				Birthdate:  "1990-01-01",
			},
			setupSigner: func() *MockSigner {
				return &MockSigner{}
			},
			expectError: false,
			validateToken: func(t *testing.T, token *jwt.Token) {
				if token == nil {
					t.Error("expected token but got nil")
					return
				}
				if token.Claims.Email != "test@example.com" {
					t.Errorf("expected email 'test@example.com', got '%s'", token.Claims.Email)
				}
				if token.Claims.Nonce != "test-nonce" {
					t.Errorf("expected nonce 'test-nonce', got '%s'", token.Claims.Nonce)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service := &s2sAuthService{
				mint: tc.setupSigner(),
			}

			token, err := service.MintToken(tc.claims)

			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				} else if tc.errorContains != "" && !contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain '%s', got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tc.validateToken != nil {
					tc.validateToken(t, token)
				}
			}
		})
	}
}

// =============================================================================
// PersistRefresh Tests
// =============================================================================

func TestPersistRefresh(t *testing.T) {
	testCases := []struct {
		name          string
		refresh       types.S2sRefresh
		setupRepo     func() *MockAuthRepository
		setupIndexer  func() *MockIndexer
		setupCryptor  func() *MockCryptor
		expectError   bool
		errorContains string
	}{
		{
			name: "successful refresh persistence",
			refresh: types.S2sRefresh{
				ServiceName:  "test-service",
				RefreshToken: "test-refresh-token-1234567890",
				ClientId:     "test-client-id",
				CreatedAt:    data.CustomTime{Time: time.Now()},
				Revoked:      false,
			},
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					InsertRefreshTokenFunc: func(token types.S2sRefresh) error {
						if token.Uuid == "" {
							return fmt.Errorf("uuid not set")
						}
						if token.RefreshIndex == "" {
							return fmt.Errorf("refresh index not set")
						}
						if token.ClientIndex == "" {
							return fmt.Errorf("client index not set")
						}
						return nil
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{}
			},
			expectError: false,
		},
		{
			name: "indexer error for refresh token",
			refresh: types.S2sRefresh{
				ServiceName:  "test-service",
				RefreshToken: "test-refresh-token-1234567890",
				ClientId:     "test-client-id",
				CreatedAt:    data.CustomTime{Time: time.Now()},
				Revoked:      false,
			},
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				callCount := 0
				return &MockIndexer{
					ObtainBlindIndexFunc: func(s string) (string, error) {
						callCount++
						if s == "test-refresh-token-1234567890" {
							return "", fmt.Errorf("failed to generate blind index")
						}
						return "mock-index-" + s, nil
					},
				}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{}
			},
			expectError:   true,
			errorContains: ErrGenIndex,
		},
		{
			name: "encryption error for service name",
			refresh: types.S2sRefresh{
				ServiceName:  "test-service",
				RefreshToken: "test-refresh-token-1234567890",
				ClientId:     "test-client-id",
				CreatedAt:    data.CustomTime{Time: time.Now()},
				Revoked:      false,
			},
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{
					EncryptServiceDataFunc: func(clear []byte) (string, error) {
						if string(clear) == "test-service" {
							return "", fmt.Errorf("encryption failed")
						}
						return "encrypted-" + string(clear), nil
					},
				}
			},
			expectError:   true,
			errorContains: ErrEncryptServiceName,
		},
		{
			name: "encryption error for refresh token",
			refresh: types.S2sRefresh{
				ServiceName:  "test-service",
				RefreshToken: "test-refresh-token-1234567890",
				ClientId:     "test-client-id",
				CreatedAt:    data.CustomTime{Time: time.Now()},
				Revoked:      false,
			},
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{
					EncryptServiceDataFunc: func(clear []byte) (string, error) {
						if string(clear) == "test-refresh-token-1234567890" {
							return "", fmt.Errorf("encryption failed")
						}
						return "encrypted-" + string(clear), nil
					},
				}
			},
			expectError:   true,
			errorContains: ErrEncryptRefresh,
		},
		{
			name: "encryption error for client id",
			refresh: types.S2sRefresh{
				ServiceName:  "test-service",
				RefreshToken: "test-refresh-token-1234567890",
				ClientId:     "test-client-id",
				CreatedAt:    data.CustomTime{Time: time.Now()},
				Revoked:      false,
			},
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{
					EncryptServiceDataFunc: func(clear []byte) (string, error) {
						if string(clear) == "test-client-id" {
							return "", fmt.Errorf("encryption failed")
						}
						return "encrypted-" + string(clear), nil
					},
				}
			},
			expectError:   true,
			errorContains: ErrEncryptClientId,
		},
		{
			name: "database insert error",
			refresh: types.S2sRefresh{
				ServiceName:  "test-service",
				RefreshToken: "test-refresh-token-1234567890",
				ClientId:     "test-client-id",
				CreatedAt:    data.CustomTime{Time: time.Now()},
				Revoked:      false,
			},
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					InsertRefreshTokenFunc: func(token types.S2sRefresh) error {
						return fmt.Errorf("database connection failed")
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{}
			},
			expectError:   true,
			errorContains: "failed to persist refresh token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service := &s2sAuthService{
				sql:     tc.setupRepo(),
				indexer: tc.setupIndexer(),
				cryptor: tc.setupCryptor(),
			}

			err := service.PersistRefresh(tc.refresh)

			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				} else if tc.errorContains != "" && !contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain '%s', got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// =============================================================================
// GetRefreshToken Tests
// =============================================================================

func TestGetRefreshToken(t *testing.T) {
	testCases := []struct {
		name          string
		refreshToken  string
		setupRepo     func() *MockAuthRepository
		setupIndexer  func() *MockIndexer
		setupCryptor  func() *MockCryptor
		expectError   bool
		errorContains string
		validate      func(*testing.T, *types.S2sRefresh)
	}{
		{
			name:         "successful refresh token retrieval",
			refreshToken: "valid-refresh-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					FindRefreshTokenFunc: func(index string) (*types.S2sRefresh, error) {
						return &types.S2sRefresh{
							Uuid:         "test-uuid",
							RefreshIndex: index,
							ServiceName:  "dGVzdC1zZXJ2aWNl",
							RefreshToken: "dmFsaWQtcmVmcmVzaC10b2tlbi0xMjM0NTY3ODkw",
							ClientId:     "dGVzdC1jbGllbnQtaWQ=",
							ClientIndex:  "test-client-index",
							CreatedAt:    data.CustomTime{Time: time.Now()},
							Revoked:      false,
						}, nil
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{}
			},
			expectError: false,
			validate: func(t *testing.T, refresh *types.S2sRefresh) {
				if refresh == nil {
					t.Error("expected refresh token but got nil")
					return
				}
				if refresh.ServiceName != "test-service" {
					t.Errorf("expected service name 'test-service', got '%s'", refresh.ServiceName)
				}
				if refresh.ClientId != "test-client-id" {
					t.Errorf("expected client id 'test-client-id', got '%s'", refresh.ClientId)
				}
			},
		},
		{
			name:         "invalid refresh token length - too short",
			refreshToken: "short",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{}
			},
			expectError:   true,
			errorContains: "invalid refresh token",
		},
		{
			name:         "invalid refresh token length - too long",
			refreshToken: "this-is-a-very-long-refresh-token-that-exceeds-the-maximum-allowed-length-of-64-characters",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{}
			},
			expectError:   true,
			errorContains: "invalid refresh token",
		},
		{
			name:         "indexer error",
			refreshToken: "valid-refresh-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{
					ObtainBlindIndexFunc: func(s string) (string, error) {
						return "", fmt.Errorf("failed to create index")
					},
				}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{}
			},
			expectError:   true,
			errorContains: "failed to create blind index value",
		},
		{
			name:         "refresh token not found",
			refreshToken: "nonexistent-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					FindRefreshTokenFunc: func(index string) (*types.S2sRefresh, error) {
						return nil, fmt.Errorf("refresh token with index %s does not exist", index)
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{}
			},
			expectError:   true,
			errorContains: "does not exist",
		},
		{
			name:         "revoked refresh token",
			refreshToken: "revoked-refresh-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					FindRefreshTokenFunc: func(index string) (*types.S2sRefresh, error) {
						return &types.S2sRefresh{
							Uuid:         "test-uuid",
							RefreshIndex: index,
							ServiceName:  "dGVzdC1zZXJ2aWNl",
							RefreshToken: "cmV2b2tlZC1yZWZyZXNoLXRva2VuLTEyMzQ1Njc4OTA=",
							ClientId:     "dGVzdC1jbGllbnQtaWQ=",
							ClientIndex:  "test-client-index",
							CreatedAt:    data.CustomTime{Time: time.Now()},
							Revoked:      true,
						}, nil
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{}
			},
			expectError:   true,
			errorContains: "has been revoked",
		},
		{
			name:         "expired refresh token",
			refreshToken: "expired-refresh-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					FindRefreshTokenFunc: func(index string) (*types.S2sRefresh, error) {
						return &types.S2sRefresh{
							Uuid:         "test-uuid",
							RefreshIndex: index,
							ServiceName:  "dGVzdC1zZXJ2aWNl",
							RefreshToken: "ZXhwaXJlZC1yZWZyZXNoLXRva2VuLTEyMzQ1Njc4OTA=",
							ClientId:     "dGVzdC1jbGllbnQtaWQ=",
							ClientIndex:  "test-client-index",
							CreatedAt:    data.CustomTime{Time: time.Now().Add(-200 * time.Minute)},
							Revoked:      false,
						}, nil
					},
					DeleteRefreshByIdFunc: func(id string) error {
						return nil
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{}
			},
			expectError:   true,
			errorContains: "is expired",
		},
		{
			name:         "decryption error for service name",
			refreshToken: "valid-refresh-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					FindRefreshTokenFunc: func(index string) (*types.S2sRefresh, error) {
						return &types.S2sRefresh{
							Uuid:         "test-uuid",
							RefreshIndex: index,
							ServiceName:  "corrupted-service-data",
							RefreshToken: "dmFsaWQtcmVmcmVzaC10b2tlbi0xMjM0NTY3ODkw",
							ClientId:     "dGVzdC1jbGllbnQtaWQ=",
							ClientIndex:  "test-client-index",
							CreatedAt:    data.CustomTime{Time: time.Now()},
							Revoked:      false,
						}, nil
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			setupCryptor: func() *MockCryptor {
				return &MockCryptor{
					DecryptServiceDataFunc: func(ciphertext string) ([]byte, error) {
						if ciphertext == "corrupted-service-data" {
							return nil, fmt.Errorf("decryption failed")
						}
						return nil, nil
					},
				}
			},
			expectError:   true,
			errorContains: "failed to decrypt service name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service := &s2sAuthService{
				sql:     tc.setupRepo(),
				indexer: tc.setupIndexer(),
				cryptor: tc.setupCryptor(),
				logger:  slog.Default(),
			}

			ctx := context.Background()

			result, err := service.GetRefreshToken(ctx, tc.refreshToken)

			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				} else if tc.errorContains != "" && !contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain '%s', got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tc.validate != nil {
					tc.validate(t, result)
				}
			}
		})
	}
}

// =============================================================================
// DestroyRefresh Tests
// =============================================================================

func TestDestroyRefresh(t *testing.T) {
	testCases := []struct {
		name          string
		token         string
		setupRepo     func() *MockAuthRepository
		setupIndexer  func() *MockIndexer
		expectError   bool
		errorContains string
	}{
		{
			name:  "successful refresh deletion",
			token: "valid-refresh-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					RefreshExistsFunc: func(index string) (bool, error) {
						return true, nil
					},
					DeleteRefreshByIndexFunc: func(index string) error {
						return nil
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			expectError: false,
		},
		{
			name:  "invalid token - too short",
			token: "short",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			expectError:   true,
			errorContains: "invalid refresh token",
		},
		{
			name:  "invalid token - too long",
			token: "this-is-a-very-long-refresh-token-that-exceeds-the-maximum-allowed-length",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			expectError:   true,
			errorContains: "invalid refresh token",
		},
		{
			name:  "indexer error",
			token: "valid-refresh-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{
					ObtainBlindIndexFunc: func(s string) (string, error) {
						return "", fmt.Errorf("index generation failed")
					},
				}
			},
			expectError:   true,
			errorContains: "failed to generate blind index",
		},
		{
			name:  "token does not exist",
			token: "nonexistent-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					RefreshExistsFunc: func(index string) (bool, error) {
						return false, nil
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			expectError:   true,
			errorContains: "does not exist",
		},
		{
			name:  "database error checking existence",
			token: "valid-refresh-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					RefreshExistsFunc: func(index string) (bool, error) {
						return false, fmt.Errorf("database connection error")
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			expectError:   true,
			errorContains: "failed to verify existence",
		},
		{
			name:  "database error during deletion",
			token: "valid-refresh-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					RefreshExistsFunc: func(index string) (bool, error) {
						return true, nil
					},
					DeleteRefreshByIndexFunc: func(index string) error {
						return fmt.Errorf("deletion failed")
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			expectError:   true,
			errorContains: "failed to delete refresh token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service := &s2sAuthService{
				sql:     tc.setupRepo(),
				indexer: tc.setupIndexer(),
			}

			err := service.DestroyRefresh(tc.token)

			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				} else if tc.errorContains != "" && !contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain '%s', got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// =============================================================================
// RevokeRefresh Tests
// =============================================================================

func TestRevokeRefresh(t *testing.T) {
	testCases := []struct {
		name          string
		token         string
		setupRepo     func() *MockAuthRepository
		setupIndexer  func() *MockIndexer
		expectError   bool
		errorContains string
	}{
		{
			name:  "successful refresh revocation",
			token: "valid-refresh-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					FindRefreshTokenFunc: func(index string) (*types.S2sRefresh, error) {
						return &types.S2sRefresh{
							Uuid:         "test-uuid",
							RefreshIndex: index,
							ServiceName:  "test-service",
							RefreshToken: "valid-refresh-token-1234567890",
							ClientId:     "test-client-id",
							ClientIndex:  "test-client-index",
							CreatedAt:    data.CustomTime{Time: time.Now()},
							Revoked:      false,
						}, nil
					},
					UpdateRefreshTokenFunc: func(token types.S2sRefresh) error {
						if !token.Revoked {
							return fmt.Errorf("token should be marked as revoked")
						}
						return nil
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			expectError: false,
		},
		{
			name:  "invalid token - too short",
			token: "short",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			expectError:   true,
			errorContains: "invalid refresh token",
		},
		{
			name:  "invalid token - too long",
			token: "this-is-a-very-long-refresh-token-that-exceeds-the-maximum-allowed-length",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			expectError:   true,
			errorContains: "invalid refresh token",
		},
		{
			name:  "indexer error",
			token: "valid-refresh-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{
					ObtainBlindIndexFunc: func(s string) (string, error) {
						return "", fmt.Errorf("index generation failed")
					},
				}
			},
			expectError:   true,
			errorContains: "failed to generate blind index",
		},
		{
			name:  "token not found",
			token: "nonexistent-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					FindRefreshTokenFunc: func(index string) (*types.S2sRefresh, error) {
						return nil, fmt.Errorf("refresh token with index %s does not exist", index)
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			expectError:   true,
			errorContains: "failed to retrieve refresh token",
		},
		{
			name:  "token already revoked",
			token: "already-revoked-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					FindRefreshTokenFunc: func(index string) (*types.S2sRefresh, error) {
						return &types.S2sRefresh{
							Uuid:         "test-uuid",
							RefreshIndex: index,
							ServiceName:  "test-service",
							RefreshToken: "already-revoked-token-1234567890",
							ClientId:     "test-client-id",
							ClientIndex:  "test-client-index",
							CreatedAt:    data.CustomTime{Time: time.Now()},
							Revoked:      true,
						}, nil
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			expectError:   true,
			errorContains: "is already revoked",
		},
		{
			name:  "database update error",
			token: "valid-refresh-token-1234567890",
			setupRepo: func() *MockAuthRepository {
				return &MockAuthRepository{
					FindRefreshTokenFunc: func(index string) (*types.S2sRefresh, error) {
						return &types.S2sRefresh{
							Uuid:         "test-uuid",
							RefreshIndex: index,
							ServiceName:  "test-service",
							RefreshToken: "valid-refresh-token-1234567890",
							ClientId:     "test-client-id",
							ClientIndex:  "test-client-index",
							CreatedAt:    data.CustomTime{Time: time.Now()},
							Revoked:      false,
						}, nil
					},
					UpdateRefreshTokenFunc: func(token types.S2sRefresh) error {
						return fmt.Errorf("database update failed")
					},
				}
			},
			setupIndexer: func() *MockIndexer {
				return &MockIndexer{}
			},
			expectError:   true,
			errorContains: "failed to revoke refresh token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service := &s2sAuthService{
				sql:     tc.setupRepo(),
				indexer: tc.setupIndexer(),
			}

			err := service.RevokeRefresh(tc.token)

			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				} else if tc.errorContains != "" && !contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain '%s', got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
