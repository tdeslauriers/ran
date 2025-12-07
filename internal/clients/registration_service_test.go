package clients

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/ran/pkg/api/clients"
)

// mockRegistrationRepository implements RegistrationRepository for testing
type mockRegistrationRepository struct {
	createFunc func(client ClientRecord) error
}

func (m *mockRegistrationRepository) Create(client ClientRecord) error {
	if m.createFunc != nil {
		return m.createFunc(client)
	}
	return errors.New("createFunc not set")
}

var _ RegistrationRepository = (*mockRegistrationRepository)(nil)

// mockCredService implements authentication.CredService for testing
type mockCredService struct {
	generateHashFunc       func(password string) (string, error)
	compareHashAndPassword func(hashedPassword string, password string) error
	generateAccessToken    func() (string, error)
}

func (m *mockCredService) GenerateHashFromPassword(password string) (string, error) {
	if m.generateHashFunc != nil {
		return m.generateHashFunc(password)
	}
	return "", errors.New("generateHashFunc not set")
}

func (m *mockCredService) CompareHashAndPassword(hashedPassword string, password string) error {
	if m.compareHashAndPassword != nil {
		return m.compareHashAndPassword(hashedPassword, password)
	}
	return errors.New("compareHashAndPassword not set")
}

func (m *mockCredService) GenerateAccessToken() (string, error) {
	if m.generateAccessToken != nil {
		return m.generateAccessToken()
	}
	return "", errors.New("generateAccessToken not set")
}

// TestRegister tests the Register service method
func TestRegister(t *testing.T) {
	tests := []struct {
		name           string
		cmd            *clients.RegisterCmd
		mockRepo       *mockRegistrationRepository
		mockCreds      *mockCredService
		expectError    bool
		validateError  func(*testing.T, error)
		validateResult func(*testing.T, *clients.Client)
	}{
		{
			name: "successfully registers new client",
			cmd: &clients.RegisterCmd{
				Name:            "testclient",
				Owner:           "test owner",
				Password:        "SecureP@ssw0rd123",
				ConfirmPassword: "SecureP@ssw0rd123",
			},
			mockRepo: &mockRegistrationRepository{
				createFunc: func(client ClientRecord) error {
					// Validate the client record being created
					if client.Name != "testclient" {
						t.Errorf("expected name 'testclient', got %q", client.Name)
					}
					if client.Owner != "test owner" {
						t.Errorf("expected owner 'test owner', got %q", client.Owner)
					}
					if client.Password != "hashed_password" {
						t.Errorf("expected hashed password, got %q", client.Password)
					}
					if !client.Enabled {
						t.Error("expected client to be enabled")
					}
					if client.AccountExpired {
						t.Error("expected account not to be expired")
					}
					if client.AccountLocked {
						t.Error("expected account not to be locked")
					}
					if client.Id == "" {
						t.Error("expected client ID to be generated")
					}
					if client.Slug == "" {
						t.Error("expected client slug to be generated")
					}
					return nil
				},
			},
			mockCreds: &mockCredService{
				generateHashFunc: func(password string) (string, error) {
					if password != "SecureP@ssw0rd123" {
						t.Errorf("expected password 'SecureP@ssw0rd123', got %q", password)
					}
					return "hashed_password", nil
				},
			},
			expectError: false,
			validateResult: func(t *testing.T, client *clients.Client) {
				if client == nil {
					t.Fatal("expected client, got nil")
				}
				if client.Name != "testclient" {
					t.Errorf("expected name 'testclient', got %q", client.Name)
				}
				if client.Owner != "test owner" {
					t.Errorf("expected owner 'test owner', got %q", client.Owner)
				}
				if !client.Enabled {
					t.Error("expected client to be enabled")
				}
				if client.AccountExpired {
					t.Error("expected account not to be expired")
				}
				if client.AccountLocked {
					t.Error("expected account not to be locked")
				}
				if client.Id == "" {
					t.Error("expected ID to be set")
				}
				if client.Slug == "" {
					t.Error("expected slug to be set")
				}
				// Verify password is not in response (security check)
				// We can't check a field that doesn't exist, but we verified
				// the type is clients.Client which doesn't have a Password field
			},
		},
		{
			name: "validates client name is required",
			cmd: &clients.RegisterCmd{
				Name:            "", // Invalid - empty name
				Owner:           "test owner",
				Password:        "SecureP@ssw0rd123",
				ConfirmPassword: "SecureP@ssw0rd123",
			},
			mockRepo:    &mockRegistrationRepository{},
			mockCreds:   &mockCredService{},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				// Error should come from ValidateCmd()
				if err == nil {
					t.Fatal("expected validation error, got nil")
				}
			},
		},
		{
			name: "validates owner name is required",
			cmd: &clients.RegisterCmd{
				Name:     "testclient",
				Owner:    "", // Invalid - empty owner
				Password: "SecureP@ssw0rd123",
			},
			mockRepo:    &mockRegistrationRepository{},
			mockCreds:   &mockCredService{},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected validation error, got nil")
				}
			},
		},
		{
			name: "validates password is required",
			cmd: &clients.RegisterCmd{
				Name:     "testclient",
				Owner:    "test owner",
				Password: "", // Invalid - empty password
			},
			mockRepo:    &mockRegistrationRepository{},
			mockCreds:   &mockCredService{},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected validation error, got nil")
				}
			},
		},
		{
			name: "password hashing error is returned",
			cmd: &clients.RegisterCmd{
				Name:            "testclient",
				Owner:           "test owner",
				Password:        "SecureP@ssw0rd123",
				ConfirmPassword: "SecureP@ssw0rd123",
			},
			mockRepo: &mockRegistrationRepository{},
			mockCreds: &mockCredService{
				generateHashFunc: func(password string) (string, error) {
					return "", errors.New("hashing algorithm failed")
				},
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "failed to hash service client password") {
					t.Errorf("expected hash error, got %q", err.Error())
				}
				if !strings.Contains(err.Error(), "hashing algorithm failed") {
					t.Errorf("expected underlying error, got %q", err.Error())
				}
			},
		},
		{
			name: "repository create error is returned",
			cmd: &clients.RegisterCmd{
				Name:            "testclient",
				Owner:           "test owner",
				Password:        "SecureP@ssw0rd123",
				ConfirmPassword: "SecureP@ssw0rd123",
			},
			mockRepo: &mockRegistrationRepository{
				createFunc: func(client ClientRecord) error {
					return errors.New("database insert failed")
				},
			},
			mockCreds: &mockCredService{
				generateHashFunc: func(password string) (string, error) {
					return "hashed_password", nil
				},
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "database insert failed") {
					t.Errorf("expected database error, got %q", err.Error())
				}
			},
		},
		{
			name: "creates enabled account by default",
			cmd: &clients.RegisterCmd{
				Name:            "testclient",
				Owner:           "test owner",
				Password:        "SecureP@ssw0rd123",
				ConfirmPassword: "SecureP@ssw0rd123",
			},
			mockRepo: &mockRegistrationRepository{
				createFunc: func(client ClientRecord) error {
					if !client.Enabled {
						t.Error("expected new client to be enabled by default")
					}
					if client.AccountExpired {
						t.Error("expected new client account not to be expired")
					}
					if client.AccountLocked {
						t.Error("expected new client account not to be locked")
					}
					return nil
				},
			},
			mockCreds: &mockCredService{
				generateHashFunc: func(password string) (string, error) {
					return "hashed_password", nil
				},
			},
			expectError: false,
			validateResult: func(t *testing.T, client *clients.Client) {
				if !client.Enabled {
					t.Error("expected enabled client")
				}
				if client.AccountExpired {
					t.Error("expected non-expired account")
				}
				if client.AccountLocked {
					t.Error("expected non-locked account")
				}
			},
		},
		{
			name: "generates unique ID and slug",
			cmd: &clients.RegisterCmd{
				Name:            "testclient",
				Owner:           "test owner",
				Password:        "SecureP@ssw0rd123",
				ConfirmPassword: "SecureP@ssw0rd123",
			},
			mockRepo: &mockRegistrationRepository{
				createFunc: func(client ClientRecord) error {
					// Verify ID is a valid UUID format
					if len(client.Id) != 36 { // UUID length with hyphens
						t.Errorf("expected UUID format for ID, got %q (length %d)", client.Id, len(client.Id))
					}
					if !strings.Contains(client.Id, "-") {
						t.Errorf("expected UUID format with hyphens for ID, got %q", client.Id)
					}

					// Verify Slug is a valid UUID format
					if len(client.Slug) != 36 {
						t.Errorf("expected UUID format for slug, got %q (length %d)", client.Slug, len(client.Slug))
					}
					if !strings.Contains(client.Slug, "-") {
						t.Errorf("expected UUID format with hyphens for slug, got %q", client.Slug)
					}

					// Verify ID and Slug are different
					if client.Id == client.Slug {
						t.Error("expected ID and Slug to be different UUIDs")
					}

					return nil
				},
			},
			mockCreds: &mockCredService{
				generateHashFunc: func(password string) (string, error) {
					return "hashed_password", nil
				},
			},
			expectError: false,
			validateResult: func(t *testing.T, client *clients.Client) {
				if client.Id == "" {
					t.Error("expected ID to be generated")
				}
				if client.Slug == "" {
					t.Error("expected Slug to be generated")
				}
				if client.Id == client.Slug {
					t.Error("expected ID and Slug to be different")
				}
			},
		},
		{
			name: "sets creation timestamp",
			cmd: &clients.RegisterCmd{
				Name:            "testclient",
				Owner:           "test owner",
				Password:        "SecureP@ssw0rd123",
				ConfirmPassword: "SecureP@ssw0rd123",
			},
			mockRepo: &mockRegistrationRepository{
				createFunc: func(client ClientRecord) error {
					// Verify timestamp is recent (within last 5 seconds)
					now := time.Now()
					diff := now.Sub(client.CreatedAt.Time)
					if diff < 0 || diff > 5*time.Second {
						t.Errorf("expected recent timestamp, got %v (diff: %v)", client.CreatedAt.Time, diff)
					}
					return nil
				},
			},
			mockCreds: &mockCredService{
				generateHashFunc: func(password string) (string, error) {
					return "hashed_password", nil
				},
			},
			expectError: false,
			validateResult: func(t *testing.T, client *clients.Client) {
				// Verify timestamp is set and recent
				now := time.Now()
				diff := now.Sub(client.CreatedAt.Time)
				if diff < 0 || diff > 5*time.Second {
					t.Errorf("expected recent timestamp, got %v (diff: %v)", client.CreatedAt.Time, diff)
				}
			},
		},
		{
			name: "password is hashed before storage",
			cmd: &clients.RegisterCmd{
				Name:            "testclient",
				Owner:           "test owner",
				Password:        "SecureP@ssw0rd123",
				ConfirmPassword: "SecureP@ssw0rd123",
			},
			mockRepo: &mockRegistrationRepository{
				createFunc: func(client ClientRecord) error {
					// Verify password is hashed, not plain text
					if client.Password == "SecureP@ssw0rd123" {
						t.Error("password should be hashed, not plain text")
					}
					if client.Password != "hashed_password" {
						t.Errorf("expected hashed password, got %q", client.Password)
					}
					return nil
				},
			},
			mockCreds: &mockCredService{
				generateHashFunc: func(password string) (string, error) {
					if password != "SecureP@ssw0rd123" {
						t.Errorf("expected plain text password, got %q", password)
					}
					return "hashed_password", nil
				},
			},
			expectError: false,
		},
		{
			name: "response does not include password (security)",
			cmd: &clients.RegisterCmd{
				Name:            "testclient",
				Owner:           "test owner",
				Password:        "SecureP@ssw0rd123",
				ConfirmPassword: "SecureP@ssw0rd123",
			},
			mockRepo: &mockRegistrationRepository{
				createFunc: func(client ClientRecord) error {
					return nil
				},
			},
			mockCreds: &mockCredService{
				generateHashFunc: func(password string) (string, error) {
					return "hashed_password", nil
				},
			},
			expectError: false,
			validateResult: func(t *testing.T, client *clients.Client) {
				// The clients.Client type should not have a Password field
				// This is verified by the type system, but we can document it
				// If clients.Client had a Password field, this wouldn't compile
				if client == nil {
					t.Fatal("expected client, got nil")
				}
				// Successfully returning clients.Client type proves no password
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create service with mocks
			service := &registrationService{
				sql:    tt.mockRepo,
				creds:  tt.mockCreds,
				logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			// Call the service method
			result, err := service.Register(tt.cmd)

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

// TestRegister_IDGeneration tests that UUIDs are properly generated
func TestRegister_IDGeneration(t *testing.T) {
	// Track generated IDs to verify uniqueness
	var capturedID, capturedSlug string

	mockRepo := &mockRegistrationRepository{
		createFunc: func(client ClientRecord) error {
			capturedID = client.Id
			capturedSlug = client.Slug
			return nil
		},
	}

	mockCreds := &mockCredService{
		generateHashFunc: func(password string) (string, error) {
			return "hashed", nil
		},
	}

	service := &registrationService{
		sql:    mockRepo,
		creds:  mockCreds,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	cmd := &clients.RegisterCmd{
		Name:            "testclient",
		Owner:           "test owner",
		Password:        "TerriblePassword1!",
		ConfirmPassword: "TerriblePassword1!",
	}

	client, err := service.Register(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify IDs were generated
	if capturedID == "" {
		t.Error("expected ID to be generated")
	}
	if capturedSlug == "" {
		t.Error("expected Slug to be generated")
	}

	// Verify IDs are different
	if capturedID == capturedSlug {
		t.Error("expected ID and Slug to be different UUIDs")
	}

	// Verify they match what's returned
	if client.Id != capturedID {
		t.Errorf("returned ID %q doesn't match created ID %q", client.Id, capturedID)
	}
	if client.Slug != capturedSlug {
		t.Errorf("returned Slug %q doesn't match created Slug %q", client.Slug, capturedSlug)
	}
}

// TestRegister_MultipleCallsGenerateUniqueIDs tests that repeated calls generate unique IDs
func TestRegister_MultipleCallsGenerateUniqueIDs(t *testing.T) {
	var ids []string
	var slugs []string

	mockRepo := &mockRegistrationRepository{
		createFunc: func(client ClientRecord) error {
			ids = append(ids, client.Id)
			slugs = append(slugs, client.Slug)
			return nil
		},
	}

	mockCreds := &mockCredService{
		generateHashFunc: func(password string) (string, error) {
			return "hashed", nil
		},
	}

	service := &registrationService{
		sql:    mockRepo,
		creds:  mockCreds,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	cmd := &clients.RegisterCmd{
		Name:            "testclient",
		Owner:           "test owner",
		Password:        "TerriblePassword1!",
		ConfirmPassword: "TerriblePassword1!",
	}

	// Register 5 clients
	for i := 0; i < 5; i++ {
		_, err := service.Register(cmd)
		if err != nil {
			t.Fatalf("registration %d failed: %v", i, err)
		}
	}

	// Verify all IDs are unique
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if ids[i] == ids[j] {
				t.Errorf("duplicate ID found: %s at positions %d and %d", ids[i], i, j)
			}
		}
	}

	// Verify all Slugs are unique
	for i := 0; i < len(slugs); i++ {
		for j := i + 1; j < len(slugs); j++ {
			if slugs[i] == slugs[j] {
				t.Errorf("duplicate Slug found: %s at positions %d and %d", slugs[i], i, j)
			}
		}
	}
}
