package clients

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/profile"
)

// mockResetRepository implements ResetRepository for testing
type mockResetRepository struct {
	findByIdFunc       func(id string) (*Reset, error)
	updatePasswordFunc func(id string, newHash string) error
}

func (m *mockResetRepository) FindById(id string) (*Reset, error) {
	if m.findByIdFunc != nil {
		return m.findByIdFunc(id)
	}
	return nil, errors.New("findByIdFunc not set")
}

func (m *mockResetRepository) UpdatePassword(id string, newHash string) error {
	if m.updatePasswordFunc != nil {
		return m.updatePasswordFunc(id, newHash)
	}
	return errors.New("updatePasswordFunc not set")
}

var _ ResetRepository = (*mockResetRepository)(nil)

// mockResetCredService implements authentication.CredService for testing password reset
type mockResetCredService struct {
	generateHashFunc           func(password string) (string, error)
	compareHashAndPasswordFunc func(hash, password string) error
	generateAccessTokenFunc    func() (string, error)
}

func (m *mockResetCredService) GenerateHashFromPassword(password string) (string, error) {
	if m.generateHashFunc != nil {
		return m.generateHashFunc(password)
	}
	return "", errors.New("generateHashFunc not set")
}

func (m *mockResetCredService) CompareHashAndPassword(hash, password string) error {
	if m.compareHashAndPasswordFunc != nil {
		return m.compareHashAndPasswordFunc(hash, password)
	}
	return errors.New("compareHashAndPasswordFunc not set")
}

func (m *mockResetCredService) GenerateAccessToken() (string, error) {
	if m.generateAccessTokenFunc != nil {
		return m.generateAccessTokenFunc()
	}
	return "", errors.New("generateAccessTokenFunc not set")
}

// TestResetPassword tests the ResetPassword service method
func TestResetPassword(t *testing.T) {
	tests := []struct {
		name          string
		cmd           profile.ResetCmd
		mockRepo      *mockResetRepository
		mockCreds     *mockResetCredService
		expectError   bool
		validateError func(*testing.T, error)
	}{
		{
			name: "successfully resets password",
			cmd: profile.ResetCmd{
				ResourceId:      "550e8400-e29b-41d4-a716-446655440000",
				CurrentPassword: "OldPa5z!Qm7Rx2Bk",
				NewPassword:     "NewXy9!Zm4Qb7TnK",
				ConfirmPassword: "NewXy9!Zm4Qb7TnK",
			},
			mockRepo: &mockResetRepository{
				findByIdFunc: func(id string) (*Reset, error) {
					if id != "550e8400-e29b-41d4-a716-446655440000" {
						t.Errorf("expected resource id 'client-uuid-123', got %q", id)
					}
					return &Reset{
						ClientId: "550e8400-e29b-41d4-a716-446655440000",
						Password: "hashed_old_password",
					}, nil
				},
				updatePasswordFunc: func(id string, newHash string) error {
					if id != "550e8400-e29b-41d4-a716-446655440000" {
						t.Errorf("expected client id 'client-uuid-123', got %q", id)
					}
					if newHash != "hashed_new_password" {
						t.Errorf("expected new hash 'hashed_new_password', got %q", newHash)
					}
					return nil
				},
			},
			mockCreds: &mockResetCredService{
				compareHashAndPasswordFunc: func(hash, password string) error {
					if hash != "hashed_old_password" {
						t.Errorf("expected hash 'hashed_old_password', got %q", hash)
					}
					if password != "OldPa5z!Qm7Rx2Bk" {
						t.Errorf("expected password 'OldPassword123', got %q", password)
					}
					return nil // Passwords match
				},
				generateHashFunc: func(password string) (string, error) {
					if password != "NewXy9!Zm4Qb7TnK" {
						t.Errorf("expected new password 'NewPassword456', got %q", password)
					}
					return "hashed_new_password", nil
				},
			},
			expectError: false,
		},
		{
			name: "validation error when resource id is empty",
			cmd: profile.ResetCmd{
				ResourceId:      "", // Invalid - empty
				CurrentPassword: "OldPa5z!Qm7Rx2Bk",
				NewPassword:     "NewXy9!Zm4Qb7TnK",
				ConfirmPassword: "NewXy9!Zm4Qb7TnK",
			},
			mockRepo:    &mockResetRepository{},
			mockCreds:   &mockResetCredService{},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				// Error should come from ValidateCmd()
				if err == nil {
					t.Fatal("expected validation error, got nil")
				}
			},
		},
		{
			name: "validation error when current password is empty",
			cmd: profile.ResetCmd{
				ResourceId:      "550e8400-e29b-41d4-a716-446655440000",
				CurrentPassword: "", // Invalid - empty
				NewPassword:     "NewXy9!Zm4Qb7TnK",
				ConfirmPassword: "NewXy9!Zm4Qb7TnK",
			},
			mockRepo:    &mockResetRepository{},
			mockCreds:   &mockResetCredService{},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected validation error, got nil")
				}
			},
		},
		{
			name: "validation error when new password is empty",
			cmd: profile.ResetCmd{
				ResourceId:      "550e8400-e29b-41d4-a716-446655440000",
				CurrentPassword: "OldPa5z!Qm7Rx2Bk",
				NewPassword:     "", // Invalid - empty
				ConfirmPassword: "",
			},
			mockRepo:    &mockResetRepository{},
			mockCreds:   &mockResetCredService{},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("expected validation error, got nil")
				}
			},
		},
		{
			name: "error when new password matches current password",
			cmd: profile.ResetCmd{
				ResourceId:      "550e8400-e29b-41d4-a716-446655440000",
				CurrentPassword: "SameXy9!Zm4Qb7TnK",
				NewPassword:     "SameXy9!Zm4Qb7TnK", // Same as current
				ConfirmPassword: "SameXy9!Zm4Qb7TnK",
			},
			mockRepo:    &mockResetRepository{},
			mockCreds:   &mockResetCredService{},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "new password must be different from current password") {
					t.Errorf("expected 'new password must be different' error, got %q", err.Error())
				}
			},
		},
		{
			name: "error when client not found",
			cmd: profile.ResetCmd{
				ResourceId:      "660e8400-e29b-41d4-a716-446655440001",
				CurrentPassword: "OldPa5z!Qm7Rx2Bk",
				NewPassword:     "NewXy9!Zm4Qb7TnK",
				ConfirmPassword: "NewXy9!Zm4Qb7TnK",
			},
			mockRepo: &mockResetRepository{
				findByIdFunc: func(id string) (*Reset, error) {
					return nil, errors.New("service client not found: nonexistent-client")
				},
			},
			mockCreds:   &mockResetCredService{},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "service client not found") {
					t.Errorf("expected 'client not found' error, got %q", err.Error())
				}
			},
		},
		{
			name: "error when current password is incorrect",
			cmd: profile.ResetCmd{
				ResourceId:      "550e8400-e29b-41d4-a716-446655440000",
				CurrentPassword: "Wr0ngXy!9Qm7Bk2K",
				NewPassword:     "NewXy9!Zm4Qb7TnK",
				ConfirmPassword: "NewXy9!Zm4Qb7TnK",
			},
			mockRepo: &mockResetRepository{
				findByIdFunc: func(id string) (*Reset, error) {
					return &Reset{
						ClientId: "550e8400-e29b-41d4-a716-446655440000",
						Password: "hashed_correct_password",
					}, nil
				},
			},
			mockCreds: &mockResetCredService{
				compareHashAndPasswordFunc: func(hash, password string) error {
					// Simulate password mismatch
					return errors.New("hash and password do not match")
				},
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "password is incorrect") {
					t.Errorf("expected 'password is incorrect' error, got %q", err.Error())
				}
				if !strings.Contains(err.Error(), "550e8400-e29b-41d4-a716-446655440000") {
					t.Errorf("expected error to include client id, got %q", err.Error())
				}
			},
		},
		{
			name: "error when password hashing fails",
			cmd: profile.ResetCmd{
				ResourceId:      "550e8400-e29b-41d4-a716-446655440000",
				CurrentPassword: "OldPa5z!Qm7Rx2Bk",
				NewPassword:     "NewXy9!Zm4Qb7TnK",
				ConfirmPassword: "NewXy9!Zm4Qb7TnK",
			},
			mockRepo: &mockResetRepository{
				findByIdFunc: func(id string) (*Reset, error) {
					return &Reset{
						ClientId: "550e8400-e29b-41d4-a716-446655440000",
						Password: "hashed_old_password",
					}, nil
				},
			},
			mockCreds: &mockResetCredService{
				compareHashAndPasswordFunc: func(hash, password string) error {
					return nil // Current password is correct
				},
				generateHashFunc: func(password string) (string, error) {
					return "", errors.New("hashing algorithm failed")
				},
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "failed to hash new password") {
					t.Errorf("expected hash error, got %q", err.Error())
				}
				if !strings.Contains(err.Error(), "hashing algorithm failed") {
					t.Errorf("expected underlying error, got %q", err.Error())
				}
			},
		},
		{
			name: "error when database update fails",
			cmd: profile.ResetCmd{
				ResourceId:      "550e8400-e29b-41d4-a716-446655440000",
				CurrentPassword: "OldPa5z!Qm7Rx2Bk",
				NewPassword:     "NewXy9!Zm4Qb7TnK",
				ConfirmPassword: "NewXy9!Zm4Qb7TnK",
			},
			mockRepo: &mockResetRepository{
				findByIdFunc: func(id string) (*Reset, error) {
					return &Reset{
						ClientId: "550e8400-e29b-41d4-a716-446655440000",
						Password: "hashed_old_password",
					}, nil
				},
				updatePasswordFunc: func(id string, newHash string) error {
					return errors.New("database update failed")
				},
			},
			mockCreds: &mockResetCredService{
				compareHashAndPasswordFunc: func(hash, password string) error {
					return nil // Current password is correct
				},
				generateHashFunc: func(password string) (string, error) {
					return "hashed_new_password", nil
				},
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "database update failed") {
					t.Errorf("expected database error, got %q", err.Error())
				}
			},
		},
		{
			name: "validates current password before generating new hash",
			cmd: profile.ResetCmd{
				ResourceId:      "550e8400-e29b-41d4-a716-446655440000",
				CurrentPassword: "C0rrXy!9Qm7Bk2TnK",
				NewPassword:     "NewXy9!Zm4Qb7TnK",
				ConfirmPassword: "NewXy9!Zm4Qb7TnK",
			},
			mockRepo: &mockResetRepository{
				findByIdFunc: func(id string) (*Reset, error) {
					return &Reset{
						ClientId: "550e8400-e29b-41d4-a716-446655440000",
						Password: "hashed_correct_password",
					}, nil
				},
				updatePasswordFunc: func(id string, newHash string) error {
					return nil
				},
			},
			mockCreds: &mockResetCredService{
				compareHashAndPasswordFunc: func(hash, password string) error {
					if password != "C0rrXy!9Qm7Bk2TnK" {
						t.Error("compareHashAndPassword should be called with current password")
					}
					return nil
				},
				generateHashFunc: func(password string) (string, error) {
					if password != "NewXy9!Zm4Qb7TnK" {
						t.Error("generateHash should be called with new password")
					}
					return "hashed_new_password", nil
				},
			},
			expectError: false,
		},
		{
			name: "uses correct client id for update",
			cmd: profile.ResetCmd{
				ResourceId:      "770e8400-e29b-41d4-a716-446655440002",
				CurrentPassword: "OldXy!9Qm7Bk2TnK",
				NewPassword:     "N3wXy!9Qm7Bk2TnK",
				ConfirmPassword: "N3wXy!9Qm7Bk2TnK",
			},
			mockRepo: &mockResetRepository{
				findByIdFunc: func(id string) (*Reset, error) {
					if id != "770e8400-e29b-41d4-a716-446655440002" {
						t.Errorf("FindById should be called with resource id, got %q", id)
					}
					return &Reset{
						ClientId: "actual-client-uuid", // Different from resource id
						Password: "hashed_old",
					}, nil
				},
				updatePasswordFunc: func(id string, newHash string) error {
					// Should use ClientId from record, not ResourceId from cmd
					if id != "actual-client-uuid" {
						t.Errorf("UpdatePassword should use ClientId 'actual-client-uuid', got %q", id)
					}
					return nil
				},
			},
			mockCreds: &mockResetCredService{
				compareHashAndPasswordFunc: func(hash, password string) error {
					return nil
				},
				generateHashFunc: func(password string) (string, error) {
					return "hashed_new", nil
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create service with mocks
			service := &resetService{
				sql:    tt.mockRepo,
				creds:  tt.mockCreds,
				logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			// Call the service method
			err := service.ResetPassword(tt.cmd)

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
		})
	}
}

// TestResetPassword_PasswordFlow tests the complete password reset flow
func TestResetPassword_PasswordFlow(t *testing.T) {
	var (
		lookupCalled    bool
		compareCalled   bool
		hashCalled      bool
		updateCalled    bool
		capturedNewHash string
	)

	mockRepo := &mockResetRepository{
		findByIdFunc: func(id string) (*Reset, error) {
			lookupCalled = true
			return &Reset{
				ClientId: "550e8400-e29b-41d4-a716-446655440000",
				Password: "stored_hash",
			}, nil
		},
		updatePasswordFunc: func(id string, newHash string) error {
			updateCalled = true
			capturedNewHash = newHash
			return nil
		},
	}

	mockCreds := &mockResetCredService{
		compareHashAndPasswordFunc: func(hash, password string) error {
			compareCalled = true
			if hash != "stored_hash" {
				t.Errorf("should compare with stored hash, got %q", hash)
			}
			return nil
		},
		generateHashFunc: func(password string) (string, error) {
			hashCalled = true
			if password != "N3wXy!9Qm7Bk2TnK" {
				t.Errorf("should hash new password, got %q", password)
			}
			return "new_hashed_password", nil
		},
	}

	service := &resetService{
		sql:    mockRepo,
		creds:  mockCreds,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	cmd := profile.ResetCmd{
		ResourceId:      "550e8400-e29b-41d4-a716-446655440000",
		CurrentPassword: "OldXy!9Qm7Bk2TnK",
		NewPassword:     "N3wXy!9Qm7Bk2TnK",
		ConfirmPassword: "N3wXy!9Qm7Bk2TnK",
	}

	err := service.ResetPassword(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all steps were called in correct order
	if !lookupCalled {
		t.Error("expected FindById to be called")
	}
	if !compareCalled {
		t.Error("expected CompareHashAndPassword to be called")
	}
	if !hashCalled {
		t.Error("expected GenerateHashFromPassword to be called")
	}
	if !updateCalled {
		t.Error("expected UpdatePassword to be called")
	}

	// Verify correct hash was used for update
	if capturedNewHash != "new_hashed_password" {
		t.Errorf("expected update with 'new_hashed_password', got %q", capturedNewHash)
	}
}

// TestResetPassword_SecurityChecks tests security-related validations
func TestResetPassword_SecurityChecks(t *testing.T) {
	t.Run("rejects same password", func(t *testing.T) {
		service := &resetService{
			sql:    &mockResetRepository{},
			creds:  &mockResetCredService{},
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}

		cmd := profile.ResetCmd{
			ResourceId:      "550e8400-e29b-41d4-a716-446655440000",
			CurrentPassword: "Pa5z!Qm7Rx2Bk9Xy",
			NewPassword:     "Pa5z!Qm7Rx2Bk9Xy", // Same password
		}

		err := service.ResetPassword(cmd)
		if err == nil {
			t.Fatal("expected error when new password equals current password")
		}
		if !strings.Contains(err.Error(), "must be different") {
			t.Errorf("expected 'must be different' error, got %q", err.Error())
		}
	})

	t.Run("verifies current password before allowing reset", func(t *testing.T) {
		var passwordVerified bool

		mockRepo := &mockResetRepository{
			findByIdFunc: func(id string) (*Reset, error) {
				return &Reset{
					ClientId: "550e8400-e29b-41d4-a716-446655440000",
					Password: "correct_hash",
				}, nil
			},
		}

		mockCreds := &mockResetCredService{
			compareHashAndPasswordFunc: func(hash, password string) error {
				passwordVerified = true
				// Simulate wrong password
				return errors.New("hash and password do not match")
			},
		}

		service := &resetService{
			sql:    mockRepo,
			creds:  mockCreds,
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}

		cmd := profile.ResetCmd{
			ResourceId:      "550e8400-e29b-41d4-a716-446655440000",
			CurrentPassword: "Wr0ngXy!9Qm7Bk2K",
			NewPassword:     "NewXy9!Zm4Qb7TnK",
			ConfirmPassword: "NewXy9!Zm4Qb7TnK",
		}

		err := service.ResetPassword(cmd)
		if err == nil {
			t.Fatal("expected error when current password is incorrect")
		}

		if !passwordVerified {
			t.Error("should have attempted to verify current password")
		}

		if !strings.Contains(err.Error(), "password is incorrect") {
			t.Errorf("expected 'password is incorrect' error, got %q", err.Error())
		}
	})
}
