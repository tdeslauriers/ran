package authentication

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

const (
	// test constants
	RealServiceName = "real-service"
	RealClientId    = "real-client"
)

type mockIndexer struct {
}

func (m *mockIndexer) ObtainBlindIndex(data string) (string, error) {
	if data == "failed index" {
		return "", errors.New(ErrGenIndex)
	}
	return "index-" + data, nil
}

type mockCryptor struct{}

func (m *mockCryptor) EncryptServiceData(data string) (string, error) {
	if data == "failed encrypt" {
		return "", errors.New("failed to encrypt")
	}
	return "encrypted-" + data, nil
}

func (m *mockCryptor) DecryptServiceData(data string) (string, error) {
	if data == "failed decrypt" {
		return "", errors.New("failed to decrypt")
	}
	return strings.TrimPrefix(data, "encrypted-"), nil
}

type mockSqlRepository struct {
}

func (m *mockSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	return nil
}
func (m *mockSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {
	return nil
}
func (m *mockSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	return true, nil
}
func (m *mockSqlRepository) InsertRecord(query string, record interface{}) error {
	if record.(types.S2sRefresh).RefreshToken == "failed insert" {
		return errors.New("failed to insert")
	}
	return nil
}
func (m *mockSqlRepository) UpdateRecord(query string, args ...interface{}) error { return nil }
func (m *mockSqlRepository) DeleteRecord(query string, args ...interface{}) error { return nil }
func (m *mockSqlRepository) Close() error                                         { return nil }

func TestPersistToken(t *testing.T) {
	// test cases
	tests := []struct {
		name        string
		refresh     types.S2sRefresh
		expectedErr error
	}{
		{
			name: "success - refresh token persisted",
			refresh: types.S2sRefresh{
				ServiceName:  RealServiceName,
				RefreshToken: "refresh-token",
				ClientId:     RealClientId,
				CreatedAt:    data.CustomTime{Time: time.Now().UTC()},
				Revoked:      false,
			},
			expectedErr: nil,
		},
		{
			name: "failed to encrypt refresh token",
			refresh: types.S2sRefresh{
				ServiceName:  RealServiceName,
				RefreshToken: "failed encrypt",
				ClientId:     RealClientId,
				CreatedAt:    data.CustomTime{Time: time.Now().UTC()},
				Revoked:      false,
			},
			expectedErr: errors.New("failed to encrypt"),
		},
		{
			name: "failed to encrypt multiple fields",
			refresh: types.S2sRefresh{
				ServiceName:  "failed encrypt",
				RefreshToken: "failed encrypt",
				ClientId:     RealClientId,
				CreatedAt:    data.CustomTime{Time: time.Now().UTC()},
				Revoked:      false,
			},
			expectedErr: errors.New("failed to encrypt"),
		},
		{
			name: "failed to insert refresh token",
			refresh: types.S2sRefresh{
				ServiceName:  RealServiceName,
				RefreshToken: "failed insert",
				ClientId:     RealClientId,
				CreatedAt:    data.CustomTime{Time: time.Now().UTC()},
				Revoked:      false,
			},
			expectedErr: errors.New("failed to insert"),
		},
	}

	mockS2sAuthService := NewS2sAuthService(&mockSqlRepository{}, nil, &mockIndexer{}, &mockCryptor{})

	// run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mockS2sAuthService.PersistRefresh(tt.refresh)
			if err != nil && !strings.Contains(err.Error(), tt.expectedErr.Error()) {
				t.Errorf("expected %v, got %v", tt.expectedErr, err)
			}
		})
	}

}
