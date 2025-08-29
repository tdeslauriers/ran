package authentication

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

const (
	// test constants
	RealServiceName = "real-service"
	RealClientId    = "real-client"

	RealScopes = "r:shaw:* w:shaw:*"
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

func (m *mockCryptor) EncryptServiceData(data []byte) (string, error) {
	if string(data) == "failed encrypt" {
		return "", errors.New("failed to encrypt")
	}
	return "encrypted-" + string(data), nil
}

func (m *mockCryptor) DecryptServiceData(data string) ([]byte, error) {
	if data == "failed decrypt" {
		return nil, errors.New("failed to decrypt")
	}
	return []byte(strings.TrimPrefix(data, "encrypted-")), nil
}

type mockCredService struct{}

func (m *mockCredService) GenerateAccessToken() (string, error) {
	return "", nil
}

func (m *mockCredService) GenerateHashFromPassword(password string) (string, error) {
	return "", nil
}

func (m *mockCredService) CompareHashAndPassword(hash, password string) error {
	return nil
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

type mockSigner struct{}

func (s *mockSigner) Mint(token *jwt.Token) error {

	if token.Claims.Subject == RealClientId {
		msg, _ := token.BuildBaseString()
		token.BaseString = msg

		token.Signature = []byte("real-signature")

		token.Token = fmt.Sprintf("%s.%s", token.BaseString, base64.URLEncoding.EncodeToString(token.Signature))

		return nil
	} else {
		return errors.New("failed to create jwt signature")
	}

}

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

	mockS2sAuthService := NewS2sAuthService(&mockSqlRepository{}, nil, &mockIndexer{}, &mockCryptor{}, nil)

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

func TestMintToken(t *testing.T) {

	tests := []struct {
		name        string
		claims      jwt.Claims
		jwt         *jwt.Token
		expectedErr error
	}{
		{
			name: "success - mint token",
			claims: jwt.Claims{
				Jti:       "jti",
				Issuer:    "issuer",
				Subject:   RealClientId,
				Audience:  []string{"audience"},
				IssuedAt:  time.Now().UTC().Unix(),
				NotBefore: time.Now().UTC().Unix(),
				Expires:   time.Now().UTC().Add(5 * time.Minute).Unix(),
				Scopes:    RealScopes,
			},
			jwt: &jwt.Token{
				Header: jwt.Header{
					Alg: "HS256",
					Typ: jwt.TokenType,
				},
				Claims: jwt.Claims{
					Jti:       "jti",
					Issuer:    "issuer",
					Subject:   RealClientId,
					Audience:  []string{"audience"},
					IssuedAt:  time.Now().UTC().Unix(),
					NotBefore: time.Now().UTC().Unix(),
					Expires:   time.Now().UTC().Add(5 * time.Minute).Unix(),
					Scopes:    RealScopes,
				},
			},
			expectedErr: nil,
		},
		{
			name: "failure - triggering jwt.Mint error",
			claims: jwt.Claims{
				Jti:       "1234",
				Issuer:    "issuer",
				Subject:   "trigger error",
				Audience:  types.BuildAudiences(RealScopes),
				IssuedAt:  time.Now().UTC().Unix(),
				NotBefore: time.Now().UTC().Unix(),
				Expires:   time.Now().Add(5 * time.Minute).Unix(),
				Scopes:    RealScopes,
			},
			jwt:         nil,
			expectedErr: errors.New("failed to mint jwt for client id"),
		},
	}

	mockS2sAuthService := NewS2sAuthService(&mockSqlRepository{}, &mockSigner{}, &mockIndexer{}, &mockCryptor{}, &mockCredService{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jot, err := mockS2sAuthService.MintToken(tt.claims)
			if err != nil && !strings.Contains(err.Error(), tt.expectedErr.Error()) {
				t.Errorf("expected %v, got %v", tt.expectedErr, err)
			}
			if err == nil {
				if jot.BaseString == "" {
					t.Errorf("expected base string to be populated")
				}

				if jot.Signature == nil {
					t.Errorf("expected signature to be populated")
				}

				if jot.Token == "" {
					t.Errorf("expected token to be populated")
				} else {
					segments := strings.Split(jot.Token, ".")
					if len(segments) != 3 {
						t.Errorf("expected token to have 3 segments, got %d", len(segments))
					}
				}
			}
		})
	}
}
