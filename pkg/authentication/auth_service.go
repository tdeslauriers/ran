package authentication

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"ran/internal/util"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"

	"golang.org/x/crypto/bcrypt"
)

const (
	TokenDuration   time.Duration = time.Duration(5)
	RefreshDuration time.Duration = time.Duration(30)
)

func NewS2sAuthService(sql data.SqlRepository, mint jwt.JwtSigner, indexer data.Indexer, ciph data.Cryptor) types.S2sAuthService {
	return &s2sAuthService{
		sql:     sql,
		mint:    mint,
		indexer: indexer,
		cryptor: ciph,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentAuthn)),
	}
}

var _ types.S2sAuthService = (*s2sAuthService)(nil)

type s2sAuthService struct {
	sql     data.SqlRepository
	mint    jwt.JwtSigner
	indexer data.Indexer
	cryptor data.Cryptor

	logger *slog.Logger
}

func (s *s2sAuthService) ValidateCredentials(clientId, clientSecret string) error {

	var s2sClient types.S2sClient
	qry := `
		SELECT 
			uuid, 
			password, 
			name, 
			owner, 
			created_at, 
			enabled, 
			account_expired, 
			account_locked 
		FROM client 
		WHERE uuid = ?`
	if err := s.sql.SelectRecord(qry, &s2sClient, clientId); err != nil {
		s.logger.Error("unable to retrieve s2s client record", "err", err.Error())
		return errors.New("unable to retrieve s2s client record")
	}

	// validate password
	secret := []byte(clientSecret)
	hash := []byte(s2sClient.Password)
	if err := bcrypt.CompareHashAndPassword(hash, secret); err != nil {
		s.logger.Error("unable to validate password", "err", err.Error())
		return errors.New("unable to validate password")
	}

	if !s2sClient.Enabled {
		return errors.New("service account disabled")
	}

	if s2sClient.AccountLocked {
		return errors.New("service account locked")
	}

	if s2sClient.AccountExpired {
		return errors.New("service account expired")
	}

	return nil
}

func (s *s2sAuthService) GetScopes(clientId, service string) ([]types.Scope, error) {

	var scopes []types.Scope
	qry := `
		SELECT 
			s.uuid,
			s.service_name,
			s.scope,
			s.name,
			s.description,
			s.created_at,
			s.active
		FROM scope s 
			LEFT JOIN client_scope cs ON s.uuid = cs.scope_uuid
		WHERE cs.client_uuid = ?
			AND s.service_name = ?`
	if err := s.sql.SelectRecords(qry, &scopes, clientId, service); err != nil {
		s.logger.Error(fmt.Sprintf("unable to retrieve scopes for client %s", clientId), "err", err.Error())
		return scopes, fmt.Errorf("unable to retrieve scopes for client %s", clientId)
	}

	return scopes, nil
}

// assumes credentials already validated
func (s *s2sAuthService) MintToken(subject, service, scopes string) (*jwt.JwtToken, error) {

	// jwt header
	header := jwt.JwtHeader{Alg: jwt.ES512, Typ: jwt.TokenType}

	// set up jwt claims fields
	jti, err := uuid.NewRandom()
	if err != nil {
		s.logger.Error("unable to create jti uuid", "err", err.Error())
		return nil, errors.New("failed to mint s2s token")
	}

	currentTime := time.Now()

	claims := jwt.JwtClaims{
		Jti:       jti.String(),
		Issuer:    "ran",
		Subject:   subject,
		Audience:  types.BuildAudiences(scopes),
		IssuedAt:  currentTime.Unix(),
		NotBefore: currentTime.Unix(),
		Expires:   currentTime.Add(TokenDuration * time.Minute).Unix(),
		Scopes:    scopes,
	}

	jot := jwt.JwtToken{Header: header, Claims: claims}

	err = s.mint.MintJwt(&jot)
	if err != nil {
		return nil, fmt.Errorf("unable to mint jwt: %v", err)
	}

	return &jot, err
}

// finds by regenerating blind index
// decrypts refresh token for use
func (s *s2sAuthService) GetRefreshToken(refreshToken string) (*types.S2sRefresh, error) {

	// re-create blind index for lookup.
	index, err := s.indexer.ObtainBlindIndex(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create blind index value for refresh token lookup: %v", err)
	}

	// look up refresh
	var refresh types.S2sRefresh
	qry := `
		SELECT 
			uuid, 
			refresh_index,
			service_name,
			refresh_token, 
			client_uuid, 
			created_at, 
			revoked 
		FROM refresh
		WHERE refresh_index = ?`
	if err := s.sql.SelectRecord(qry, &refresh, index); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("refresh token xxxxxx-%s does not exist", refreshToken[len(refreshToken)-6:])
		}
		return nil, fmt.Errorf("failed to lookup refresh token xxxxxx-%s: %v", refreshToken[len(refreshToken)-6:], err)
	}

	// check revoked status
	if refresh.Revoked {
		return nil, fmt.Errorf("refresh token xxxxxx-%s has been revoked", refreshToken[len(refreshToken)-6:])
	}

	// validate refresh token not expired server-side
	if refresh.CreatedAt.Time.Add(RefreshDuration * time.Minute).Before(time.Now().UTC()) {

		// opportunistically delete expired refresh token
		go func(id string) {
			qry := "DELETE FROM refresh WHERE uuid = ?"
			if err := s.sql.DeleteRecord(qry, id); err != nil {
				s.logger.Error(fmt.Sprintf("unable to delete expired refresh token with id %s", id), "err", err.Error())
			}

			s.logger.Info(fmt.Sprintf("deleted expired refresh token with id: %s", id))
		}(refresh.Uuid)

		return nil, errors.New("refresh token is expired")
	}

	// decrypt refresh token for use
	decrypted, err := s.cryptor.DecryptServiceData(refresh.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt refresh token with uuid %s: %v", refresh.Uuid, err)
	}
	refresh.RefreshToken = decrypted

	return &refresh, nil
}

// creates primary key and blind index
// encrypts refresh token
func (s *s2sAuthService) PersistRefresh(r types.S2sRefresh) error {

	// create primary key uuid for db record
	refreshId, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("failed to create refresh token db record primary key/uuid: %v", err)
	}
	r.Uuid = string(refreshId.String())

	// create blind index for db record
	index, err := s.indexer.ObtainBlindIndex(r.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to obtain blind index from refresh token: %v", err)
	}
	r.RefreshIndex = index

	// encrypt refresh token for db reocrd
	encrypted, err := s.cryptor.EncryptServiceData(r.RefreshToken)
	if err != nil {
		return fmt.Errorf("unable to encrypt refresh token for database entry")
	}
	r.RefreshToken = encrypted

	qry := "INSERT INTO refresh (uuid, refresh_index, service_name, refresh_token, client_uuid, created_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?)"
	if err := s.sql.InsertRecord(qry, r); err != nil {
		s.logger.Error("unable to save refresh token", "err", err.Error())
		return errors.New("unable to save refresh token")
	}
	return nil
}
