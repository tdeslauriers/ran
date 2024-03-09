package s2s

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/jwt"
	"github.com/tdeslauriers/carapace/session"
	"golang.org/x/crypto/bcrypt"
)

const (
	TokenDuration   time.Duration = time.Duration(5)
	RefreshDuration time.Duration = time.Duration(30)
)

type MariaS2sAuthService struct {
	Dao     data.SqlRepository
	Mint    jwt.JwtSigner
	Indexer data.Indexer
	Cryptor data.Cryptor
}

func NewS2sAuthService(sql data.SqlRepository, mint jwt.JwtSigner, indexer data.Indexer, ciph data.Cryptor) *MariaS2sAuthService {
	return &MariaS2sAuthService{
		Dao:     sql,
		Mint:    mint,
		Indexer: indexer,
		Cryptor: ciph,
	}
}

func (s *MariaS2sAuthService) ValidateCredentials(clientId, clientSecret string) error {

	var s2sClient session.S2sClientData
	qry := "SELECT uuid, password, name, owner, created_at, enabled, account_expired, account_locked FROM client WHERE uuid = ?"

	if err := s.Dao.SelectRecord(qry, &s2sClient, clientId); err != nil {
		log.Panicf("unable to retrieve s2s client record: %v", err)
		return errors.New("unable to retrieve s2s client record")
	}

	// password checked first to prevent account enumeration
	secret := []byte(clientSecret)
	hash := []byte(s2sClient.Password)
	if err := bcrypt.CompareHashAndPassword(hash, secret); err != nil {
		log.Printf("unable to validate password: %v", err)
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

func (s *MariaS2sAuthService) GetUserScopes(uuid, service string) ([]session.Scope, error) {

	var scopes []session.Scope
	qry := `
		SELECT 
			s.uuid,
			s.service_name
			s.scope,
			s.name,
			s.description,
			s.created_at,
			s.active
		FROM scope s 
			LEFT JOIN client_scope cs ON s.uuid = cs.scope_uuid
		WHERE cs.client_uuid = ?
			AND s.service_name = ?`
	if err := s.Dao.SelectRecords(qry, &scopes, uuid, service); err != nil {
		log.Printf("unable to retrieve scopes for client %s: %v", uuid, err)
		return scopes, fmt.Errorf("unable to retrieve scopes for client %s", uuid)
	}

	return scopes, nil
}

// assumes credentials already validated
func (s *MariaS2sAuthService) MintAuthzToken(subject, service string) (*jwt.JwtToken, error) {

	// jwt header
	header := jwt.JwtHeader{Alg: jwt.ES512, Typ: jwt.TokenType}

	// set up jwt claims fields
	jti, err := uuid.NewRandom()
	if err != nil {
		log.Printf("unable to create jti uuid: %v", err)
		return nil, errors.New("failed to mint s2s token")
	}

	currentTime := time.Now().UTC()

	scopes, err := s.GetUserScopes(subject, service)
	if err != nil {
		return nil, err
	}

	// create scopes string: scope values, space delimited
	var builder strings.Builder
	for i, v := range scopes {
		builder.WriteString(v.Scope)
		if len(scopes) > 1 && i+1 < len(scopes) {
			builder.WriteString(" ")
		}
	}

	claims := jwt.JwtClaims{
		Jti:       jti.String(),
		Issuer:    "ran",
		Subject:   subject,
		Audience:  session.BuildAudiences(scopes),
		IssuedAt:  currentTime.Unix(),
		NotBefore: currentTime.Unix(),
		Expires:   currentTime.Add(TokenDuration * time.Minute).Unix(),
		Scopes:    builder.String(),
	}

	jot := jwt.JwtToken{Header: header, Claims: claims}

	err = s.Mint.MintJwt(&jot)
	if err != nil {
		return nil, fmt.Errorf("unable to mint jwt: %v", err)
	}

	return &jot, err
}

// finds by regenerating blind index
// decrypts refresh token for use
func (s *MariaS2sAuthService) GetRefreshToken(refreshToken string) (*session.S2sRefresh, error) {

	// re-create blind index for lookup.
	index, err := s.Indexer.ObtainBlindIndex(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create blind index value for refresh token lookup: %v", err)
	}

	// look up refresh
	var refresh session.S2sRefresh
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
	if err := s.Dao.SelectRecord(qry, &refresh, index); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("refresh token does not exist")
		}
		return nil, fmt.Errorf("refresh token lookup failed: %v", err)
	}

	// check revoked status
	if refresh.Revoked {
		return nil, errors.New("refresh token has been revoked")
	}

	// validate refresh token not expired server-side
	if refresh.CreatedAt.Time.Add(RefreshDuration * time.Minute).Before(time.Now().UTC()) {

		// opportunistically delete expired refresh tokens
		go func(id string) {
			qry := "DELETE FROM refresh WHERE uuid = ?"
			if err := s.Dao.DeleteRecord(qry, id); err != nil {
				log.Printf("unable to delete expired refresh token %s: %v", id, err)
			}

			log.Printf("deleted expired refresh token id: %s", id)
		}(refresh.Uuid)

		return nil, errors.New("refresh token is expired")
	}

	// decrypt refresh token for use
	decrypted, err := s.Cryptor.DecyptServiceData(refresh.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt refresh token with uuid %s: %v", refresh.Uuid, err)
	}
	refresh.RefreshToken = decrypted

	return &refresh, nil
}

// creates primary key and blind index
// encrypts refresh token
func (s *MariaS2sAuthService) PersistRefresh(r session.S2sRefresh) error {

	// create primary key uuid for db record
	refreshId, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("failed to create refresh token db record primary key/uuid: %v", err)
	}
	r.Uuid = string(refreshId.String())

	// create blind index for db record
	index, err := s.Indexer.ObtainBlindIndex(r.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to obtain blind index from refresh token: %v", err)
	}
	r.RefreshIndex = index

	// encrypt refresh token for db reocrd
	encrypted, err := s.Cryptor.EncyptServiceData(r.RefreshToken)
	if err != nil {
		return fmt.Errorf("unable to encrypt refresh token for database entry")
	}
	r.RefreshToken = encrypted

	qry := "INSERT INTO refresh (uuid, refresh_index, service_name, refresh_token, client_uuid, created_at, revoked) VALUES (?, ?, ?, ?, ?)"
	if err := s.Dao.InsertRecord(qry, r); err != nil {
		log.Printf("unable to save refresh token: %v", err)
		return errors.New("unable to save refresh token")
	}
	return nil
}
