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

type S2sLoginCmd struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type MariaS2sAuthService struct {
	Dao  data.SqlRepository
	Mint jwt.JwtSigner
}

func NewS2sAuthService(sql data.SqlRepository, mint jwt.JwtSigner) *MariaS2sAuthService {
	return &MariaS2sAuthService{
		Dao:  sql,
		Mint: mint,
	}
}

func (s *MariaS2sAuthService) ValidateCredentials(clientId, clientSecret string) error {

	var s2sClient session.S2sClientData
	qry := "SELECT uuid, password, name, owner, created_at, enabled, account_expired, account_locked FROM client WHERE uuid = ?"

	if err := s.Dao.SelectRecord(qry, &s2sClient, clientId); err != nil {
		log.Panicf("unable to retrieve s2s client record: %v", err)
		return err
	}

	// password checked first to prevent account enumeration
	secret := []byte(clientSecret)
	hash := []byte(s2sClient.Password)
	if err := bcrypt.CompareHashAndPassword(hash, secret); err != nil {
		return fmt.Errorf("unable to validate password: %v", err)
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

func (s *MariaS2sAuthService) GetUserScopes(uuid string) ([]session.Scope, error) {

	var scopes []session.Scope
	qry := `
		SELECT 
			s.uuid,
			s.scope,
			s.name,
			s.description,
			s.created_at,
			s.active
		FROM scope s 
			LEFT JOIN client_scope cs ON s.uuid = cs.scope_uuid
		WHERE cs.client_uuid = ?`
	if err := s.Dao.SelectRecords(qry, &scopes, uuid); err != nil {
		return scopes, fmt.Errorf("unable to retrieve scopes for client %s: %v", uuid, err)
	}

	return scopes, nil
}

// assumes credentials already validated
func (s *MariaS2sAuthService) MintAuthzToken(subject string) (*jwt.JwtToken, error) {

	// jwt header
	header := jwt.JwtHeader{Alg: jwt.ES512, Typ: jwt.TokenType}

	// set up jwt claims fields
	jti, err := uuid.NewRandom()
	if err != nil {
		log.Panicf("Unable to create jti uuid")
	}

	currentTime := time.Now().UTC()

	scopes, err := s.GetUserScopes(subject)
	if err != nil {
		return nil, err
	}

	// create scopes string: scope values, space delimited
	var builder strings.Builder
	for _, v := range scopes {
		builder.WriteString(v.Scope)
		builder.WriteString(" ")
	}

	claims := jwt.JwtClaims{
		Jti:       jti.String(),
		Issuer:    "ran",
		Subject:   subject,
		Audience:  session.BuildAudiences(scopes),
		IssuedAt:  currentTime.Unix(),
		NotBefore: currentTime.Unix(),
		Expires:   currentTime.Add(10 * time.Minute).Unix(),
		Scopes:    builder.String(),
	}

	jot := jwt.JwtToken{Header: header, Claims: claims}

	err = s.Mint.MintJwt(&jot)
	if err != nil {
		return nil, err
	}

	return &jot, err
}

func (s *MariaS2sAuthService) GetRefreshToken(refreshToken string) (*session.S2sRefresh, error) {

	// look up refresh
	var refresh session.S2sRefresh
	qry := `
		SELECT 
			uuid, 
			refresh_token, 
			client_uuid, 
			created_at, 
			revoked 
		FROM refresh
		WHERE refresh_token = ?`
	if err := s.Dao.SelectRecord(qry, &refresh, refreshToken); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("refresh token does not exist")
		}
		return nil, fmt.Errorf("refresh token lookup failed: %v", err)
	}

	// check revoke status
	if refresh.Revoked {
		return nil, fmt.Errorf("refresh token has been revoked")
	}

	// validate refresh token not expired server-side
	if refresh.CreatedAt.Time.Add(30 * time.Minute).Before(time.Now().UTC()) {

		// opportunistically delete expired refresh tokens
		go func(id string) {
			qry := "DELETE FROM refresh WHERE uuid = ?"
			if err := s.Dao.DeleteRecord(qry, id); err != nil {
				log.Printf("unable to delete expired refresh token %s", id)
			}

			log.Printf("deleted expired refresh token id: %s", id)
		}(refresh.Uuid)

		return nil, fmt.Errorf("refresh token is expired")
	}

	return &refresh, nil
}

func (s *MariaS2sAuthService) PersistRefresh(r session.S2sRefresh) error {

	qry := "INSERT INTO refresh (uuid, refresh_token, client_uuid, created_at, revoked) VALUES (?, ?, ?, ?, ?)"
	if err := s.Dao.InsertRecord(qry, r); err != nil {
		return fmt.Errorf("unable to save refresh token: %v", err)
	}
	return nil
}
