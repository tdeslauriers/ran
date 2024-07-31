package authentication

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"ran/internal/util"
	"strings"
	"sync"
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

func NewS2sAuthService(sql data.SqlRepository, mint jwt.Signer, indexer data.Indexer, ciph data.Cryptor) types.S2sAuthService {
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
	mint    jwt.Signer
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
func (s *s2sAuthService) MintToken(subject, scopes string) (*jwt.Token, error) {

	// jwt header
	header := jwt.Header{Alg: jwt.ES512, Typ: jwt.TokenType}

	// set up jwt claims fields
	jti, err := uuid.NewRandom()
	if err != nil {
		s.logger.Error("unable to create jwt jti uuid", "err", err.Error())
		return nil, errors.New("failed to mint s2s token")
	}

	currentTime := time.Now().UTC()

	claims := jwt.Claims{
		Jti:       jti.String(),
		Issuer:    util.SericeName,
		Subject:   subject,
		Audience:  types.BuildAudiences(scopes),
		IssuedAt:  currentTime.Unix(),
		NotBefore: currentTime.Unix(),
		Expires:   currentTime.Add(TokenDuration * time.Minute).Unix(),
		Scopes:    scopes,
	}

	jot := jwt.Token{Header: header, Claims: claims}

	if err := s.mint.Mint(&jot); err != nil {
		return nil, fmt.Errorf("unable to mint jwt for client id %s: %v", subject, err)
	}

	return &jot, nil
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
			client_index,
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
				s.logger.Error(fmt.Sprintf("failed to delete expired refresh token with id %s", id), "err", err.Error())
			}

			s.logger.Info(fmt.Sprintf("deleted expired refresh token with id: %s", id))
		}(refresh.Uuid)

		return nil, errors.New("refresh token is expired")
	}

	var (
		wgDecrypt        sync.WaitGroup
		decryptedService string
		decryptedRefresh string
		decryptedClient  string
	)
	errChan := make(chan error, 3)

	// decrypt service name
	wgDecrypt.Add(1)
	go func(service string, decryptedService *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		decrypted, err := s.cryptor.DecryptServiceData(service)
		if err != nil {
			ch <- fmt.Errorf("failed to decrypt service name %s for refresh token xxxxxx-%s: %v", service, refreshToken[len(refreshToken)-6:], err)
			return
		}
		*decryptedService = decrypted
	}(refresh.ServiceName, &decryptedService, errChan, &wgDecrypt)

	// decrypt refresh token
	wgDecrypt.Add(1)
	go func(refresh string, decryptedRefresh *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		decrypted, err := s.cryptor.DecryptServiceData(refresh)
		if err != nil {
			ch <- fmt.Errorf("failed to decrypt refresh token xxxxxx-%s: %v", refresh[len(refresh)-6:], err)
			return
		}
		*decryptedRefresh = decrypted
	}(refresh.RefreshToken, &decryptedRefresh, errChan, &wgDecrypt)

	// decrypt client id
	wgDecrypt.Add(1)
	go func(client string, decryptedClient *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		decrypted, err := s.cryptor.DecryptServiceData(client)
		if err != nil {
			ch <- fmt.Errorf("failed to decrypt client id %s for refresh token xxxxxx-%s: %v", client, refreshToken[len(refreshToken)-6:], err)
			return
		}
		*decryptedClient = decrypted
	}(refresh.ClientId, &decryptedClient, errChan, &wgDecrypt)

	// wait for all decryption go routines to finish
	wgDecrypt.Wait()
	close(errChan)

	// check for errors and consolidate
	if len(errChan) > 0 {
		var builder strings.Builder
		count := 0
		for e := range errChan {
			builder.WriteString(e.Error())
			if count < len(errChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return nil, errors.New(builder.String())
	}

	// update refresh struct with decrypted values
	refresh.ServiceName = decryptedService
	refresh.RefreshToken = decryptedRefresh
	refresh.ClientId = decryptedClient

	return &refresh, nil
}

// creates primary key and blind index
// encrypts refresh token
func (s *s2sAuthService) PersistRefresh(r types.S2sRefresh) error {

	var (
		wgRecord         sync.WaitGroup
		id               uuid.UUID
		index            string
		encryptedService string
		encryptedRefresh string
		encryptedClient  string
		clientIndex      string
	)
	errChan := make(chan error, 6)

	// create primary key uuid for db record
	wgRecord.Add(1)
	go func(id *uuid.UUID, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		i, err := uuid.NewRandom()
		if err != nil {
			ch <- fmt.Errorf("failed to create refresh token db record primary key/uuid: %v", err)
			return
		}
		*id = i
	}(&id, errChan, &wgRecord)

	// create blind index for db record
	wgRecord.Add(1)
	go func(refresh string, index *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		ndx, err := s.indexer.ObtainBlindIndex(refresh)
		if err != nil {
			ch <- fmt.Errorf("failed to create blind index for refresh token xxxxxx-%s: %v", refresh[:len(refresh)-6], err)
			return
		}
		*index = ndx
	}(r.RefreshToken, &index, errChan, &wgRecord)

	// encrypt service name for db record
	wgRecord.Add(1)
	go func(service string, encryptedService *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData(service)
		if err != nil {
			ch <- fmt.Errorf("failed to encrypt service name %s for db record: %v", service, err)
			return
		}
		*encryptedService = encrypted
	}(r.ServiceName, &encryptedService, errChan, &wgRecord)

	// encrypt refresh token for db record
	wgRecord.Add(1)
	go func(refresh string, encryptedRefresh *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData(refresh)
		if err != nil {
			ch <- fmt.Errorf("failed to encrypt refresh token xxxxxx-%s for db record: %v", refresh[:len(refresh)-6], err)
			return
		}
		*encryptedRefresh = encrypted
	}(r.RefreshToken, &encryptedRefresh, errChan, &wgRecord)

	// encrypt client id for db record
	wgRecord.Add(1)
	go func(client string, encryptedClient *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData(client)
		if err != nil {
			ch <- fmt.Errorf("failed to encrypt client id %s for db record: %v", client, err)
			return
		}
		*encryptedClient = encrypted
	}(r.ClientId, &encryptedClient, errChan, &wgRecord)

	// create client id blind index for db record
	wgRecord.Add(1)
	go func(client string, index *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		i, err := s.indexer.ObtainBlindIndex(client)
		if err != nil {
			ch <- fmt.Errorf("failed to create blind index for client id %s: %v", client, err)
			return
		}
		*index = i
	}(r.ClientId, &clientIndex, errChan, &wgRecord)

	// wait for all record creation go routines to finish
	wgRecord.Wait()
	close(errChan)

	// check for errors and consolidate
	if len(errChan) > 0 {
		var builder strings.Builder
		count := 0
		for e := range errChan {
			builder.WriteString(e.Error())
			if count < len(errChan)-1 {
				builder.WriteString("; ")
			}
			count++
		}
		return errors.New(builder.String())
	}

	// update refresh struct with new values
	r.Uuid = id.String()
	r.RefreshIndex = index
	r.ServiceName = encryptedService
	r.RefreshToken = encryptedRefresh
	r.ClientId = encryptedClient
	r.ClientIndex = clientIndex

	qry := "INSERT INTO refresh (uuid, refresh_index, service_name, refresh_token, client_uuid, client_index, created_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
	if err := s.sql.InsertRecord(qry, r); err != nil {
		s.logger.Error("unable to save refresh token", "err", err.Error())
		return errors.New("unable to save refresh token")
	}
	return nil
}
