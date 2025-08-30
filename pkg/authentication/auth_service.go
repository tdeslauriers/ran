package authentication

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/ran/internal/util"
)

const (
	TokenDuration   time.Duration = time.Duration(5)   // minutes
	RefreshDuration time.Duration = time.Duration(180) // minutes
)

func NewS2sAuthService(sql data.SqlRepository, mint jwt.Signer, i data.Indexer, ciph data.Cryptor, creds CredService) types.S2sAuthService {
	return &s2sAuthService{
		sql:         sql,
		mint:        mint,
		indexer:     i,
		cryptor:     ciph,
		credService: creds,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentAuthn)),
	}
}

var _ types.S2sAuthService = (*s2sAuthService)(nil)

type s2sAuthService struct {
	sql         data.SqlRepository
	mint        jwt.Signer
	indexer     data.Indexer
	cryptor     data.Cryptor
	credService CredService

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
			account_locked, 
			slug
		FROM client 
		WHERE uuid = ?`
	if err := s.sql.SelectRecord(qry, &s2sClient, clientId); err != nil {
		s.logger.Error("failed to retrieve s2s client record", "err", err.Error())
		return errors.New("failed to retrieve s2s client record")
	}

	// validate password
	if err := s.credService.CompareHashAndPassword(s2sClient.Password, clientSecret); err != nil {
		s.logger.Error("failed to validate password", "err", err.Error())
		return errors.New("failed to validate password")
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
			s.active,
			slug
		FROM scope s 
			LEFT JOIN client_scope cs ON s.uuid = cs.scope_uuid
		WHERE cs.client_uuid = ?
			AND s.service_name = ?`
	if err := s.sql.SelectRecords(qry, &scopes, clientId, service); err != nil {
		s.logger.Error(fmt.Sprintf("failed to retrieve scopes for client %s", clientId), "err", err.Error())
		return scopes, fmt.Errorf("failed to retrieve scopes for client %s", clientId)
	}

	return scopes, nil
}

// assumes credentials already validated
func (s *s2sAuthService) MintToken(claims jwt.Claims) (*jwt.Token, error) {

	// jwt header
	header := jwt.Header{
		Alg: jwt.ES512,
		Typ: jwt.TokenType,
	}

	jot := jwt.Token{
		Header: header,
		Claims: claims,
	}

	if err := s.mint.Mint(&jot); err != nil {
		return nil, fmt.Errorf("failed to mint jwt for client id %s: %v", claims.Subject, err)
	}

	return &jot, nil
}

// finds by regenerating blind index
// decrypts refresh token for use
func (s *s2sAuthService) GetRefreshToken(refreshToken string) (*types.S2sRefresh, error) {

	if len(refreshToken) < 16 || len(refreshToken) > 64 {
		return nil, errors.New("invalid refresh token")
	}

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

		return nil, fmt.Errorf("refresh token xxxxxx-%s is expired", refreshToken[len(refreshToken)-6:])
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
		*decryptedService = string(decrypted)
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
		*decryptedRefresh = string(decrypted)
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
		*decryptedClient = (string(decrypted))
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
			ch <- fmt.Errorf("%s for refresh token xxxxxx-%s: %v", ErrGenIndex, refresh[len(refresh)-6:], err)
			return
		}
		*index = ndx
	}(r.RefreshToken, &index, errChan, &wgRecord)

	// encrypt service name for db record
	wgRecord.Add(1)
	go func(service string, encryptedService *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData([]byte(service))
		if err != nil {
			ch <- fmt.Errorf("%s %s for db record: %v", ErrEncryptServiceName, service, err)
			return
		}
		*encryptedService = encrypted
	}(r.ServiceName, &encryptedService, errChan, &wgRecord)

	// encrypt refresh token for db record
	wgRecord.Add(1)
	go func(refresh string, encryptedRefresh *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData([]byte(refresh))
		if err != nil {
			ch <- fmt.Errorf("%s xxxxxx-%s for db record: %v", ErrEncryptRefresh, refresh[len(refresh)-6:], err)
			return
		}
		*encryptedRefresh = encrypted
	}(r.RefreshToken, &encryptedRefresh, errChan, &wgRecord)

	// encrypt client id for db record
	wgRecord.Add(1)
	go func(client string, encryptedClient *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData([]byte(client))
		if err != nil {
			ch <- fmt.Errorf("%s %s for db record: %v", ErrEncryptClientId, client, err)
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
			ch <- fmt.Errorf("failed to generate blind index for client id %s: %v", client, err)
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
		s.logger.Error("faied to save refresh token", "err", err.Error())
		return errors.New("failed to save refresh token")
	}
	return nil
}

// DestroyRefresh deletes a refresh token record from the database.
func (s *s2sAuthService) DestroyRefresh(token string) error {

	// light validation: redundant check, but good practice
	if len(token) < 16 || len(token) > 64 {
		return fmt.Errorf("invalid refresh token: must be between %d and %d characters", 16, 64)
	}

	// create blind index
	index, err := s.indexer.ObtainBlindIndex(token)
	if err != nil {
		return fmt.Errorf("failed to generate blind index for refresh token xxxxxx-%s: %v", token[len(token)-6:], err)
	}

	// calling record to validate it exists
	// TODO: update crud functions in carapace to return rows affected so calls can be consolidated.
	qry := `SELECT EXISTS (SELECT 1 FROM refresh WHERE refresh_index = ?)`
	if exists, err := s.sql.SelectExists(qry, index); err != nil {
		return fmt.Errorf("failed to lookup refresh token xxxxxx-%s record: %v", token[len(token)-6:], err)
	} else if !exists {
		return fmt.Errorf("refresh token xxxxxx-%s record does not exist", token[len(token)-6:])
	}

	// delete record
	qry = `DELETE FROM refresh WHERE refresh_index = ?`
	if err := s.sql.DeleteRecord(qry, index); err != nil {
		return fmt.Errorf("failed to delete refresh token xxxxxx-%s record: %v", token[len(token)-6:], err)
	}

	return nil
}

// TODO: implement
func (s *s2sAuthService) RevokeRefresh(token string) error {
	return nil
}
