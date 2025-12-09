package authentication

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/ran/internal/definitions"
	"github.com/tdeslauriers/ran/pkg/scopes"
)

const (
	TokenDuration   time.Duration = time.Duration(5)   // minutes
	RefreshDuration time.Duration = time.Duration(180) // minutes
)

// AuthService is an interface for authentication services that validates credentials, gets scopes, and mints authorization tokens
type AuthService interface {
	// ValidateCredentials validates credentials provided by client, whether s2s or user
	ValidateCredentials(id, secret string) error

	// GetScopes gets scopes specific to a service for a given identifier.
	// 'user' parameter can be a username or a client id.
	GetScopes(user, service string) ([]scopes.Scope, error)

	// MintToken builds and signs a jwt token for a given claims struct.
	// It does not validate or perform checks on these values, it assumes they are valid.
	MintToken(claims jwt.Claims) (*jwt.Token, error)
}

// S2sAuthService is an interface for service-to-service authentication services
// and contains the AuthService interface and the RefreshService interface
type S2sAuthService interface {
	AuthService
	types.RefreshService[types.S2sRefresh]
}

// NewS2sAuthService creates a new S2sAuthService interface instance returning
// a pointer to the underlying concrete implementation.
func NewS2sAuthService(sql *sql.DB, mint jwt.Signer, i data.Indexer, ciph data.Cryptor, creds CredService) S2sAuthService {
	return &s2sAuthService{
		sql:         NewAuthRepository(sql),
		mint:        mint,
		indexer:     i,
		cryptor:     ciph,
		credService: creds,

		logger: slog.Default().
			With(slog.String(definitions.ComponentKey, definitions.ComponentAuthn)).
			With(definitions.PackageKey, definitions.PackageAuthentication),
	}
}

var _ S2sAuthService = (*s2sAuthService)(nil)

// s2sAuthService implements the S2sAuthService interface for service-to-service authentication.
type s2sAuthService struct {
	sql         AuthRepository
	mint        jwt.Signer
	indexer     data.Indexer
	cryptor     data.Cryptor
	credService CredService

	logger *slog.Logger
}

// ValidateCredentials checks the provided client ID and secret against the database.
func (s *s2sAuthService) ValidateCredentials(clientId, clientSecret string) error {

	// get record from the database if exists
	c, err := s.sql.GetClientById(clientId)
	if err != nil {
		return err
	}

	// check if client is enabled
	if !c.Enabled {
		return fmt.Errorf("s2s client with id %s is not enabled", clientId)
	}

	// check if account is locked
	if c.AccountLocked {
		return fmt.Errorf("s2s client with id %s is locked", clientId)
	}

	// check if account is expired
	if c.AccountExpired {
		return fmt.Errorf("s2s client with id %s has expired", clientId)
	}

	// validate password
	if err := s.credService.CompareHashAndPassword(c.Password, clientSecret); err != nil {
		return fmt.Errorf("failed to validate credentials for s2s client id %s: %v", clientId, err)
	}

	return nil
}

// GetScopes gets scopes specific to a service for a given client id.
func (s *s2sAuthService) GetScopes(clientId, service string) ([]scopes.Scope, error) {

	// get scopes from database
	return s.sql.GetScopes(clientId, service)
}

// MintToken builds and signs a jwt token for a given claims struct.
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

// GetRefreshToken gets refresh token from persistence and decrypts it.
func (s *s2sAuthService) GetRefreshToken(ctx context.Context, refreshToken string) (*types.S2sRefresh, error) {

	log := s.logger

	telemetry, ok := connect.GetTelemetryFromContext(ctx)
	if ok && telemetry != nil {
		log = log.With(telemetry.TelemetryFields()...)
	} else {
		log.Warn("failed to extract context for GetRefreshToken")
	}

	if len(refreshToken) < 16 || len(refreshToken) > 64 {
		return nil, errors.New("invalid refresh token")
	}

	// re-create blind index for lookup.
	index, err := s.indexer.ObtainBlindIndex(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create blind index value for refresh token lookup: %v", err)
	}

	// look up refresh
	refresh, err := s.sql.FindRefreshToken(index)
	if err != nil {
		return nil, err
	}

	// check revoked status
	if refresh.Revoked {
		return nil, fmt.Errorf("refresh token xxxxxx-%s has been revoked", refreshToken[len(refreshToken)-6:])
	}

	// validate refresh token not expired server-side
	if refresh.CreatedAt.Time.Add(RefreshDuration * time.Minute).Before(time.Now().UTC()) {

		// opportunistically delete expired refresh token
		go func(id string) {

			// delete refresh from db
			if err := s.sql.DeleteRefreshById(id); err != nil {
				log.Error(fmt.Sprintf("failed to delete expired refresh token with id: %s", id), slog.String("error", err.Error()))
				return
			}

			log.Info(fmt.Sprintf("deleted expired refresh token with id: %s", id))
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
			ch <- fmt.Errorf("failed to decrypt client id %s for refresh token xxxxxx-%s: %v",
				client, refreshToken[len(refreshToken)-6:], err)
			return
		}
		*decryptedClient = (string(decrypted))
	}(refresh.ClientId, &decryptedClient, errChan, &wgDecrypt)

	// wait for all decryption go routines to finish
	wgDecrypt.Wait()
	close(errChan)

	// check for errors and consolidate
	if len(errChan) > 0 {
		var errs []error
		for e := range errChan {
			errs = append(errs, e)
		}
		return nil, fmt.Errorf("errors occurred during decryption of refresh token xxxxxx-%s: %s",
			refreshToken[len(refreshToken)-6:], errors.Join(errs...))
	}

	// update refresh struct with decrypted values
	refresh.ServiceName = decryptedService
	refresh.RefreshToken = decryptedRefresh
	refresh.ClientId = decryptedClient

	return refresh, nil
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

	// persist refresh token to db
	if err := s.sql.InsertRefreshToken(r); err != nil {
		return fmt.Errorf("failed to persist refresh token: %v", err)
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

	// lookup refresh to validate it exists
	exists, err := s.sql.RefreshExists(index)
	if err != nil {
		return fmt.Errorf("failed to verify existence of refresh token xxxxxx-%s: %v", token[len(token)-6:], err)
	}
	if !exists {
		return fmt.Errorf("refresh token xxxxxx-%s does not exist", token[len(token)-6:])
	}

	// delete record
	if err := s.sql.DeleteRefreshByIndex(index); err != nil {
		return fmt.Errorf("failed to delete refresh token xxxxxx-%s: %v", token[len(token)-6:], err)
	}

	return nil
}

// RevokeRefresh marks a refresh token as revoked in the database.
func (s *s2sAuthService) RevokeRefresh(token string) error {

	// light validation: redundant check, but good practice
	if len(token) < 16 || len(token) > 64 {
		return fmt.Errorf("invalid refresh token: must be between %d and %d characters", 16, 64)
	}

	// create blind index
	index, err := s.indexer.ObtainBlindIndex(token)
	if err != nil {
		return fmt.Errorf("failed to generate blind index for refresh token xxxxxx-%s: %v", token[len(token)-6:], err)
	}

	// lookup refresh token record
	refresh, err := s.sql.FindRefreshToken(index)
	if err != nil {
		return fmt.Errorf("failed to retrieve refresh token xxxxxx-%s for revocation: %v", token[len(token)-6:], err)
	}

	// check if already revoked
	if refresh.Revoked {
		return fmt.Errorf("refresh token xxxxxx-%s is already revoked", token[len(token)-6:])
	}

	// mark as revoked
	refresh.Revoked = true

	// update record in db
	if err := s.sql.UpdateRefreshToken(*refresh); err != nil {
		return fmt.Errorf("failed to revoke refresh token xxxxxx-%s: %v", token[len(token)-6:], err)
	}

	return nil
}
