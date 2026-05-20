package authentication

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect/telemetry"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/ran/internal/clients"
	"github.com/tdeslauriers/ran/internal/definitions"
	"github.com/tdeslauriers/ran/pkg/api/scopes"
)

const (
	TokenDuration   time.Duration = time.Duration(5)   // minutes
	RefreshDuration time.Duration = time.Duration(180) // minutes
)

// AuthService is an interface for authentication services that validates credentials, gets scopes, and mints authorization tokens
type AuthService interface {
	// ValidateCredentials validates credentials provided by client, returning the client account if valid.
	ValidateCredentials(id, secret string) (*clients.ClientAccount, error)

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

// ValidateCredentials checks the provided client ID and secret against the database, returning the client account if valid.
func (s *s2sAuthService) ValidateCredentials(clientId, clientSecret string) (*clients.ClientAccount, error) {

	// get record from the database if exists
	record, err := s.sql.FindClientById(clientId)
	if err != nil {
		return nil, err
	}

	// validate password
	if err := s.credService.CompareHashAndPassword(record.Password, clientSecret); err != nil {
		return nil, fmt.Errorf("failed to validate credentials for s2s client id %s: %v", clientId, err)
	}

	// check if client is enabled
	if !record.Enabled {
		return nil, fmt.Errorf("s2s client with id %s is not enabled", clientId)
	}

	// check if account is locked
	if record.AccountLocked {
		return nil, fmt.Errorf("s2s client with id %s is locked", clientId)
	}

	// check if account is expired
	if record.AccountExpired {
		return nil, fmt.Errorf("s2s client with id %s has expired", clientId)
	}

	return &clients.ClientAccount{
		Id:             record.Id,
		Name:           record.Name,
		Owner:          record.Owner,
		CreatedAt:      record.CreatedAt,
		Enabled:        record.Enabled,
		AccountExpired: record.AccountExpired,
		AccountLocked:  record.AccountLocked,
		Slug:           record.Slug,
	}, nil
}

// GetScopes gets scopes specific to a service for a given client id.
func (s *s2sAuthService) GetScopes(clientId, service string) ([]scopes.Scope, error) {

	// get scopes from database
	return s.sql.FindScopes(clientId, service)
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

	tel, ok := ctx.Value(telemetry.TelemetryKey).(*telemetry.Telemetry)
	if ok && tel != nil {
		log = log.With(tel.TelemetryFields()...)
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
		wgDecrypt           sync.WaitGroup
		decryptedServiceCh  = make(chan string, 1)
		decryptedRefreshCh  = make(chan string, 1)
		decryptedClientIdCh = make(chan string, 1)
		decryptedClientName = make(chan string, 1)
		errChan             = make(chan error, 4)
	)

	// decrypt service name
	wgDecrypt.Add(1)
	go func(service string, decryptedServiceCh chan string, errCh chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		decrypted, err := s.cryptor.DecryptServiceData(service)
		if err != nil {
			errCh <- fmt.Errorf("failed to decrypt service name %s for refresh token xxxxxx-%s: %v", service, refreshToken[len(refreshToken)-6:], err)
			return
		}
		decryptedServiceCh <- string(decrypted)
	}(refresh.ServiceName, decryptedServiceCh, errChan, &wgDecrypt)

	// decrypt refresh token
	wgDecrypt.Add(1)
	go func(refresh string, decryptedRefresh chan string, errCh chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		decrypted, err := s.cryptor.DecryptServiceData(refresh)
		if err != nil {
			errCh <- fmt.Errorf("failed to decrypt refresh token xxxxxx-%s: %v", refresh[len(refresh)-6:], err)
			return
		}
		decryptedRefresh <- string(decrypted)
	}(refresh.RefreshToken, decryptedRefreshCh, errChan, &wgDecrypt)

	// decrypt client id
	wgDecrypt.Add(1)
	go func(client string, decryptedClientIdCh chan string, errCh chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		decrypted, err := s.cryptor.DecryptServiceData(client)
		if err != nil {
			errCh <- fmt.Errorf("failed to decrypt client id %s for refresh token xxxxxx-%s: %v",
				client, refreshToken[len(refreshToken)-6:], err)
			return
		}
		decryptedClientIdCh <- string(decrypted)
	}(refresh.ClientId, decryptedClientIdCh, errChan, &wgDecrypt)

	// decrypt client name
	wgDecrypt.Add(1)
	go func(clientName string, decryptedClientName chan string, errCh chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		decrypted, err := s.cryptor.DecryptServiceData(clientName)
		if err != nil {
			errCh <- fmt.Errorf("failed to decrypt client name for refresh token xxxxxx-%s: %v",
				refreshToken[len(refreshToken)-6:], err)
			return
		}
		decryptedClientName <- string(decrypted)
	}(refresh.ClientName, decryptedClientName, errChan, &wgDecrypt)

	// wait for all decryption go routines to finish
	wgDecrypt.Wait()
	close(errChan)

	// check for errors and consolidate
	if len(errChan) > 0 {
		var errs []error
		for e := range errChan {
			errs = append(errs, e)
		}
		return nil, fmt.Errorf("failed to decrypt refresh token xxxxxx-%s: %s",
			refreshToken[len(refreshToken)-6:], errors.Join(errs...))
	}

	// update refresh struct with decrypted values
	refreshSvc, ok := <-decryptedServiceCh
	if !ok {
		return nil, fmt.Errorf("failed to decrypt service name for refresh token xxxxxx-%s", refreshToken[len(refreshToken)-6:])
	}
	refresh.ServiceName = refreshSvc

	tkn, ok := <-decryptedRefreshCh
	if !ok {
		return nil, fmt.Errorf("failed to decrypt refresh token xxxxxx-%s", refreshToken[len(refreshToken)-6:])
	}
	refresh.RefreshToken = tkn

	cId, ok := <-decryptedClientIdCh
	if !ok {
		return nil, fmt.Errorf("failed to decrypt client id for refresh token xxxxxx-%s", refreshToken[len(refreshToken)-6:])
	}
	refresh.ClientId = cId

	cName, ok := <-decryptedClientName
	if !ok {
		return nil, fmt.Errorf("failed to decrypt client name for refresh token xxxxxx-%s", refreshToken[len(refreshToken)-6:])
	}
	refresh.ClientName = cName

	return refresh, nil
}

// creates primary key and blind index
// encrypts refresh token
func (s *s2sAuthService) PersistRefresh(r types.S2sRefresh) error {

	var (
		wgRecord              sync.WaitGroup
		uuidCh                = make(chan uuid.UUID, 1)
		refreshIndexCh        = make(chan string, 1)
		encryptedServiceCh    = make(chan string, 1)
		encryptedRefreshCh    = make(chan string, 1)
		encryptedClientIdCh   = make(chan string, 1)
		clientIndexCh         = make(chan string, 1)
		encryptedClientNameCh = make(chan string, 1)
		errChan               = make(chan error, 7)
	)

	// create primary key uuid for db record
	wgRecord.Add(1)
	go func(uuidCh chan uuid.UUID, errCh chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		i, err := uuid.NewRandom()
		if err != nil {
			errCh <- fmt.Errorf("failed to create refresh token db record primary key/uuid: %v", err)
			return
		}
		uuidCh <- i
	}(uuidCh, errChan, &wgRecord)

	// create blind index for db record
	wgRecord.Add(1)
	go func(refresh string, refreshIndexCh chan string, errCh chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		ndx, err := s.indexer.ObtainBlindIndex(refresh)
		if err != nil {
			errCh <- fmt.Errorf("%s for refresh token xxxxxx-%s: %v", ErrGenIndex, refresh[len(refresh)-6:], err)
			return
		}
		refreshIndexCh <- ndx
	}(r.RefreshToken, refreshIndexCh, errChan, &wgRecord)

	// encrypt service name for db record
	wgRecord.Add(1)
	go func(service string, encryptedServiceCh chan string, errch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData([]byte(service))
		if err != nil {
			errch <- fmt.Errorf("%s %s for db record: %v", ErrEncryptServiceName, service, err)
			return
		}
		encryptedServiceCh <- encrypted
	}(r.ServiceName, encryptedServiceCh, errChan, &wgRecord)

	// encrypt refresh token for db record
	wgRecord.Add(1)
	go func(refresh string, encryptedRefreshCh chan string, errCh chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData([]byte(refresh))
		if err != nil {
			errCh <- fmt.Errorf("%s xxxxxx-%s for db record: %v", ErrEncryptRefresh, refresh[len(refresh)-6:], err)
			return
		}
		encryptedRefreshCh <- encrypted
	}(r.RefreshToken, encryptedRefreshCh, errChan, &wgRecord)

	// encrypt client id for db record
	wgRecord.Add(1)
	go func(clientId string, encryptedClientIdCh chan string, errCh chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData([]byte(clientId))
		if err != nil {
			errCh <- fmt.Errorf("%s %s for db record: %v", ErrEncryptClientId, clientId, err)
			return
		}
		encryptedClientIdCh <- encrypted
	}(r.ClientId, encryptedClientIdCh, errChan, &wgRecord)

	// create client id blind index for db record
	wgRecord.Add(1)
	go func(client string, clientIndexCh chan string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		i, err := s.indexer.ObtainBlindIndex(client)
		if err != nil {
			ch <- fmt.Errorf("failed to generate blind index for client id %s: %v", client, err)
			return
		}
		clientIndexCh <- i
	}(r.ClientId, clientIndexCh, errChan, &wgRecord)

	// encrypt client name for db record
	wgRecord.Add(1)
	go func(clientName string, encryptedClientNameCh chan string, errCh chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		encrypted, err := s.cryptor.EncryptServiceData([]byte(clientName))
		if err != nil {
			errCh <- fmt.Errorf("%s %s for db record: %v", ErrEncryptClientName, clientName, err)
			return
		}
		encryptedClientNameCh <- encrypted
	}(r.ClientName, encryptedClientNameCh, errChan, &wgRecord)

	// wait for all record creation go routines to finish
	wgRecord.Wait()
	close(errChan)

	// check for errors and consolidate
	if len(errChan) > 0 {
		var errs []error
		for e := range errChan {
			errs = append(errs, e)
		}
		return fmt.Errorf("failed to encrypt refresh token db record for client id %s: %s", r.ClientId, errors.Join(errs...))
	}

	// set the values if they are not empty
	// these should never be empty since errors are checked above -> good practice
	id, ok := <-uuidCh
	if !ok {
		return fmt.Errorf("failed to generate primary key for refresh token db record for client id %s", r.ClientId)
	}
	r.Uuid = id.String()

	rIdx, ok := <-refreshIndexCh
	if !ok {
		return fmt.Errorf("failed to generate blind index for refresh token db record for client id %s", r.ClientId)
	}
	r.RefreshIndex = rIdx

	svc, ok := <-encryptedServiceCh
	if !ok {
		return fmt.Errorf("failed to encrypt service name for refresh token db record for client id %s", r.ClientId)
	}
	r.ServiceName = svc

	rsh, ok := <-encryptedRefreshCh
	if !ok {
		return fmt.Errorf("failed to encrypt refresh token for refresh token db record for client id %s", r.ClientId)
	}
	r.RefreshToken = rsh

	cId, ok := <-encryptedClientIdCh
	if !ok {
		return fmt.Errorf("failed to encrypt client id for refresh token db record for client id %s", r.ClientId)
	}
	r.ClientId = cId

	cIdx, ok := <-clientIndexCh
	if !ok {
		return fmt.Errorf("failed to generate client id blind index for refresh token db record for client id %s", r.ClientId)
	}
	r.ClientIndex = cIdx

	cName, ok := <-encryptedClientNameCh
	if !ok {
		return fmt.Errorf("failed to encrypt client name for refresh token db record for client id %s", r.ClientId)
	}
	r.ClientName = cName

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
