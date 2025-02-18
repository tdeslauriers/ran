package s2s

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"ran/internal/util"
	"ran/pkg/authentication"
	"ran/pkg/clients"
	"ran/pkg/scopes"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/diagnostics"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/schedule"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/carapace/pkg/sign"
)

type S2s interface {
	Run() error
	CloseDb() error
}

func New(config config.Config) (S2s, error) {

	// pki for s2s
	// server
	serverPki := &connect.Pki{
		CertFile: *config.Certs.ServerCert,
		KeyFile:  *config.Certs.ServerKey,
		CaFiles:  []string{*config.Certs.ServerCa},
	}

	serverTlsConfig, err := connect.NewTlsServerConfig(config.Tls, serverPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure s2s server mtls: %v", err)
	}

	// db client
	dbClientPki := &connect.Pki{
		CertFile: *config.Certs.DbClientCert,
		KeyFile:  *config.Certs.DbClientKey,
		CaFiles:  []string{*config.Certs.DbCaCert},
	}

	dbClientTlsConfig, err := connect.NewTlsClientConfig(dbClientPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure db client tls: %v", err)
	}

	// db connection config
	dbUrl := data.DbUrl{
		Name:     config.Database.Name,
		Addr:     config.Database.Url,
		Username: config.Database.Username,
		Password: config.Database.Password,
	}

	// database
	db, err := data.NewSqlDbConnector(dbUrl, dbClientTlsConfig).Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	repository := data.NewSqlRepository(db)

	// indexer
	hmacSecret, err := base64.StdEncoding.DecodeString(config.Database.IndexSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hmac key: %v", err)
	}

	indexer := data.NewIndexer(hmacSecret)

	// field level encryption
	aes, err := base64.StdEncoding.DecodeString(config.Database.FieldSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode field level encryption key: %v", err)
	}

	cryptor := data.NewServiceAesGcmKey(aes)

	// jwt signer
	s2sPrivateKey, err := sign.ParsePrivateEcdsaCert(config.Jwt.S2sSigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse s2s signing private key: %v", err)
	}

	s2sSigner := jwt.NewSigner(s2sPrivateKey)

	// jwt s2sVerifier
	s2sVerifier := jwt.NewVerifier(config.ServiceName, &s2sPrivateKey.PublicKey)

	// jwt iamVerifier
	iamPublicKey, err := sign.ParsePublicEcdsaCert(config.Jwt.UserVerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse iam verifying public key: %v", err)
	}

	iamVerifier := jwt.NewVerifier(config.ServiceName, iamPublicKey)

	// s2s auth service
	s2sAuthService := authentication.NewS2sAuthService(repository, s2sSigner, indexer, cryptor)

	// scopes service
	scopesService := scopes.NewSerivce(repository)

	// clients service
	clientsService := clients.NewService(repository)

	// clean up: database
	cleanup := schedule.NewCleanup(repository)

	return &s2s{
		config:         config,
		serverTls:      serverTlsConfig,
		repository:     repository,
		s2sVerifier:    s2sVerifier,
		iamVerifier:    iamVerifier,
		authService:    s2sAuthService,
		scopesService:  scopesService,
		clientsService: clientsService,
		cleanup:        cleanup,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentS2s)),
	}, nil

}

var _ S2s = (*s2s)(nil)

type s2s struct {
	config         config.Config
	serverTls      *tls.Config
	repository     data.SqlRepository
	s2sVerifier    jwt.Verifier
	iamVerifier    jwt.Verifier
	authService    types.S2sAuthService
	scopesService  scopes.Service
	clientsService clients.Service
	cleanup        schedule.Cleanup

	logger *slog.Logger
}

func (s s2s) CloseDb() error {
	if err := s.repository.Close(); err != nil {
		return err
	}
	return nil
}

func (s *s2s) Run() error {

	loginHander := authentication.NewS2sLoginHandler(s.authService)
	refreshHandler := authentication.NewS2sRefreshHandler(s.authService)

	s2sScopesHandler := scopes.NewHandler(s.scopesService, s.s2sVerifier, nil) // user jwt verifier not needed
	iamScopesHandler := scopes.NewHandler(s.scopesService, s.s2sVerifier, s.iamVerifier)

	clientHanlder := clients.NewHandler(s.clientsService, s.scopesService, s.s2sVerifier, s.iamVerifier)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)

	mux.HandleFunc("/login", loginHander.HandleS2sLogin)
	mux.HandleFunc("/refresh", refreshHandler.HandleS2sRefresh)

	// scopes endpoint for services (not user facing)
	// requires s2s service-call-specific scopes
	mux.HandleFunc("/service/scopes", s2sScopesHandler.HandleScopes)
	mux.HandleFunc("/service/scopes/active", s2sScopesHandler.HandleActiveScopes)

	// scopes endpoint for users, ie, admin
	mux.HandleFunc("/scopes", iamScopesHandler.HandleScopes)
	mux.HandleFunc("/scopes/active", iamScopesHandler.HandleActiveScopes)
	mux.HandleFunc("/scopes/add", iamScopesHandler.HandleAdd)
	mux.HandleFunc("/scopes/", iamScopesHandler.HandleScope)

	mux.HandleFunc("/clients", clientHanlder.HandleClients)
	mux.HandleFunc("/clients/register", clientHanlder.HandleRegistration)
	mux.HandleFunc("/clients/reset", clientHanlder.HandleReset)
	mux.HandleFunc("/clients/", clientHanlder.HandleClient)
	mux.HandleFunc("/clients/scopes", clientHanlder.HandleScopes)

	s2sServer := &connect.TlsServer{
		Addr:      s.config.ServicePort,
		Mux:       mux,
		TlsConfig: s.serverTls,
	}

	go func() {

		s.logger.Info(fmt.Sprintf("starting %s s2s authentication service on %s...", s.config.ServiceName, s2sServer.Addr[1:]))
		if err := s2sServer.Initialize(); err != http.ErrServerClosed {
			s.logger.Error(fmt.Sprintf("failed to start %s s2s authenticaiton service: %v", s.config.ServiceName, err.Error()))
		}
	}()

	go s.cleanup.ExpiredRefresh(3) // 2am +- 30; refresh tokens live 3 hours

	return nil
}
