package s2s

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"ran/internal/util"
	"ran/pkg/authentication"
	"ran/pkg/scopes"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/diagnostics"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/schedule"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

type S2sAuthentication interface {
	Run() error
	CloseDb() error
}

func New(config config.Config) (S2sAuthentication, error) {

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
	aes, err := base64.StdEncoding.DecodeString(config.Database.FieldKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode field level encryption key: %v", err)
	}

	cryptor := data.NewServiceAesGcmKey(aes)

	// jwt signer
	privPem, err := base64.StdEncoding.DecodeString(config.Jwt.S2sSigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt signing key: %v", err)
	}
	privBlock, _ := pem.Decode(privPem)
	privateKey, err := x509.ParseECPrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse x509 EC Private Key: %v", err)
	}

	signer := jwt.NewSigner(privateKey)

	// jwt verifier
	verifier := jwt.NewVerifier(config.ServiceName, &privateKey.PublicKey)

	// s2s auth service
	authService := authentication.NewS2sAuthService(repository, signer, indexer, cryptor)

	// scopes service
	scopesService := scopes.NewScopesSerivce(repository)

	// clean up: database
	cleanup := schedule.NewCleanup(repository)

	return &s2sAuthentication{
		config:        config,
		serverTls:     serverTlsConfig,
		repository:    repository,
		verifier:      verifier,
		authService:   authService,
		scopesService: scopesService,
		cleanup:       cleanup,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentS2s)),
	}, nil

}

var _ S2sAuthentication = (*s2sAuthentication)(nil)

type s2sAuthentication struct {
	config        config.Config
	serverTls     *tls.Config
	repository    data.SqlRepository
	verifier      jwt.Verifier
	authService   types.S2sAuthService
	scopesService scopes.ScopesService
	cleanup       schedule.Cleanup

	logger *slog.Logger
}

func (s2s s2sAuthentication) CloseDb() error {
	if err := s2s.repository.Close(); err != nil {
		return err
	}
	return nil
}

func (s2s *s2sAuthentication) Run() error {

	loginHander := authentication.NewS2sLoginHandler(s2s.authService)
	refreshHandler := authentication.NewS2sRefreshHandler(s2s.authService)

	scopesHandler := scopes.NewScopesHandler(s2s.scopesService, s2s.verifier)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)
	mux.HandleFunc("/login", loginHander.HandleS2sLogin)
	mux.HandleFunc("/refresh", refreshHandler.HandleS2sRefresh)
	mux.HandleFunc("/scopes", scopesHandler.GetActiveScopes)

	s2sServer := &connect.TlsServer{
		Addr:      s2s.config.ServicePort,
		Mux:       mux,
		TlsConfig: s2s.serverTls,
	}

	go func() {

		s2s.logger.Info(fmt.Sprintf("starting %s s2s authentication service on %s...", s2s.config.ServiceName, s2sServer.Addr[1:]))
		if err := s2sServer.Initialize(); err != http.ErrServerClosed {
			s2s.logger.Error(fmt.Sprintf("failed to start %s s2s authenticaiton service: %v", s2s.config.ServiceName, err.Error()))
		}
	}()

	go s2s.cleanup.ExpiredRefresh(3) // 2am +- 30; refresh tokens live 3 hours

	return nil
}
