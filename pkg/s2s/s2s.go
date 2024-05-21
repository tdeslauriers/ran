package s2s

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"ran/pkg/authentication"
	"ran/pkg/scopes"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/diagnostics"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session"
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

	indexer := data.NewHmacIndexer(hmacSecret)

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
		log.Fatalf("unable to parse x509 EC Private Key: %v", err)
	}

	signer := jwt.NewJwtSigner(privateKey)

	// jwt verifier
	verifier := jwt.NewJwtVerifier(config.Name, &privateKey.PublicKey)

	// s2s auth service
	authService := authentication.NewS2sAuthService(repository, signer, indexer, cryptor)

	// scopes service
	scopesService := scopes.NewScopesSerivce(repository)

	return &s2sAuthentication{
		congig:        config,
		serverTls:     serverTlsConfig,
		repository:    repository,
		verifier:      verifier,
		authService:   authService,
		scopesService: scopesService,
	}, nil

}

var _ S2sAuthentication = (*s2sAuthentication)(nil)

type s2sAuthentication struct {
	congig        config.Config
	serverTls     *tls.Config
	repository    data.SqlRepository
	verifier      jwt.JwtVerifier
	authService   session.S2sAuthService
	scopesService scopes.ScopesService
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

	ran := &connect.TlsServer{
		Addr:      ":8444",
		Mux:       mux,
		TlsConfig: s2s.serverTls,
	}

	go func() {

		log.Printf("Starting Ran s2s authentication service on %s...", ran.Addr[1:])
		if err := ran.Initialize(); err != http.ErrServerClosed {
			log.Fatalf("Failed to start Ran s2s authenticaiton servce: %v", err)
		}
	}()

	return nil
}
