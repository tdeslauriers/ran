package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"net/http"
	"os"
	"ran/s2s"
	"ran/scopes"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/diagnostics"
	"github.com/tdeslauriers/carapace/jwt"
)

const (
	EnvCaCert       string = "RAN_CA_CERT"
	EnvServerCert   string = "RAN_SERVER_CERT"
	EnvServerKey    string = "RAN_SERVER_KEY"
	EnvDbClientCert string = "RAN_DB_CLIENT_CERT"
	EnvDbClientKey  string = "RAN_DB_CLIENT_KEY"

	// db config
	EnvDbUrl      string = "RAN_DATABASE_URL"
	EnvDbName     string = "RAN_DATABASE_NAME"
	EnvDbUsername string = "RAN_DATABASE_USERNAME"
	EnvDbPassword string = "RAN_DATABASE_PASSWORD"

	// sign s2s jwts
	EnvJwtSigningKey string = "RAN_SIGNING_KEY"

	// verifying s2s jwts
	EnvS2sJwtVerifyKey string = "RAN_JWT_VERIFYING_KEY"
)

func main() {

	// set up server pki
	serverPki := &connect.Pki{
		CertFile: os.Getenv(EnvServerCert),
		KeyFile:  os.Getenv(EnvServerKey),
		CaFiles:  []string{os.Getenv(EnvCaCert)},
	}

	mtls, err := connect.NewTLSConfig("mutual", serverPki)
	if err != nil {
		log.Fatalf("unable to configure mutual tls: %v", err)
	}

	// set up db
	dbClientPki := &connect.Pki{
		CertFile: os.Getenv(EnvDbClientCert),
		KeyFile:  os.Getenv(EnvDbClientKey),
		CaFiles:  []string{os.Getenv(EnvCaCert)},
	}

	dbClientConfig := connect.ClientConfig{Config: dbClientPki}

	dbUrl := data.DbUrl{
		Name:     os.Getenv(EnvDbName),
		Addr:     os.Getenv(EnvDbUrl),
		Username: os.Getenv(EnvDbUsername),
		Password: os.Getenv(EnvDbPassword),
	}

	dbConnector := &data.MariaDbConnector{
		TlsConfig:     dbClientConfig,
		ConnectionUrl: dbUrl.Build(),
	}

	dao := &data.MariaDbRepository{
		SqlDb: dbConnector,
	}

	// set up jwt signer
	privPem, err := base64.StdEncoding.DecodeString(os.Getenv(EnvJwtSigningKey))
	if err != nil {
		log.Fatalf("Could not decode (base64) signing key Env var: %v", err)
	}
	privBlock, _ := pem.Decode(privPem)
	privateKey, err := x509.ParseECPrivateKey(privBlock.Bytes)
	if err != nil {
		log.Fatalf("unable to parse x509 EC Private Key: %v", err)
	}
	signer := jwt.JwtSignerService{PrivateKey: privateKey}

	// set up jwt verifier
	verifier := &jwt.JwtVerifierService{PublicKey: &privateKey.PublicKey}

	// set up service + handlers
	authService := s2s.NewS2sAuthService(dao, &signer)
	loginHander := s2s.NewS2sLoginHandler(authService)
	refreshHandler := s2s.NewS2sRefreshHandler(authService)

	scopesService := scopes.NewAuthzScopesSerivce(dao)
	scopesHandler := scopes.NewScopesHandler(scopesService, verifier)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)
	mux.HandleFunc("/login", loginHander.HandleS2sLogin)
	mux.HandleFunc("/refresh", refreshHandler.HandleS2sRefresh)
	mux.HandleFunc("/scopes", scopesHandler.GetActiveScopes)

	// set up server
	server := &connect.TlsServer{
		Addr:      ":8444",
		Mux:       mux,
		TlsConfig: mtls,
	}

	go func() {

		log.Printf("Starting mTLS server on %s...", server.Addr[1:])
		if err := server.Initialize(); err != http.ErrServerClosed {
			log.Fatalf("Failed to start Erebor Gateway server: %v", err)
		}
	}()

	select {}

}
