package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/ran/internal/definitions"
	"github.com/tdeslauriers/ran/internal/s2s"
)

func main() {

	// set logging to json format for application
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	// set default logger for all packages to use json format
	slog.SetDefault(slog.New(jsonHandler).
		With(slog.String(definitions.ServiceKey, definitions.ServiceS2s)))

	// set up logger for main
	logger := slog.Default().
		With(slog.String(definitions.PackageKey, definitions.PackageMain)).
		With(slog.String(definitions.ComponentKey, definitions.ComponentMain))

	// service definitions
	def := config.SvcDefinition{
		ServiceName: definitions.ServiceS2s,
		Tls:         config.MutualTls,
		Requires: config.Requires{
			S2sClient:        false,
			Db:               true,
			IndexSecret:      true,
			AesSecret:        true,
			PatGenerator:     true,
			S2sSigningKey:    true,
			S2sVerifyingKey:  true,
			UserSigningKey:   false,
			UserVerifyingKey: true,
			OauthRedirect:    false,
		},
	}

	// load config values for service creation
	config, err := config.Load(def)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to load %s s2s config", definitions.ServiceS2s), "err", err.Error())
		os.Exit(1)
	}

	s2s, err := s2s.New(*config)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create %s s2s service", definitions.ServiceS2s), "err", err.Error())
		os.Exit(1)
	}

	defer s2s.CloseDb()

	if err := s2s.Run(); err != nil {
		logger.Error(fmt.Sprintf("failed to run %s s2s service", definitions.ServiceS2s), "err", err.Error())
		os.Exit(1)
	}

	select {}
}
