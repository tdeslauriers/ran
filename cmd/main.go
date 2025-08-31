package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/ran/internal/util"
	"github.com/tdeslauriers/ran/pkg/s2s"
)

func main() {

	// set logging to json format for application
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(jsonHandler))

	// set up logger for main
	logger := slog.Default().
		With(slog.String(util.ServiceKey, util.ServiceS2s)).
		With(slog.String(util.PackageKey, util.PackageMain)).
		With(slog.String(util.ComponentKey, util.ComponentMain))

	// service definitions
	def := config.SvcDefinition{
		ServiceName: util.ServiceS2s,
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
		logger.Error(fmt.Sprintf("failed to load %s s2s config: %v", util.ServiceS2s, err))
		os.Exit(1)
	}

	s2s, err := s2s.New(*config)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create %s s2s service: %v", util.ServiceS2s, err))
		os.Exit(1)
	}

	defer s2s.CloseDb()

	if err := s2s.Run(); err != nil {
		logger.Error(fmt.Sprintf("failed to run %s s2s service: %v", util.ServiceS2s, err))
		os.Exit(1)
	}

	select {}
}
