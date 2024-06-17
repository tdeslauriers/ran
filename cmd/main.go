package main

import (
	"log/slog"
	"os"
	"ran/internal/util"
	"ran/pkg/s2s"

	"github.com/tdeslauriers/carapace/pkg/config"
)

func main() {

	logger := slog.Default().With(slog.String(util.ComponentKey, util.ComponentMain))

	// service definitions
	def := config.SvcDefinition{
		ServiceName: "ran",
		Tls:         config.MutualTls,
		Requires: config.Requires{
			Client:           false,
			Db:               true,
			IndexKey:         true,
			AesKey:           true,
			S2sSigningKey:    true,
			S2sVerifyingKey:  true,
			UserSigningKey:   false,
			UserVerifyingKey: false,
		},
	}

	// load config values for service creation
	config, err := config.Load(def)
	if err != nil {
		logger.Error("failed to load ran config", "err", err.Error())
		os.Exit(1)
	}

	s2s, err := s2s.New(*config)
	if err != nil {
		logger.Error("failed to create s2s service", "err", err.Error())
		os.Exit(1)
	}

	defer s2s.CloseDb()

	if err := s2s.Run(); err != nil {
		logger.Error("failed to run  Ran s2s service", "err", err.Error())
		os.Exit(1)
	}

	select {}
}
