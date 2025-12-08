package register

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/ran/internal/clients"
	"github.com/tdeslauriers/ran/internal/definitions"
	api "github.com/tdeslauriers/ran/pkg/api/clients"
	"github.com/tdeslauriers/ran/pkg/api/register"
	"github.com/tdeslauriers/ran/pkg/authentication"
)

// RegistrationService provides client registration service operations
type RegistrationService interface {

	// RegisterClient registers a new service client
	Register(cmd *register.RegisterCmd) (*api.Client, error)
}

// NewRegistrationService creates a new client registration service interface abstracting a concrete implementation
func NewRegistrationService(sql *sql.DB, creds authentication.CredService) RegistrationService {
	return &registrationService{
		sql:   NewRegistrationRepository(sql),
		creds: creds,

		logger: slog.Default().
			With(slog.String(definitions.PackageKey, definitions.PackageClients)).
			With(slog.String(definitions.ComponentKey, definitions.ComponentRegister)),
	}
}

var _ RegistrationService = (*registrationService)(nil)

// registrationService is a concrete implementation of the RegistrationService interface
type registrationService struct {
	sql   RegistrationRepository
	creds authentication.CredService // used to hash passwords for storage

	logger *slog.Logger
}

// RegisterClient is the concrete impl of the RegistrationService interface method: registers a new service client.
func (s *registrationService) Register(cmd *register.RegisterCmd) (*api.Client, error) {

	// validate client data
	// redundant validation, but good practice
	if err := cmd.ValidateCmd(); err != nil {
		return nil, err
	}

	// create new client uuid
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate service client uuid: %v", err)
	}

	// create new client slug
	slug, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate service client slug: %v", err)
	}

	// hash password for storage
	hashed, err := s.creds.GenerateHashFromPassword(cmd.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash service client password: %v", err)
	}

	// prepare service client record
	client := clients.ClientRecord{
		Id:             id.String(),
		Password:       string(hashed),
		Name:           cmd.Name,
		Owner:          cmd.Owner,
		CreatedAt:      data.CustomTime{Time: time.Now()},
		Enabled:        true,
		AccountExpired: false,
		AccountLocked:  false,
		Slug:           slug.String(),
	}

	// insert client record into db
	if err := s.sql.Create(client); err != nil {
		return nil, err
	}

	// changing type from ClientRecord to Client so password is not returned
	return &api.Client{
		Id:             client.Id,
		Name:           client.Name,
		Owner:          client.Owner,
		CreatedAt:      client.CreatedAt,
		Enabled:        client.Enabled,
		AccountExpired: client.AccountExpired,
		AccountLocked:  client.AccountLocked,
		Slug:           client.Slug,
	}, nil
}
