package reset

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/ran/internal/definitions"
	"github.com/tdeslauriers/ran/pkg/authentication"
)

// ResetService provides service client password reset operations
type ResetService interface {

	// ResetPassword resets a service client password
	ResetPassword(cmd profile.ResetCmd) error
}

// NewResetService creates a new service client ResetService interface abstracting a concrete implementation
func NewResetService(sql *sql.DB, creds authentication.CredService) ResetService {
	return &resetService{
		sql:   NewResetRepository(sql),
		creds: creds,

		logger: slog.Default().
			With(slog.String(definitions.PackageKey, definitions.PackageClients)).
			With(slog.String(definitions.ComponentKey, definitions.ComponentReset)),
	}
}

var _ ResetService = (*resetService)(nil)

// resetService is a concrete implementation of the ResetService interface
type resetService struct {
	sql   ResetRepository
	creds authentication.CredService // used to hash passwords for storage

	logger *slog.Logger
}

// ResetPassword is a concrete impl of the ResetService interface method: resets a service client password
func (s *resetService) ResetPassword(cmd profile.ResetCmd) error {

	// validate cmd
	// redundant validation, but good practice
	if err := cmd.ValidateCmd(); err != nil {
		return err
	}

	// check new and old dont match:
	// note: this is unnecessary in user identity service because it has a pw history table
	if cmd.CurrentPassword == cmd.NewPassword {
		return fmt.Errorf("new password must be different from current password")
	}

	// look up client record
	record, err := s.sql.FindById(cmd.ResourceId)
	if err != nil {
		return err
	}

	// validate current password
	if err := s.creds.CompareHashAndPassword(record.Password, cmd.CurrentPassword); err != nil {
		return fmt.Errorf("%s for service client: %s", "password is incorrect", cmd.ResourceId)
	}

	// hash new password
	newHash, err := s.creds.GenerateHashFromPassword(cmd.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password for service client %s: %v", cmd.ResourceId, err)
	}

	// update password in client table
	if err := s.sql.UpdatePassword(record.ClientId, newHash); err != nil {
		return err
	}

	return nil
}
