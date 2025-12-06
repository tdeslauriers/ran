package clients

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/tdeslauriers/carapace/pkg/data"
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
		sql:   sql,
		creds: creds,

		logger: slog.Default().
			With(slog.String(definitions.PackageKey, definitions.PackageClients)).
			With(slog.String(definitions.ComponentKey, definitions.ComponentReset)),
	}
}

var _ ResetService = (*resetService)(nil)

// resetService is a concrete implementation of the ResetService interface
type resetService struct {
	sql   *sql.DB
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
	qry := "SELECT uuid, password FROM client WHERE uuid = ?"
	record, err := data.SelectOneRecord[Reset](s.sql, qry, cmd.ResourceId)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("service client not found: %s", cmd.ResourceId)
		} else {
			return fmt.Errorf("failed to retrieve service client record %s for password reset: %v", cmd.ResourceId, err)
		}
	}

	// validate current password
	if err := s.creds.CompareHashAndPassword(record.Password, cmd.CurrentPassword); err != nil {
		return fmt.Errorf("%s for service client: %s", ErrIncorrectPassword, cmd.ResourceId)
	}

	// hash new password
	newHash, err := s.creds.GenerateHashFromPassword(cmd.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password for service client %s: %v", cmd.ResourceId, err)
	}

	// update password in client table
	qry = "UPDATE client SET password = ? WHERE uuid = ?"
	if err := data.UpdateRecord(s.sql, qry, newHash, cmd.ResourceId); err != nil {
		return fmt.Errorf("failed to update service client %s password: %v", cmd.ResourceId, err)
	}

	return nil
}
