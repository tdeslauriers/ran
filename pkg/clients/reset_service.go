package clients

import (
	"database/sql"
	"fmt"
	"log/slog"
	"ran/internal/util"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"golang.org/x/crypto/bcrypt"
)

// ResetService provides service client password reset operations
type ResetService interface {

	// ResetPassword resets a service client password
	ResetPassword(cmd profile.ResetCmd) error
}

// NewResetService creates a new service client ResetService interface abstracting a concrete implementation
func NewResetService(sql data.SqlRepository) ResetService {
	return &resetService{
		sql: sql,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceS2s)).
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentReset)),
	}
}

var _ ResetService = (*resetService)(nil)

// resetService is a concrete implementation of the ResetService interface
type resetService struct {
	sql data.SqlRepository

	logger *slog.Logger
}

// ResetPassword is a concrete impl of the ResetService interface method: resets a service client password
func (s *resetService) ResetPassword(cmd profile.ResetCmd) error {

	// validate cmd
	// redundant validation, but good practice
	if err := cmd.ValidateCmd(); err != nil {
		s.logger.Error("failed to validate service client password refresh request", "err", err.Error())
		return err
	}

	// check new and old dont match:
	// note: this is unnecessary in user identity service because it has a pw history table
	if cmd.CurrentPassword == cmd.NewPassword {
		return fmt.Errorf("new password must be different from current password")
	}

	// validate client exists
	var reset Reset
	qry := "SELECT uuid, password FROM client WHERE uuid = ?"
	if err := s.sql.SelectRecord(qry, &reset, cmd.ResourceId); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%s: %s", ErrClientNotFound, cmd.ResourceId)
		} else {
			return fmt.Errorf("failed to retrieve service client record %s for password reset: %v", cmd.ResourceId, err)
		}
	}

	// validate current password
	current := []byte(cmd.CurrentPassword)
	currentHash := []byte(reset.Password)
	if err := bcrypt.CompareHashAndPassword(currentHash, current); err != nil {
		return fmt.Errorf("%s for service client: %s", ErrIncorrectPassword, cmd.ResourceId)
	}

	// hash new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(cmd.NewPassword), 13)
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to hash new password for service client %s: %v", cmd.ResourceId, err))
		return fmt.Errorf("failed to hash new password")
	}

	// update password in client table
	qry = "UPDATE client SET password = ? WHERE uuid = ?"
	if err := s.sql.UpdateRecord(qry, newHash, cmd.ResourceId); err != nil {
		return fmt.Errorf("failed to update service client %s password: %v", cmd.ResourceId, err)
	}

	return nil
}
