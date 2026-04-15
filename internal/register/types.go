package register

import (
	"errors"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

type S2sRegisterCmd struct {
	Uuid           string `db:"uuid" json:"client_id,omitempty"`
	Password       string `db:"password" json:"client_secret,omitempty"`
	Confirm        string `json:"confirm_password,omitempty"`
	Name           string `db:"name" json:"name"`
	Owner          string `db:"owner" json:"owner"`
	CreatedAt      string `db:"created_at" json:"created_at,omitempty"`
	Enabled        bool   `db:"enabled"  json:"enabled"`
	AccountExpired bool   `db:"acccount_expired" json:"account_expired"`
	AccountLocked  bool   `db:"account_locked" json:"account_locked"`
	Slug           string `db:"slug" json:"slug,omitempty"`
}

func (cmd *S2sRegisterCmd) ValidateCmd() error {

	if cmd.Uuid != "" {
		if err := validate.ValidateUuid(cmd.Uuid); err != nil {
			return fmt.Errorf("invalid or not well formatted client id")
		}
	}

	if err := validate.ValidateServiceName(cmd.Name); err != nil {
		return fmt.Errorf("invalid client name: %v", err)
	}

	if err := validate.ValidateName(cmd.Owner); err != nil {
		return fmt.Errorf("invalid client owner: %v", err)
	}

	if cmd.Slug != "" {
		if err := validate.ValidateUuid(cmd.Slug); err != nil {
			return fmt.Errorf("invalid or not well formatted client slug")
		}
	}

	if err := validate.ValidatePassword(cmd.Password); err != nil {
		return fmt.Errorf("invalid client password: %v", err)
	}

	if cmd.Password != cmd.Confirm {
		return errors.New("password does not match confirm password")
	}

	return nil
}
