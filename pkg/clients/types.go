package clients

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (
	ErrInvalidSlug    = "invalid service client slug"
	ErrInvalidClient  = "invalid service client"
	ErrClientNotFound = "service client not found"
)

type Client struct {
	Id             string          `json:"id,omitempty" db:"uuid"`
	Name           string          `json:"name" db:"name"`
	Owner          string          `json:"owner" db:"owner"`
	CreatedAt      data.CustomTime `json:"created_at" db:"created_at"`
	Enabled        bool            `json:"enabled" db:"enabled"`
	AccountExpired bool            `json:"account_expired" db:"account_expired"`
	AccountLocked  bool            `json:"account_locked" db:"account_locked"`
	Slug           string          `json:"slug,omitempty" db:"slug"`
}

// ValidateCmd performs input validation check on client fields.
func (c *Client) Validate() error {

	if c.Id != "" && !validate.IsValidUuid(c.Id) {
		return fmt.Errorf("invalid or not well formatted servcice client id")
	}

	if valid, err := validate.IsValidServiceName(c.Name); !valid {
		return fmt.Errorf("invalid service client name: %v", err)
	}

	if err := validate.IsValidName(c.Owner); err != nil {
		return fmt.Errorf("invalid service client owner: %v", err)
	}

	// CreatedAt is a timestamp created programmatically,
	// no validation needed, will be dropped on all updates

	// Enabled is a boolean, no validation needed

	// AccountExpired is a boolean, no validation needed

	// AccountLocked is a boolean, no validation needed

	if c.Slug != "" && !validate.IsValidUuid(c.Slug) {
		return fmt.Errorf("invalid or not well formatted service client slug")
	}

	return nil
}
