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

// ClientScope is a model for a database join query of a client and its associated scopes
type ClientScope struct {
	ClientId        string          `json:"client_id,omitempty" db:"uuid"`
	ClientName      string          `json:"client_name" db:"name"`
	Owner           string          `json:"owner" db:"owner"`
	ClientCreatedAt data.CustomTime `json:"client_created_at" db:"created_at"`
	Enabled         bool            `json:"enabled" db:"enabled"`
	AccountExpired  bool            `json:"account_expired" db:"account_expired"`
	AccountLocked   bool            `json:"account_locked" db:"account_locked"`
	CLientSlug      string          `json:"client_slug,omitempty" db:"slug"`

	ScopeId     string `db:"scope_id" json:"scope_id,omitempty"`
	ServiceName string `db:"service_name" json:"service_name"`
	Scope       string `db:"scope" json:"scope"`
	ScopeName   string `db:"scope_name"  json:"name"`
	Description string `db:"description" json:"description"`
	ScopeCreatedAt   string `db:"scope_created_at" json:"created_at"`
	Active      bool   `db:"active" json:"active"`
	ScopeSlug   string `db:"scope_slug" json:"slug,omitempty"`
}
