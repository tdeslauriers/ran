package clients

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/ran/pkg/api/scopes"
)

// Client is a model for a json object representing a service Client
type Client struct {
	Id             string          `json:"id,omitempty"`
	Name           string          `json:"name"`
	Owner          string          `json:"owner"`
	CreatedAt      data.CustomTime `json:"created_at"`
	Enabled        bool            `json:"enabled"`
	AccountExpired bool            `json:"account_expired"`
	AccountLocked  bool            `json:"account_locked"`
	Slug           string          `json:"slug,omitempty"`
	Scopes         []scopes.Scope  `json:"scopes,omitempty"`
}

// Validate performs input validation check on client fields.
func (c *Client) Validate() error {

	if c.Id != "" {
		if err := validate.ValidateUuid(c.Id); err != nil {
			return fmt.Errorf("invalid or not well formatted servcice client id")
		}
	}

	if err := validate.ValidateServiceName(c.Name); err != nil {
		return fmt.Errorf("invalid service client name: %v", err)
	}

	if err := validate.ValidateName(c.Owner); err != nil {
		return fmt.Errorf("invalid service client owner: %v", err)
	}

	// CreatedAt is a timestamp created programmatically,
	// no validation needed, will be dropped on all updates

	// Enabled is a boolean, no validation needed

	// AccountExpired is a boolean, no validation needed

	// AccountLocked is a boolean, no validation needed

	if c.Slug != "" {
		if err := validate.ValidateUuid(c.Slug); err != nil {
			return fmt.Errorf("invalid or not well formatted service client slug")
		}
	}

	return nil
}

// ClientService is a model for client-scopes cmds received by the client handler
type ClientScopesCmd struct {
	ClientSlug string   `json:"client_slug"`
	ScopeSlugs []string `json:"scope_slugs"` // uuids of the scope slugs => for lookup
}

// ValidateCmd performs input validation check on client scopes fields.
func (c *ClientScopesCmd) ValidateCmd() error {

	if err := validate.ValidateUuid(c.ClientSlug); err != nil {
		return fmt.Errorf("invalid client slug")
	}

	if len(c.ScopeSlugs) > 0 {
		for _, slug := range c.ScopeSlugs {
			if err := validate.ValidateUuid(slug); err != nil {
				return fmt.Errorf("invalid scope slug submitted: all slugs must be valid uuids")
			}
		}
	}

	return nil
}
