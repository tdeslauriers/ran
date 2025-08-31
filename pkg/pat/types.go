package pat

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// PatRecord represents a personal access token (PAT) record in the database
// NOTE: the actual token is never stored, only a blind index of it for verification purposes
type PatRecord struct {
	Id        string          `db:"uuid"`
	PatIndex  string          `db:"pat_index"` // this is the blind index of the generated pat
	CreatedAt data.CustomTime `db:"created_at"`
	Active    bool            `db:"active"`
	Revoked   bool            `db:"revoked"`
	Expired   bool            `db:"expired"`
}

// PatClientXref represents a cross-reference between a PAT and a service client in the database
type PatClientXref struct {
	Id        int             `db:"id"`
	PatID     string          `db:"pat_uuid"`
	ClientID  string          `db:"client_uuid"`
	CreatedAt data.CustomTime `db:"created_at"`
}

// Pat is the output model representing a personal access token (PAT) --> it is never stored.
type Pat struct {
	Client    string `json:"client,omitempty"` // client name: convenience field
	Token     string `json:"token,omitempty"`  // the actual token is only returned once, upon creation
	CreatedAt string `json:"created_at"`
	Active    bool   `json:"active"`
	Revoked   bool   `json:"revoked"`
	Expired   bool   `json:"expired"`
}

// GeneratePatCmd represents the command to generate a personal access token (PAT)
type GeneratePatCmd struct {
	Csrf string `json:"csrf,omitempty"` // csrf may not be present in some cases
	Slug string `json:"slug,omitempty"`
}

// Validate validates the GeneratePatCmd fields
func (cmd *GeneratePatCmd) Validate() error {

	// validate csrf token if present
	if cmd.Csrf != "" {
		if len(cmd.Csrf) < 16 || len(cmd.Csrf) > 64 {
			return fmt.Errorf("csrf token must be between 16 and 128 characters")
		}

		if !validate.IsValidUuid(cmd.Csrf) {
			return fmt.Errorf("csrf token must be a valid uuid")
		}
	}

	// validate slug --> must be present and between 3 and 64 characters
	if cmd.Slug == "" {
		return fmt.Errorf("slug is required")
	}

	if len(cmd.Slug) < 16 || len(cmd.Slug) > 64 {
		return fmt.Errorf("slug must be between 16 and 64 characters")
	}

	if !validate.IsValidUuid(cmd.Slug) {
		return fmt.Errorf("slug must be well formed uuid")
	}

	return nil
}

// querys for client status checks
const (
	clientDisabledQry       = `SELECT EXISTS(SELECT 1 FROM client WHERE slug = ? AND enabled = FALSE`
	clientAccountExpiredQry = `SELECT EXISTS(SELECT 1 FROM client WHERE slug = ? AND account_expired = TRUE`
	clientAccountLockedQry  = `SELECT EXISTS(SELECT 1 FROM client WHERE slug = ? AND account_locked = TRUE`
)
