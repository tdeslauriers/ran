package pat

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

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
