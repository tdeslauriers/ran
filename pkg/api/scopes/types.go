package scopes

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Scope is a model for the scope table data, NOT jwt string object in the jwt package.
// Do not add fields from other contexts/concerns like csrf.
type Scope struct {
	Uuid        string `db:"uuid" json:"scope_id,omitempty"`
	ServiceName string `db:"service_name" json:"service_name"`
	Scope       string `db:"scope" json:"scope"`
	Name        string `db:"name"  json:"name"`
	Description string `db:"description" json:"description"`
	CreatedAt   string `db:"created_at" json:"created_at"`
	Active      bool   `db:"active" json:"active"`
	Slug        string `db:"slug" json:"slug,omitempty"`
}

// ValidateCmd performs regex checks on scope fields.
func (s *Scope) ValidateCmd() error {

	// uuid's and dates may not yet exist, so those should only be validated if they are set.
	// additional checks are performed by services, so if uuid values are removed, it is not a problem.

	if s.Uuid != "" {
		if err := validate.ValidateUuid(s.Uuid); err != nil {
			return fmt.Errorf("invalid scope id in scope payload")
		}
	}

	if err := validate.ValidateServiceName(s.ServiceName); err != nil {
		return fmt.Errorf("invalid service name in scope payload: %v", err)
	}

	// Replace IsValidScope with an appropriate validation function or implement it in the validate package.
	if err := validate.ValidateScope(s.Scope); err != nil {
		return fmt.Errorf("invalid scope in scope payload: %v", err)
	}

	// Example: Use ValidateName if it exists, or implement your own logic here.
	if err := validate.ValidateName(s.Name); err != nil {
		return fmt.Errorf("invalid scope name in scope payload: %v", err)
	}

	if validate.TooShort(s.Description, 2) || validate.TooLong(s.Description, 256) {
		return fmt.Errorf("invalid description in scope payload")
	}

	if s.Slug != "" {
		if err := validate.ValidateUuid(s.Slug); err != nil {
			return fmt.Errorf("invalid slug in scope payload")
		}
	}

	return nil
}
