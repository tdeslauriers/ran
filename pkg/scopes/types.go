package scopes

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (

	// 400
	ErrInvalidSlug string = "invalid slug"

	//404
	ErrScopeNotFound string = "scope not found"

	//500
	ErrGenSlugBlindIndex string = "failed to obtain blind index for slug"
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
		if !validate.IsValidUuid(s.Uuid) {
			return fmt.Errorf("invalid scope id in scope payload")
		}
	}

	if ok, err := validate.IsValidServiceName(s.ServiceName); !ok {
		return fmt.Errorf("invalid service name in scope payload: %v", err)
	}

	if ok, err := validate.IsValidScope(s.Scope); !ok {
		return fmt.Errorf("invalid scope in scope payload: %v", err)
	}

	if ok, err := validate.IsValidScopeName(s.Name); !ok {
		return fmt.Errorf("invalid scope name in scope payload: %v", err)
	}

	if validate.TooShort(s.Description, 2) || validate.TooLong(s.Description, 256) {
		return fmt.Errorf("invalid description in scope payload")
	}

	if s.Slug != "" {
		if !validate.IsValidUuid(s.Slug) {
			return fmt.Errorf("invalid slug in scope payload")
		}
	}

	return nil
}
