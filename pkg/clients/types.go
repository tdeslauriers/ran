package clients

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (
	ErrInvalidSlug    = "invalid service client slug"
	ErrInvalidClient  = "invalid service client"
	ErrClientNotFound = "service client not found"

	ErrInvalidResourceId = "invalid resource id"
	ErrInvalidCurrentPw  = "invalid current password"
	ErrInvalidNewPw      = "invalid new password"
	ErrInvalidPwMismatch = "new password and confirm password do not match"

	ErrIncorrectPassword = "incorrect password"
)

// service endpoints require s2s-only endpoint scopes
var s2sAllowedRead []string = []string{"r:ran:s2s:clients:*"}

// user endpoints require user endpoint scopes
// NOTE: user-only endpoint scopes will issued to services when they are acting on behalf of a user,
// but in those cases, their must be a user token present in the request ALSO.
var userAllowedRead = []string{"r:ran:clients:*"}
var userAllowedWrite = []string{"w:ran:clients:*"}

// Handler provides http handlers for service client requests
type Handler interface {
	ClientHandler
	ResetHandler
}

// NewHandler creates a new service client Handler interface abstracting a concrete implementations
func NewHandler(s Service, s2s, iam jwt.Verifier) Handler {
	return &handler{
		ClientHandler: NewClientHandler(s, s2s, iam),
		ResetHandler:  NewResetHandler(s, s2s, iam),
	}
}

var _ Handler = (*handler)(nil)

// handler is a concrete implementation of the Handler interface abstracting smaller interfaces
type handler struct {
	ClientHandler
	ResetHandler
}

type Service interface {
	ClientService
	ResetService
	ClientErrService
}

// NewService creates a new service interface abstracting a concrete implementations of
// the ClientService and ClientErrService interfaces
func NewService(sql data.SqlRepository) Service {
	return &service{
		ClientService:    NewClientService(sql),
		ResetService:     NewResetService(sql),
		ClientErrService: NewErrHandlingService(),
	}
}

var _ Service = (*service)(nil)

type service struct {
	ClientService
	ResetService
	ClientErrService
}

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

// Reset is a model for a service client uuid and pw for lookup by reset service
type Reset struct {
	ClientId string `db:"uuid"`
	Password string `db:"password"`
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

	ScopeId        string `db:"scope_id" json:"scope_id,omitempty"`
	ServiceName    string `db:"service_name" json:"service_name"`
	Scope          string `db:"scope" json:"scope"`
	ScopeName      string `db:"scope_name"  json:"name"`
	Description    string `db:"description" json:"description"`
	ScopeCreatedAt string `db:"scope_created_at" json:"created_at"`
	Active         bool   `db:"active" json:"active"`
	ScopeSlug      string `db:"scope_slug" json:"slug,omitempty"`
}
