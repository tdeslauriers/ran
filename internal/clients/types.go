package clients

import (
	"github.com/tdeslauriers/carapace/pkg/data"
)

// service endpoints require s2s-only endpoint scopes
var S2sAllowedRead []string = []string{"r:ran:s2s:clients:*"}

// user endpoints require user endpoint scopes
// NOTE: user-only endpoint scopes will issued to services when they are acting on behalf of a user,
// but in those cases, their must be a user token present in the request ALSO.
var UserAllowedRead = []string{"r:ran:clients:*", "r:ran:*"}
var UserAllowedWrite = []string{"w:ran:clients:*", "w:ran:*"}

// ClientRecord is a model for a client record in the database, including password
type ClientRecord struct {
	Id             string          `json:"id,omitempty" db:"uuid"`
	Password       string          `json:"password" db:"password"`
	Name           string          `json:"name" db:"name"`
	Owner          string          `json:"owner" db:"owner"`
	CreatedAt      data.CustomTime `json:"created_at" db:"created_at"`
	Enabled        bool            `json:"enabled" db:"enabled"`
	AccountExpired bool            `json:"account_expired" db:"account_expired"`
	AccountLocked  bool            `json:"account_locked" db:"account_locked"`
	Slug           string          `json:"slug,omitempty" db:"slug"`
}

// ClientAccount is the model for the client record in the database minus the password
type ClientAccount struct {
	Id             string          `json:"id,omitempty" db:"uuid"`
	Name           string          `json:"name" db:"name"`
	Owner          string          `json:"owner" db:"owner"`
	CreatedAt      data.CustomTime `json:"created_at" db:"created_at"`
	Enabled        bool            `json:"enabled" db:"enabled"`
	AccountExpired bool            `json:"account_expired" db:"account_expired"`
	AccountLocked  bool            `json:"account_locked" db:"account_locked"`
	Slug           string          `json:"slug,omitempty" db:"slug"`
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

// ClientScopeXref is a model for a many-to-many xref table holding clients <--> scopes
type ClientScopeXref struct {
	ClientId  string          `db:"client_uuid"`
	ScopeId   string          `db:"scope_uuid"`
	CreatedAt data.CustomTime `db:"created_at"`
}
