package pat

import (
	"github.com/tdeslauriers/carapace/pkg/data"
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

// ScopePatRecord represents a query row scope + client id associated with a personal access token (PAT)
// via xref table joins
type ScopePatRecord struct {
	ScopeId          string `db:"scope_uuid"`
	ServiceName      string `db:"service_name"`
	Scope            string `db:"scope"`
	ScopeName        string `db:"scope_name"`
	ScopeDescription string `db:"scope_description"`
	ScopeCreatedAt   string `db:"scope_created_at"`
	ScopeActive      bool   `db:"scope_active"`
	ScopeSlug        string `db:"scope_slug"`
	ClientId         string `db:"client_uuid"`
}
