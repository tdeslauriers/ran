package pat

import (
	"database/sql"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/ran/internal/clients"
)

// PatRepository defines the interface for personal access token-related data operations.
type PatRepository interface {

	// FindClientBySlug retrieves a client by its slug from database.
	FindClientBySlug(slug string) (*clients.ClientRecord, error)

	// FindPatByIndex retrieves a pat by its lookup index from database.
	FindPatByIndex(patIndex string) (*PatRecord, error)

	// FindPatScopes retrieves the scopes associated with a pat lookup index.
	FindPatScopes(patIndex string) ([]ScopePatRecord, error)

	// FindClientByPat retrieves the client associated with a given pat index.
	FindClientByPat(patIndex string) (*ClientStatus, error)

	// InsertPat inserts a new personal access token record into the database.
	InsertPat(pat PatRecord) error

	// InsertPatClientXref inserts a new pat-client cross reference record into the database's xref table.
	InsertPatClientXref(xref PatClientXref) error
}

// NewPatRepository creates a new instance of PatRepository and returns and underlying concrete implementation.
func NewPatRepository(sql *sql.DB) PatRepository {

	return &patRepository{

		sql: sql,
	}
}

var _ PatRepository = (*patRepository)(nil)

// patRepository is the concrete implementation of PatRepository interface.
type patRepository struct {
	sql *sql.DB
}

// FindClientBySlug retrieves a client by its slug from database.
func (r *patRepository) FindClientBySlug(slug string) (*clients.ClientRecord, error) {

	qry := `
		SELECT
			uuid,
			name,
			owner,
			created_at,
			enabled,
			account_expired,
			account_locked,
			slug
		FROM client WHERE slug = ?`
	c, err := data.SelectOneRecord[clients.ClientRecord](r.sql, qry, slug)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("client with slug %s does not exist", slug)
		} else {
			return nil, fmt.Errorf("failed to retrieve client with slug %s: %v", slug, err)
		}
	}

	return &c, nil
}

// FindPatByIndex retrieves a pat by its lookup index from database.
func (r *patRepository) FindPatByIndex(patIndex string) (*PatRecord, error) {

	qry := `
		SELECT
			uuid,
			pat_index,
			created_at,
			active,
			revoked,
			expired
		FROM pat WHERE pat_index = ?`
	p, err := data.SelectOneRecord[PatRecord](r.sql, qry, patIndex)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("pat with provided index not found")
		} else {
			return nil, fmt.Errorf("failed to retrieve pat by index: %v", err)
		}
	}

	return &p, nil
}

// FindPatScopes retrieves the scopes associated with a pat lookup index.
func (r *patRepository) FindPatScopes(patIndex string) ([]ScopePatRecord, error) {

	qry := `
		SELECT
			s.uuid AS scope_uuid,
			s.service_name,
			s.scope,
			s.name AS scope_name,
			s.description AS scope_description,
			s.created_at AS scope_created_at,
			s.active AS scope_active,
			s.slug AS scope_slug,
			c.uuid AS client_uuid
		FROM scope s
			LEFT OUTER JOIN client_scope cs ON s.uuid = cs.scope_uuid
			LEFT OUTER JOIN client c ON cs.client_uuid = c.uuid
			LEFT OUTER JOIN pat_client pc ON c.uuid = pc.client_uuid
			LEFT OUTER JOIN pat p ON pc.pat_uuid = p.uuid
		WHERE p.pat_index = ?
			AND s.active = TRUE
			AND c.enabled = TRUE
			AND c.account_expired = FALSE
			AND c.account_locked = FALSE
			AND p.active = TRUE
			AND p.revoked = FALSE
			AND p.expired = FALSE`
	records, err := data.SelectRecords[ScopePatRecord](r.sql, qry, patIndex)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// ClientStatus is a model representing the fields of a client record in the database needed
// to evaluate if it is disabled, locked, or expired.
type ClientStatus struct {
	Id             string `db:"uuid"`
	Name           string `db:"name"`
	Enabled        bool   `db:"enabled"`
	AccountExpired bool   `db:"account_expired"`
	AccountLocked  bool   `db:"account_locked"`
}

// FindClientByPat retrieves the client associated with a given pat index.
func (r *patRepository) FindClientByPat(patIndex string) (*ClientStatus, error) {

	qry := `
		SELECT 
			c.uuid,
			c.name,
			c.enabled,
			c.account_expired,
			c.account_locked
		FROM client c
			LEFT OUTER JOIN pat_client pc ON c.uuid = pc.client_uuid
			LEFT OUTER JOIN pat p ON pc.pat_uuid = p.uuid
		WHERE p.pat_index = ?`
	status, err := data.SelectOneRecord[ClientStatus](r.sql, qry, patIndex)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("client associated with pat index not found")
		} else {
			return nil, fmt.Errorf("failed to retrieve client for pat index: %v", err)
		}
	}

	return &status, nil
}

// InsertPat inserts a new personal access token record into the database.
func (r *patRepository) InsertPat(pat PatRecord) error {

	qry := `
		INSERT INTO pat (
			uuid,
			pat_index,
			created_at,
			active,
			revoked,
			expired
		) VALUES (?, ?, ?, ?, ?, ?)`
	if err := data.InsertRecord(r.sql, qry, pat); err != nil {
		return err
	}

	return nil
}

// InsertPatClientXref inserts a new pat-client cross reference record into the database's xref table.
func (r *patRepository) InsertPatClientXref(xref PatClientXref) error {

	qry := `
		INSERT INTO pat_client (
			id,
			pat_uuid,
			client_uuid,
			created_at
		) VALUES (?, ?, ?, ?)`
	if err := data.InsertRecord(r.sql, qry, xref); err != nil {
		return err
	}

	return nil
}
