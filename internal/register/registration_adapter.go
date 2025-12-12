package register

import (
	"database/sql"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/ran/internal/clients"
)

// RegistrationRepository provides client registration repository/persistance operations
type RegistrationRepository interface {

	// Create inserts a new client record into the database
	Create(client clients.ClientRecord) error
}

// NewRegistrationRepository creates a new registration repository interface abstracting a concrete implementation
func NewRegistrationRepository(sql *sql.DB) RegistrationRepository {

	return &mariaRegistrationRepository{
		sql: sql,
	}
}

var _ RegistrationRepository = (*mariaRegistrationRepository)(nil)

// mariaRegistrationRepository is a concrete implementation of the RegistrationRepository interface
type mariaRegistrationRepository struct {
	sql *sql.DB
}

// Create is a concrete impl of the RegistrationRepository interface method: inserts a new client record into the database
func (r *mariaRegistrationRepository) Create(client clients.ClientRecord) error {

	// insert client record into db
	query := `
		INSERT INTO client (
			uuid,
			password,
			name,
			owner,
			created_at,
			enabled,
			account_expired,
			account_locked,
			slug)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if err := data.InsertRecord(r.sql, query, client); err != nil {
		return fmt.Errorf("failed to insert service client %s record into database: %v", client.Name, err)
	}

	return nil
}
