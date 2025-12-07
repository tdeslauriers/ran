package clients

import (
	"database/sql"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// ResetRepository provides client password reset repository/persistance operations
type ResetRepository interface {

	// FindById gets a client id and password by uuid from the database
	FindById(id string) (*Reset, error)

	// UpdatePassword updates a service client's password in the database
	UpdatePassword(id string, newHash string) error
}

// NewResetRepository creates a new reset repository interface abstracting a concrete implementation
func NewResetRepository(sql *sql.DB) ResetRepository {

	return &mariaResetRepository{
		sql: sql,
	}
}

var _ ResetRepository = (*mariaResetRepository)(nil)

// mariaResetRepository is a concrete implementation of the ResetRepository interface
type mariaResetRepository struct {
	sql *sql.DB
}

// FindById is a concrete impl of the ResetRepository interface method: gets a client id and
// password by uuid from the database
func (r *mariaResetRepository) FindById(id string) (*Reset, error) {

	qry := "SELECT uuid, password FROM client WHERE uuid = ?"
	record, err := data.SelectOneRecord[Reset](r.sql, qry, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("service client not found: %s", id)
		} else {
			return nil, fmt.Errorf("failed to retrieve service client record %s from database: %v", id, err)
		}
	}

	return &record, nil
}

// UpdatePassword is a concrete impl of the ResetRepository interface method: updates a
// service client's password in the database
func (r *mariaResetRepository) UpdatePassword(id string, newHash string) error {

	qry := "UPDATE client SET password = ? WHERE uuid = ?"
	if err := data.UpdateRecord(r.sql, qry, newHash, id); err != nil {
		return fmt.Errorf("failed to update service client %s password: %v", id, err)
	}

	return nil
}
