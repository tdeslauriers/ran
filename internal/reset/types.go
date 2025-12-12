package reset

// Reset is a model for a service client uuid and pw for lookup by reset service
type Reset struct {
	ClientId string `db:"uuid"`
	Password string `db:"password"`
}
