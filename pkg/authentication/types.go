package authentication

const (

	// 500 Internal Server Error
	ErrInternalServer string = "internal server error"

	ErrGenIndex string = "failed to generate bind index"

	ErrEncryptRefresh     string = "failed to encrypt refresh token"
	ErrEncryptServiceName string = "failed to encrypt service name"
	ErrEncryptClientId    string = "failed to encrypt client id"

	ErrDecryptRefresh     string = "failed to decrypt refresh token"
	ErrDecryptServiceName string = "failed to decrypt service name"
	ErrDecryptClientId    string = "failed to decrypt client id"
)
