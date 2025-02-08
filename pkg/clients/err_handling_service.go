package clients

import (
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

// ClientErrService provides error handling for service clients service failures
type ClientErrService interface {

	// HandleServiceError handles a service client service error
	HandleServiceError(w http.ResponseWriter, err error)
}

// NewErrHandlingService creates a new service client ErrHandlingService interface abstracting a concrete implementation
func NewErrHandlingService() ClientErrService {
	return &clientErrService{}
}

var _ ClientErrService = (*clientErrService)(nil)

// clientErrService is a concrete implementation of the ErrHandlingService interface
type clientErrService struct{}

// HandleServiceError handles service errors
func (s *clientErrService) HandleServiceError(w http.ResponseWriter, err error) {

	switch {
	case strings.Contains(err.Error(), ErrInvalidSlug):
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    ErrInvalidSlug,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrInvalidPwMismatch):
	case strings.Contains(err.Error(), "invalid"):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrClientNotFound):
		e := connect.ErrorHttp{
			StatusCode: http.StatusNotFound,
			Message:    ErrClientNotFound,
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrIncorrectPassword):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
	default:
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}
}
