package pat

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/ran/internal/util"
)

// authorization scopes required
// There is no read scope for PATs, as they are post only endpoints
var requiredScopes = []string{"w:ran:*", "w:ran:generate:pat:*"}

// Handler provides methods for handling personal access token (PAT) operations
type Handler interface {

	// HandleGeneratePat handles a request to generate a personal access token (PAT)
	HandleGeneratePat(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new personal access token (PAT) handler interface abstracting a concrete implementation
func NewHandler(s Service, s2s, iam jwt.Verifier) Handler {
	return &handler{
		service: s,
		s2s:     s2s,
		iam:     iam,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceKey)).
			With(slog.String(util.PackageKey, util.PackagePAT)).
			With(slog.String(util.ComponentKey, util.ComponentPatHandler)),
	}
}

var _ Handler = (*handler)(nil)

// handler is a concrete implementation of the Handler interface
type handler struct {
	service Service
	s2s     jwt.Verifier
	iam     jwt.Verifier

	logger *slog.Logger
}

// HandleGeneratePat is the concrete implentation of the interface method which
// handles a request to generate a personal access token (PAT)
func (h *handler) HandleGeneratePat(w http.ResponseWriter, r *http.Request) {

	// validate the method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed on /generate/pat endpoint", http.StatusMethodNotAllowed)
		return
	}

	// check service authorization
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(requiredScopes, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate s2s token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// check user access token
	userToken := r.Header.Get("Authorization")
	authorized, err := h.iam.BuildAuthorized(requiredScopes, userToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate user token: %v", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// decode request body
	var cmd GeneratePatCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("failed to decode request body: %v", err)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate request formatting
	if err := cmd.Validate(); err != nil {
		h.logger.Error("failed to validate generate pat cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// generate the PAT
	pat, err := h.service.GeneratePat(cmd.Slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to generate pat: %v", err.Error()))
		h.respondServiceError(err, w)
		return
	}

	h.logger.Info(fmt.Sprintf("pat token generated for client '%s' by user '%s'", pat.Client, authorized.Claims.Subject))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(pat); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode pat json response: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode pat json response",
		}
		e.SendJsonErr(w)
		return
	}
}

// respondServiceError is a helper method to respond with error messages and the correct http code
// if the underlying service fails
func (h *handler) respondServiceError(err error, w http.ResponseWriter) {

	switch {
	case strings.Contains(err.Error(), "disabled"):
	case strings.Contains(err.Error(), "locked"):
	case strings.Contains(err.Error(), "expired"):
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), "not found"):
		e := connect.ErrorHttp{
			StatusCode: http.StatusNotFound,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), "invalid"):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	default:
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}
}
