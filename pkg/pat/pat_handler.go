package pat

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/pat"
	"github.com/tdeslauriers/ran/internal/util"
)

// authorization scopes required
// There is no read scope for PATs, as they are post only endpoints
var (
	requiredPatGenScopes        = []string{"w:ran:*", "w:ran:generate:pat:*"}
	requiredPatIntrospectScopes = []string{"w:ran:*", "w:ran:introspect:*"}
)

// Handler provides methods for handling personal access token (PAT) operations
type Handler interface {

	// HandleGeneratePat handles a request to generate a personal access token (PAT)
	HandleGeneratePat(w http.ResponseWriter, r *http.Request)

	// HandleIntrospectPat handles a request to introspect a personal access token (PAT)
	HandleIntrospectPat(w http.ResponseWriter, r *http.Request)
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

	// generate telemetry
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate the method is POST
	if r.Method != http.MethodPost {
		log.Error(fmt.Sprintf("method %s not allowed", r.Method),
			slog.String("err", "only POST method is allowed"))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// check service authorization
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(requiredPatGenScopes, svcToken); err != nil {
		log.Error("failed to validate s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// check user access token
	userToken := r.Header.Get("Authorization")
	authorized, err := h.iam.BuildAuthorized(requiredPatGenScopes, userToken)
	if err != nil {
		log.Error("failed to validate user token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// decode request body
	var cmd GeneratePatCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to json decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request formatting
	if err := cmd.Validate(); err != nil {
		log.Error("failed to validate generate pat cmd", "err", err.Error())
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
		log.Error("failed to generate pat token", "err", err.Error())
		h.respondServiceError(err, w)
		return
	}

	log.Info(fmt.Sprintf("pat token generated for client '%s' by user '%s'", pat.Client, authorized.Claims.Subject))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(pat); err != nil {
		log.Error("failed to encode pat json response", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode pat json response",
		}
		e.SendJsonErr(w)
		return
	}
}

// HandleIntrospectPat is the concrete implementation of the interface method which
// handles a request to introspect a personal access token (PAT)
func (h *handler) HandleIntrospectPat(w http.ResponseWriter, r *http.Request) {

	// generate telemetry
	tel := connect.NewTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate the method is POST
	if r.Method != http.MethodPost {
		log.Error(fmt.Sprintf("method %s not allowed", r.Method))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2s authorization
	// Only internal, authorized services can call /introspect
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(requiredPatIntrospectScopes, svcToken); err != nil {
		log.Error("failed to validate s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// decode request body
	var token pat.IntrospectCmd
	if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
		log.Error("failed to decode request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to json decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request formatting
	if err := token.Validate(); err != nil {
		log.Error("failed to validate introspect cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get introspection results
	result, err := h.service.IntrospectPat(token.Token)
	if err != nil {
		// if result is nil, we have a service error
		if result == nil {
			log.Error("failed to introspect pat token", "err", err.Error())
			h.respondServiceError(err, w)
			return
		}

		// otherwise, we have a valid response with not found, revoked, expired, or inactive status
		// log the error because it isnt a service error, only an issue with the token itself
		log.Error(fmt.Sprintf("introspection yielded a pat error: %v", err.Error()))

		// return a successful introspection that yeilds an active == false status
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			log.Error("failed to encode pat introspection json response", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "failed to encode pat introspection json response",
			}
			e.SendJsonErr(w)
			return
		}

	}

	// successful introspection --> active, not revoked, not expired set of scopes found
	if result != nil {
		log.Info(fmt.Sprintf("pat token introspected for client '%s'", result.ServiceName))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			log.Error("failed to encode pat introspection json response", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "failed to encode pat introspection json response",
			}
			e.SendJsonErr(w)
			return
		}
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
