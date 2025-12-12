package reset

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/ran/internal/clients"
	"github.com/tdeslauriers/ran/internal/definitions"
)

// ResetHandler provides http handlers for service client password reset requests
type ResetHandler interface {
	// HandleReset handles a service client password reset request
	HandleReset(w http.ResponseWriter, r *http.Request)
}

// NewResetHandler creates a new service client ResetHandler interface abstracting a concrete implementation
func NewResetHandler(s ResetService, s2s, iam jwt.Verifier) ResetHandler {

	return &resetHandler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(definitions.PackageKey, definitions.PackageClients)).
			With(slog.String(definitions.ComponentKey, definitions.ComponentClients))}
}

var _ ResetHandler = (*resetHandler)(nil)

// resetHandler is a concrete implementation of the ResetHandler interface
type resetHandler struct {
	service     ResetService
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleReset is a concrete impl of the ResetHandler interface method: handles a service client password reset request
func (h *resetHandler) HandleReset(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	if r.Method != http.MethodPost {
		log.Error("invalid method", "err", "only POST method is allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST is allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	authorizedSvc, err := h.s2sVerifier.BuildAuthorized(clients.UserAllowedWrite, svcToken)
	if err != nil {
		log.Error("failed to authorize s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam access token
	accessToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(clients.UserAllowedWrite, accessToken)
	if err != nil {
		log.Error("failed to authorize iam access token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// parse request body
	var cmd profile.ResetCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode reset password request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to decode reset password request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate input
	if err := cmd.ValidateCmd(); err != nil {
		log.Error(fmt.Sprintf("failed to validate service client %s password reset request", cmd.ResourceId), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// reset client password
	if err := h.service.ResetPassword(cmd); err != nil {
		log.Error(fmt.Sprintf("failed to reset password for service client %s", cmd.ResourceId), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to reset password for service client %s", cmd.ResourceId),
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully reset password for service client %s", cmd.ResourceId),
		slog.String("requesting_service", authorizedSvc.Claims.Subject),
		slog.String("actor", authorized.Claims.Subject))

	// respond with success
	w.WriteHeader(http.StatusNoContent)
}
