package clients

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"ran/internal/util"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/profile"
)

// ResetHandler provides http handlers for service client password reset requests
type ResetHandler interface {
	// HandleReset handles a service client password reset request
	HandleReset(w http.ResponseWriter, r *http.Request)
}

// NewResetHandler creates a new service client ResetHandler interface abstracting a concrete implementation
func NewResetHandler(s Service, s2s, iam jwt.Verifier) ResetHandler {
	return &resetHandler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceS2s)).
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClients))}
}

var _ ResetHandler = (*resetHandler)(nil)

// resetHandler is a concrete implementation of the ResetHandler interface
type resetHandler struct {
	service     Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleReset is a concrete impl of the ResetHandler interface method: handles a service client password reset request
func (h *resetHandler) HandleReset(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		h.logger.Error("invalid http method: only POST is allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "invalid http method: only POST is allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2sVerifier.IsAuthorized(userAllowedWrite, svcToken); !authorized {
		h.logger.Error(fmt.Sprintf("password reset handler failed to authorize service token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam access token
	accessToken := r.Header.Get("Authorization")
	if authorized, err := h.iamVerifier.IsAuthorized(userAllowedWrite, accessToken); !authorized {
		h.logger.Error(fmt.Sprintf("password reset handler failed to authorize iam token: %v", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// parse request body
	var cmd profile.ResetCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("failed to decode json reset request body", "err", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate input
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate service client %s password reset request: %v", cmd.ResourceId, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// reset client password
	if err := h.service.ResetPassword(cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to reset service client %s password: %v", cmd.ResourceId, err.Error()))
		h.service.HandleServiceError(w, err)
		return
	}

	jot, _ := jwt.BuildFromToken(accessToken) // ignore error, already validated so parsing should be successful
		h.logger.Info(fmt.Sprintf("service client %s password was reset successfully by %s", cmd.ResourceId, jot.Claims.Subject))

	// respond with success
	w.WriteHeader(http.StatusNoContent)
}
