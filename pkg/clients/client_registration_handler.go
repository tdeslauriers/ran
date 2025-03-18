package clients

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"ran/internal/util"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
)

// RegistrationHandler provides an interface for handling client registration requests
type RegistrationHandler interface {

	// HandleRegistration handles a client registration request
	HandleRegistration(w http.ResponseWriter, r *http.Request)
}

// NewRegistrationHandler creates a new client registration handler interface abstracting a concrete implementation
func NewRegistrationHandler(s Service, s2s, iam jwt.Verifier) RegistrationHandler {
	return &registrationHandler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceKey)).
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentRegister)),
	}
}

var _ RegistrationHandler = (*registrationHandler)(nil)

// registrationHandler is a concrete implementation of the RegistrationHandler interface
type registrationHandler struct {
	service     Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleRegistration handles a client registration request
func (h *registrationHandler) HandleRegistration(w http.ResponseWriter, r *http.Request) {

	// validate request is a POST
	if r.Method != http.MethodPost {
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only post requests are allowed to /clients/register endpoint",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	// NOTE: the s2s scopes needed are the ones for a service calling a user endpoint.
	if _, err := h.s2sVerifier.BuildAuthorized(userAllowedWrite, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/clients/{slug} handler failed to validate s2s token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	usrToken := r.Header.Get("Authorization")
	if _, err := h.iamVerifier.BuildAuthorized(userAllowedWrite, usrToken); err != nil {
		h.logger.Error(fmt.Sprintf("/clients/{slug} handler failed to validate user token: %v", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// decode request body
	var cmd RegisterCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("failed to decode json request body: %v", err)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate registration cmd
	if err := cmd.ValidateCmd(); err != nil {
		errMsg := fmt.Sprintf("failed to validate registration cmd: %v", err)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// get all current clients (to make sure not already registered or duplicate)
	clients, err := h.service.GetClients()
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get clients records from db: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// check for duplicate client
	for _, client := range clients {
		if cmd.Name == client.Name {
			errMsg := fmt.Sprintf("service client name '%s' already exists", cmd.Name)
			h.logger.Error(errMsg)
			e := connect.ErrorHttp{
				StatusCode: http.StatusConflict,
				Message:    errMsg,
			}
			e.SendJsonErr(w)
			return
		}
	}

	// register client
	client, err := h.service.Register(&cmd)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to register client %s: %v", cmd.Name, err))
		h.service.HandleServiceError(w, err)
		return
	}

	h.logger.Info(fmt.Sprintf("client %s registered successfully", client.Name))

	// respond with client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(client); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode client %s: %v", client.Name, err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}
}
