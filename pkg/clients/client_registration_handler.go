package clients

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/ran/internal/util"
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

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate request is a POST
	if r.Method != http.MethodPost {
		log.Error("invalid request method", "err", "only POST method is allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only post requests are allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	// NOTE: the s2s scopes needed are the ones for a service calling a user endpoint.
	if _, err := h.s2sVerifier.BuildAuthorized(userAllowedWrite, svcToken); err != nil {
		log.Error("failed to validate s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	usrToken := r.Header.Get("Authorization")
	authroized, err := h.iamVerifier.BuildAuthorized(userAllowedWrite, usrToken)
	if err != nil {
		log.Error("failed to validate user access token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// decode request body
	var cmd RegisterCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode registration cmd request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to json decode registration cmd request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate registration cmd
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate registration cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get all current clients (to make sure not already registered or duplicate)
	clients, err := h.service.GetClients()
	if err != nil {
		log.Error("failed to get clients from persistance", "err", err.Error())
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
			log.Error(fmt.Sprintf("client name %s already exists", cmd.Name))
			e := connect.ErrorHttp{
				StatusCode: http.StatusConflict,
				Message:    fmt.Sprintf("client name %s already exists", cmd.Name),
			}
			e.SendJsonErr(w)
			return
		}
	}

	// register client
	client, err := h.service.Register(&cmd)
	if err != nil {
		log.Error("failed to register client", "err", err.Error())
		h.service.HandleServiceError(w, err)
		return
	}

	h.logger.Info(fmt.Sprintf("client %s registered successfully", client.Name),
		slog.String("actor", authroized.Claims.Subject),
		slog.String("client_id", client.Id))

	// respond with client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(client); err != nil {
		log.Error("failed to encode registered client json response", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode registered client json response",
		}
		e.SendJsonErr(w)
		return
	}
}
