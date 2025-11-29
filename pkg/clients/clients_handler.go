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

// ClientHandler provides http handlers for client (model) requests
type ClientHandler interface {

	// HandleClients handles all requests for clients: GET, POST, PUT, DELETE
	HandleClients(w http.ResponseWriter, r *http.Request)
}

// NewClientHandler creates a new ClientHandler interface, returning a pointer to a concrete implementation
func NewClientHandler(s Service, s2s, iam jwt.Verifier) ClientHandler {
	return &clientHandler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClients)),
	}
}

var _ ClientHandler = (*clientHandler)(nil)

// clientHandler is a concrete implementation of the ClientHandler interface
type clientHandler struct {
	service     Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleClients implements handling all requests for a single client: GET, POST, PUT, DELETE,
// concrete impl of the Handler interface method
func (h *clientHandler) HandleClients(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:

		// get slug if exists
		slug := r.PathValue("slug")
		if slug != "" {

			h.getAllClients(w, r)
			return
		} else {

			h.getClientBySlug(w, r)
			return
		}
	case http.MethodPut:
		h.updateClient(w, r)
		return
	default:
		// get telemetry from request
		tel := connect.ObtainTelemetry(r, h.logger)
		log := h.logger.With(tel.TelemetryFields()...)
		log.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path),
		}
		e.SendJsonErr(w)
		return
	}
}

// getAllClients handles GET requests for all clients
func (h *clientHandler) getAllClients(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// determine allowed scopes based on whether iamVerifier is nil --> service endpoint or user endpoint
	var allowedRead []string
	if h.iamVerifier == nil {
		allowedRead = s2sAllowedRead
	} else {
		allowedRead = userAllowedRead
	}

	// validate service token
	svcToken := r.Header.Get("Service-Authorization")
	authorizedService, err := h.s2sVerifier.BuildAuthorized(allowedRead, svcToken)
	if err != nil {
		log.Error("failed to validate s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// check if iamVerifier is nil, if not nil, validate user token
	authorizedUser := &jwt.Token{}
	if h.iamVerifier != nil {
		usrToken := r.Header.Get("Authorization")
		authorized, err := h.iamVerifier.BuildAuthorized(allowedRead, usrToken)
		if err != nil {
			log.Error("failed to validate user access token", "err", err.Error())
			connect.RespondAuthFailure(connect.User, err, w)
			return
		}
		authorizedUser = authorized
	}

	clients, err := h.service.GetClients()
	if err != nil {
		log.Error("failed to get clients", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get clients",
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d clients", len(clients)),
		slog.String("requesting_service", authorizedService.Claims.Subject),
		slog.String("actor", authorizedUser.Claims.Subject))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(clients); err != nil {
		log.Error("failed to encode clients to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode clients to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// getClientBySlug handles GET requests for a single client by slug
func (h *clientHandler) getClientBySlug(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate s2s token
	// NOTE: the s2s scopes needed are the ones for a service calling a user endpoint.
	svcToken := r.Header.Get("Service-Authorization")
	authorizedSvc, err := h.s2sVerifier.BuildAuthorized(userAllowedRead, svcToken)
	if err != nil {
		log.Error("failed to validate s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	usrToken := r.Header.Get("Authorization")
	authorizedUser, err := h.iamVerifier.BuildAuthorized(userAllowedRead, usrToken)
	if err != nil {
		log.Error("failed to validate user access token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("invalid service client slug", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get client by slug from persistence layer
	client, err := h.service.GetClient(slug)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get client - slug %s", slug), "err", err.Error())
		h.service.HandleServiceError(w, err)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved client %s - slug %s", client.Name, slug),
		slog.String("requesting_service", authorizedSvc.Claims.Subject),
		slog.String("actor", authorizedUser.Claims.Subject))

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(client); err != nil {
		log.Error(fmt.Sprintf("failed to encode client %s - slug %s to json", client.Name, client.Slug), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to encode client %s - slug %s to json", client.Name, client.Slug),
		}
		e.SendJsonErr(w)
		return
	}
}

// handlePost handles POST requests for a single client
func (h *clientHandler) updateClient(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate s2s token
	// NOTE: the s2s scopes needed are the ones for a service calling a user endpoint.
	svcToken := r.Header.Get("Service-Authorization")
	authorizedSvc, err := h.s2sVerifier.BuildAuthorized(userAllowedWrite, svcToken)
	if err != nil {
		log.Error("failed to validate s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	userToken := r.Header.Get("Authorization")
	authorizedUser, err := h.iamVerifier.BuildAuthorized(userAllowedWrite, userToken)
	if err != nil {
		log.Error("failed to validate user access token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("invalid service client slug", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get cmd from request body
	var cmd Client
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate client
	if err := cmd.Validate(); err != nil {
		log.Error("failed to validate client update cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// look up record in db
	record, err := h.service.GetClient(slug)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get client - slug %s", slug), "err", err.Error())
		h.service.HandleServiceError(w, err)
		return
	}

	// prepare updated client
	updated := &Client{
		Id:             record.Id, // not allowed to update id
		Name:           cmd.Name,
		Owner:          cmd.Owner,
		CreatedAt:      record.CreatedAt, // not allowed to update created_at
		Enabled:        cmd.Enabled,
		AccountExpired: cmd.AccountExpired,
		AccountLocked:  cmd.AccountLocked,
		Slug:           record.Slug, // not allowed to update slug
	}

	// update client
	err = h.service.UpdateClient(updated)
	if err != nil {
		log.Error(fmt.Sprintf("failed to update client %s - slug %s", updated.Name, updated.Slug), "err", err.Error())
		h.service.HandleServiceError(w, err)
		return
	}

	// log updated fields if any
	var updatedFields []any

	if updated.Name != record.Name {
		updatedFields = append(updatedFields,
			slog.String("client_name_previous", record.Name),
			slog.String("client_name_updated", updated.Name))
	}

	if updated.Owner != record.Owner {
		updatedFields = append(updatedFields,
			slog.String("client_owner_previous", record.Owner),
			slog.String("client_owner_updated", updated.Owner))
	}

	if updated.Enabled != record.Enabled {
		updatedFields = append(updatedFields,
			slog.Bool("client_enabled_previous", record.Enabled),
			slog.Bool("client_enabled_updated", updated.Enabled))
	}

	if updated.AccountExpired != record.AccountExpired {
		updatedFields = append(updatedFields,
			slog.Bool("client_account_expired_previous", record.AccountExpired),
			slog.Bool("client_account_expired_updated", updated.AccountExpired))
	}

	if updated.AccountLocked != record.AccountLocked {
		updatedFields = append(updatedFields,
			slog.Bool("client_account_locked_previous", record.AccountLocked),
			slog.Bool("client_account_locked_updated", updated.AccountLocked))
	}

	if len(updatedFields) > 0 {
		log = log.With(updatedFields...)
		log.Info(fmt.Sprintf("successfully updated client %s - slug %s", updated.Name, updated.Slug),
			slog.String("requesting_service", authorizedSvc.Claims.Subject),
			slog.String("actor", authorizedUser.Claims.Subject))
	} else {
		log.Warn(fmt.Sprintf("updated executed, but no fields changed for client %s - slug %s", updated.Name, updated.Slug),
			slog.String("requesting_service", authorizedSvc.Claims.Subject),
			slog.String("actor", authorizedUser.Claims.Subject))
	}

	// respond with updated client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		log.Error(fmt.Sprintf("failed to encode updated client %s - slug %s to json", updated.Name, updated.Slug), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode updated client to json",
		}
		e.SendJsonErr(w)
		return
	}
}
