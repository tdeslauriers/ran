package clients

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"ran/internal/util"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/profile"
)

// ClientHandler provides http handlers for client (model) requests
type ClientHandler interface {

	// HandleClients returns all clients
	HandleClients(w http.ResponseWriter, r *http.Request)

	// HandleClient handles all requests for a single client: GET, POST, PUT, DELETE
	HandleClient(w http.ResponseWriter, r *http.Request)
}

// NewClientHandler creates a new client handler
func NewClientHandler(s Service, s2s, iam jwt.Verifier) ClientHandler {
	return &clientHandler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceS2s)).
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClients)),
	}
}

var _ ClientHandler = (*clientHandler)(nil)

type clientHandler struct {
	service     Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleClients returns all clients
// concrete impl of the Handler interface method
func (h *clientHandler) HandleClients(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed on /clients endpoint", http.StatusMethodNotAllowed)
		return
	}

	// determine allowed scopes based on whether iamVerifier is nil --> service endpoint or user endpoint
	var allowedRead []string
	if h.iamVerifier == nil {
		allowedRead = s2sAllowedRead
	} else {
		allowedRead = userAllowedRead
	}

	// validate service token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2sVerifier.BuildAuthorized(allowedRead, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate s2s token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// check if iamVerifier is nil, if not nil, validate user token
	if h.iamVerifier != nil {
		usrToken := r.Header.Get("Authorization")
		if _, err := h.iamVerifier.BuildAuthorized(allowedRead, usrToken); err != nil {
			h.logger.Error(fmt.Sprintf("failed to validate user token: %v", err.Error()))
			connect.RespondAuthFailure(connect.User, err, w)
			return
		}
	}

	clients, err := h.service.GetClients()
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get clients: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	clientsJson, err := json.Marshal(clients)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to marshal clients: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(clientsJson)

}

// HandleClient handles all requests for a single client: GET, POST, PUT, DELETE
// concrete impl of the Handler interface method
func (h *clientHandler) HandleClient(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r)
		return
	case http.MethodPost:
		h.handlePost(w, r)
		return
	// case http.MethodPut:
	// case http.MethodDelete:
	default:
		h.logger.Error(fmt.Sprintf("method not allowed on /clients/slug endpoint: %s", r.Method))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGet handles GET requests for a single client by slug
func (h *clientHandler) handleGet(w http.ResponseWriter, r *http.Request) {

	// get slug param from request
	segments := strings.Split(r.URL.Path, "/")

	var slug string
	if len(segments) > 1 {
		slug = segments[len(segments)-1]
	} else {
		h.logger.Error("missing slug param in request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "missing slug param in request",
		}
		e.SendJsonErr(w)
		return
	}

	// light weight input validation (not checking if slug is valid or well-formed)
	if len(slug) < 16 || len(slug) > 64 {
		h.logger.Error("invalid scope slug")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid scope slug",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	// NOTE: the s2s scopes needed are the ones for a service calling a user endpoint.
	if _, err := h.s2sVerifier.BuildAuthorized(userAllowedRead, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/clients/{slug} handler failed to validate s2s token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	usrToken := r.Header.Get("Authorization")
	if _, err := h.iamVerifier.BuildAuthorized(userAllowedRead, usrToken); err != nil {
		h.logger.Error(fmt.Sprintf("/clients/{slug} handler failed to validate user token: %v", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	client, err := h.service.GetClient(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get client: %v", err.Error()))
		h.service.HandleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(client); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode service client to json: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode service client to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// handlePost handles POST requests for a single client
func (h *clientHandler) handlePost(w http.ResponseWriter, r *http.Request) {

	// get slug param from request
	segments := strings.Split(r.URL.Path, "/")

	var slug string
	if len(segments) > 1 {
		slug = segments[len(segments)-1]
	} else {
		h.logger.Error("missing service client slug param in request")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "missing service slug param in request",
		}
		e.SendJsonErr(w)
		return
	}

	// light weight input validation (not checking if slug is valid or well-formed)
	if len(slug) < 16 || len(slug) > 64 {
		h.logger.Error("invalid service client slug")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	// NOTE: the s2s scopes needed are the ones for a service calling a user endpoint.
	if _, err := h.s2sVerifier.BuildAuthorized(userAllowedWrite, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("post /client/{slug} handler failed to validate s2s token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	userToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(userAllowedWrite, userToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("post /client/{slug} handler failed to validate user token: %v", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get cmd from request body
	var cmd profile.Client
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode request body: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate client
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("invalid client: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "invalid client",
		}
		e.SendJsonErr(w)
		return
	}

	// look up client in db
	client, err := h.service.GetClient(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get client: %v", err.Error()))
		h.service.HandleServiceError(w, err)
		return
	}

	// prepare updated client
	updated := &Client{
		Id:             client.Id, // not allowed to update id
		Name:           cmd.Name,
		Owner:          cmd.Owner,
		CreatedAt:      client.CreatedAt, // not allowed to update created_at
		Enabled:        cmd.Enabled,
		AccountExpired: cmd.AccountExpired,
		AccountLocked:  cmd.AccountLocked,
		Slug:           client.Slug, // not allowed to update slug
	}

	// update client
	err = h.service.UpdateClient(updated)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to update client: %v", err.Error()))
		h.service.HandleServiceError(w, err)
		return
	}

	// log updates
	if cmd.Name != client.Name {
		h.logger.Info(fmt.Sprintf("sesrvice client name updated from %s to %s by %s", client.Name, cmd.Name, authorized.Claims.Subject))
	}

	if cmd.Owner != client.Owner {
		h.logger.Info(fmt.Sprintf("sesrvice client owner updated from %s to %s by %s", client.Owner, cmd.Owner, authorized.Claims.Subject))
	}

	if cmd.Enabled != client.Enabled {
		h.logger.Info(fmt.Sprintf("sesrvice client enabled updated from %t to %t by %s", client.Enabled, cmd.Enabled, authorized.Claims.Subject))
	}

	if cmd.AccountExpired != client.AccountExpired {
		h.logger.Info(fmt.Sprintf("sesrvice client account_expired updated from %t to %t by %s", client.AccountExpired, cmd.AccountExpired, authorized.Claims.Subject))
	}

	if cmd.AccountLocked != client.AccountLocked {
		h.logger.Info(fmt.Sprintf("sesrvice client account_locked updated from %t to %t by %s", client.AccountLocked, cmd.AccountLocked, authorized.Claims.Subject))
	}

	// respond with updated client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode updated sesrvice client to json: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode updated client to json",
		}
		e.SendJsonErr(w)
		return
	}
}
