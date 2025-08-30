package scopes

import (
	"encoding/json"
	"fmt"

	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/ran/internal/util"
)

// service endpoints require s2s-only endpoint scopes
var s2sAllowedRead []string = []string{"r:ran:s2s:scopes:*"}

// var s2sllowedWrite []string = []string{"w:ran:s2s:scopes:*"}

// user endpoints require user endpoint scopes
// NOTE: user-only endpoint scopes will issued to services when they are acting on behalf of a user,
// but in those cases, their must be a user token present in the request ALSO.
var userAllowedRead []string = []string{"r:ran:scopes:*"}
var userAllowedWrite []string = []string{"w:ran:scopes:*"}

// Handler provides http handlers for scopes requests
type Handler interface {

	// HandleScopes returns all scopes, active or inactive
	HandleScopes(w http.ResponseWriter, r *http.Request)

	// HandleActiveScopes returns all active scopes
	HandleActiveScopes(w http.ResponseWriter, r *http.Request)

	// HandleAdd handles requests to add a new scope
	HandleAdd(w http.ResponseWriter, r *http.Request)

	// HandleScope handles all requests for a single scope: GET, PUT, POST, DELETE
	HandleScope(w http.ResponseWriter, r *http.Request)
}

// NewS2sHandler creates a new handler for scopes requests from services,
// ie. s2s requests with no user access token
// if iamVerifier is nil/set to nil when instantiated, it indicates handler is service facing ONLY
func NewHandler(s Service, s2s, iam jwt.Verifier) Handler {
	return &handler{
		svc:         s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceS2s)).
			With(slog.String(util.PackageKey, util.PackageScopes)).
			With(slog.String(util.ComponentKey, util.ComponentScopes)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	svc         Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier // if iamVerifier is nil, it indicates handler is service facing ONLY

	logger *slog.Logger
}

func (h *handler) HandleScopes(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET http method allowed",
		}
		e.SendJsonErr(w)
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

	scopes, err := h.svc.GetScopes()
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get scopes: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	scopesJson, err := json.Marshal(scopes)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to marshal scopes to json payload: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(scopesJson)
}

// s2s handler: meant for provideing data to services, not users, no identity jwt validation
func (h *handler) HandleActiveScopes(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		h.logger.Error("only GET http method allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET http method allowed",
		}
		e.SendJsonErr(w)
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

	scopes, err := h.svc.GetActiveScopes()
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get active scopes from database: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error: failed get scopes from database",
		}
		e.SendJsonErr(w)
		return
	}

	scopesJson, err := json.Marshal(scopes)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to marshal scopes to json payload: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(scopesJson)

}

// HandleAdd handles requests to add a new scope
// concrete impl for the HandleAdd method
func (h *handler) HandleAdd(w http.ResponseWriter, r *http.Request) {

	// validate http method
	if r.Method != "POST" {
		h.logger.Error("only POST http method allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST http method allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2sVerifier.BuildAuthorized(userAllowedWrite, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/scopes/add handler failed to validate s2s token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	usrToken := r.Header.Get("Authorization")
	if _, err := h.iamVerifier.BuildAuthorized(userAllowedWrite, usrToken); err != nil {
		h.logger.Error(fmt.Sprintf("/scopes/add handler failed to validate user token: %v", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get cmd from request body
	var cmd types.Scope
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode scope from request body: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode scope from request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate scope
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate scope: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("failed to validate scope: %v", err.Error()),
		}
		e.SendJsonErr(w)
		return
	}

	// add scope
	scope, err := h.svc.AddScope(&cmd)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to add scope: %v", err.Error()))
		h.HandleServiceError(w, err)
		return
	}

	// respond 201
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(scope); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode scope to json: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode scope to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// HandleScope handles all requests for a single scope: GET, PUT, POST, DELETE
// concrete impl for the HandleScope method
func (h *handler) HandleScope(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r)
		return
	// case "PUT":
	// 	return
	case http.MethodPost:
		h.handlePost(w, r)
		return
	// case "DELETE":
	// 	return
	default:
		h.logger.Error("only GET, PUT, POST, DELETE http methods allowed")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET, PUT, POST, DELETE http methods allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGet handles GET requests for a single scope
// concrete impl for the GET part of HandleScope method
func (h *handler) handleGet(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2sVerifier.BuildAuthorized(userAllowedRead, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/scopes/{slug} handler failed to validate s2s token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	usrToken := r.Header.Get("Authorization")
	if _, err := h.iamVerifier.BuildAuthorized(userAllowedRead, usrToken); err != nil {
		h.logger.Error(fmt.Sprintf("/scopes/{slug} handler failed to validate user token: %v", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get valid slug from request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get scope
	scope, err := h.svc.GetScope(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get scope %s: %v", slug, err.Error()))
		h.HandleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(scope)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode scope to json: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode scope to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// handlePost handles PUT requests for a single scope
// concrete impl for the PUT part of HandleScope method
func (h *handler) handlePost(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2sVerifier.BuildAuthorized(userAllowedWrite, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/scopes/{slug} handler failed to validate s2s token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	usrToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(userAllowedWrite, usrToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/scopes/{slug} handler failed to validate user token: %v", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get valid slug from request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get cmd from request body
	var cmd types.Scope
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode scope from request body: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode scope from request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate scope
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate scope: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("failed to validate scope: %v", err.Error()),
		}
		e.SendJsonErr(w)
		return
	}

	// look up scope by slug --> and error if bad scope
	scope, err := h.svc.GetScope(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get scope %s for update: %v", slug, err.Error()))
		h.HandleServiceError(w, err)
		return
	}

	// prepare updated scope
	updated := &types.Scope{
		Uuid:        scope.Uuid, // not allowed to update uuid
		ServiceName: cmd.ServiceName,
		Scope:       cmd.Scope,
		Name:        cmd.Name,
		Description: cmd.Description,
		CreatedAt:   scope.CreatedAt, // not allowed to update created_at
		Active:      cmd.Active,
		Slug:        scope.Slug, // not allowed to update slug
	}

	// update scope
	err = h.svc.UpdateScope(updated)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to update scope %s: %v", slug, err.Error()))
		h.HandleServiceError(w, err)
		return
	}

	// log updates
	if cmd.ServiceName != scope.ServiceName {
		h.logger.Info(fmt.Sprintf("service name updated from '%s' to '%s' by %s", scope.ServiceName, cmd.ServiceName, authorized.Claims.Subject))
	}

	if cmd.Scope != scope.Scope {
		h.logger.Info(fmt.Sprintf("scope updated from '%s' to '%s' by %s", scope.Scope, cmd.Scope, authorized.Claims.Subject))
	}

	if cmd.Name != scope.Name {
		h.logger.Info(fmt.Sprintf("name updated from '%s' to '%s' by %s", scope.Name, cmd.Name, authorized.Claims.Subject))
	}

	if cmd.Description != scope.Description {
		h.logger.Info(fmt.Sprintf("description updated from '%s' to '%s' by %s", scope.Description, cmd.Description, authorized.Claims.Subject))
	}

	if cmd.Active != scope.Active {
		h.logger.Info(fmt.Sprintf("active updated from %t to %t by %s", scope.Active, cmd.Active, authorized.Claims.Subject))
	}

	// respond with updated scope
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode updated scope to json: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode updated scope to json",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *handler) HandleServiceError(w http.ResponseWriter, err error) {

	switch {
	case strings.Contains(err.Error(), ErrInvalidSlug):
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    ErrInvalidSlug,
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
	case strings.Contains(err.Error(), ErrScopeNotFound):
		e := connect.ErrorHttp{
			StatusCode: http.StatusNotFound,
			Message:    ErrScopeNotFound,
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
