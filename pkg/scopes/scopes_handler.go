package scopes

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

	// HandleScope handles all requests for a single scope: GET, PUT, POST, DELETE
	HandleScopes(w http.ResponseWriter, r *http.Request)
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

// HandleScopes is the concrete implementation of the interface method
// which handles all requests for a single scope: GET, PUT, POST, DELETE
func (h *handler) HandleScopes(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:

		slug := r.PathValue("slug")
		switch slug {
		case "":
			h.getAllScopes(w, r)
		case "active":
			h.getActiveScopes(w, r)
			return
		default:
			h.getScopeBySlug(w, r)
			return
		}
	case http.MethodPut:
		h.updateScope(w, r)
		return
	case http.MethodPost:

		slug := r.PathValue("slug")
		if slug != "add" {
			// get telemetry from request
			tel := connect.ObtainTelemetry(r, h.logger)
			log := h.logger.With(tel.TelemetryFields()...)

			log.Error("only posts to /add are allowed")
			e := connect.ErrorHttp{
				StatusCode: http.StatusBadRequest,
				Message:    "only posts to /add are allowed",
			}
			e.SendJsonErr(w)
			return
		}

		h.createScope(w, r)
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

func (h *handler) getAllScopes(w http.ResponseWriter, r *http.Request) {

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
	authorizedSvc, err := h.s2sVerifier.BuildAuthorized(allowedRead, svcToken)
	if err != nil {
		log.Error("failed to validate s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// check if iamVerifier is nil, if not nil, validate user token
	authorized := &jwt.Token{}
	if h.iamVerifier != nil {
		usrToken := r.Header.Get("Authorization")
		authorizedUser, err := h.iamVerifier.BuildAuthorized(allowedRead, usrToken)
		if err != nil {
			log.Error("failed to validate user token", "err", err.Error())
			connect.RespondAuthFailure(connect.User, err, w)
			return
		}
		authorized = authorizedUser
	}

	// get scopes from persistence layer
	scopes, err := h.svc.GetScopes()
	if err != nil {
		log.Error("failed to get scopes", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get scopes",
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d scopes", len(scopes)),
		slog.String("requesting_service", authorizedSvc.Claims.Subject),
		slog.String("actor", authorized.Claims.Subject))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(scopes); err != nil {
		h.logger.Error("failed to encode scopes to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode scopes to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// getActiveScopes retrieves all active scopes from the database and returns them as a json response
func (h *handler) getActiveScopes(w http.ResponseWriter, r *http.Request) {

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
	authorizedSvc, err := h.s2sVerifier.BuildAuthorized(allowedRead, svcToken)
	if err != nil {
		log.Error("failed to validate s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// check if iamVerifier is nil, if not nil, validate user token
	authorized := &jwt.Token{}
	if h.iamVerifier != nil {
		usrToken := r.Header.Get("Authorization")
		authorizedUser, err := h.iamVerifier.BuildAuthorized(allowedRead, usrToken)
		if err != nil {
			log.Error("failed to validate user token", "err", err.Error())
			connect.RespondAuthFailure(connect.User, err, w)
			return
		}
		authorized = authorizedUser
	}

	// get active scopes from persistence layer
	scopes, err := h.svc.GetActiveScopes()
	if err != nil {
		log.Error("failed to get active scopes", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed get active scopes from database",
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d active scopes", len(scopes)),
		slog.String("requesting_service", authorizedSvc.Claims.Subject),
		slog.String("actor", authorized.Claims.Subject))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(scopes); err != nil {
		h.logger.Error("failed to encode active scopes to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode active scopes to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// createScope handles requests to add a new scope
func (h *handler) createScope(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	authorizedSvc, err := h.s2sVerifier.BuildAuthorized(userAllowedWrite, svcToken)
	if err != nil {
		log.Error("failed to validate s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	usrToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(userAllowedWrite, usrToken)
	if err != nil {
		log.Error("failed to validate user token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get cmd from request body
	var cmd Scope
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate scope
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate scope", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// add scope
	scope, err := h.svc.AddScope(&cmd)
	if err != nil {
		log.Error("failed to add scope", "err", err.Error())
		h.HandleServiceError(w, err)
		return
	}

	log.Info(fmt.Sprintf("successfully added scope %s", scope.Name),
		slog.String("requesting_service", authorizedSvc.Claims.Subject),
		slog.String("actor", authorized.Claims.Subject))

	// respond 201
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(scope); err != nil {
		log.Error("failed to encode created scope to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode created scope to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGet handles GET requests for a single scope
// concrete impl for the GET part of HandleScope method
func (h *handler) getScopeBySlug(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	authorizedSvc, err := h.s2sVerifier.BuildAuthorized(userAllowedRead, svcToken)
	if err != nil {
		log.Error("failed to validate s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	usrToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(userAllowedRead, usrToken)
	if err != nil {
		log.Error("failed to validate user token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get valid slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get scope from persistence layer
	scope, err := h.svc.GetScope(slug)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get scope %s", slug), "err", err.Error())
		h.HandleServiceError(w, err)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved scope %s", scope.Name),
		slog.String("requesting_service", authorizedSvc.Claims.Subject),
		slog.String("actor", authorized.Claims.Subject))

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(scope)
	if err != nil {
		log.Error("failed to encode scope to json", "err", err.Error())
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
func (h *handler) updateScope(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	authorizedSvc, err := h.s2sVerifier.BuildAuthorized(userAllowedWrite, svcToken)
	if err != nil {
		log.Error("failed to validate s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	usrToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(userAllowedWrite, usrToken)
	if err != nil {
		log.Error("failed to validate user token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get valid slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get cmd from request body
	var cmd Scope
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode scope from request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate scope
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate scope", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// look up record by slug --> and error if bad record
	record, err := h.svc.GetScope(slug)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get scope %s", slug), "err", err.Error())
		h.HandleServiceError(w, err)
		return
	}

	// prepare updated scope
	updated := &Scope{
		Uuid:        record.Uuid, // not allowed to update uuid
		ServiceName: cmd.ServiceName,
		Scope:       cmd.Scope,
		Name:        cmd.Name,
		Description: cmd.Description,
		CreatedAt:   record.CreatedAt, // not allowed to update created_at
		Active:      cmd.Active,
		Slug:        record.Slug, // not allowed to update slug
	}

	// update scope in persistence layer
	err = h.svc.UpdateScope(updated)
	if err != nil {
		log.Error(fmt.Sprintf("failed to update scope %s", slug), "err", err.Error())
		h.HandleServiceError(w, err)
		return
	}

	// log updates
	var updatedFields []any

	if updated.ServiceName != record.ServiceName {
		updatedFields = append(updatedFields,
			slog.String("scope_service_name_previous", record.ServiceName),
			slog.String("scope_service_name_updated", updated.ServiceName))
	}

	if updated.Scope != record.Scope {
		updatedFields = append(updatedFields,
			slog.String("scope_previous", record.Scope),
			slog.String("scope_updated", updated.Scope))
	}

	if updated.Name != record.Name {
		updatedFields = append(updatedFields,
			slog.String("scope_name_previous", record.Name),
			slog.String("scope_name_updated", updated.Name))
	}

	if updated.Description != record.Description {
		updatedFields = append(updatedFields,
			slog.String("scope_description_previous", record.Description),
			slog.String("scope_description_updated", updated.Description))
	}

	if updated.Active != record.Active {
		updatedFields = append(updatedFields,
			slog.Bool("scope_active_previous", record.Active),
			slog.Bool("scope_active_updated", updated.Active))
	}

	if len(updatedFields) > 0 {
		log = log.With(updatedFields...)
		log.Info(fmt.Sprintf("successfully updated scope - slug %s", record.Slug),
			slog.String("requesting_service", authorizedSvc.Claims.Subject),
			slog.String("actor", authorized.Claims.Subject))
	}

	// respond with updated scope
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		log.Error("failed to encode updated scope to json", "err", err.Error())
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
