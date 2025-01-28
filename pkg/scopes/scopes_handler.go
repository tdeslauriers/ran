package scopes

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"ran/internal/util"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
)

// service endpoints require s2s-only endpoint scopes
var s2sAllowedRead []string = []string{"r:ran:s2s:scopes:*"}
var s2sllowedWrite []string = []string{"w:ran:s2s:scopes:*"}

// user endpoints require user endpoint scopes
// NOTE: user-only endpoint scopes will issued to services when they are acting on behalf of a user,
// but in those cases, their must be a user token present in the request ALSO.
var userAllowedRead []string = []string{"r:ran:scopes:*"}
var userAllowedWrite []string = []string{"w:ran:scopes:*"}

// Handler provides http handlers for scopes requests
type Handler interface {

	// HandleScopes returns all scopes, active or inactive
	HandleScopes(w http.ResponseWriter, r *http.Request)

	// HandleScope handles all requests for a single scope: GET, PUT, POST, DELETE
	HandleScope(w http.ResponseWriter, r *http.Request)

	// HandleActiveScopes returns all active scopes
	HandleActiveScopes(w http.ResponseWriter, r *http.Request)
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
			With(slog.String(util.ServiceKey, util.ServiceKey)).
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
	if authorized, err := h.s2sVerifier.IsAuthorized(allowedRead, svcToken); !authorized {
		h.logger.Error(fmt.Sprintf("failed to validate s2s token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// check if iamVerifier is nil, if not nil, validate user token
	if h.iamVerifier != nil {
		usrToken := r.Header.Get("Authorization")
		if authorized, err := h.iamVerifier.IsAuthorized(allowedRead, usrToken); !authorized {
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

// HandleScope handles all requests for a single scope: GET, PUT, POST, DELETE
// concrete impl for the HandleScope method
func (h *handler) HandleScope(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		h.handleGet(w, r)
		return
	case "PUT":
		return
	// case "POST":
	// 	return
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
	if authorized, err := h.s2sVerifier.IsAuthorized(allowedRead, svcToken); !authorized {
		h.logger.Error(fmt.Sprintf("failed to validate s2s token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// check if iamVerifier is nil, if not nil, validate user token
	if h.iamVerifier != nil {
		usrToken := r.Header.Get("Authorization")
		if authorized, err := h.iamVerifier.IsAuthorized(allowedRead, usrToken); !authorized {
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

// handleGet handles GET requests for a single scope
// concrete impl for the GET part of HandleScope method
func (h *handler) handleGet(w http.ResponseWriter, r *http.Request) {

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
	if authorized, err := h.s2sVerifier.IsAuthorized(userAllowedRead, svcToken); !authorized {
		h.logger.Error(fmt.Sprintf("/scope/{scope} handler failed to validate s2s token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	usrToken := r.Header.Get("Authorization")
	if authorized, err := h.iamVerifier.IsAuthorized(userAllowedRead, usrToken); !authorized {
		h.logger.Error(fmt.Sprintf("/scope/{scope} handler failed to validate user token: %v", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

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

func (h *handler) HandleServiceError(w http.ResponseWriter, err error) {

	switch {
	case strings.Contains(err.Error(), ErrInvalidSlug):
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    ErrInvalidSlug,
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
