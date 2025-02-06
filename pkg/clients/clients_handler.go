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
)

// service endpoints require s2s-only endpoint scopes
var s2sAllowedRead []string = []string{"r:ran:s2s:clients:*"}

// user endpoints require user endpoint scopes
// NOTE: user-only endpoint scopes will issued to services when they are acting on behalf of a user,
// but in those cases, their must be a user token present in the request ALSO.
var userAllowedRead = []string{"r:ran:clients:*"}
var userAllowedWrite = []string{"w:ran:clients:*"}

// Handler provides http handlers for client (model) requests
type Handler interface {

	// HandleClients returns all clients
	HandleClients(w http.ResponseWriter, r *http.Request)

	// HandleClient handles all requests for a single client: GET, POST, PUT, DELETE
	HandleClient(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new client handler
func NewHandler(s Service, s2s, iam jwt.Verifier) Handler {
	return &handler{
		service:     s,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceKey)).
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClients)),
	}
}

var _ Handler = (*handler)(nil)

type handler struct {
	service     Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleClients returns all clients
// concrete impl of the Handler interface method
func (h *handler) HandleClients(w http.ResponseWriter, r *http.Request) {

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
func (h *handler) HandleClient(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r)
		return
	// case http.MethodPost:
	// 	h.handlePost(w, r)
	// 	return
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
		h.logger.Error(fmt.Sprintf("/clients/{slug} handler failed to validate s2s token: %v", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate user access token
	usrToken := r.Header.Get("Authorization")
	if authorized, err := h.iamVerifier.IsAuthorized(userAllowedRead, usrToken); !authorized {
		h.logger.Error(fmt.Sprintf("/clients/{slug} handler failed to validate user token: %v", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	client, err := h.service.GetClient(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get client: %v", err.Error()))
		h.HandleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(client)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode service client to json: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode service client to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// HandleServiceError handles service errors
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
	case strings.Contains(err.Error(), ErrClientNotFound):
		e := connect.ErrorHttp{
			StatusCode: http.StatusNotFound,
			Message:    ErrClientNotFound,
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
