package clients

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"ran/internal/util"
	"ran/pkg/scopes"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// ScopesHanlder provides http handlers for service client requests to update assigned scopes
type ScopesHanlder interface {

	// HandleScopes handles a the request to update a clients assigned scopes
	HandleScopes(w http.ResponseWriter, r *http.Request)
}

// NewScopesHandler creates a new service client ScopesHanlder interface abstracting a concrete implementation
func NewScopesHandler(s Service, scope scopes.Service, s2s, iam jwt.Verifier) ScopesHanlder {
	return &scopesHandler{
		clientSvc:   s,
		scopesSvc:   scope,
		s2sVerifier: s2s,
		iamVerifier: iam,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceS2s)).
			With(slog.String(util.PackageKey, util.PackageClients)).
			With(slog.String(util.ComponentKey, util.ComponentClients)),
	}
}

var _ ScopesHanlder = (*scopesHandler)(nil)

// scopesHandler is a concrete implementation of the ScopesHanlder interface
type scopesHandler struct {
	clientSvc   Service
	scopesSvc   scopes.Service
	s2sVerifier jwt.Verifier
	iamVerifier jwt.Verifier

	logger *slog.Logger
}

// HandleScopes is a concrete impl of the ScopesHanlder interface method: handles a the request to update a clients assigned scopes
func (h *scopesHandler) HandleScopes(w http.ResponseWriter, r *http.Request) {

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
	if _, err := h.s2sVerifier.BuildAuthorized(userAllowedWrite, svcToken); err != nil {
		h.logger.Error("password reset handler failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam access token
	accessToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerifier.BuildAuthorized(userAllowedWrite, accessToken)
	if err != nil {
		h.logger.Error("password reset handler failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// decode request body
	var cmd ClientScopesCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		errMsg := fmt.Sprintf("failed to decode request body: %v", err)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// validate cmd
	if err := cmd.ValidateCmd(); err != nil {
		errMsg := fmt.Sprintf("invalid /client/scopes request: %v", err)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// lookup client
	client, err := h.clientSvc.GetClient(cmd.ClientSlug)
	if err != nil {
		errMsg := fmt.Sprintf("failed to retrieve client record: %v", err)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusNotFound,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// get scopes and lookup each slug
	// Note: chose to pull back all scopes and loop thru, rather than call the db for each slug
	allScopes, err := h.scopesSvc.GetScopes()
	if err != nil {
		errMsg := fmt.Sprintf("failed to retrieve scopes records: %v", err)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "interal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// scopes slice being empty indicates all scopes were removed, so still needs to be
	// submitted to the client service to remove them all.
	var updated []types.Scope
	if len(cmd.ScopeSlugs) > 0 {
		for _, slug := range cmd.ScopeSlugs {
			var exists bool
			for _, s := range allScopes {
				if s.Slug == slug {
					updated = append(updated, s)
					exists = true
					break
				}
			}
			// all slugs must be existing scope slugs or the request is invalid
			if !exists {
				errMsg := fmt.Sprintf("scope slug not found: %s", slug)
				h.logger.Error(errMsg)
				e := connect.ErrorHttp{
					StatusCode: http.StatusNotFound,
					Message:    errMsg,
				}
				e.SendJsonErr(w)
				return
			}
		}
	}

	// update client record
	// Note: empty scopes slice indicates all scopes were removed --> valid request --> update client record
	if err := h.clientSvc.UpdateScopes(client, updated); err != nil {
		errMsg := fmt.Sprintf("failed to update client %s's assigned scopes: %v", client.Name, err)
		h.logger.Error(errMsg)
		h.clientSvc.HandleServiceError(w, err)
		return
	}

	// log success
	h.logger.Info(fmt.Sprintf("service client %s's assigned scopes were updated successfully by %s", client.Name, authorized.Claims.Subject))

	// respond 204
	w.WriteHeader(http.StatusNoContent)
}
