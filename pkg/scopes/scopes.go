package scopes

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"ran/internal/util"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session"
)

// service scopes required
var allowed []string = []string{"r:ran:*"}

type ScopesService interface {
	GetActiveScopes() ([]session.Scope, error)
}

func NewScopesSerivce(sql data.SqlRepository) ScopesService {
	return &scopesService{
		sql: sql,
	}
}

var _ ScopesService = (*scopesService)(nil)

type scopesService struct {
	sql data.SqlRepository
}

func (a *scopesService) GetActiveScopes() ([]session.Scope, error) {

	var scopes []session.Scope
	query := `
			SELECT 
				uuid, 
				service_name, 
				scope, 
				name, 
				description, 
				created_at, 
				active 
			FROM scope 
			WHERE active = true`
	err := a.sql.SelectRecords(query, &scopes)
	if err != nil {
		return nil, fmt.Errorf("unable to get scopes records from db: %v", err)
	}

	return scopes, nil
}

type ScopesHandler interface {
	GetActiveScopes(w http.ResponseWriter, r *http.Request)
}

func NewScopesHandler(scopes ScopesService, v jwt.JwtVerifier) ScopesHandler {
	return &scopesHandler{
		scopes:   scopes,
		verifier: v,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentScopes)),
	}
}

var _ ScopesHandler = (*scopesHandler)(nil)

type scopesHandler struct {
	scopes   ScopesService
	verifier jwt.JwtVerifier

	logger *slog.Logger
}

func (h *scopesHandler) GetActiveScopes(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET http method allowed",
		}
		e.SendJsonErr(w)
		return
	}

	// validate service token
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.verifier.IsAuthorized(allowed, svcToken); !authorized {
		h.logger.Error("failed to validate s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
	}

	scopes, err := h.scopes.GetActiveScopes()
	if err != nil {
		h.logger.Error("failed to get active scopes", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error: unable to return scopes",
		}
		e.SendJsonErr(w)
		return
	}

	scopesJson, err := json.Marshal(scopes)
	if err != nil {
		h.logger.Error("failed to unmarshal scopes json payload", "err", err.Error())
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
