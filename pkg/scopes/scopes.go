package scopes

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"ran/internal/util"
	"strings"

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
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// validate service token
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.verifier.IsAuthorized(allowed, svcToken); !authorized {
		if strings.Contains(err.Error(), "unauthorized") {
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnauthorized,
				Message:    err.Error(),
			}
			e.SendJsonErr(w)
			return
		} else {
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("unable to validate/build service token: %v", err),
			}
			e.SendJsonErr(w)
			return
		}
	}

	scopes, err := h.scopes.GetActiveScopes()
	if err != nil {
		h.logger.Error(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	scopesJson, err := json.Marshal(scopes)
	if err != nil {
		h.logger.Error(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(scopesJson)

}
