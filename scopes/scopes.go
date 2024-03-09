package scopes

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/jwt"
	"github.com/tdeslauriers/carapace/session"
)

// service scopes required
var allowed []string = []string{"r:ran:*"}

type ScopesService interface {
	GetActiveScopes() ([]session.Scope, error)
}

type AuthzScopesService struct {
	Dao data.SqlRepository
}

func NewAuthzScopesSerivce(sql data.SqlRepository) *AuthzScopesService {
	return &AuthzScopesService{
		Dao: sql,
	}
}

func (a *AuthzScopesService) GetActiveScopes() ([]session.Scope, error) {

	var scopes []session.Scope
	query := "SELECT uuid, scope, name, description, created_at, active FROM scope WHERE active = true"
	err := a.Dao.SelectRecords(query, &scopes)
	if err != nil {
		return nil, fmt.Errorf("unable to get scopes records from db: %v", err)
	}

	return scopes, nil
}

type ScopesHandler struct {
	Scopes   ScopesService
	Verifier jwt.JwtVerifier
}

func NewScopesHandler(scopes ScopesService, v jwt.JwtVerifier) *ScopesHandler {
	return &ScopesHandler{
		Scopes:   scopes,
		Verifier: v,
	}
}

func (h *ScopesHandler) GetActiveScopes(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// validate service token
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.Verifier.IsAuthorized(allowed, svcToken); !authorized {
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

	scopes, err := h.Scopes.GetActiveScopes()
	if err != nil {
		log.Print(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	scopesJson, err := json.Marshal(scopes)
	if err != nil {
		log.Print(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(scopesJson)

}
