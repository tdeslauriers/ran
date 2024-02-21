package s2s

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/session"
)

// s2s login handler -> handles incoming login
type S2sLoginHandler struct {
	AuthService session.S2sAuthService
}

func NewS2sLoginHandler(service session.S2sAuthService) *S2sLoginHandler {
	return &S2sLoginHandler{
		AuthService: service,
	}
}

func (h *S2sLoginHandler) HandleS2sLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var cmd session.S2sLoginCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// input validation
	if err := cmd.ValidateCmd(); err != nil {
		http.Error(w, fmt.Sprintf("%s", err), http.StatusBadRequest)
		return
	}

	// validate creds
	if err := h.AuthService.ValidateCredentials(cmd.ClientId, cmd.ClientSecret); err != nil {
		http.Error(w, fmt.Sprintf("invalid client credentials: %s", err), http.StatusUnauthorized)
		return
	}

	// create token
	token, err := h.AuthService.MintAuthzToken(cmd.ClientId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// create refresh
	refreshId, err := uuid.NewRandom()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	refreshToken, err := uuid.NewRandom()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	refresh := session.S2sRefresh{
		Uuid:         refreshId.String(),
		RefreshToken: refreshToken.String(),
		ClientId:     cmd.ClientId,
		CreatedAt:    data.CustomTime{Time: time.Unix(token.Claims.IssuedAt, 0)},
		Revoked:      false,
	}

	// don't wait to return jwt
	go func(r session.S2sRefresh) {
		err := h.AuthService.PersistRefresh(r)
		if err != nil {
			// only logging since refresh is a convenience
			log.Print(err)
		}
	}(refresh)

	// respond with authorization data
	authz := session.S2sAuthorization{
		Jti:            token.Claims.Jti,
		ServiceToken:   token.Token,
		TokenExpires:   data.CustomTime{Time: time.Unix(token.Claims.Expires, 0)},
		RefreshToken:   refresh.RefreshToken,
		RefreshExpires: data.CustomTime{Time: time.Unix(token.Claims.IssuedAt, 0).Add(30 * time.Minute)},
	}
	authzJson, err := json.Marshal(authz)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(authzJson)
}
