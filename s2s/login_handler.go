package s2s

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/session"
)

const loginFailedMsg string = "login failed due to server error."

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
		err := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "Only POST method is allowed",
		}
		err.SendJsonErr(w)
		return
	}

	var cmd session.S2sLoginCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		log.Printf("unable to decode json s2s login payload: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "Unable to decode json s2s login payload.",
		}
		e.SendJsonErr(w)
		return
	}

	// input validation
	if err := cmd.ValidateCmd(); err != nil {
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate creds
	if err := h.AuthService.ValidateCredentials(cmd.ClientId, cmd.ClientSecret); err != nil {
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    fmt.Sprintf("invalid client credentials: %s", err),
		}
		e.SendJsonErr(w)
		return
	}

	// create token
	token, err := h.AuthService.MintAuthzToken(cmd.ClientId)
	if err != nil {
		log.Printf("unable to mint s2s token: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    loginFailedMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// create refresh
	refreshId, err := uuid.NewRandom()
	if err != nil {
		log.Printf("failed to create refresh token id uuid: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    loginFailedMsg,
		}
		e.SendJsonErr(w)
		return
	}
	refreshToken, err := uuid.NewRandom()
	if err != nil {
		log.Printf("failed to create refresh token uuid: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    loginFailedMsg,
		}
		e.SendJsonErr(w)
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
			log.Printf("error persisting s2s refresh token: %v", err)
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
		log.Printf("unable to marshal s2s login response body: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    loginFailedMsg,
		}
		e.SendJsonErr(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(authzJson)
}
