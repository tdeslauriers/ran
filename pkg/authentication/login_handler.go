package authentication

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"ran/internal/util"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session"
)

const loginFailedMsg string = "login failed due to server error."

type LoginHandler interface {
	HandleS2sLogin(w http.ResponseWriter, r *http.Request)
}

func NewS2sLoginHandler(service session.S2sAuthService) LoginHandler {
	return &s2sLoginHandler{
		authService: service,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ LoginHandler = (*s2sLoginHandler)(nil)

type s2sLoginHandler struct {
	authService session.S2sAuthService

	logger *slog.Logger
}

func (h *s2sLoginHandler) HandleS2sLogin(w http.ResponseWriter, r *http.Request) {

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
		h.logger.Error("unable to decode json s2s login payload: %v", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "Unable to decode json s2s login payload.",
		}
		e.SendJsonErr(w)
		return
	}

	// input validation
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("unable to validate login cmd format: %v", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate creds
	if err := h.authService.ValidateCredentials(cmd.ClientId, cmd.ClientSecret); err != nil {
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    fmt.Sprintf("invalid client credentials: %s", err),
		}
		e.SendJsonErr(w)
		return
	}

	// create token
	token, err := h.authService.MintAuthzToken(cmd.ClientId, cmd.ServiceName)
	if err != nil {
		h.logger.Error("unable to mint s2s token: %v", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    loginFailedMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// create refresh
	refreshToken, err := uuid.NewRandom()
	if err != nil {
		h.logger.Error("failed to create refresh token: %v", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    loginFailedMsg,
		}
		e.SendJsonErr(w)
		return
	}
	refresh := session.S2sRefresh{
		// primary key uuid created by PersistRefresh
		// index created by PersistRefresh
		ServiceName:  cmd.ServiceName,
		RefreshToken: refreshToken.String(),
		ClientId:     cmd.ClientId,
		CreatedAt:    data.CustomTime{Time: time.Unix(token.Claims.IssuedAt, 0)},
		Revoked:      false,
	}

	// don't wait to return jwt
	go func(r session.S2sRefresh) {
		err := h.authService.PersistRefresh(r) // encrypts refresh token
		if err != nil {
			// only logging since refresh is a convenience
			h.logger.Error("error persisting s2s refresh token: %v", "err", err.Error())
		}
	}(refresh)

	// respond with authorization data
	authz := session.S2sAuthorization{
		Jti:            token.Claims.Jti,
		ServiceName:    cmd.ServiceName,
		ServiceToken:   token.Token,
		TokenExpires:   data.CustomTime{Time: time.Unix(token.Claims.Expires, 0)},
		RefreshToken:   refresh.RefreshToken,
		RefreshExpires: data.CustomTime{Time: time.Unix(token.Claims.IssuedAt, 0).Add(RefreshDuration * time.Minute)},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(authz); err != nil {
		h.logger.Error("unable to marshal/send s2s login response body: %v", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "unable to send s2s login response body due to interal service error",
		}
		e.SendJsonErr(w)
		return
	}
}
