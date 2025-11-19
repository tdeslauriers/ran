package authentication

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"github.com/tdeslauriers/ran/internal/util"
)

const loginFailedMsg string = "login failed due to server error."

type LoginHandler interface {
	HandleS2sLogin(w http.ResponseWriter, r *http.Request)
}

func NewS2sLoginHandler(service types.S2sAuthService) LoginHandler {
	return &s2sLoginHandler{
		authService: service,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ LoginHandler = (*s2sLoginHandler)(nil)

type s2sLoginHandler struct {
	authService types.S2sAuthService

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

	var cmd types.S2sLoginCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode s2s login payload: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "Failed to decode json s2s login payload.",
		}
		e.SendJsonErr(w)
		return
	}

	// // input validation
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("failed to validate login cmd format: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
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

	// get scopes
	scopes, err := h.authService.GetScopes(cmd.ClientId, cmd.ServiceName)
	if len(scopes) < 1 {
		h.logger.Error(fmt.Sprintf("client id %s has no scopes for this service: %s", cmd.ClientId, cmd.ServiceName))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    fmt.Sprintf("client has no scopes for this service: %s", cmd.ServiceName),
		}
		e.SendJsonErr(w)
	}
	if err != nil {
		h.logger.Error(fmt.Sprintf("unable to get scope for client id %s: %v", cmd.ClientId, err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    loginFailedMsg,
		}
		e.SendJsonErr(w)
	}

	// create scopes string: scope values, space delimited
	var scopesBuilder strings.Builder
	for i, v := range scopes {
		scopesBuilder.WriteString(v.Scope)
		if len(scopes) > 1 && i+1 < len(scopes) {
			scopesBuilder.WriteString(" ")
		}
	}

	// set up jwt claims fields
	jti, err := uuid.NewRandom()
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to create jti for s2s token: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to mint s2s token",
		}
		e.SendJsonErr(w)
		return
	}

	currentTime := time.Now().UTC()

	claims := jwt.Claims{
		Jti:       jti.String(),
		Issuer:    util.SericeName,
		Subject:   cmd.ClientId,
		Audience:  types.BuildAudiences(scopesBuilder.String()),
		IssuedAt:  currentTime.Unix(),
		NotBefore: currentTime.Unix(),
		Expires:   currentTime.Add(TokenDuration * time.Minute).Unix(),
		Scopes:    scopesBuilder.String(),
	}

	// create token
	token, err := h.authService.MintToken(claims)
	if err != nil {
		h.logger.Error(fmt.Sprintf("%s: %v", loginFailedMsg, err.Error()))
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
		h.logger.Error(fmt.Sprintf("failed to create s2s refresh token: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    loginFailedMsg,
		}
		e.SendJsonErr(w)
		return
	}
	refresh := types.S2sRefresh{
		// primary key uuid created by PersistRefresh
		// index created by PersistRefresh
		ServiceName:  cmd.ServiceName,
		RefreshToken: refreshToken.String(),
		ClientId:     cmd.ClientId,
		CreatedAt:    data.CustomTime{Time: time.Unix(token.Claims.IssuedAt, 0)},
		Revoked:      false,
	}

	// don't wait to return jwt
	go func(r types.S2sRefresh) {
		err := h.authService.PersistRefresh(r) // encrypts refresh token
		if err != nil {
			// only logging since refresh is a convenience
			h.logger.Error(fmt.Sprintf("failed to persist s2s refresh token for client id %s: %v", cmd.ClientId, err.Error()))
		}
	}(refresh)

	// respond with authorization data
	authz := provider.S2sAuthorization{
		Jti:            token.Claims.Jti,
		ServiceName:    cmd.ServiceName,
		ServiceToken:   token.Token,
		TokenExpires:   data.CustomTime{Time: time.Unix(token.Claims.Expires, 0).UTC()},
		RefreshToken:   refresh.RefreshToken,
		RefreshExpires: data.CustomTime{Time: time.Unix(token.Claims.IssuedAt, 0).UTC().Add(RefreshDuration * time.Minute)},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(authz); err != nil {
		h.logger.Error(fmt.Sprintf("failed to marshal/send s2s login response body: %v", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to send s2s login response body due to interal service error",
		}
		e.SendJsonErr(w)
		return
	}
}
