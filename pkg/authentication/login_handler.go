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

// LoginHandler provides methods for handling s2s login operations
type LoginHandler interface {

	// HandleS2sLogin handles a request to login to a s2s service using client credentials
	HandleS2sLogin(w http.ResponseWriter, r *http.Request)
}

// NewS2sLoginHandler creates a new s2s login handler interface returning
// a pointer to a concrete implementation
func NewS2sLoginHandler(service S2sAuthService) LoginHandler {
	return &s2sLoginHandler{
		authService: service,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageAuthentication)).
			With(slog.String(util.ComponentKey, util.ComponentLogin)),
	}
}

var _ LoginHandler = (*s2sLoginHandler)(nil)

// s2sLoginHandler is a concrete implementation of the LoginHandler interface
type s2sLoginHandler struct {
	authService S2sAuthService

	logger *slog.Logger
}

// HandleS2sLogin is the concrete implementation of the interface method which
// handles a request to login to a s2s service using client credentials
func (h *s2sLoginHandler) HandleS2sLogin(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	if r.Method != "POST" {
		log.Error("invalid method", "err", "only POST method is allowed")
		err := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "Only POST method is allowed",
		}
		err.SendJsonErr(w)
		return
	}

	// decode request body into struct
	var cmd types.S2sLoginCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		log.Error("failed to json decode s2s login payload", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "Failed to json decode s2s login payload.",
		}
		e.SendJsonErr(w)
		return
	}

	// // input validation
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate login cmd", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate creds
	if err := h.authService.ValidateCredentials(cmd.ClientId, cmd.ClientSecret); err != nil {
		log.Error(fmt.Sprintf("failed to validate s2s login credentials for client id %s", cmd.ClientId), "err", err.Error())
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
		log.Error(fmt.Sprintf("client id %s has no scopes for this service: %s", cmd.ClientId, cmd.ServiceName))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    fmt.Sprintf("client id %s has no scopes for this service: %s", cmd.ClientId, cmd.ServiceName),
		}
		e.SendJsonErr(w)
	}
	if err != nil {
		log.Error(fmt.Sprintf("failed to get %s scopes for client id %s", cmd.ServiceName, cmd.ClientId), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
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
		log.Error("failed to create jti for s2s token", "err", err.Error())
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
		log.Error(fmt.Sprintf("%s: %v", loginFailedMsg, err.Error()))
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
		log.Error("failed to create s2s refresh token", "err", err.Error())
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
			log.Error(fmt.Sprintf("failed to persist s2s refresh token for client id %s", cmd.ClientId), "err", err.Error())
		}

		log.Info(fmt.Sprintf("persisted s2s refresh token for client id %s", cmd.ClientId))
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

	log.Info(fmt.Sprintf("s2s login successful for client id %s", cmd.ClientId))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(authz); err != nil {
		log.Error("failed to json s2s login response body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode s2s login response body",
		}
		e.SendJsonErr(w)
		return
	}
}
