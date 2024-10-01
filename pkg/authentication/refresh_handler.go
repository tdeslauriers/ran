package authentication

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"ran/internal/util"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

type S2sRefreshHandler interface {
	HandleS2sRefresh(w http.ResponseWriter, r *http.Request)
}

func NewS2sRefreshHandler(service types.S2sAuthService) S2sRefreshHandler {
	return &s2sRefreshHandler{
		authService: service,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentRefresh)),
	}
}

var _ S2sRefreshHandler = (*s2sRefreshHandler)(nil)

type s2sRefreshHandler struct {
	authService types.S2sAuthService

	logger *slog.Logger
}

func (h *s2sRefreshHandler) HandleS2sRefresh(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST http method allowed",
		}
		e.SendJsonErr(w)
		return
	}
	var cmd types.S2sRefreshCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		h.logger.Error("failed to decode s2s refresh cmd request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "s2s refresh request improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request formatting
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error("failed to validate refresh token format", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// lookup refresh token
	refresh, err := h.authService.GetRefreshToken(cmd.RefreshToken)
	if err != nil {
		h.logger.Error("failed to get refresh token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "invalid refresh token",
		}
		e.SendJsonErr(w)
		return
	}

	// check if refresh is for service requested
	// this check secondary, but may indicate malicous request
	if refresh != nil && refresh.ServiceName != cmd.ServiceName {
		h.logger.Error(fmt.Sprintf("refresh id %s - refresh token requested for incorrect service: requested: %s, refresh token: %s", refresh.Uuid, cmd.ServiceName, refresh.ServiceName))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "incorrect service name provided",
		}
		e.SendJsonErr(w)
		return
	}

	if refresh != nil {
		// mint new token/s2s access token
		// get scopes
		scopes, err := h.authService.GetScopes(refresh.ClientId, refresh.ServiceName)
		if len(scopes) < 1 {
			h.logger.Error(fmt.Sprintf("client id %s has no scopes for this %s", refresh.ClientId, cmd.ServiceName))
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnauthorized,
				Message:    "client has no scopes for this service",
			}
			e.SendJsonErr(w)
		}
		if err != nil {
			h.logger.Error(fmt.Sprintf("failed to get scopes for client id %s", refresh.ClientId), "err", err.Error())
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
			h.logger.Error("unable to create jwt jti uuid", "err", err.Error())
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
			Subject:   refresh.ClientId,
			Audience:  types.BuildAudiences(scopesBuilder.String()),
			IssuedAt:  currentTime.Unix(),
			NotBefore: currentTime.Unix(),
			Expires:   currentTime.Add(TokenDuration * time.Minute).Unix(),
			Scopes:    scopesBuilder.String(),
		}

		// mint new token
		token, err := h.authService.MintToken(claims)
		if err != nil {
			h.logger.Error(fmt.Sprintf("failed to mint new jwt for client id %s", refresh.ClientId), "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "failed to mint new s2s token from refresh token",
			}
			e.SendJsonErr(w)
			return
		}

		// oppotunistically delete claimed refresh token
		go func(id string) {
			if err := h.authService.DestroyRefresh(id); err != nil {
				h.logger.Error(fmt.Sprintf("failed to delete claimed refresh token record uuid %s", id), "err", err.Error())
				return
			}
			h.logger.Info(fmt.Sprintf("deleted claimed refresh token record uuid %s", id))
		}(refresh.Uuid)

		// respond with authorization data
		authz := &provider.S2sAuthorization{
			Jti:            token.Claims.Jti,
			ServiceName:    cmd.ServiceName,
			ServiceToken:   token.Token,
			TokenExpires:   data.CustomTime{Time: time.Unix(token.Claims.Expires, 0)},
			RefreshToken:   refresh.RefreshToken,
			RefreshExpires: data.CustomTime{Time: refresh.CreatedAt.Add(RefreshDuration * time.Minute)}, //  same expiry
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(authz); err != nil {
			h.logger.Error("failed to marshal/send s2s refresh response body", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "failed to send s2s refresh response body due to interal service error",
			}
			e.SendJsonErr(w)
			return
		}
	}
}
