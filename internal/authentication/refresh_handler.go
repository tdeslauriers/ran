package authentication

import (
	"context"
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
	"github.com/tdeslauriers/ran/internal/definitions"
)

// S2sRefreshHandler provides methods for handling s2s token refresh operations
type S2sRefreshHandler interface {

	// HandleS2sRefresh handles a request to refresh a s2s jwt token using a refresh token
	HandleS2sRefresh(w http.ResponseWriter, r *http.Request)
}

// NewS2sRefreshHandler creates a new s2s token refresh handler interface returning
// a pointer to a concrete implementation
func NewS2sRefreshHandler(service S2sAuthService) S2sRefreshHandler {

	return &s2sRefreshHandler{
		authService: service,

		logger: slog.Default().
			With(slog.String(definitions.PackageKey, definitions.PackageAuthentication)).
			With(slog.String(definitions.ComponentKey, definitions.ComponentRefresh)),
	}
}

var _ S2sRefreshHandler = (*s2sRefreshHandler)(nil)

// s2sRefreshHandler is a concrete implementation of the S2sRefreshHandler interface
type s2sRefreshHandler struct {
	authService S2sAuthService

	logger *slog.Logger
}

// HandleS2sRefresh is the concrete implementation of the interface method which
// handles a request to refresh a s2s token using a refresh token
func (h *s2sRefreshHandler) HandleS2sRefresh(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	if r.Method != "POST" {
		log.Error("invalid method for s2s refresh endpoint", "err", "only POST method is allowed")
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
		log.Error("failed to decode s2s refresh cmd request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "s2s refresh request improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request formatting
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate refresh token format", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// lookup refresh token
	refresh, err := h.authService.GetRefreshToken(ctx, cmd.RefreshToken)
	if err != nil {
		log.Error("failed to lookup s2s refresh token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// check if refresh is for service requested
	// this check secondary, but may indicate malicous request
	if refresh != nil && refresh.ServiceName != cmd.ServiceName {
		log.Error(fmt.Sprintf("refresh id %s: refresh token requested for incorrect service", refresh.Uuid),
			slog.String("err", fmt.Sprintf("requested %s, wanted %s", cmd.ServiceName, refresh.ServiceName)))
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
			log.Error(fmt.Sprintf("client id %s has no %s scopes assigned to it", refresh.ClientId, cmd.ServiceName))
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnauthorized,
				Message:    fmt.Sprintf("client id %s has no %s scopes assigned to it", refresh.ClientId, cmd.ServiceName),
			}
			e.SendJsonErr(w)
		}
		if err != nil {
			log.Error(fmt.Sprintf("failed to get scopes for client id %s", refresh.ClientId), "err", err.Error())
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
			log.Error("unable to create jwt jti uuid", "err", err.Error())
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
			Issuer:    definitions.SericeName,
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
			log.Error(fmt.Sprintf("failed to mint refreshed jwt for client id %s", refresh.ClientId), "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "failed to mint new s2s token from refresh token",
			}
			e.SendJsonErr(w)
			return
		}

		// oppotunistically delete claimed refresh token
		go func(token string) {
			if err := h.authService.DestroyRefresh(token); err != nil {
				log.Error(fmt.Sprintf("failed to delete claimed refresh token record uuid %s", refresh.Uuid), "err", err.Error())
				return
			}

			log.Info(fmt.Sprintf("deleted claimed refresh token record uuid %s", refresh.Uuid))
		}(refresh.RefreshToken)

		// create a new refresh token to return with new access token to
		// replace the one just claimed by the requesting service.
		replace, err := uuid.NewRandom()
		if err != nil {
			// log only, refresh token is a convenience
			log.Error("unable to create refresh token uuid", "err", err.Error())

		}

		// build and persist new refresh, but do not wait to return response
		go func(r string) {
			if r != "" {
				if err := h.authService.PersistRefresh(types.S2sRefresh{
					// primary key uuid created by PersistRefresh
					// index created by PersistRefresh
					ServiceName:  cmd.ServiceName,
					RefreshToken: r,
					ClientId:     refresh.ClientId, // from the claimed refresh model object
					CreatedAt: data.CustomTime{
						Time: time.Unix(token.Claims.IssuedAt, 0),
					}, // need to preserve the original issued at time for expiry calculations
					Revoked: false,
				}); err != nil {
					// only logging err since refresh is a convenience
					log.Error(fmt.Sprintf("failed to persist replacement s2s refresh token for client id %s", refresh.ClientId), "err", err.Error())
				}
			}
		}(replace.String())

		// respond with authorization data
		authz := &provider.S2sAuthorization{
			Jti:          token.Claims.Jti,
			ServiceName:  cmd.ServiceName,
			ServiceToken: token.Token,
			TokenExpires: data.CustomTime{
				Time: time.Unix(token.Claims.Expires, 0),
			},
			RefreshToken: replace.String(), // if "", will error downstream which is fine because convenience only
			RefreshExpires: data.CustomTime{
				Time: refresh.CreatedAt.Add(RefreshDuration * time.Minute),
			}, //  same expiry
		}

		log.Info(fmt.Sprintf("successfully refreshed and minted new s2s token for client id %s", refresh.ClientId))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(authz); err != nil {
			log.Error("failed to json encode s2s refresh response body", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "failed to json encode s2s refresh response body",
			}
			e.SendJsonErr(w)
			return
		}
	}
}
