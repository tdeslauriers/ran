package authentication

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"ran/internal/util"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
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
	var cmd types.RefreshCmd
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
		h.logger.Error("failed to validate refresh token formatt", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
	}

	// lookup refresh
	// receiver function decrypts refresh token
	refresh, err := h.authService.GetRefreshToken(cmd.RefreshToken)
	if err != nil {
		h.logger.Error("unable to get refresh token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "invalid refresh token",
		}
		e.SendJsonErr(w)
	}

	// check refresh is for service requested
	// this check secondary, but may indicate malicous request
	if refresh != nil && refresh.ServiceName != cmd.ServiceName {
		h.logger.Error(fmt.Sprintf("refresh id %s - refresh token requested for incorrect service: requested: %s, refresh token: %s", refresh.Uuid, cmd.ServiceName, refresh.ServiceName))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "incorrect service name provided",
		}
		e.SendJsonErr(w)
	}

	if refresh != nil {
		// mint new token/s2s access token
		token, err := h.authService.MintToken(refresh.ClientId, refresh.ServiceName)
		if err != nil {
			h.logger.Error(fmt.Sprintf("failed to mint new jwt for client id %s", refresh.ClientId), "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "failed to mint new s2s token from refresh token",
			}
			e.SendJsonErr(w)
			return
		}

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
