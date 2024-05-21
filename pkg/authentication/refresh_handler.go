package authentication

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session"
)

type S2sRefreshHandler struct {
	AuthService session.S2sAuthService
}

func NewS2sRefreshHandler(service session.S2sAuthService) *S2sRefreshHandler {
	return &S2sRefreshHandler{
		AuthService: service,
	}
}

func (h *S2sRefreshHandler) HandleS2sRefresh(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only POST http method allowed",
		}
		e.SendJsonErr(w)
		return
	}
	var cmd session.RefreshCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		log.Printf("unable to decode s2s refresh cmd request body: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "s2s refresh request improperly formatted json",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request formatting
	if err := cmd.ValidateCmd(); err != nil {
		log.Printf("unable to validate refresh token formatt: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
	}

	// lookup refresh
	// receiver function decrypts refresh token
	refresh, err := h.AuthService.GetRefreshToken(cmd.RefreshToken)
	if err != nil {
		log.Printf("unable to get refresh token: %v", err)
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "invalid refresh token",
		}
		e.SendJsonErr(w)
	}

	// check refresh is for service requested
	// this check secondary, but may indicate malicous request
	if refresh != nil && refresh.ServiceName != cmd.ServiceName {
		log.Printf("refresh id %s - refresh token requested for incorrect service: requested: %s, refresh token: %s", refresh.Uuid, cmd.ServiceName, refresh.ServiceName)
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "incorrect service name provided",
		}
		e.SendJsonErr(w)
	}

	if refresh != nil {
		// mint new token/s2s access token
		token, err := h.AuthService.MintAuthzToken(refresh.ClientId, refresh.ServiceName)
		if err != nil {
			log.Printf("unable to mint new jwt for client id %s: %v", refresh.ClientId, err)
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "unable to mint new s2s token from refresh token",
			}
			e.SendJsonErr(w)
			return
		}

		// respond with authorization data
		authz := &session.S2sAuthorization{
			Jti:            token.Claims.Jti,
			ServiceName:    cmd.ServiceName,
			ServiceToken:   token.Token,
			TokenExpires:   data.CustomTime{Time: time.Unix(token.Claims.Expires, 0)},
			RefreshToken:   refresh.RefreshToken,
			RefreshExpires: data.CustomTime{Time: refresh.CreatedAt.Add(RefreshDuration * time.Minute)}, //  same expiry
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(authz); err != nil {
			log.Printf("unable to marshal/send s2s refresh response body: %v", err)
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "unable to send s2s refresh response body due to interal service error",
			}
			e.SendJsonErr(w)
			return
		}
	}
}
