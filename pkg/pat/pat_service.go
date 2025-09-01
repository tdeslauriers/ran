package pat

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/pat"
	exo "github.com/tdeslauriers/carapace/pkg/pat"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/ran/internal/util"
	"github.com/tdeslauriers/ran/pkg/clients"
)

// Service is an interface for personal access token services
type Service interface {

	// GeneratePat generates a new personal access token (PAT) for a given client slug
	GeneratePat(slug string) (*Pat, error)

	// IntrospectPat validates and introspects a given personal access token (PAT), and will
	// return the associated pat scopes if it it is valid, active, not revoked, and not expired.
	// Will return an error if the token is invalid, inactive, revoked, or expired.
	IntrospectPat(token string) (*pat.IntrospectResponse, error)
}

// NewService creates a new personal access token (PAT) service interface abstracting a concrete implementation
func NewService(sql data.SqlRepository, p exo.PatTokener) Service {
	return &service{
		sql: sql,
		pat: p,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceKey)).
			With(slog.String(util.PackageKey, util.PackagePAT)).
			With(slog.String(util.ComponentKey, util.ComponentPatService)),
	}
}

var _ Service = (*service)(nil)

// service is a concrete implementation of the Service interface
type service struct {
	sql data.SqlRepository
	pat exo.PatTokener

	logger *slog.Logger
}

// GeneratePat is the concrete implentation of the Service interface method which
// generates a new personal access token (PAT) for a given client slug
func (s *service) GeneratePat(slug string) (*Pat, error) {

	// validate the slug is a valid uuid
	// redundant validation, but good practice
	if !validate.IsValidUuid(slug) {
		return nil, fmt.Errorf("invalid client slug format")
	}

	// lookup the client uuid for xref record creation
	qry := `
		SELECT
			uuid,
			name,
			owner,
			created_at,
			enabled,
			account_expired,
			account_locked,
			slug
		FROM client WHERE slug = ?
			AND enabled = true
			AND account_expired = false
			AND account_locked = false`
	var client clients.Client
	if err := s.sql.SelectRecord(qry, &client, slug); err != nil {
		if err == sql.ErrNoRows {
			return nil, s.handleClientLookupErr(slug)
		} else {
			return nil, fmt.Errorf("failed to retrieve client record for slug %s: %v", slug, err)
		}
	}

	// generate a new pat uuid
	patId, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate pat uuid: %v", err)
	}

	// generate a new pat token (64 byte random byte slice -> base64 url encoded)
	raw, token, err := s.pat.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate pat token: %v", err)
	}

	// create lookup index from the raw token to persist in the db
	index, err := s.pat.ObtainIndex(raw)

	// persist the pat record
	record := PatRecord{
		Id:        patId.String(),
		PatIndex:  index,
		CreatedAt: data.CustomTime{Time: time.Now().UTC()},
		Active:    true,
		Revoked:   false,
		Expired:   false,
	}
	qry = `
		INSERT INTO pat (
			uuid,
			pat_index,
			created_at,
			active,
			revoked,
			expired
		) VALUES (?, ?, ?, ?, ?, ?)`
	if err := s.sql.InsertRecord(qry, record); err != nil {
		return nil, fmt.Errorf("failed to persist pat record: %v", err)
	}

	// persist the xref record
	xref := PatClientXref{
		Id:        0, // autoincrement
		PatID:     patId.String(),
		ClientID:  client.Id,
		CreatedAt: data.CustomTime{Time: time.Now().UTC()},
	}
	qry = `
		INSERT INTO pat_client (
			id,
			pat_uuid,
			client_uuid,
			created_at
		) VALUES (?, ?, ?, ?)`
	if err := s.sql.InsertRecord(qry, xref); err != nil {
		return nil, fmt.Errorf("failed to persist pat client xref record: %v", err)
	}

	// return the pat model (with token)
	return &Pat{
		Client:    client.Name,
		Token:     token,
		CreatedAt: record.CreatedAt.Format(time.RFC3339),
		Active:    record.Active,
		Revoked:   record.Revoked,
		Expired:   record.Expired,
	}, nil
}

// handleClientLookupErr is a helper method to determine why a client lookup failed by conducting a series of
// 'exists queries' to determine if the client does not exist, is disabled, locked, or expired
func (s *service) handleClientLookupErr(clientSlug string) error {

	// check if client exists at all
	found, err := s.sql.SelectExists(clientNotFoundQry, clientSlug)
	if err != nil {
		return fmt.Errorf("failed to retrieve client record for slug %s: %v", clientSlug, err)
	}
	if !found {
		return fmt.Errorf("client (slug '%s') not found", clientSlug)
	}

	// check if client exists but disabled
	disabled, err := s.sql.SelectExists(clientDisabledQry, clientSlug)
	if err != nil {
		return fmt.Errorf("failed to retrieve client record for slug %s: %v", clientSlug, err)
	}
	if disabled {
		return fmt.Errorf("client (slug '%s') is disabled", clientSlug)
	}

	// check if client exists but locked
	locked, err := s.sql.SelectExists(clientAccountLockedQry, clientSlug)
	if err != nil {
		return fmt.Errorf("failed to retrieve client record for slug %s: %v", clientSlug, err)
	}
	if locked {
		return fmt.Errorf("client (slug '%s') is locked", clientSlug)
	}

	// check if client exists but expired
	expired, err := s.sql.SelectExists(clientAccountExpiredQry, clientSlug)
	if err != nil {
		return fmt.Errorf("failed to retrieve client record for slug %s: %v", clientSlug, err)
	}
	if expired {
		return fmt.Errorf("client (slug '%s') account has expired", clientSlug)
	}

	return fmt.Errorf("client (slug '%s') not found for unxepected/unhandled reason", clientSlug)
}

// IntrospectPat validates and introspects a given personal access token (PAT), and will
// return the associated pat scopes if it it is valid, active, not revoked, and not expired.
// Will return an error if the token is invalid, inactive, revoked, or expired.
func (s *service) IntrospectPat(token string) (*pat.IntrospectResponse, error) {

	// validate the token format
	// redundant validation, but good practice
	if len(token) < 64 || len(token) > 128 {
		return nil, fmt.Errorf("invalid pat token format.  Token length must be between 64 and 128 characters")
	}

	// decode token from base64 url encoding
	raw, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode pat token from base64 url encoding: %v", err)
	}

	// obtain the lookup index from the raw token
	// Note: the index is derived from a hash of the raw token -> same as on generation
	index, err := s.pat.ObtainIndex(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain lookup index from pat token: %v", err)
	}

	// lookup the service and scopes from via via xref against the pat index
	// Note: in this exact impl, the index look up serves as the hash comparison
	// to validate the token, since the index is derived from a hash of the raw token
	qry := `
		SELECT
			s.uuid AS scope_uuid,
			s.service_name,
			s.scope,
			s.name AS scope_name,
			s.description AS scope_description,
			s.created_at AS scope_created_at,
			s.active AS scope_active,
			s.slug AS scope_slug,
			c.uuid AS client_uuid,
		FROM scope s
			LEFT OUTER JOIN scope_client sc ON s.uuid = sc.scope_uuid
			LEFT OUTER JOIN client c ON sc.client_uuid = c.uuid
			LEFT OUTER JOIN pat_client pc ON c.uuid = pc.client_uuid
			LEFT OUTER JOIN pat p ON pc.pat_uuid = p.uuid
		WHERE p.pat_index = ?
			AND s.active = TRUE
			AND c.enabled = TRUE
			AND c.account_expired = FALSE
			AND c.account_locked = FALSE
			AND p.active = TRUE
			AND p.revoked = FALSE
			AND p.expired = FALSE`
	var scopes []ScopePatRecord
	if err := s.sql.SelectRecords(qry, &scopes, index); err != nil {
		return nil, fmt.Errorf("failed to retrieve scopes for pat token from database: %v", err)
	}

	// validate the scopes slice is not empty,
	// or, if it is, deterine why and return the appropriate error
	if len(scopes) < 1 {
		return s.buildPatFailResponse(index)
	}

	// build the scope strings slice
	var sb strings.Builder
	for i, v := range scopes {
		sb.WriteString(v.Scope)
		if len(scopes) > 1 && i+1 < len(scopes) {
			sb.WriteString(" ")
		}
	}

	// return the introspect response with the scopes
	return &pat.IntrospectResponse{
		Active:      true,
		Scope:       sb.String(),
		Sub:         scopes[0].ClientId,
		ServiceName: scopes[0].ServiceName,
		Iss:         util.SericeName,
	}, nil
}

// buildPatFailResponse is a helper method to build the appropriate pat.IntrospectResponse
// and error message if the pat token introspection fails due to the pat being inactive,
// revoked, expired, or if the associated client is disabled, locked, or expired.
func (s *service) buildPatFailResponse(patIndex string) (*pat.IntrospectResponse, error) {

	// Client status checks
	// check if the client is disabled, locked, or expired
	disabled, err := s.sql.SelectExists(clientDisabledQry, patIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve client record for pat token: %v", err)
	}
	if disabled {
		return &pat.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("client associated with this pat token is disabled")
	}

	// check if the client is locked
	locked, err := s.sql.SelectExists(clientAccountLockedQry, patIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve client record for pat token: %v", err)
	}
	if locked {
		return &pat.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("client associated with this pat token is locked")
	}

	// check if the client is expired
	clientExpired, err := s.sql.SelectExists(clientAccountExpiredQry, patIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve client record for pat token: %v", err)
	}
	if clientExpired {
		return &pat.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("client associated with this pat token has expired")
	}

	// check if pat exists but inactive
	inactive, err := s.sql.SelectExists(patInactiveQry, patIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve pat record for token: %v", err)
	}
	if inactive {
		return &pat.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("pat token is inactive")
	}

	// Pat status checks
	// check if pat exists but revoked
	revoked, err := s.sql.SelectExists(patRevokedQry, patIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve pat record for token: %v", err)
	}
	if revoked {
		return &pat.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("pat token has been revoked")
	}

	// check if pat exists but expired
	patExpired, err := s.sql.SelectExists(patExpiredQry, patIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve pat record for token: %v", err)
	}
	if patExpired {
		return &pat.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("pat token has expired")
	}

	// check if pat exists
	found, err := s.sql.SelectExists(patNotFoundQry, patIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve pat record for token: %v", err)
	}
	if !found {
		return &pat.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("pat token not found")
	}

	return &pat.IntrospectResponse{
		Active: false,
	}, fmt.Errorf("no active scopes found for this pat token")
}
