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
	exo "github.com/tdeslauriers/carapace/pkg/pat"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/ran/internal/definitions"
)

// Service is an interface for personal access token services
type Service interface {

	// GeneratePat generates a new personal access token (PAT) for a given client slug
	GeneratePat(slug string) (*Pat, error)

	// IntrospectPat validates and introspects a given personal access token (PAT), and will
	// return the associated pat scopes if it it is valid, active, not revoked, and not expired.
	// Will return an error if the token is invalid, inactive, revoked, or expired.
	IntrospectPat(token string) (*exo.IntrospectResponse, error)
}

// NewService creates a new personal access token (PAT) service interface abstracting a concrete implementation
func NewService(sql *sql.DB, p exo.PatTokener) Service {
	return &service{
		sql: NewPatRepository(sql),
		pat: p,

		logger: slog.Default().
			With(slog.String(definitions.ServiceKey, definitions.ServiceKey)).
			With(slog.String(definitions.PackageKey, definitions.PackagePAT)).
			With(slog.String(definitions.ComponentKey, definitions.ComponentPatService)),
	}
}

var _ Service = (*service)(nil)

// service is a concrete implementation of the Service interface
type service struct {
	sql PatRepository
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
	client, err := s.sql.FindClientBySlug(slug)
	if err != nil {
		return nil, err
	}

	// check that the client is enabled, not locked, and not expired
	if !client.Enabled {
		return nil, fmt.Errorf("client (slug '%s') is disabled", slug)
	}

	if client.AccountLocked {
		return nil, fmt.Errorf("client (slug '%s') is locked", slug)
	}

	if client.AccountExpired {
		return nil, fmt.Errorf("client (slug '%s') account has expired", slug)
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
	if err != nil {
		return nil, fmt.Errorf("failed to obtain pat index from raw token: %v", err)
	}

	// persist the pat record
	record := PatRecord{
		Id:        patId.String(),
		PatIndex:  index,
		CreatedAt: data.CustomTime{Time: time.Now().UTC()},
		Active:    true,
		Revoked:   false,
		Expired:   false,
	}

	// insert the pat record into the database
	if err := s.sql.InsertPat(record); err != nil {
		return nil, fmt.Errorf("failed to persist pat record into database: %v", err)
	}

	// build xref record
	xref := PatClientXref{
		Id:        0, // autoincrement
		PatID:     patId.String(),
		ClientID:  client.Id,
		CreatedAt: data.CustomTime{Time: time.Now().UTC()},
	}

	// persist the xref record
	if err := s.sql.InsertPatClientXref(xref); err != nil {
		return nil, fmt.Errorf("failed to persist pat-client xref record: %v", err)
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

// IntrospectPat validates and introspects a given personal access token (PAT), and will
// return the associated pat scopes if it it is valid, active, not revoked, and not expired.
// Will return an error if the token is invalid, inactive, revoked, or expired.
func (s *service) IntrospectPat(token string) (*exo.IntrospectResponse, error) {

	// validate the token format
	// redundant validation, but good practice
	if len(token) < 64 || len(token) > 128 {
		return nil, fmt.Errorf("invalid pat token format.  Token length must be between 64 and 128 characters")
	}

	// decode token from base64 url encoding
	raw, err := base64.StdEncoding.DecodeString(token)
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
	scopes, err := s.sql.FindPatScopes(index)
	if err != nil {
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
	return &exo.IntrospectResponse{
		Active:      true,
		Scope:       sb.String(),
		Sub:         scopes[0].ClientId,
		ServiceName: scopes[0].ServiceName,
		Iss:         definitions.SericeName,
	}, nil
}

// buildPatFailResponse is a helper method to build the appropriate pat.IntrospectResponse
// and error message if the pat token introspection fails due to the pat being inactive,
// revoked, expired, or if the associated client is disabled, locked, or expired.
func (s *service) buildPatFailResponse(patIndex string) (*exo.IntrospectResponse, error) {

	// check if pat exists, or is not active, revoked, or expired
	// get pat record from db
	pat, err := s.sql.FindPatByIndex(patIndex)
	if err != nil {
		return &exo.IntrospectResponse{
			Active: false,
		}, err
	}

	// check if pat is inactive
	if !pat.Active {
		return &exo.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("pat token is inactive")
	}

	// check if pat is revoked
	if pat.Revoked {
		return &exo.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("pat token has been revoked")
	}

	// check if pat is expired
	if pat.Expired {
		return &exo.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("pat token has expired")
	}

	// Client status checks
	// get client from database if exists
	clientStatus, err := s.sql.FindClientByPat(patIndex)
	if err != nil {
		return &exo.IntrospectResponse{
			Active: false,
		}, err
	}

	// check if the client is disabled, locked, or expired
	// check if client is enabled
	if !clientStatus.Enabled {
		return &exo.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("client associated with this pat token is disabled")
	}

	// check if the client is locked

	if clientStatus.AccountLocked {
		return &exo.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("client associated with this pat token is locked")
	}

	// check if the client is expired
	if clientStatus.AccountExpired {
		return &exo.IntrospectResponse{
			Active: false,
		}, fmt.Errorf("client associated with this pat token has expired")
	}

	// if none of the above conditions removed and error, then it is likely
	// no scopes are associated with this pat token and client
	return &exo.IntrospectResponse{
		Active: false,
	}, fmt.Errorf("no active scopes found for this pat token")
}
