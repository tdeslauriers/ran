package scopes

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	ValidScopeSlug = "c25f41ed-6721-42ff-9b84-87a647678862"
)

func TestGetScope(t *testing.T) {
	testCases := []struct {
		name string
		slug string
		err  error
	}{
		{
			name: "valid scope",
			slug: ValidScopeSlug,
			err:  nil,
		},
		{
			name: "invalid slug",
			slug: "invalid-slug",
			err:  errors.New(ErrInvalidSlug),
		},
		{
			name: "scope not found",
			slug: "9473a064-5cbb-48f2-92ba-ea896dd68aed", // random uuid
			err:  errors.New(ErrScopeNotFound),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSerivce(&mockSqlRepository{})
			_, err := s.GetScope(tc.slug)
			if err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
				t.Errorf("expected error: %v, got: %v", tc.err, err)
			}
		})
	}
}

func TestUpdateScope(t *testing.T) {
	testCases := []struct {
		name  string
		scope *Scope
		err   error
	}{
		{
			name: "valid scope",
			scope: &Scope{
				Uuid:        "5e614e33-6562-4cda-bc55-c7fec00762fe",
				ServiceName: "real-service",
				Scope:       "r:shaw:*",
				Name:        "shaw",
				Description: "shaw scope",
				CreatedAt:   time.Now().UTC().Format(time.RFC3339),
				Active:      true,
				Slug:        ValidScopeSlug,
			},
			err: nil,
		},
		{
			name:  "fail nil scope",
			scope: nil,
			err:   errors.New("scope is nil"),
		},
		{
			name: "invalid slug",
			scope: &Scope{
				Uuid:        "5e614e33-6562-4cda-bc55-c7fec00762fe",
				ServiceName: "real-service",
				Scope:       "r:shaw:*",
				Name:        "shaw",
				Description: "shaw scope",
				CreatedAt:   time.Now().UTC().Format(time.RFC3339),
				Active:      true,
				Slug:        "invalid-slug",
			},
			err: errors.New(ErrInvalidSlug),
		},

		{
			name: "fail invalid service name",
			scope: &Scope{
				Uuid:        "5e614e33-6562-4cda-bc55-c7fec00762fe",
				ServiceName: "SERVICE",
				Scope:       "r:shaw:*",
				Name:        "shaw",
				Description: "shaw scope",
				CreatedAt:   time.Now().UTC().Format(time.RFC3339),
				Active:      true,
				Slug:        ValidScopeSlug,
			},
			err: errors.New("invalid scope: invalid service name"),
		},
		{
			name: "fail invalid scope",
			scope: &Scope{
				Uuid:        "5e614e33-6562-4cda-bc55-c7fec00762fe",
				ServiceName: "real-service",
				Scope:       "r:sh",
				Name:        "shaw",
				Description: "shaw scope",
				CreatedAt:   time.Now().UTC().Format(time.RFC3339),
				Active:      true,
				Slug:        ValidScopeSlug,
			},
			err: errors.New("invalid scope: invalid scope"),
		},
		{
			name: "scope not found",
			scope: &Scope{
				Uuid:        "5e614e33-6562-4cda-bc55-c7fec00762fe",
				ServiceName: "real-service",
				Scope:       "r:shaw:*",
				Name:        "shaw",
				Description: "shaw scope",
				CreatedAt:   time.Now().UTC().Format(time.RFC3339),
				Active:      true,
				Slug:        "9473a064-5cbb-48f2-92ba-ea896dd68aed", // random uuid
			},
			err: errors.New(ErrScopeNotFound),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSerivce(&mockSqlRepository{})
			err := s.UpdateScope(tc.scope)

			if err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
				t.Errorf("expected error: %s, got: %s", tc.err, err)
			}
		})
	}
}

type mockSqlRepository struct {
}

func (m *mockSqlRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {
	return nil
}
func (m *mockSqlRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {
	switch r := record.(type) {
	case *Scope:
		if args[0] == ValidScopeSlug {
			r.Uuid = "5e614e33-6562-4cda-bc55-c7fec00762fe"
			r.ServiceName = "real-service"
			r.Scope = "r:shaw:*"
			r.Name = "shaw"
			r.Description = "shaw scope"
			r.CreatedAt = time.Now().UTC().Format(time.RFC3339)
			r.Active = true
			r.Slug = ValidScopeSlug
		}
	default:
		return sql.ErrNoRows
	}

	return nil
}
func (m *mockSqlRepository) SelectExists(query string, args ...interface{}) (bool, error) {
	return true, nil
}
func (m *mockSqlRepository) InsertRecord(query string, record interface{}) error {

	return nil
}
func (m *mockSqlRepository) UpdateRecord(query string, args ...interface{}) error {
	if args[5] == "9473a064-5cbb-48f2-92ba-ea896dd68aed" {
		return errors.New(ErrScopeNotFound)
	}
	return nil
}
func (m *mockSqlRepository) DeleteRecord(query string, args ...interface{}) error { return nil }
func (m *mockSqlRepository) Close() error                                         { return nil }
