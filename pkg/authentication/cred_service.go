package authentication

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"ran/internal/util"
)

const (
	tokenLength = 42
	charSet     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

type CredService interface {
	// GenerateAccessToken generates a new access token for the given service
	GenerateAccessToken() (string, error)

	// GenerateHashFromPassword generates a hash from the given password
	// Note: this is for machine credentials only and does not include a work product
	// like a hash for user passwords requires.
	GenerateHashFromPassword(password string) (string, error)

	// CompareHashAndPassword compares the given hash and password
	// Note: this is for machine credentials only and does not include a work product
	CompareHashAndPassword(hash, password string) error
}

func NewCredService(secret []byte) CredService {
	return &credService{
		secret: secret,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceS2s)).
			With(slog.String(util.ComponentKey, util.ComponentCreds)).
			With(slog.String(util.PackageKey, util.PackageAuthentication)),
	}
}

var _ CredService = (*credService)(nil)

// credService is a concrete implementation of the CredService interface
// uses a secret to generate a unique hmac sha256 hash for credential validation and lookups
type credService struct {
	secret []byte // used to generate a unique hmac sah256 hash for cred validation and lookups

	logger *slog.Logger
}

// GenerateAccessToken is the concrete impl of the interface method which
// generates a new access token. In this case, a 42 character(no specials) long key prefixed with "dws_"
func (c *credService) GenerateAccessToken() (string, error) {

	token := make([]byte, 42)
	for i := range token {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
		if err != nil {
			c.logger.Error(fmt.Sprintf("failed to generate random number: %v", err))
			return "", err
		}

		token[i] = charSet[num.Int64()]
	}

	return "dws_" + string(token), nil
}

// GenerateHashFromPassword generates a hash from the given password
func (c *credService) GenerateHashFromPassword(password string) (string, error) {
	hash, err := c.generateHashFromPassword(password)
	if err != nil {
		return "", fmt.Errorf("failed to generate hash from password: %v", err)
	}

	return hex.EncodeToString(hash), nil
}

// gererateHashFromPassword generates a hash from the given password
// Note: password could either be a service client password or a api token, like a pat token
func (c *credService) generateHashFromPassword(password string) ([]byte, error) {

	h := hmac.New(sha256.New, c.secret)
	if _, err := h.Write([]byte(password)); err != nil {
		return nil, fmt.Errorf("failed to hmac/hash text to blind index: %v", err)
	}

	return h.Sum(nil), nil
}

// Compare hash and credential/password
func (c *credService) CompareHashAndPassword(hash, password string) error {

	// decode the hex string of the hash to bytes
	h, err := hex.DecodeString(hash)
	if err != nil {
		return fmt.Errorf("failed to decode hex string of hash to bytes: %v", err)
	}

	// generate the hash from the password
	pwHash, err := c.generateHashFromPassword(password)
	if err != nil {
		return fmt.Errorf("failed to generate hash from password: %v", err)
	}

	// compare the two hashes
	if !hmac.Equal(h, pwHash) {
		return fmt.Errorf("hash and password do not match")
	}

	return nil
}
