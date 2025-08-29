package authentication

import (
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// simulates dependency injection for testing
const secret string = "aGFzaGluZ18yX2VsZWNydHJpY19ib29nYWxvbwo="

func TestCredService(t *testing.T) {

	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Fatalf("failed to decode secret: %v", err)
	}

	credService := NewCredService([]byte(decoded))
	if credService == nil {
		t.Fatal("expected non-nil CredService instance")
	}

	// Test GenerateAccessToken
	token, err := credService.GenerateAccessToken()
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}
	t.Logf("Generated access token: %s", token)

	// Test GenerateHashFromPassword
	// password := "test-password"
	hash, err := credService.GenerateHashFromPassword(token)
	if err != nil {
		t.Fatalf("GenerateHashFromPassword failed: %v", err)
	}
	if len(hash) == 0 {
		t.Error("expected non-empty hash from password")
	}

	// compare hash and password
	if err = credService.CompareHashAndPassword(hash, token); err != nil {
		t.Errorf("CompareHashAndPassword failed: %v", err)
	} else {
		t.Logf("Successfully compared hash and password")
	}
}

// bench mark bcrypt to compare with hmac --> just for fun
func BenchmarkCredService_GenerateHmacHash(b *testing.B) {
	credService := NewCredService([]byte(secret))
	if credService == nil {
		b.Fatal("expected non-nil CredService instance")
	}

	password := "test-password"
	for i := 0; i < b.N; i++ {
		if _, err := credService.GenerateHashFromPassword(password); err != nil {
			b.Fatalf("GenerateHashFromPassword failed: %v", err)
		}
	}

}

func BenchmarkCredService_GenerateBcryptHash(b *testing.B) {

	pw := "test-password"
	cost := bcrypt.DefaultCost

	for i := 0; i < b.N; i++ {
		_, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
		if err != nil {
			b.Fatalf("GenerateFromPassword failed: %v", err)
		}

	}

}
