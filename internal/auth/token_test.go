

package auth

import (
	"testing"
	"time"
	"github.com/golang-jwt/jwt/v5"

)

func newTestTokenManager(ttl time.Duration) *TokenManager {
	return NewTokenManager(
		"test-secret-that-is-long-enough-for-testing-123",
		"flwn-auth",
		"flwn-api",
		ttl,
	)
}

func TestVerifyAccessTokenAcceptsValidToken(t *testing.T) {
	manager := newTestTokenManager(15 * time.Minute)

	token, err := manager.IssueAccessToken(
		"user-123",
		"workspace-456",
		[]string{"profile:read"},
	)
	if err != nil {
		t.Fatalf("IssueAccessToken() error = %v", err)
	}

	claims, err := manager.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}

	if claims.Subject != "user-123" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user-123")
	}

	if claims.WorkspaceID != "workspace-456" {
		t.Errorf("WorkspaceID = %q, want %q", claims.WorkspaceID, "workspace-456")
	}

	if claims.Type != HumanTokenType {
		t.Errorf("Type = %q, want %q", claims.Type, HumanTokenType)
	}

	if !HasScope(claims, "profile:read") {
		t.Error("expected token to contain profile:read scope")
	}
}

func TestVerifyAccessTokenRejectsTamperedToken(t *testing.T) {
	manager := newTestTokenManager(15 * time.Minute)

	token, err := manager.IssueAccessToken(
		"user-123",
		"workspace-456",
		[]string{"profile:read"},
	)
	if err != nil {
		t.Fatalf("IssueAccessToken() error = %v", err)
	}

	tamperedToken := token + "x"

	_, err = manager.VerifyAccessToken(tamperedToken)
	if err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
}


func TestVerifyAccessTokenRejectsExpiredToken(t *testing.T) {
	manager := newTestTokenManager(15 * time.Minute)

	// Issue a valid token first.
	token, err := manager.IssueAccessToken(
		"user-123",
		"workspace-456",
		[]string{"profile:read"},
	)
	if err != nil {
		t.Fatalf("IssueAccessToken() error = %v", err)
	}

	// Parse its claims without verifying expiration.
	claims := &Claims{}
	_, _, err = new(jwt.Parser).ParseUnverified(token, claims)
	if err != nil {
		t.Fatalf("ParseUnverified() error = %v", err)
	}

	// Set expiration two minutes in the past.
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Minute))

	// Sign the modified claims with the test secret.
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := expiredToken.SignedString(manager.secret)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	// The verifier must reject the expired token.
	_, err = manager.VerifyAccessToken(signedToken)
	if err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}
