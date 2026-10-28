package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"maps"
	"testing"
	"time"
)

func newTestTokenManager(ttl time.Duration) *TokenManager {
	return NewTokenManager(
		"test-secret-that-is-long-enough-for-testing-123",
		"flwn-auth",
		"flwn-api",
		ttl,
	)
}

func TestVerifyAccessTokenRejectsWrongIssuerAudienceTypeAndKeyID(t *testing.T) {
	manager := newTestTokenManager(15 * time.Minute)
	manager.SetKeyID("expected")
	base := Claims{WorkspaceID: "workspace", Type: HumanTokenType, Scopes: []string{"profile:read"}, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: manager.issuer, Subject: "user", Audience: jwt.ClaimStrings{manager.audience},
		IssuedAt: jwt.NewNumericDate(time.Now()), NotBefore: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)), ID: "jti",
	}}
	tests := []struct {
		name   string
		mutate func(*Claims)
		kid    string
	}{
		{"issuer", func(c *Claims) { c.Issuer = "other" }, "expected"},
		{"audience", func(c *Claims) { c.Audience = jwt.ClaimStrings{"other"} }, "expected"},
		{"type", func(c *Claims) { c.Type = "service" }, "expected"},
		{"missing subject", func(c *Claims) { c.Subject = "" }, "expected"},
		{"missing workspace", func(c *Claims) { c.WorkspaceID = "" }, "expected"},
		{"missing jti", func(c *Claims) { c.ID = "" }, "expected"},
		{"unknown kid", func(*Claims) {}, "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := base
			claims.RegisteredClaims = base.RegisteredClaims
			tc.mutate(&claims)
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			token.Header["kid"] = tc.kid
			raw, err := token.SignedString(manager.secret)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.VerifyAccessToken(raw); err == nil {
				t.Fatal("expected token rejection")
			}
		})
	}
}

func TestVerifyAccessTokenRejectsUnsupportedAlgorithmAndRevokedJTI(t *testing.T) {
	manager := newTestTokenManager(time.Minute)
	tokenText, err := manager.IssueAccessToken("user", "workspace", []string{"read"})
	if err != nil {
		t.Fatal(err)
	}
	claims := &Claims{}
	if _, _, err := new(jwt.Parser).ParseUnverified(tokenText, claims); err != nil {
		t.Fatal(err)
	}
	wrongAlgorithm := jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	wrongText, err := wrongAlgorithm.SignedString(manager.secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.VerifyAccessToken(wrongText); err == nil {
		t.Fatal("accepted unsupported signing algorithm")
	}

	validClaims, err := manager.VerifyAccessToken(tokenText)
	if err != nil {
		t.Fatal(err)
	}
	manager.Revoke(validClaims.ID, validClaims.ExpiresAt.Time)
	if _, err := manager.VerifyAccessToken(tokenText); err == nil {
		t.Fatal("accepted revoked token")
	}
}

func TestVerifyAccessTokenRequiresTimeClaimsAndSingleAudience(t *testing.T) {
	manager := newTestTokenManager(15 * time.Minute)
	now := time.Now()
	base := jwt.MapClaims{
		"iss": manager.issuer, "aud": []string{manager.audience}, "sub": "user",
		"ws": "workspace", "typ": HumanTokenType, "scope": []string{"read"},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": "jti",
	}
	tests := []struct {
		name   string
		mutate func(jwt.MapClaims)
	}{
		{"missing iat", func(c jwt.MapClaims) { delete(c, "iat") }},
		{"missing nbf", func(c jwt.MapClaims) { delete(c, "nbf") }},
		{"invalid iat", func(c jwt.MapClaims) { c["iat"] = "not-a-timestamp" }},
		{"invalid nbf", func(c jwt.MapClaims) { c["nbf"] = "not-a-timestamp" }},
		{"invalid exp", func(c jwt.MapClaims) { c["exp"] = "not-a-timestamp" }},
		{"future iat beyond skew", func(c jwt.MapClaims) { c["iat"] = time.Now().Add(35 * time.Second).Unix() }},
		{"future nbf beyond skew", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(35 * time.Second).Unix() }},
		{"additional audience", func(c jwt.MapClaims) { c["aud"] = []string{manager.audience, "another-service"} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := maps.Clone(base)
			tc.mutate(claims)
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			raw, err := token.SignedString(manager.secret)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.VerifyAccessToken(raw); err == nil {
				t.Fatal("expected invalid claims to be rejected")
			}
		})
	}
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
