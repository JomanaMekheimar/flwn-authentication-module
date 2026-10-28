package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (m *TokenManager) VerifyAccessToken(
	rawToken string,
) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(
		rawToken,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing algorithm")
			}
			if m.keyID != "" && token.Header["kid"] != m.keyID {
				return nil, fmt.Errorf("unexpected signing key ID")
			}

			return m.secret, nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience(m.audience),
		jwt.WithExpirationRequired(),
		jwt.WithNotBeforeRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid access token")
	}

	// jwt.WithIssuedAt validates future iat values when present, but the
	// library intentionally does not require iat. This token contract does.
	if claims.IssuedAt == nil {
		return nil, fmt.Errorf("missing issued-at time")
	}
	// WithAudience checks that the configured audience is present. This issuer
	// contract is single-audience, so reject tokens addressed to extra services.
	if len(claims.Audience) != 1 || claims.Audience[0] != m.audience {
		return nil, fmt.Errorf("unexpected token audience")
	}

	if claims.Type != HumanTokenType {
		return nil, fmt.Errorf("unexpected token type")
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("missing user ID")
	}

	if claims.WorkspaceID == "" {
		return nil, fmt.Errorf("missing workspace ID")
	}

	if claims.ID == "" {
		return nil, fmt.Errorf("missing token ID")
	}
	if m.IsRevoked(claims.ID) {
		return nil, fmt.Errorf("access token has been revoked")
	}

	return claims, nil
}
