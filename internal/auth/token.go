package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenManager struct {
	secret   []byte
	issuer   string
	audience string
	keyID    string
	ttl      time.Duration
	revoked  TokenRevocationStore
}

// TokenRevocationStore is the adapter boundary for access-token revocation.
// Shared production implementations should persist each jti through exp.
type TokenRevocationStore interface {
	Revoke(jti string, expiresAt time.Time)
	IsRevoked(jti string) bool
}

// MemoryTokenRevocations is process-local and suitable only for development.
type MemoryTokenRevocations struct {
	mu      sync.Mutex
	revoked map[string]time.Time
}

func NewMemoryTokenRevocations() *MemoryTokenRevocations {
	return &MemoryTokenRevocations{revoked: make(map[string]time.Time)}
}

func (s *MemoryTokenRevocations) Revoke(jti string, expiresAt time.Time) {
	if jti == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, expiry := range s.revoked {
		if !expiry.After(now) {
			delete(s.revoked, id)
		}
	}
	if expiresAt.After(now) {
		s.revoked[jti] = expiresAt
	}
}

func (s *MemoryTokenRevocations) IsRevoked(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.revoked[jti]
	if ok && !expiry.After(time.Now()) {
		delete(s.revoked, jti)
		return false
	}
	return ok
}

func NewTokenManager(
	secret string,
	issuer string,
	audience string,
	ttl time.Duration,
) *TokenManager {
	return NewTokenManagerWithRevocations(secret, issuer, audience, ttl, NewMemoryTokenRevocations())
}

// NewTokenManagerWithRevocations allows an application to supply a shared
// revocation adapter. It does not make an in-memory adapter cross-instance.
func NewTokenManagerWithRevocations(secret, issuer, audience string, ttl time.Duration, revocations TokenRevocationStore) *TokenManager {
	if revocations == nil {
		revocations = NewMemoryTokenRevocations()
	}
	return &TokenManager{
		secret:   []byte(secret),
		issuer:   issuer,
		audience: audience,
		ttl:      ttl,
		revoked:  revocations,
	}
}

// Revoke prevents a token ID from being accepted until its expiry.
func (m *TokenManager) Revoke(jti string, expiresAt time.Time) {
	m.revoked.Revoke(jti, expiresAt)
}

func (m *TokenManager) IsRevoked(jti string) bool {
	return m.revoked.IsRevoked(jti)
}

// SetKeyID configures the signing key identifier included in the JWT header.
func (m *TokenManager) SetKeyID(keyID string) { m.keyID = keyID }

func randomTokenID() (string, error) {
	b := make([]byte, 32)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (m *TokenManager) IssueAccessToken(
	userID string,
	workspaceID string,
	scopes []string,
) (string, error) {
	if userID == "" || workspaceID == "" {
		return "", fmt.Errorf("user ID and workspace ID are required")
	}

	jti, err := randomTokenID()
	if err != nil {
		return "", fmt.Errorf("generate token ID: %w", err)
	}

	now := time.Now()

	claims := Claims{
		WorkspaceID: workspaceID,
		Type:        HumanTokenType,
		Scopes:      scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{m.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if m.keyID != "" {
		token.Header["kid"] = m.keyID
	}

	signedToken, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}

	return signedToken, nil
}
