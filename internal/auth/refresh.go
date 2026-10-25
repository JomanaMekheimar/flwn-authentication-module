package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	ErrRefreshTokenInvalid = errors.New("invalid refresh token")
	ErrRefreshTokenExpired = errors.New("refresh token expired")
)

type refreshSession struct {
	UserID      string
	WorkspaceID string
	Scopes      []string
	ExpiresAt   time.Time
}

type RefreshStore struct {
	mu       sync.Mutex
	sessions map[[32]byte]refreshSession
	ttl      time.Duration
}

func NewRefreshStore(ttl time.Duration) *RefreshStore {
	return &RefreshStore{
		sessions: make(map[[32]byte]refreshSession),
		ttl:      ttl,
	}
}

func hashRefreshToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func newRefreshToken() (string, error) {
	b := make([]byte, 32)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *RefreshStore) Create(
	userID string,
	workspaceID string,
	scopes []string,
) (string, error) {
	raw, err := newRefreshToken()
	if err != nil {
		return "", err
	}

	session := refreshSession{
		UserID:      userID,
		WorkspaceID: workspaceID,
		Scopes:      append([]string(nil), scopes...),
		ExpiresAt:   time.Now().Add(s.ttl),
	}

	s.mu.Lock()
	s.sessions[hashRefreshToken(raw)] = session
	s.mu.Unlock()

	return raw, nil
}

// Rotate consumes a refresh token and returns a replacement.
// The caller must issue a new access token using the returned identity.
func (s *RefreshStore) Rotate(
	raw string,
) (string, string, string, []string, error) {
	oldHash := hashRefreshToken(raw)

	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[oldHash]
	if !ok {
		return "", "", "", nil, ErrRefreshTokenInvalid
	}

	delete(s.sessions, oldHash)

	if time.Now().After(session.ExpiresAt) {
		return "", "", "", nil, ErrRefreshTokenExpired
	}

	replacement, err := newRefreshToken()
	if err != nil {
		return "", "", "", nil, err
	}

	session.ExpiresAt = time.Now().Add(s.ttl)
	s.sessions[hashRefreshToken(replacement)] = session

	return replacement, session.UserID, session.WorkspaceID,
		append([]string(nil), session.Scopes...), nil
}

func (s *RefreshStore) Revoke(raw string) {
	s.mu.Lock()
	delete(s.sessions, hashRefreshToken(raw))
	s.mu.Unlock()
}
