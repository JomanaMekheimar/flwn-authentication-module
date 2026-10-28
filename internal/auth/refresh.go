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
	ErrRefreshTokenInvalid    = errors.New("invalid refresh token")
	ErrRefreshTokenExpired    = errors.New("refresh token expired")
	ErrRefreshTokenConcurrent = errors.New("refresh token was concurrently rotated")
)

type RefreshSessionSnapshot struct {
	UserID      string
	WorkspaceID string
	// Generation is an opaque store-issued version. It is internal to the
	// refresh flow and must not be accepted from an HTTP client.
	Generation uint64
}

type refreshSession struct {
	UserID      string
	WorkspaceID string
	Scopes      []string
	ExpiresAt   time.Time
	Generation  uint64
}

type rotatedRefresh struct {
	generation uint64
	expiresAt  time.Time
}

type RefreshStore struct {
	mu       sync.Mutex
	sessions map[[32]byte]refreshSession
	rotated  map[[32]byte]rotatedRefresh
	ttl      time.Duration
}

func NewRefreshStore(ttl time.Duration) *RefreshStore {
	return &RefreshStore{
		sessions: make(map[[32]byte]refreshSession),
		rotated:  make(map[[32]byte]rotatedRefresh),
		ttl:      ttl,
	}
}

func (s *RefreshStore) TTL() time.Duration { return s.ttl }

// Inspect returns session identity and a version without consuming the token.
// Callers should validate current membership before the conditional Rotate.
func (s *RefreshStore) Inspect(raw string) (RefreshSessionSnapshot, error) {
	hash := hashRefreshToken(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneRotatedLocked(time.Now())
	session, ok := s.sessions[hash]
	if !ok {
		return RefreshSessionSnapshot{}, ErrRefreshTokenInvalid
	}
	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, hash)
		return RefreshSessionSnapshot{}, ErrRefreshTokenExpired
	}
	return RefreshSessionSnapshot{UserID: session.UserID, WorkspaceID: session.WorkspaceID, Generation: session.Generation}, nil
}

func (s *RefreshStore) pruneRotatedLocked(now time.Time) {
	for hash, entry := range s.rotated {
		if !entry.expiresAt.After(now) {
			delete(s.rotated, hash)
		}
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
	s.pruneRotatedLocked(time.Now())
	s.sessions[hashRefreshToken(raw)] = session
	s.mu.Unlock()

	return raw, nil
}

// Rotate consumes a refresh token and returns a replacement.
// The caller must issue a new access token using the returned identity.
func (s *RefreshStore) Rotate(
	raw string,
	generation uint64,
) (string, string, string, []string, error) {
	oldHash := hashRefreshToken(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.pruneRotatedLocked(now)

	session, ok := s.sessions[oldHash]
	if !ok {
		if consumed, exists := s.rotated[oldHash]; exists {
			if !consumed.expiresAt.After(now) {
				delete(s.rotated, oldHash)
				return "", "", "", nil, ErrRefreshTokenExpired
			}
			if consumed.generation == generation {
				return "", "", "", nil, ErrRefreshTokenConcurrent
			}
		}
		return "", "", "", nil, ErrRefreshTokenInvalid
	}

	if now.After(session.ExpiresAt) {
		delete(s.sessions, oldHash)
		return "", "", "", nil, ErrRefreshTokenExpired
	}
	if session.Generation != generation {
		return "", "", "", nil, ErrRefreshTokenInvalid
	}

	replacement, err := newRefreshToken()
	if err != nil {
		return "", "", "", nil, err
	}

	delete(s.sessions, oldHash)
	s.rotated[oldHash] = rotatedRefresh{generation: session.Generation, expiresAt: session.ExpiresAt}
	session.Generation++
	session.ExpiresAt = time.Now().Add(s.ttl)
	s.sessions[hashRefreshToken(replacement)] = session

	return replacement, session.UserID, session.WorkspaceID,
		append([]string(nil), session.Scopes...), nil
}

func (s *RefreshStore) Revoke(raw string) error {
	hash := hashRefreshToken(raw)
	s.mu.Lock()
	s.pruneRotatedLocked(time.Now())
	delete(s.sessions, hash)
	s.mu.Unlock()
	return nil
}
