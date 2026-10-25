package auth

import (
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrAccountDisabled    = errors.New("account is disabled")
)

type User struct {
	ID           string
	Email        string
	WorkspaceID  string
	PasswordHash []byte
	Scopes       []string
	Active       bool
}

type UserStore interface {
	FindByEmail(email string) (*User, error)
	FindByID(id string) (*User, error)
}

type AuthService struct {
	users        UserStore
	tokens       *TokenManager
	refreshStore *RefreshStore
	refreshTTL   time.Duration
}

func NewAuthService(
	users UserStore,
	tokens *TokenManager,
	refreshStore *RefreshStore,
	refreshTTL time.Duration,
) *AuthService {
	return &AuthService{
		users:        users,
		tokens:       tokens,
		refreshStore: refreshStore,
		refreshTTL:   refreshTTL,
	}
}

type LoginResult struct {
	AccessToken  string
	RefreshToken string
}

// Login verifies the user's credentials and returns an access token.
func (s *AuthService) Login(email, password string) (*LoginResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	if email == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := s.users.FindByEmail(email)
	if err != nil || user == nil {
		return nil, ErrInvalidCredentials
	}

	if bcrypt.CompareHashAndPassword(
		user.PasswordHash,
		[]byte(password),
	) != nil {
		return nil, ErrInvalidCredentials
	}

	if !user.Active {
		return nil, ErrAccountDisabled
	}

	accessToken, err := s.tokens.IssueAccessToken(
		user.ID,
		user.WorkspaceID,
		user.Scopes,
	)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.refreshStore.Create(
		user.ID,
		user.WorkspaceID,
		user.Scopes,
	)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// Refresh rotates a refresh token and rechecks the member's current status and grants.
func (s *AuthService) Refresh(raw string) (*LoginResult, error) {
	replacement, userID, workspaceID, _, err := s.refreshStore.Rotate(raw)
	if err != nil {
		return nil, err
	}
	user, err := s.users.FindByID(userID)
	if err != nil || user == nil || !user.Active || user.WorkspaceID != workspaceID {
		return nil, ErrAccountDisabled
	}
	access, err := s.tokens.IssueAccessToken(user.ID, user.WorkspaceID, user.Scopes)
	if err != nil {
		return nil, err
	}
	return &LoginResult{AccessToken: access, RefreshToken: replacement}, nil
}
