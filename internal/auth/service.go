package auth

import (
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials      = errors.New("invalid email or password")
	ErrAccountDisabled         = errors.New("account is disabled")
	ErrMemberStoreUnavailable  = errors.New("member store unavailable")
	ErrRefreshStoreUnavailable = errors.New("refresh store unavailable")
	ErrRefreshCleanupFailed    = errors.New("refresh session cleanup failed")
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

// RefreshTokenStore is the persistence boundary for hashed, single-use refresh
// sessions. Inspect must not consume a token and returns a store-issued
// generation that callers must pass unchanged to Rotate. Production Rotate
// must atomically consume one token and install its replacement across
// instances. Failed rotation must preserve the old session except when it
// reports expiry, invalidity, revocation, or a concurrent rotation.
type RefreshTokenStore interface {
	TTL() time.Duration
	Create(userID, workspaceID string, scopes []string) (string, error)
	Inspect(raw string) (RefreshSessionSnapshot, error)
	Rotate(raw string, generation uint64) (replacement, userID, workspaceID string, scopes []string, err error)
	Revoke(raw string) error
}

type AccessTokenIssuer interface {
	IssueAccessToken(userID, workspaceID string, scopes []string) (string, error)
}

type AuthService struct {
	users        UserStore
	tokens       AccessTokenIssuer
	refreshStore RefreshTokenStore
	refreshTTL   time.Duration
}

func NewAuthService(
	users UserStore,
	tokens AccessTokenIssuer,
	refreshStore RefreshTokenStore,
) *AuthService {
	return &AuthService{
		users:        users,
		tokens:       tokens,
		refreshStore: refreshStore,
		refreshTTL:   refreshStore.TTL(),
	}
}

// RefreshTokenTTL reports the lifetime used by this service and its configured
// refresh store. Callers should use the same lifetime for browser cookies.
func (s *AuthService) RefreshTokenTTL() time.Duration { return s.refreshTTL }

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
		return nil, errors.Join(ErrRefreshStoreUnavailable, err)
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// Refresh rotates a refresh token and rechecks the member's current status and grants.
func (s *AuthService) Refresh(raw string) (*LoginResult, error) {
	session, err := s.refreshStore.Inspect(raw)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenInvalid) || errors.Is(err, ErrRefreshTokenExpired) {
			return nil, err
		}
		return nil, errors.Join(ErrRefreshStoreUnavailable, err)
	}
	user, err := s.users.FindByID(session.UserID)
	if errors.Is(err, ErrUserNotFound) || (err == nil && user == nil) || (err == nil && (!user.Active || user.WorkspaceID != session.WorkspaceID)) {
		if revokeErr := s.revokeRefresh(raw); revokeErr != nil {
			return nil, errors.Join(ErrAccountDisabled, revokeErr)
		}
		return nil, ErrAccountDisabled
	}
	if err != nil {
		return nil, errors.Join(ErrMemberStoreUnavailable, err)
	}

	replacement, rotatedUserID, rotatedWorkspaceID, _, err := s.refreshStore.Rotate(raw, session.Generation)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenInvalid) || errors.Is(err, ErrRefreshTokenExpired) {
			return nil, err
		}
		if errors.Is(err, ErrRefreshTokenConcurrent) {
			return nil, ErrRefreshTokenConcurrent
		}
		return nil, errors.Join(ErrRefreshStoreUnavailable, err)
	}
	if rotatedUserID != session.UserID || rotatedWorkspaceID != session.WorkspaceID {
		cleanupErr := s.revokeRefresh(replacement)
		return nil, errors.Join(errors.New("refresh session identity changed during rotation"), cleanupErr)
	}
	access, err := s.tokens.IssueAccessToken(user.ID, user.WorkspaceID, user.Scopes)
	if err != nil {
		return nil, errors.Join(err, s.revokeRefresh(replacement))
	}
	return &LoginResult{AccessToken: access, RefreshToken: replacement}, nil
}

func (s *AuthService) Logout(rawRefreshToken string) error {
	if rawRefreshToken == "" {
		return nil
	}
	return s.revokeRefresh(rawRefreshToken)
}

func (s *AuthService) revokeRefresh(raw string) error {
	if err := s.refreshStore.Revoke(raw); err != nil {
		return errors.Join(ErrRefreshCleanupFailed, err)
	}
	return nil
}
