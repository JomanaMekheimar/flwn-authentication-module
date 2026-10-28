package auth

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type findByIDErrorStore struct {
	UserStore
	err error
}

func (s findByIDErrorStore) FindByID(string) (*User, error) { return nil, s.err }

type trackingRefreshStore struct {
	base         *RefreshStore
	lastCreated  string
	lastReplaced string
	revokeErr    error
	revokeCalls  int
}

func (s *trackingRefreshStore) TTL() time.Duration { return s.base.TTL() }
func (s *trackingRefreshStore) Create(userID, workspaceID string, scopes []string) (string, error) {
	raw, err := s.base.Create(userID, workspaceID, scopes)
	s.lastCreated = raw
	return raw, err
}
func (s *trackingRefreshStore) Inspect(raw string) (RefreshSessionSnapshot, error) {
	return s.base.Inspect(raw)
}
func (s *trackingRefreshStore) Rotate(raw string, generation uint64) (string, string, string, []string, error) {
	replacement, userID, workspaceID, scopes, err := s.base.Rotate(raw, generation)
	s.lastReplaced = replacement
	return replacement, userID, workspaceID, scopes, err
}
func (s *trackingRefreshStore) Revoke(raw string) error {
	s.revokeCalls++
	if s.revokeErr != nil {
		return s.revokeErr
	}
	return s.base.Revoke(raw)
}

type failingTokenIssuer struct{ err error }

func (s failingTokenIssuer) IssueAccessToken(string, string, []string) (string, error) {
	return "", s.err
}

func newTestService(t *testing.T, active bool) (*AuthService, *MemoryUserStore, *TokenManager) {
	t.Helper()
	users := NewMemoryUserStore()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	users.Add(User{ID: "member-1", Email: "member@example.test", WorkspaceID: "workspace-1", PasswordHash: hash, Scopes: []string{"profile:read"}, Active: active})
	tokens := newTestTokenManager(15 * time.Minute)
	return NewAuthService(users, tokens, NewRefreshStore(time.Hour)), users, tokens
}

func TestLoginReturnsBothTokensAndRejectsInvalidOrDisabledUsers(t *testing.T) {
	service, _, _ := newTestService(t, true)
	result, err := service.Login(" MEMBER@example.test ", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatalf("expected both tokens, got %#v", result)
	}
	if _, err := service.Login("member@example.test", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("invalid login error = %v", err)
	}
	disabled, _, _ := newTestService(t, false)
	if _, err := disabled.Login("member@example.test", "correct horse battery"); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("disabled login error = %v", err)
	}
}

func TestRefreshRotationLogoutAndMemberRevalidation(t *testing.T) {
	service, users, tokens := newTestService(t, true)
	login, err := service.Login("member@example.test", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := service.Refresh(login.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.AccessToken == "" || rotated.RefreshToken == "" {
		t.Fatal("refresh did not return both tokens")
	}
	if _, err := service.Refresh(login.RefreshToken); !errors.Is(err, ErrRefreshTokenInvalid) {
		t.Fatalf("reuse error = %v", err)
	}
	claims, err := tokens.VerifyAccessToken(rotated.AccessToken)
	if err != nil || claims.Subject != "member-1" {
		t.Fatalf("new access token claims=%v err=%v", claims, err)
	}
	users.Add(User{ID: "member-1", Email: "member@example.test", WorkspaceID: "workspace-1", Active: false})
	if _, err := service.Refresh(rotated.RefreshToken); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("disabled refresh error = %v", err)
	}
	if _, err := service.refreshStore.Inspect(rotated.RefreshToken); !errors.Is(err, ErrRefreshTokenInvalid) {
		t.Fatalf("disabled member's refresh session remains usable: %v", err)
	}
	logoutService, _, _ := newTestService(t, true)
	login, err = logoutService.Login("member@example.test", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	logoutService.Logout(login.RefreshToken)
	if _, err := logoutService.Refresh(login.RefreshToken); !errors.Is(err, ErrRefreshTokenInvalid) {
		t.Fatalf("logout did not revoke token: %v", err)
	}
}

func TestRefreshRejectsChangedWorkspace(t *testing.T) {
	service, users, _ := newTestService(t, true)
	login, err := service.Login("member@example.test", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	users.Add(User{ID: "member-1", Email: "member@example.test", WorkspaceID: "workspace-2", Active: true, Scopes: []string{"profile:read"}})
	if _, err := service.Refresh(login.RefreshToken); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("refresh after workspace change error = %v", err)
	}
	if _, err := service.refreshStore.Inspect(login.RefreshToken); !errors.Is(err, ErrRefreshTokenInvalid) {
		t.Fatalf("changed-workspace refresh session remains usable: %v", err)
	}
}

func TestRefreshUsesCurrentScopesInsteadOfStoredScopes(t *testing.T) {
	service, users, tokens := newTestService(t, true)
	login, err := service.Login("member@example.test", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	users.Add(User{ID: "member-1", Email: "member@example.test", WorkspaceID: "workspace-1", Active: true, Scopes: []string{"billing:read"}})
	rotated, err := service.Refresh(login.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := tokens.VerifyAccessToken(rotated.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if HasScope(claims, "profile:read") || !HasScope(claims, "billing:read") {
		t.Fatalf("refresh scopes = %v, want only current billing:read scope", claims.Scopes)
	}
}

func TestTransientMemberStoreFailurePreservesRefreshSession(t *testing.T) {
	service, users, _ := newTestService(t, true)
	login, err := service.Login("member@example.test", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	service.users = findByIDErrorStore{UserStore: users, err: errors.New("temporary database outage")}
	result, err := service.Refresh(login.RefreshToken)
	if result != nil {
		t.Fatal("refresh returned credentials during user-store outage")
	}
	if !errors.Is(err, ErrMemberStoreUnavailable) {
		t.Fatalf("refresh error = %v", err)
	}
	if _, inspectErr := service.refreshStore.Inspect(login.RefreshToken); inspectErr != nil {
		t.Fatalf("refresh session was consumed during transient failure: %v", inspectErr)
	}
	service.users = users
	result, err = service.Refresh(login.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("retry did not return refreshed credentials")
	}
}

func TestMissingMemberRevokesRefreshSession(t *testing.T) {
	service, users, _ := newTestService(t, true)
	login, err := service.Login("member@example.test", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	service.users = findByIDErrorStore{UserStore: users, err: ErrUserNotFound}
	result, err := service.Refresh(login.RefreshToken)
	if result != nil {
		t.Fatal("refresh returned credentials for a missing member")
	}
	if !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("refresh error = %v", err)
	}
	if _, err := service.refreshStore.Inspect(login.RefreshToken); !errors.Is(err, ErrRefreshTokenInvalid) {
		t.Fatalf("missing-member session remains usable: %v", err)
	}
}

func TestSigningFailureRevokesReplacementAndPreservesOriginalError(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup_fails_%t", cleanupFails), func(t *testing.T) {
			users := NewMemoryUserStore()
			hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			users.Add(User{ID: "member-1", Email: "member@example.test", WorkspaceID: "workspace-1", PasswordHash: hash, Active: true})
			base := NewRefreshStore(time.Hour)
			store := &trackingRefreshStore{base: base}
			issuer := newTestTokenManager(time.Minute)
			service := NewAuthService(users, issuer, store)
			login, err := service.Login("member@example.test", "correct horse battery")
			if err != nil {
				t.Fatal(err)
			}
			issueErr := errors.New("signing failed")
			service.tokens = failingTokenIssuer{err: issueErr}
			if cleanupFails {
				store.revokeErr = errors.New("revoke unavailable")
			}
			result, err := service.Refresh(login.RefreshToken)
			if result != nil {
				t.Fatal("refresh returned credentials after signing failure")
			}
			if !errors.Is(err, issueErr) {
				t.Fatalf("original signing error was lost: %v", err)
			}
			if store.lastReplaced == "" || store.revokeCalls != 1 {
				t.Fatalf("replacement cleanup not attempted; replacement present=%t calls=%d", store.lastReplaced != "", store.revokeCalls)
			}
			_, inspectErr := base.Inspect(store.lastReplaced)
			if cleanupFails {
				if !errors.Is(err, ErrRefreshCleanupFailed) {
					t.Fatalf("cleanup failure not reported: %v", err)
				}
				if inspectErr != nil {
					t.Fatalf("failed cleanup unexpectedly removed replacement: %v", inspectErr)
				}
			} else if !errors.Is(inspectErr, ErrRefreshTokenInvalid) {
				t.Fatalf("replacement remains usable after successful cleanup: %v", inspectErr)
			}
		})
	}
}

func TestRefreshRejectsExpiredAndMalformedTokens(t *testing.T) {
	store := NewRefreshStore(-time.Second)
	raw, err := store.Create("member", "workspace", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := store.Rotate(raw, 0); !errors.Is(err, ErrRefreshTokenExpired) {
		t.Fatalf("expired token error = %v", err)
	}
	if _, _, _, _, err := store.Rotate("malformed", 0); !errors.Is(err, ErrRefreshTokenInvalid) {
		t.Fatalf("malformed token error = %v", err)
	}
}

func TestRefreshRotationAllowsOnlyOneConcurrentConsumer(t *testing.T) {
	store := NewRefreshStore(time.Hour)
	raw, err := store.Create("member", "workspace", nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Inspect(raw)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _, rotateErr := store.Rotate(raw, snapshot.Generation)
			results <- rotateErr
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	concurrentFailures := 0
	for rotateErr := range results {
		if rotateErr == nil {
			successes++
		} else if errors.Is(rotateErr, ErrRefreshTokenConcurrent) {
			concurrentFailures++
		}
	}
	if successes != 1 || concurrentFailures != 1 {
		t.Fatalf("concurrent outcomes: successful=%d concurrent=%d, want 1 each", successes, concurrentFailures)
	}
}
