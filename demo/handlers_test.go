package demo

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"flwn-authentication-module/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

type observingRefreshStore struct {
	*auth.RefreshStore
	created   string
	revokeErr error
	revokeNum int
}

type barrierRefreshStore struct {
	*auth.RefreshStore
	mu      sync.Mutex
	arrived int
	ready   chan struct{}
}

func (s *barrierRefreshStore) Inspect(raw string) (auth.RefreshSessionSnapshot, error) {
	snapshot, err := s.RefreshStore.Inspect(raw)
	if err != nil {
		return snapshot, err
	}
	s.mu.Lock()
	s.arrived++
	shouldWait := s.arrived <= 2
	if s.arrived == 2 {
		close(s.ready)
	}
	ready := s.ready
	s.mu.Unlock()
	if shouldWait {
		<-ready
	}
	return snapshot, nil
}

func (s *barrierRefreshStore) Rotate(raw string, generation uint64) (string, string, string, []string, error) {
	return s.RefreshStore.Rotate(raw, generation)
}

func (s *observingRefreshStore) Create(userID, workspaceID string, scopes []string) (string, error) {
	raw, err := s.RefreshStore.Create(userID, workspaceID, scopes)
	s.created = raw
	return raw, err
}

func (s *observingRefreshStore) Revoke(raw string) error {
	s.revokeNum++
	if s.revokeErr != nil {
		return s.revokeErr
	}
	return s.RefreshStore.Revoke(raw)
}

func testHandler(t *testing.T) (*Handlers, *auth.TokenManager, *auth.MemoryUserStore) {
	return testHandlerWithRefreshTTL(t, time.Hour)
}

func testHandlerWithRefreshTTL(t *testing.T, refreshTTL time.Duration) (*Handlers, *auth.TokenManager, *auth.MemoryUserStore) {
	return testHandlerWithStore(t, auth.NewRefreshStore(refreshTTL))
}

func testHandlerWithStore(t *testing.T, store auth.RefreshTokenStore) (*Handlers, *auth.TokenManager, *auth.MemoryUserStore) {
	t.Helper()
	users := auth.NewMemoryUserStore()
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	users.Add(auth.User{ID: "user-1", Email: "user@example.test", WorkspaceID: "ws-1", PasswordHash: hash, Scopes: []string{"profile:read"}, Active: true})
	tokens := auth.NewTokenManager("test-secret-that-is-long-enough-for-testing-123", "issuer", "audience", time.Minute)
	service := auth.NewAuthService(users, tokens, store)
	return &Handlers{Auth: service}, tokens, users
}

func TestConcurrentBrowserRefreshLoserDoesNotClearWinnerCookies(t *testing.T) {
	store := &barrierRefreshStore{RefreshStore: auth.NewRefreshStore(time.Hour), ready: make(chan struct{})}
	h, _, _ := testHandlerWithStore(t, store)
	h.RefreshCookieSecure = true
	login := httptest.NewRecorder()
	h.BrowserLogin(login, httptest.NewRequest(http.MethodPost, "/auth/browser/login", strings.NewReader(`{"email":"user@example.test","password":"password"}`)))
	if login.Code != http.StatusOK {
		t.Fatalf("browser login status=%d", login.Code)
	}
	var csrfBody map[string]string
	if err := json.Unmarshal(login.Body.Bytes(), &csrfBody); err != nil {
		t.Fatal(err)
	}
	var oldRefresh, csrfCookie *http.Cookie
	for _, cookie := range login.Result().Cookies() {
		switch cookie.Name {
		case "flwn_refresh":
			oldRefresh = cookie
		case "flwn_csrf":
			csrfCookie = cookie
		}
	}
	if oldRefresh == nil || csrfCookie == nil {
		t.Fatal("browser login did not establish both cookies")
	}

	responses := make(chan *httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/auth/browser/refresh", nil)
			req.AddCookie(oldRefresh)
			req.AddCookie(csrfCookie)
			req.Header.Set("X-CSRF-Token", csrfBody["csrf_token"])
			res := httptest.NewRecorder()
			h.BrowserRefresh(res, req)
			responses <- res
		}()
	}
	wg.Wait()
	close(responses)

	var winner, loser *httptest.ResponseRecorder
	for res := range responses {
		switch res.Code {
		case http.StatusOK:
			winner = res
		case http.StatusConflict:
			loser = res
		default:
			t.Fatalf("concurrent refresh status=%d body=%s", res.Code, res.Body)
		}
	}
	if winner == nil || loser == nil {
		t.Fatalf("expected one success and one concurrent conflict; winner=%t loser=%t", winner != nil, loser != nil)
	}
	if len(loser.Result().Cookies()) != 0 {
		t.Fatal("losing concurrent refresh set or cleared cookies")
	}
	var newRefresh *http.Cookie
	for _, cookie := range winner.Result().Cookies() {
		if cookie.Name == "flwn_refresh" {
			newRefresh = cookie
		}
	}
	if newRefresh == nil || newRefresh.Value == oldRefresh.Value {
		t.Fatal("winning refresh did not establish a rotated refresh cookie")
	}

	// Apply response cookies in both possible orders. The loser must never erase
	// the cookie set by the successful response.
	for _, winnerFirst := range []bool{true, false} {
		jar := map[string]*http.Cookie{}
		apply := func(res *httptest.ResponseRecorder) {
			for _, cookie := range res.Result().Cookies() {
				if cookie.MaxAge < 0 {
					delete(jar, cookie.Name)
				} else {
					jar[cookie.Name] = cookie
				}
			}
		}
		if winnerFirst {
			apply(winner)
			apply(loser)
		} else {
			apply(loser)
			apply(winner)
		}
		if jar["flwn_refresh"] == nil || jar["flwn_refresh"].Value != newRefresh.Value {
			t.Fatalf("winner cookie lost when winnerFirst=%t", winnerFirst)
		}
	}

	// A later request which did not inspect the token before rotation remains a
	// genuinely stale replay and follows the existing clear-cookie behavior.
	stale := httptest.NewRequest(http.MethodPost, "/auth/browser/refresh", nil)
	stale.AddCookie(oldRefresh)
	stale.AddCookie(csrfCookie)
	stale.Header.Set("X-CSRF-Token", csrfBody["csrf_token"])
	staleResponse := httptest.NewRecorder()
	h.BrowserRefresh(staleResponse, stale)
	if staleResponse.Code != http.StatusUnauthorized || len(staleResponse.Result().Cookies()) != 2 {
		t.Fatalf("stale replay response status=%d cookies=%d", staleResponse.Code, len(staleResponse.Result().Cookies()))
	}
}

func TestBrowserCookieLifetimeMatchesRefreshTTL(t *testing.T) {
	for _, ttl := range []time.Duration{24 * time.Hour, 30 * 24 * time.Hour} {
		t.Run(ttl.String(), func(t *testing.T) {
			h, _, _ := testHandlerWithRefreshTTL(t, ttl)
			login := httptest.NewRecorder()
			h.BrowserLogin(login, httptest.NewRequest(http.MethodPost, "/auth/browser/login", strings.NewReader(`{"email":"user@example.test","password":"password"}`)))
			if login.Code != http.StatusOK {
				t.Fatalf("browser login status=%d", login.Code)
			}
			seen := 0
			for _, cookie := range login.Result().Cookies() {
				if cookie.Name != "flwn_refresh" && cookie.Name != "flwn_csrf" {
					continue
				}
				seen++
				wantAge := int(ttl.Seconds())
				if cookie.MaxAge != wantAge {
					t.Errorf("%s MaxAge=%d, want %d", cookie.Name, cookie.MaxAge, wantAge)
				}
				remaining := time.Until(cookie.Expires)
				if remaining < ttl-time.Second || remaining > ttl+time.Second {
					t.Errorf("%s expiry remaining=%s, want about %s", cookie.Name, remaining, ttl)
				}
			}
			if seen != 2 {
				t.Fatalf("received %d session cookies, want 2", seen)
			}
		})
	}
}

func TestLoginResponseContainsBothTokenFieldsAndRefreshRotates(t *testing.T) {
	h, _, _ := testHandler(t)
	login := httptest.NewRecorder()
	h.Login(login, httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"email":"user@example.test","password":"password"}`)))
	if login.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.Code, login.Body)
	}
	var pair map[string]string
	if err := json.Unmarshal(login.Body.Bytes(), &pair); err != nil {
		t.Fatal(err)
	}
	if pair["access_token"] == "" || pair["refresh_token"] == "" || pair["token_type"] != "Bearer" {
		t.Fatalf("incomplete login response: %#v", pair)
	}
	refresh := httptest.NewRecorder()
	h.Refresh(refresh, httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(`{"refresh_token":"`+pair["refresh_token"]+`"}`)))
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", refresh.Code, refresh.Body)
	}
	var next map[string]string
	if err := json.Unmarshal(refresh.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	if next["refresh_token"] == "" || next["refresh_token"] == pair["refresh_token"] || next["access_token"] == "" {
		t.Fatalf("rotation response invalid: %#v", next)
	}
}

func TestProtectedEndpointRejectsRefreshTokenAndRechecksMember(t *testing.T) {
	h, tokens, users := testHandler(t)
	login, err := h.Auth.Login("user@example.test", "password")
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(tokens, users, h)
	for _, bearer := range []string{login.RefreshToken} {
		req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("refresh token accepted: %d", res.Code)
		}
	}
	users.Add(auth.User{ID: "user-1", Email: "user@example.test", WorkspaceID: "ws-1", Active: true})
	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer "+login.AccessToken)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("removed scope status=%d want 403", res.Code)
	}
	noScope, err := tokens.IssueAccessToken("user-1", "ws-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer "+noScope)
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("missing operation scope status=%d want 403", res.Code)
	}
}

func TestBrowserSessionUsesHttpOnlyRefreshCookieAndCSRF(t *testing.T) {
	h, _, _ := testHandler(t)
	h.RefreshCookieSecure = true
	login := httptest.NewRecorder()
	h.BrowserLogin(login, httptest.NewRequest(http.MethodPost, "/auth/browser/login", strings.NewReader(`{"email":"user@example.test","password":"password"}`)))
	if login.Code != http.StatusOK {
		t.Fatalf("browser login status=%d", login.Code)
	}
	var payload map[string]string
	if err := json.Unmarshal(login.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["access_token"] == "" || payload["csrf_token"] == "" {
		t.Fatalf("missing browser credentials: %#v", payload)
	}
	if _, exists := payload["refresh_token"]; exists {
		t.Fatal("browser login leaked refresh token in JSON")
	}
	var refreshCookie, csrfCookie *http.Cookie
	for _, cookie := range login.Result().Cookies() {
		switch cookie.Name {
		case "flwn_refresh":
			refreshCookie = cookie
		case "flwn_csrf":
			csrfCookie = cookie
		}
	}
	if refreshCookie == nil || !refreshCookie.HttpOnly || !refreshCookie.Secure || refreshCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("refresh cookie flags incorrect: %#v", refreshCookie)
	}
	if csrfCookie == nil || csrfCookie.HttpOnly {
		t.Fatalf("CSRF cookie should be readable by browser client: %#v", csrfCookie)
	}

	bad := httptest.NewRequest(http.MethodPost, "/auth/browser/refresh", nil)
	bad.AddCookie(refreshCookie)
	bad.AddCookie(csrfCookie)
	badResponse := httptest.NewRecorder()
	h.BrowserRefresh(badResponse, bad)
	if badResponse.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF header status=%d", badResponse.Code)
	}

	good := httptest.NewRequest(http.MethodPost, "/auth/browser/refresh", nil)
	good.AddCookie(refreshCookie)
	good.AddCookie(csrfCookie)
	good.Header.Set("X-CSRF-Token", payload["csrf_token"])
	goodResponse := httptest.NewRecorder()
	h.BrowserRefresh(goodResponse, good)
	if goodResponse.Code != http.StatusOK {
		t.Fatalf("browser refresh status=%d body=%s", goodResponse.Code, goodResponse.Body)
	}
	for _, cookie := range goodResponse.Result().Cookies() {
		if cookie.Name == "flwn_refresh" && cookie.Value == refreshCookie.Value {
			t.Fatal("browser refresh did not rotate cookie")
		}
	}
}

func TestBrowserLogoutRequiresCSRFAndDeletesCookies(t *testing.T) {
	h, _, _ := testHandler(t)
	h.RefreshCookieSecure = true
	login := httptest.NewRecorder()
	h.BrowserLogin(login, httptest.NewRequest(http.MethodPost, "/auth/browser/login", strings.NewReader(`{"email":"user@example.test","password":"password"}`)))
	if login.Code != http.StatusOK {
		t.Fatalf("browser login status=%d", login.Code)
	}
	var csrf string
	var refreshCookie, csrfCookie *http.Cookie
	var body map[string]string
	if err := json.Unmarshal(login.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	csrf = body["csrf_token"]
	for _, cookie := range login.Result().Cookies() {
		switch cookie.Name {
		case "flwn_refresh":
			refreshCookie = cookie
		case "flwn_csrf":
			csrfCookie = cookie
		}
	}
	if refreshCookie == nil || csrfCookie == nil {
		t.Fatal("login did not set browser cookies")
	}

	for _, header := range []string{"", "invalid"} {
		req := httptest.NewRequest(http.MethodPost, "/auth/browser/logout", nil)
		req.AddCookie(refreshCookie)
		req.AddCookie(csrfCookie)
		if header != "" {
			req.Header.Set("X-CSRF-Token", header)
		}
		res := httptest.NewRecorder()
		h.BrowserLogout(res, req)
		if res.Code != http.StatusForbidden {
			t.Errorf("logout with CSRF header %q status=%d", header, res.Code)
		}
		if len(res.Result().Cookies()) != 0 {
			t.Error("rejected logout cleared cookies")
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/browser/logout", nil)
	req.AddCookie(refreshCookie)
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", csrf)
	res := httptest.NewRecorder()
	h.BrowserLogout(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d", res.Code)
	}
	cleared := map[string]*http.Cookie{}
	for _, cookie := range res.Result().Cookies() {
		cleared[cookie.Name] = cookie
	}
	for _, name := range []string{"flwn_refresh", "flwn_csrf"} {
		cookie := cleared[name]
		if cookie == nil || cookie.MaxAge >= 0 || !cookie.Expires.Before(time.Now()) || cookie.Path != "/auth/browser" || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
			t.Errorf("%s deletion attributes incorrect: %#v", name, cookie)
		}
	}
	if cookie := cleared["flwn_refresh"]; cookie != nil && !cookie.HttpOnly {
		t.Error("refresh deletion lost HttpOnly attribute")
	}
	if _, err := h.Auth.Refresh(refreshCookie.Value); err == nil {
		t.Fatal("logout did not revoke refresh token")
	}
}

func TestBrowserLoginCSRFGenerationFailureRevokesUnreturnedRefreshSession(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "cleanup_succeeds", true: "cleanup_fails"}[cleanupFails], func(t *testing.T) {
			users := auth.NewMemoryUserStore()
			hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			users.Add(auth.User{ID: "user-1", Email: "user@example.test", WorkspaceID: "ws-1", PasswordHash: hash, Scopes: []string{"profile:read"}, Active: true})
			store := &observingRefreshStore{RefreshStore: auth.NewRefreshStore(time.Hour)}
			cleanupErr := errors.New("cleanup unavailable")
			if cleanupFails {
				store.revokeErr = cleanupErr
			}
			tokens := auth.NewTokenManager("test-secret-that-is-long-enough-for-testing-123", "issuer", "audience", time.Minute)
			csrfErr := errors.New("csrf entropy failure")
			h := &Handlers{Auth: auth.NewAuthService(users, tokens, store), csrfTokenGenerator: func() (string, error) { return "", csrfErr }}
			res := httptest.NewRecorder()
			h.BrowserLogin(res, httptest.NewRequest(http.MethodPost, "/auth/browser/login", strings.NewReader(`{"email":"user@example.test","password":"password"}`)))
			if res.Code != http.StatusInternalServerError && !(cleanupFails && res.Code == http.StatusServiceUnavailable) {
				t.Fatalf("status=%d", res.Code)
			}
			if len(res.Result().Cookies()) != 0 {
				t.Fatal("failed login set session cookies")
			}
			if strings.Contains(res.Body.String(), store.created) || strings.Contains(res.Body.String(), "csrf entropy failure") {
				t.Fatal("failed login exposed credentials or internal errors")
			}
			if store.created == "" || store.revokeNum != 1 {
				t.Fatalf("cleanup not attempted: created=%t calls=%d", store.created != "", store.revokeNum)
			}
			_, inspectErr := store.RefreshStore.Inspect(store.created)
			if cleanupFails {
				if inspectErr != nil {
					t.Fatalf("session unexpectedly revoked despite cleanup failure: %v", inspectErr)
				}
				// The response path reports cleanup failure; inspect confirms it could not revoke.
			} else if !errors.Is(inspectErr, auth.ErrRefreshTokenInvalid) {
				t.Fatalf("unreturned refresh session remains usable: %v", inspectErr)
			}
			probe, err := h.Auth.Login("user@example.test", "password")
			if err != nil {
				t.Fatal(err)
			}
			_, prepareErr := h.prepareBrowserSession(probe.RefreshToken)
			if !errors.Is(prepareErr, csrfErr) {
				t.Fatalf("CSRF generation error was not preserved: %v", prepareErr)
			}
			if cleanupFails && !errors.Is(prepareErr, auth.ErrRefreshCleanupFailed) {
				t.Fatalf("CSRF cleanup failure was not reported: %v", prepareErr)
			}
		})
	}
}
