package demo

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flwn-authentication-module/internal/auth"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

type Handlers struct {
	Auth                *auth.AuthService
	RefreshCookieSecure bool
	csrfTokenGenerator  func() (string, error)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	result, err := h.Auth.Login(req.Email, req.Password)
	if err != nil {
		status, message := loginErrorResponse(err)
		writeJSON(w, status, map[string]string{"error": message})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"token_type":    "Bearer",
	})
}

func (h *Handlers) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	if strings.TrimSpace(req.RefreshToken) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "refresh token required",
		})
		return
	}

	result, err := h.Auth.Refresh(req.RefreshToken)
	if err != nil {
		status, message := refreshErrorResponse(err)
		writeJSON(w, status, map[string]string{"error": message})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"token_type":    "Bearer",
	})
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	var req logoutRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	if err := h.Auth.Logout(req.RefreshToken); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "logout could not be completed"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// BrowserLogin is the browser-session endpoint. The refresh token is never
// returned in JSON; JavaScript receives only a CSRF token and access token.
func (h *Handlers) BrowserLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	result, err := h.Auth.Login(req.Email, req.Password)
	if err != nil {
		status, message := loginErrorResponse(err)
		writeJSON(w, status, map[string]string{"error": message})
		return
	}
	csrf, err := h.prepareBrowserSession(result.RefreshToken)
	if err != nil {
		status, message := refreshErrorResponse(err)
		writeJSON(w, status, map[string]string{"error": message})
		return
	}
	h.setBrowserCookies(w, result.RefreshToken, csrf)
	writeJSON(w, http.StatusOK, map[string]string{"access_token": result.AccessToken, "token_type": "Bearer", "csrf_token": csrf})
}

func (h *Handlers) BrowserRefresh(w http.ResponseWriter, r *http.Request) {
	if !validCSRF(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf validation failed"})
		return
	}
	cookie, err := r.Cookie("flwn_refresh")
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "refresh token required"})
		return
	}
	result, err := h.Auth.Refresh(cookie.Value)
	if err != nil {
		status, message := refreshErrorResponse(err)
		if !errors.Is(err, auth.ErrMemberStoreUnavailable) &&
			!errors.Is(err, auth.ErrRefreshStoreUnavailable) &&
			!errors.Is(err, auth.ErrRefreshTokenConcurrent) {
			h.clearBrowserCookies(w)
		}
		if errors.Is(err, auth.ErrRefreshCleanupFailed) {
			h.clearBrowserCookies(w)
		}
		writeJSON(w, status, map[string]string{"error": message})
		return
	}
	csrf, err := h.prepareBrowserSession(result.RefreshToken)
	if err != nil {
		h.clearBrowserCookies(w)
		status, message := refreshErrorResponse(err)
		writeJSON(w, status, map[string]string{"error": message})
		return
	}
	h.setBrowserCookies(w, result.RefreshToken, csrf)
	writeJSON(w, http.StatusOK, map[string]string{"access_token": result.AccessToken, "token_type": "Bearer", "csrf_token": csrf})
}

func (h *Handlers) BrowserLogout(w http.ResponseWriter, r *http.Request) {
	if !validCSRF(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf validation failed"})
		return
	}
	var revokeErr error
	if cookie, err := r.Cookie("flwn_refresh"); err == nil {
		revokeErr = h.Auth.Logout(cookie.Value)
	}
	h.clearBrowserCookies(w)
	if revokeErr != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "logout could not be completed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) prepareBrowserSession(refreshToken string) (string, error) {
	generator := h.csrfTokenGenerator
	if generator == nil {
		generator = newCSRFToken
	}
	csrf, err := generator()
	if err != nil {
		return "", errors.Join(err, h.Auth.Logout(refreshToken))
	}
	return csrf, nil
}

func refreshErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, auth.ErrMemberStoreUnavailable),
		errors.Is(err, auth.ErrRefreshStoreUnavailable),
		errors.Is(err, auth.ErrRefreshCleanupFailed):
		return http.StatusServiceUnavailable, "authentication temporarily unavailable"
	case errors.Is(err, auth.ErrRefreshTokenInvalid),
		errors.Is(err, auth.ErrRefreshTokenExpired),
		errors.Is(err, auth.ErrAccountDisabled):
		return http.StatusUnauthorized, "invalid or expired refresh token"
	case errors.Is(err, auth.ErrRefreshTokenConcurrent):
		return http.StatusConflict, "refresh already in progress; retry with the current session"
	default:
		return http.StatusInternalServerError, "unable to refresh session"
	}
}

func loginErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrAccountDisabled):
		return http.StatusUnauthorized, "invalid email or password"
	case errors.Is(err, auth.ErrRefreshStoreUnavailable):
		return http.StatusServiceUnavailable, "authentication temporarily unavailable"
	default:
		return http.StatusInternalServerError, "unable to complete login"
	}
}

func newCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func validCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("flwn_csrf")
	if err != nil {
		return false
	}
	header := r.Header.Get("X-CSRF-Token")
	return header != "" && subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) == 1
}

func (h *Handlers) setBrowserCookies(w http.ResponseWriter, refresh, csrf string) {
	ttl := h.Auth.RefreshTokenTTL()
	maxAge := int(math.Ceil(ttl.Seconds()))
	if maxAge < 1 {
		maxAge = 1
	}
	expires := time.Now().Add(ttl)
	http.SetCookie(w, &http.Cookie{Name: "flwn_refresh", Value: refresh, Path: "/auth/browser", HttpOnly: true, Secure: h.RefreshCookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge, Expires: expires})
	http.SetCookie(w, &http.Cookie{Name: "flwn_csrf", Value: csrf, Path: "/auth/browser", Secure: h.RefreshCookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge, Expires: expires})
}

func (h *Handlers) clearBrowserCookies(w http.ResponseWriter) {
	deletionExpiry := time.Unix(1, 0).UTC()
	http.SetCookie(w, &http.Cookie{Name: "flwn_refresh", Value: "", Path: "/auth/browser", HttpOnly: true, Secure: h.RefreshCookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: deletionExpiry})
	http.SetCookie(w, &http.Cookie{Name: "flwn_csrf", Value: "", Path: "/auth/browser", Secure: h.RefreshCookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: deletionExpiry})
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request must contain exactly one JSON value")
		}
		return err
	}

	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
