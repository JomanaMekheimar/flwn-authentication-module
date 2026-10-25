package demo

import (
	"encoding/json"
	"errors"
	"net/http"

	"flwn-authentication-module/internal/auth"
)

type Handlers struct {
	Auth                *auth.AuthService
	RefreshCookieSecure bool
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req loginRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	result, err := h.Auth.Login(req.Email, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrAccountDisabled) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "account is disabled",
			})
			return
		}

		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid email or password",
		})
		return
	}

	h.setRefreshCookie(w, result.RefreshToken)
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token": result.AccessToken,
		"token_type":   "Bearer",
	})
}

func (h *Handlers) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("flwn_refresh")
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "refresh token required"})
		return
	}
	result, err := h.Auth.Refresh(cookie.Value)
	if err != nil {
		h.clearRefreshCookie(w)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid refresh token"})
		return
	}
	h.setRefreshCookie(w, result.RefreshToken)
	writeJSON(w, http.StatusOK, map[string]string{"access_token": result.AccessToken, "token_type": "Bearer"})
}

func (h *Handlers) setRefreshCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{Name: "flwn_refresh", Value: value, Path: "/auth", HttpOnly: true, Secure: h.RefreshCookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: 7 * 24 * 60 * 60})
}
func (h *Handlers) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "flwn_refresh", Value: "", Path: "/auth", HttpOnly: true, Secure: h.RefreshCookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
