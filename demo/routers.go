package demo

import (
	"net/http"

	"flwn-authentication-module/internal/auth"
)

func NewRouter(tokens *auth.TokenManager, users auth.UserStore, handlers *Handlers) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", HealthHandler)
	mux.HandleFunc("POST /auth/login", handlers.Login)
	mux.HandleFunc("POST /auth/refresh", handlers.Refresh)
	mux.HandleFunc("POST /auth/logout", handlers.Logout)
	mux.HandleFunc("POST /auth/browser/login", handlers.BrowserLogin)
	mux.HandleFunc("POST /auth/browser/refresh", handlers.BrowserRefresh)
	mux.HandleFunc("POST /auth/browser/logout", handlers.BrowserLogout)

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := auth.ClaimsFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "authentication required",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"message":      "Authenticated successfully",
			"user_id":      claims.Subject,
			"workspace_id": claims.WorkspaceID,
			"scopes":       claims.Scopes,
		})
	})

	mux.Handle("GET /api/protected", auth.MemberAuthMiddleware(tokens, users, auth.RequireScope("profile:read", protected)))

	return mux
}
