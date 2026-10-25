package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
)

type contextKey string

const ClaimsContextKey contextKey = "auth_claims"

func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*Claims)
	return claims, ok && claims != nil
}

func AuthMiddleware(
	tokens *TokenManager,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		parts := strings.Fields(header)

		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeAuthError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}

		claims, err := tokens.VerifyAccessToken(parts[1])
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "invalid or expired access token")
			return
		}

		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MemberAuthMiddleware also checks current member status, workspace membership,
// and that token scopes remain within the member's current grants.
func MemberAuthMiddleware(tokens *TokenManager, users UserStore, next http.Handler) http.Handler {
	return AuthMiddleware(tokens, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := ClaimsFromContext(r.Context())
		user, err := users.FindByID(claims.Subject)
		if err != nil || user == nil || !user.Active {
			writeAuthError(w, http.StatusUnauthorized, "member is inactive")
			return
		}
		if user.WorkspaceID != claims.WorkspaceID {
			writeAuthError(w, http.StatusForbidden, "workspace access denied")
			return
		}
		for _, scope := range claims.Scopes {
			if !slices.Contains(user.Scopes, scope) {
				writeAuthError(w, http.StatusForbidden, "scope access denied")
				return
			}
		}
		next.ServeHTTP(w, r)
	}))
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}
