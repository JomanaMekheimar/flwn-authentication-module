package auth

import "slices"

// HasScope reports whether the token contains the requested scope.
func HasScope(claims *Claims, requiredScope string) bool {
	if claims == nil || requiredScope == "" {
		return false
	}

	return slices.Contains(claims.Scopes, requiredScope)
}
