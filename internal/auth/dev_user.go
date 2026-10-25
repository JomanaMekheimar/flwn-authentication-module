package auth

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// AddDevelopmentUser adds a local-only test account when explicitly enabled.
// Do not enable this in production.
func AddDevelopmentUser(store *MemoryUserStore) error {
	if os.Getenv("FLWN_ENABLE_DEV_USER") != "true" {
		return nil
	}

	email := strings.ToLower(strings.TrimSpace(os.Getenv("FLWN_DEV_EMAIL")))
	password := os.Getenv("FLWN_DEV_PASSWORD")

	if email == "" || password == "" {
		return fmt.Errorf(
			"FLWN_DEV_EMAIL and FLWN_DEV_PASSWORD are required when the dev user is enabled",
		)
	}

	if len(password) < 12 {
		return fmt.Errorf("development password must be at least 12 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash development password: %w", err)
	}

	store.Add(User{
		ID:           "dev-user-001",
		Email:        email,
		WorkspaceID:  "dev-workspace-001",
		PasswordHash: hash,
		Scopes:       []string{"profile:read"},
		Active:       true,
	})

	return nil
}
