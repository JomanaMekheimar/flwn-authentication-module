package main

import (
	"log"
	"net/http"
	"time"

	"flwn-authentication-module/demo"
	"flwn-authentication-module/internal/auth"
	"flwn-authentication-module/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load configuration: %v", err)
	}

	tokens := auth.NewTokenManager(
		cfg.JWTSecret,
		cfg.JWTIssuer,
		cfg.JWTAudience,
		cfg.AccessTokenTTL,
	)
	tokens.SetKeyID(cfg.JWTKeyID)

	// Temporary in-memory store for local development.
	// Replace with Flwn's real user database before production.
	users := auth.NewMemoryUserStore()

	if err := auth.AddDevelopmentUser(users); err != nil {
		log.Fatalf("initialize development user: %v", err)
	}

	refreshStore := auth.NewRefreshStore(cfg.RefreshTokenTTL)

	authService := auth.NewAuthService(
		users,
		tokens,
		refreshStore,
		cfg.RefreshTokenTTL,
	)
	handlers := &demo.Handlers{
		Auth:                authService,
		RefreshCookieSecure: cfg.RefreshCookieSecure,
	}

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           demo.NewRouter(tokens, users, handlers),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("Flwn authentication prototype listening on %s", cfg.HTTPAddr)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server: %v", err)
	}
}
