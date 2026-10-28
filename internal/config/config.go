package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr            string
	JWTSecret           string
	JWTIssuer           string
	JWTAudience         string
	JWTKeyID            string
	RefreshCookieSecure bool
	AgentTokensEnabled  bool
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:    getEnv("HTTP_ADDR", ":8080"),
		JWTIssuer:   getEnv("JWT_ISSUER", "flwn-auth"),
		JWTAudience: getEnv("JWT_AUDIENCE", "flwn-api"),
		JWTKeyID:    getEnv("JWT_KEY_ID", "local-v1"),
	}
	cookieSecure, err := strconv.ParseBool(getEnv("REFRESH_COOKIE_SECURE", "true"))
	if err != nil {
		return Config{}, fmt.Errorf("REFRESH_COOKIE_SECURE must be true or false")
	}
	cfg.RefreshCookieSecure = cookieSecure
	if !cookieSecure && getEnv("FLWN_ENV", "") != "development" {
		return Config{}, fmt.Errorf("REFRESH_COOKIE_SECURE=false is allowed only when FLWN_ENV=development")
	}
	agentTokensEnabled, err := strconv.ParseBool(getEnv("AGENT_TOKENS_ENABLED", "false"))
	if err != nil || agentTokensEnabled {
		return Config{}, fmt.Errorf("AGENT_TOKENS_ENABLED must remain false; delegated token issuance is not implemented")
	}
	cfg.AgentTokensEnabled = false

	secret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if len(secret) < 32 {
		return Config{}, fmt.Errorf(
			"JWT_SECRET must contain at least 32 characters",
		)
	}
	cfg.JWTSecret = secret

	ttlText := getEnv("ACCESS_TOKEN_TTL", "15m")
	ttl, err := time.ParseDuration(ttlText)
	if err != nil || ttl <= 0 {
		return Config{}, fmt.Errorf(
			"ACCESS_TOKEN_TTL must be a positive duration, e.g. 15m",
		)
	}
	if ttl > 15*time.Minute {
		return Config{}, fmt.Errorf(
			"ACCESS_TOKEN_TTL cannot exceed 15 minutes in this prototype",
		)
	}
	cfg.AccessTokenTTL = ttl

	refreshTTLText := getEnv("REFRESH_TOKEN_TTL", "168h")
	refreshTTL, err := time.ParseDuration(refreshTTLText)
	if err != nil || refreshTTL <= 0 {
		return Config{}, fmt.Errorf(
			"REFRESH_TOKEN_TTL must be a positive duration, e.g. 168h",
		)
	}
	cfg.RefreshTokenTTL = refreshTTL

	return cfg, nil
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
