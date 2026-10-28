package config

import "testing"

func setValidConfig(t *testing.T) {
	t.Helper()
	t.Setenv("JWT_SECRET", "test-secret-that-is-long-enough-for-testing-123")
	t.Setenv("AGENT_TOKENS_ENABLED", "false")
	t.Setenv("REFRESH_COOKIE_SECURE", "true")
	t.Setenv("FLWN_ENV", "")
}

func TestInsecureRefreshCookieRequiresExplicitDevelopmentEnvironment(t *testing.T) {
	setValidConfig(t)
	t.Setenv("REFRESH_COOKIE_SECURE", "false")
	if _, err := Load(); err == nil {
		t.Fatal("accepted insecure refresh cookie outside development")
	}
	setValidConfig(t)
	t.Setenv("REFRESH_COOKIE_SECURE", "false")
	t.Setenv("FLWN_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RefreshCookieSecure {
		t.Fatal("development override did not disable Secure")
	}
}

func TestAgentTokensDefaultDisabledAndCannotBeEnabled(t *testing.T) {
	setValidConfig(t)
	t.Setenv("AGENT_TOKENS_ENABLED", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentTokensEnabled {
		t.Fatal("agent tokens enabled by default")
	}
	setValidConfig(t)
	t.Setenv("AGENT_TOKENS_ENABLED", "true")
	if _, err := Load(); err == nil {
		t.Fatal("configuration accepted unimplemented agent-token issuance")
	}
}
