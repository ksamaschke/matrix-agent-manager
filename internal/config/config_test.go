package config

import "testing"

func TestLoadRejectsMissingProductionConfiguration(t *testing.T) {
	env := map[string]string{
		"AGENT_MANAGER_ENV": "production",
	}

	_, err := Load(envLookup(env))
	if err == nil {
		t.Fatal("expected production configuration validation to fail")
	}
}

func TestLoadAcceptsDevelopmentConfigurationWithoutExternalServices(t *testing.T) {
	env := map[string]string{
		"AGENT_MANAGER_ENV": "development",
	}

	cfg, err := Load(envLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Environment != "development" {
		t.Fatalf("Environment = %q, want development", cfg.Environment)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
}

func TestLoadUsesConfiguredValuesWithoutLoggingSecrets(t *testing.T) {
	env := map[string]string{
		"AGENT_MANAGER_ENV":                         "production",
		"AGENT_MANAGER_OIDC_ISSUER_URL":             "https://idp.example.invalid/realms/example",
		"AGENT_MANAGER_OIDC_CLIENT_ID":              "agent-manager",
		"AGENT_MANAGER_OIDC_AUDIENCE":               "agent-manager",
		"AGENT_MANAGER_OIDC_CLIENT_SECRET_FILE":     "/var/run/secrets/oidc/client-secret",
		"AGENT_MANAGER_OIDC_REDIRECT_URL":           "https://app.example.invalid/auth/callback",
		"AGENT_MANAGER_OIDC_ROLES_CLAIM":            "roles",
		"AGENT_MANAGER_OIDC_REQUIRED_ROLES":         "matrix-agent-admin,matrix-agent-viewer",
		"AGENT_MANAGER_OIDC_ADMIN_ROLES":            "matrix-agent-admin",
		"AGENT_MANAGER_OIDC_VIEWER_ROLES":           "matrix-agent-admin,matrix-agent-viewer",
		"AGENT_MANAGER_COOKIE_SECURE":               "true",
		"AGENT_MANAGER_SESSION_KEY_FILE":            "/var/run/secrets/session/key",
		"AGENT_MANAGER_MAS_BASE_URL":                "https://mas.example.invalid",
		"AGENT_MANAGER_MAS_TOKEN_URL":               "https://mas.example.invalid/oauth2/token",
		"AGENT_MANAGER_MAS_USERS_URL":               "https://mas.example.invalid/api/admin/v1/users",
		"AGENT_MANAGER_MAS_PERSONAL_SESSIONS_URL":   "https://mas.example.invalid/api/admin/v1/personal-sessions",
		"AGENT_MANAGER_MAS_CLIENT_ID":               "agent-manager-admin",
		"AGENT_MANAGER_MAS_CLIENT_SECRET_FILE":      "/var/run/secrets/mas/client-secret",
		"AGENT_MANAGER_MATRIX_USER_ID_TEMPLATE":     "@{localpart}:example.invalid",
		"AGENT_MANAGER_MATRIX_PROFILE_URL_TEMPLATE": "https://matrix.example.invalid/_matrix/client/v3/profile/{user_id}/displayname",
		"AGENT_MANAGER_SECRET_BACKEND":              "kubernetes",
		"AGENT_MANAGER_SECRET_NAMESPACE":            "agent-manager",
		"AGENT_MANAGER_AGENT_SECRET_NAME_PREFIX":    "matrix-agent",
		"AGENT_MANAGER_AGENT_TOKEN_SCOPE":           "openid urn:matrix:client:api:* urn:matrix:client:device:{device_id}",
		"AGENT_MANAGER_AGENT_DEVICE_ID_TEMPLATE":    "agent-{agent_name}",
		"AGENT_MANAGER_AGENT_TOKEN_EXPIRY_SECONDS":  "2592000",
	}

	cfg, err := Load(envLookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.MASClientSecretFile == "" {
		t.Fatal("MASClientSecretFile must be retained as a path")
	}
	if cfg.MASClientID != "agent-manager-admin" {
		t.Fatalf("MASClientID = %q, want agent-manager-admin", cfg.MASClientID)
	}
}

func envLookup(values map[string]string) Lookup {
	return func(key string) string { return values[key] }
}
