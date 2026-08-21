package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Lookup retrieves a configuration value by environment variable name.
type Lookup func(string) string

// Config contains deployment-neutral runtime configuration.
// Secret values are deliberately represented by file paths, never by values.
type Config struct {
	Environment string
	HTTPAddr    string

	OIDCIssuerURL string
	OIDCClientID  string
	OIDCAudience  string

	MASBaseURL          string
	MASClientID         string
	MASClientSecretFile string

	SecretBackend   string
	SecretNamespace string
}

// Load reads and validates configuration from environment variables.
// Development mode has only local defaults. Production requires every
// external trust boundary to be explicitly configured.
func Load(get Lookup) (Config, error) {
	if get == nil {
		return Config{}, errors.New("configuration lookup is required")
	}

	cfg := Config{
		Environment:         valueOr(get("AGENT_MANAGER_ENV"), "development"),
		HTTPAddr:            valueOr(get("AGENT_MANAGER_HTTP_ADDR"), ":8080"),
		OIDCIssuerURL:       get("AGENT_MANAGER_OIDC_ISSUER_URL"),
		OIDCClientID:        get("AGENT_MANAGER_OIDC_CLIENT_ID"),
		OIDCAudience:        get("AGENT_MANAGER_OIDC_AUDIENCE"),
		MASBaseURL:          get("AGENT_MANAGER_MAS_BASE_URL"),
		MASClientID:         get("AGENT_MANAGER_MAS_CLIENT_ID"),
		MASClientSecretFile: get("AGENT_MANAGER_MAS_CLIENT_SECRET_FILE"),
		SecretBackend:       valueOr(get("AGENT_MANAGER_SECRET_BACKEND"), "memory"),
		SecretNamespace:     get("AGENT_MANAGER_SECRET_NAMESPACE"),
	}

	if cfg.Environment != "development" && cfg.Environment != "test" && cfg.Environment != "production" {
		return Config{}, fmt.Errorf("AGENT_MANAGER_ENV must be development, test, or production, got %q", cfg.Environment)
	}
	if cfg.Environment != "production" {
		return cfg, nil
	}

	required := map[string]string{
		"AGENT_MANAGER_OIDC_ISSUER_URL":        cfg.OIDCIssuerURL,
		"AGENT_MANAGER_OIDC_CLIENT_ID":         cfg.OIDCClientID,
		"AGENT_MANAGER_OIDC_AUDIENCE":          cfg.OIDCAudience,
		"AGENT_MANAGER_MAS_BASE_URL":           cfg.MASBaseURL,
		"AGENT_MANAGER_MAS_CLIENT_ID":          cfg.MASClientID,
		"AGENT_MANAGER_MAS_CLIENT_SECRET_FILE": cfg.MASClientSecretFile,
		"AGENT_MANAGER_SECRET_BACKEND":         cfg.SecretBackend,
		"AGENT_MANAGER_SECRET_NAMESPACE":       cfg.SecretNamespace,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return Config{}, fmt.Errorf("%s is required in production", name)
		}
	}
	for name, raw := range map[string]string{
		"AGENT_MANAGER_OIDC_ISSUER_URL": cfg.OIDCIssuerURL,
		"AGENT_MANAGER_MAS_BASE_URL":    cfg.MASBaseURL,
	} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return Config{}, fmt.Errorf("%s must be an absolute https URL without userinfo", name)
		}
	}
	if cfg.SecretBackend != "kubernetes" {
		return Config{}, fmt.Errorf("production secret backend must be kubernetes, got %q", cfg.SecretBackend)
	}
	return cfg, nil
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
