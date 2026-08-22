package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Lookup retrieves a configuration value by environment variable name.
type Lookup func(string) string

// Config contains deployment-neutral runtime configuration.
// Secret values are deliberately represented by file paths, never by values.
type Config struct {
	Environment string
	HTTPAddr    string

	OIDCIssuerURL        string
	OIDCClientID         string
	OIDCAudience         string
	OIDCClientSecretFile string
	OIDCRedirectURL      string
	OIDCRolesClaim       string
	OIDCRequiredRoles    []string
	OIDCAdminRoles       []string
	OIDCViewerRoles      []string
	CookieSecure         bool
	SessionKeyFile       string
	SessionTTLSeconds    uint32

	MASBaseURL             string
	MASAllowInsecureHTTP   bool
	MASTokenURL            string
	MASUsersURL            string
	MASPersonalSessionsURL string
	MASClientID            string
	MASClientSecretFile    string

	MatrixUserIDTemplate     string
	MatrixProfileURLTemplate string

	SecretBackend           string
	SecretNamespace         string
	AgentSecretNamePrefix   string
	AgentTokenScope         string
	AgentDeviceIDTemplate   string
	AgentTokenExpirySeconds uint32
}

// Load reads and validates configuration from environment variables.
// Development mode has only local defaults. Production requires every
// external trust boundary to be explicitly configured.
func Load(get Lookup) (Config, error) {
	if get == nil {
		return Config{}, errors.New("configuration lookup is required")
	}

	cfg := Config{
		Environment:              valueOr(get("AGENT_MANAGER_ENV"), "development"),
		HTTPAddr:                 valueOr(get("AGENT_MANAGER_HTTP_ADDR"), ":8080"),
		OIDCIssuerURL:            get("AGENT_MANAGER_OIDC_ISSUER_URL"),
		OIDCClientID:             get("AGENT_MANAGER_OIDC_CLIENT_ID"),
		OIDCAudience:             get("AGENT_MANAGER_OIDC_AUDIENCE"),
		OIDCClientSecretFile:     get("AGENT_MANAGER_OIDC_CLIENT_SECRET_FILE"),
		OIDCRedirectURL:          get("AGENT_MANAGER_OIDC_REDIRECT_URL"),
		OIDCRolesClaim:           get("AGENT_MANAGER_OIDC_ROLES_CLAIM"),
		OIDCRequiredRoles:        splitCSV(get("AGENT_MANAGER_OIDC_REQUIRED_ROLES")),
		OIDCAdminRoles:           splitCSV(get("AGENT_MANAGER_OIDC_ADMIN_ROLES")),
		OIDCViewerRoles:          splitCSV(get("AGENT_MANAGER_OIDC_VIEWER_ROLES")),
		CookieSecure:             valueOr(get("AGENT_MANAGER_COOKIE_SECURE"), "false") == "true",
		SessionKeyFile:           get("AGENT_MANAGER_SESSION_KEY_FILE"),
		SessionTTLSeconds:        900,
		MASBaseURL:               get("AGENT_MANAGER_MAS_BASE_URL"),
		MASAllowInsecureHTTP:     valueOr(get("AGENT_MANAGER_MAS_ALLOW_INSECURE_HTTP"), "false") == "true",
		MASTokenURL:              get("AGENT_MANAGER_MAS_TOKEN_URL"),
		MASUsersURL:              get("AGENT_MANAGER_MAS_USERS_URL"),
		MASPersonalSessionsURL:   get("AGENT_MANAGER_MAS_PERSONAL_SESSIONS_URL"),
		MASClientID:              get("AGENT_MANAGER_MAS_CLIENT_ID"),
		MASClientSecretFile:      get("AGENT_MANAGER_MAS_CLIENT_SECRET_FILE"),
		MatrixUserIDTemplate:     get("AGENT_MANAGER_MATRIX_USER_ID_TEMPLATE"),
		MatrixProfileURLTemplate: get("AGENT_MANAGER_MATRIX_PROFILE_URL_TEMPLATE"),
		SecretBackend:            valueOr(get("AGENT_MANAGER_SECRET_BACKEND"), "memory"),
		SecretNamespace:          get("AGENT_MANAGER_SECRET_NAMESPACE"),
		AgentSecretNamePrefix:    get("AGENT_MANAGER_AGENT_SECRET_NAME_PREFIX"),
		AgentTokenScope:          get("AGENT_MANAGER_AGENT_TOKEN_SCOPE"),
		AgentDeviceIDTemplate:    get("AGENT_MANAGER_AGENT_DEVICE_ID_TEMPLATE"),
	}
	if raw := get("AGENT_MANAGER_AGENT_TOKEN_EXPIRY_SECONDS"); raw != "" {
		seconds, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return Config{}, fmt.Errorf("AGENT_MANAGER_AGENT_TOKEN_EXPIRY_SECONDS must be an unsigned integer: %w", err)
		}
		cfg.AgentTokenExpirySeconds = uint32(seconds)
	}
	if raw := get("AGENT_MANAGER_SESSION_TTL_SECONDS"); raw != "" {
		seconds, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return Config{}, fmt.Errorf("AGENT_MANAGER_SESSION_TTL_SECONDS must be an unsigned integer: %w", err)
		}
		cfg.SessionTTLSeconds = uint32(seconds)
	}

	if cfg.Environment != "development" && cfg.Environment != "test" && cfg.Environment != "production" {
		return Config{}, fmt.Errorf("AGENT_MANAGER_ENV must be development, test, or production, got %q", cfg.Environment)
	}
	if cfg.Environment != "production" {
		return cfg, nil
	}

	required := map[string]string{
		"AGENT_MANAGER_OIDC_ISSUER_URL":             cfg.OIDCIssuerURL,
		"AGENT_MANAGER_OIDC_CLIENT_ID":              cfg.OIDCClientID,
		"AGENT_MANAGER_OIDC_AUDIENCE":               cfg.OIDCAudience,
		"AGENT_MANAGER_OIDC_CLIENT_SECRET_FILE":     cfg.OIDCClientSecretFile,
		"AGENT_MANAGER_OIDC_REDIRECT_URL":           cfg.OIDCRedirectURL,
		"AGENT_MANAGER_OIDC_ROLES_CLAIM":            cfg.OIDCRolesClaim,
		"AGENT_MANAGER_SESSION_KEY_FILE":            cfg.SessionKeyFile,
		"AGENT_MANAGER_OIDC_ADMIN_ROLES":            strings.Join(cfg.OIDCAdminRoles, ","),
		"AGENT_MANAGER_OIDC_VIEWER_ROLES":           strings.Join(cfg.OIDCViewerRoles, ","),
		"AGENT_MANAGER_MAS_BASE_URL":                cfg.MASBaseURL,
		"AGENT_MANAGER_MAS_TOKEN_URL":               cfg.MASTokenURL,
		"AGENT_MANAGER_MAS_USERS_URL":               cfg.MASUsersURL,
		"AGENT_MANAGER_MAS_PERSONAL_SESSIONS_URL":   cfg.MASPersonalSessionsURL,
		"AGENT_MANAGER_MAS_CLIENT_ID":               cfg.MASClientID,
		"AGENT_MANAGER_MAS_CLIENT_SECRET_FILE":      cfg.MASClientSecretFile,
		"AGENT_MANAGER_MATRIX_USER_ID_TEMPLATE":     cfg.MatrixUserIDTemplate,
		"AGENT_MANAGER_MATRIX_PROFILE_URL_TEMPLATE": cfg.MatrixProfileURLTemplate,
		"AGENT_MANAGER_SECRET_BACKEND":              cfg.SecretBackend,
		"AGENT_MANAGER_SECRET_NAMESPACE":            cfg.SecretNamespace,
		"AGENT_MANAGER_AGENT_SECRET_NAME_PREFIX":    cfg.AgentSecretNamePrefix,
		"AGENT_MANAGER_AGENT_TOKEN_SCOPE":           cfg.AgentTokenScope,
		"AGENT_MANAGER_AGENT_DEVICE_ID_TEMPLATE":    cfg.AgentDeviceIDTemplate,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return Config{}, fmt.Errorf("%s is required in production", name)
		}
	}
	for name, raw := range map[string]string{
		"AGENT_MANAGER_OIDC_ISSUER_URL":   cfg.OIDCIssuerURL,
		"AGENT_MANAGER_OIDC_REDIRECT_URL": cfg.OIDCRedirectURL,
	} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return Config{}, fmt.Errorf("%s must be an absolute https URL without userinfo", name)
		}
	}
	for name, raw := range map[string]string{
		"AGENT_MANAGER_MAS_BASE_URL":              cfg.MASBaseURL,
		"AGENT_MANAGER_MAS_TOKEN_URL":             cfg.MASTokenURL,
		"AGENT_MANAGER_MAS_USERS_URL":             cfg.MASUsersURL,
		"AGENT_MANAGER_MAS_PERSONAL_SESSIONS_URL": cfg.MASPersonalSessionsURL,
	} {
		u, err := url.Parse(raw)
		secure := u.Scheme == "https" || (cfg.MASAllowInsecureHTTP && u.Scheme == "http")
		if err != nil || !secure || u.Host == "" || u.User != nil {
			return Config{}, fmt.Errorf("%s must be an absolute HTTPS URL, or HTTP only when MASAllowInsecureHTTP is true", name)
		}
	}
	for name, raw := range map[string]string{
		"AGENT_MANAGER_MATRIX_PROFILE_URL_TEMPLATE": cfg.MatrixProfileURLTemplate,
	} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Count(raw, "{user_id}") != 1 {
			return Config{}, fmt.Errorf("%s must be an absolute HTTPS URL without userinfo, query, or fragment and contain one {user_id} placeholder", name)
		}
	}
	if strings.Count(cfg.MatrixUserIDTemplate, "{localpart}") != 1 || strings.ContainsAny(cfg.MatrixUserIDTemplate, "\r\n") {
		return Config{}, errors.New("AGENT_MANAGER_MATRIX_USER_ID_TEMPLATE must contain one {localpart} placeholder")
	}
	if cfg.SecretBackend != "kubernetes" {
		return Config{}, fmt.Errorf("production secret backend must be kubernetes, got %q", cfg.SecretBackend)
	}
	if len(cfg.OIDCRequiredRoles) == 0 {
		return Config{}, errors.New("AGENT_MANAGER_OIDC_REQUIRED_ROLES must contain at least one role in production")
	}
	if len(cfg.OIDCAdminRoles) == 0 || len(cfg.OIDCViewerRoles) == 0 {
		return Config{}, errors.New("AGENT_MANAGER_OIDC_ADMIN_ROLES and AGENT_MANAGER_OIDC_VIEWER_ROLES are required in production")
	}
	if cfg.AgentTokenExpirySeconds == 0 {
		return Config{}, errors.New("AGENT_MANAGER_AGENT_TOKEN_EXPIRY_SECONDS must be positive in production")
	}
	if cfg.SessionTTLSeconds == 0 {
		return Config{}, errors.New("AGENT_MANAGER_SESSION_TTL_SECONDS must be positive in production")
	}
	if !cfg.CookieSecure {
		return Config{}, errors.New("AGENT_MANAGER_COOKIE_SECURE must be true in production")
	}
	return cfg, nil
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
