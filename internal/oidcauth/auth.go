package oidcauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ksamaschke/matrix-agent-manager/internal/session"
	"golang.org/x/oauth2"
)

const (
	statePurpose   = "oidc-state"
	sessionPurpose = "oidc-session"
)

// Config contains deployment-neutral OIDC settings.
type Config struct {
	IssuerURL         string
	ClientID          string
	ClientSecretFile  string
	Audience          string
	RedirectURL       string
	RolesClaim        string
	RequiredRoles     []string
	CookieName        string
	CookieSecure      bool
	AllowInsecureHTTP bool
	Codec             *session.Codec
	StateStore        StateStore
	ReadSecret        func(string) ([]byte, error)
	HTTPClient        *http.Client
}

// Identity is the minimum authenticated identity used by authorization.
type Identity struct {
	Subject string
	Roles   []string
}

// RequireAnyRole authorizes an identity against configured role names.
func (i Identity) RequireAnyRole(required ...string) error {
	for _, wanted := range required {
		for _, role := range i.Roles {
			if role == wanted {
				return nil
			}
		}
	}
	return errors.New("required role is missing")
}

type statePayload struct {
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

type identityPayload struct {
	Subject string   `json:"subject"`
	Roles   []string `json:"roles"`
	Expiry  int64    `json:"expiry"`
}

// Authenticator performs OIDC discovery and authorization-code validation.
type Authenticator struct {
	provider      *oidc.Provider
	verifier      *oidc.IDTokenVerifier
	oauth         oauth2.Config
	codec         *session.Codec
	stateStore    StateStore
	now           func() time.Time
	rolesClaim    string
	requiredRoles []string
	cookieName    string
	cookieSecure  bool
}

// New discovers the configured OIDC provider and prepares strict token validation.
func New(ctx context.Context, config Config) (*Authenticator, error) {
	if config.Codec == nil {
		return nil, errors.New("OIDC session codec is required")
	}
	if strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.Audience) == "" {
		return nil, errors.New("OIDC client ID and audience are required")
	}
	if strings.TrimSpace(config.ClientSecretFile) == "" {
		return nil, errors.New("OIDC client secret file is required")
	}
	if strings.TrimSpace(config.RolesClaim) == "" {
		return nil, errors.New("OIDC roles claim is required")
	}
	if len(config.RequiredRoles) == 0 {
		return nil, errors.New("at least one required OIDC role is required")
	}
	if config.StateStore == nil {
		return nil, errors.New("OIDC state store is required")
	}
	if !config.CookieSecure && !config.AllowInsecureHTTP {
		return nil, errors.New("secure cookies are required unless insecure HTTP is explicitly enabled")
	}
	if err := validateURL("OIDC issuer", config.IssuerURL, config.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	if err := validateURL("OIDC redirect", config.RedirectURL, config.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	readSecret := config.ReadSecret
	if readSecret == nil {
		readSecret = os.ReadFile
	}
	secret, err := readSecret(config.ClientSecretFile)
	if err != nil {
		return nil, fmt.Errorf("read OIDC client secret: %w", err)
	}
	clientSecret := strings.TrimSpace(string(secret))
	if clientSecret == "" {
		return nil, errors.New("OIDC client secret is empty")
	}
	providerCtx := oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(providerCtx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: config.Audience})
	cookieName := config.CookieName
	if cookieName == "" {
		cookieName = "agent_manager_session"
	}
	return &Authenticator{
		provider: provider,
		verifier: verifier,
		oauth: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  config.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile"},
		},
		codec:         config.Codec,
		stateStore:    config.StateStore,
		now:           time.Now,
		rolesClaim:    config.RolesClaim,
		requiredRoles: append([]string(nil), config.RequiredRoles...),
		cookieName:    cookieName,
		cookieSecure:  config.CookieSecure,
	}, nil
}

// LoginURL creates a stateful PKCE authorization URL.
func (a *Authenticator) LoginURL() (string, error) {
	nonce, err := randomValue(32)
	if err != nil {
		return "", fmt.Errorf("generate OIDC nonce: %w", err)
	}
	verifier, err := randomValue(32)
	if err != nil {
		return "", fmt.Errorf("generate PKCE verifier: %w", err)
	}
	state, err := a.sealState(statePayload{Nonce: nonce, Verifier: verifier})
	if err != nil {
		return "", err
	}
	return a.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)), nil
}

// Complete exchanges the callback code, verifies the ID token and roles, and
// returns a session cookie value. The state value is single-use at the handler
// layer and must be deleted after a successful exchange.
func (a *Authenticator) Complete(ctx context.Context, state, code string) (Identity, *http.Cookie, error) {
	if strings.TrimSpace(state) == "" || strings.TrimSpace(code) == "" {
		return Identity{}, nil, errors.New("OIDC state and code are required")
	}
	stateData, err := a.openState(state)
	if err != nil {
		return Identity{}, nil, err
	}
	token, err := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(stateData.Verifier))
	if err != nil {
		return Identity{}, nil, fmt.Errorf("exchange OIDC authorization code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, nil, errors.New("OIDC token response did not contain an ID token")
	}
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, nil, fmt.Errorf("verify OIDC ID token: %w", err)
	}
	if idToken.Nonce != stateData.Nonce {
		return Identity{}, nil, errors.New("OIDC nonce mismatch")
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, nil, fmt.Errorf("read OIDC claims: %w", err)
	}
	roles, err := rolesFromClaims(claims, a.rolesClaim)
	if err != nil {
		return Identity{}, nil, err
	}
	identity := Identity{Subject: idToken.Subject, Roles: roles}
	if err := identity.RequireAnyRole(a.requiredRoles...); err != nil {
		return Identity{}, nil, err
	}
	sessionValue, err := a.codec.Seal(sessionPurpose, a.now().Add(8*time.Hour), identityPayload{
		Subject: identity.Subject,
		Roles:   identity.Roles,
		Expiry:  a.now().Add(8 * time.Hour).Unix(),
	})
	if err != nil {
		return Identity{}, nil, err
	}
	cookie := &http.Cookie{
		Name:     a.cookieName,
		Value:    sessionValue,
		Path:     "/",
		Secure:   a.cookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   8 * 60 * 60,
	}
	return identity, cookie, nil
}

// IdentityFromRequest validates the opaque session cookie.
func (a *Authenticator) IdentityFromRequest(r *http.Request) (Identity, error) {
	cookie, err := r.Cookie(a.cookieName)
	if err != nil {
		return Identity{}, errors.New("authentication required")
	}
	var payload identityPayload
	if err := a.codec.Open(cookie.Value, sessionPurpose, &payload); err != nil {
		return Identity{}, errors.New("authentication required")
	}
	if payload.Subject == "" {
		return Identity{}, errors.New("authenticated subject is missing")
	}
	return Identity{Subject: payload.Subject, Roles: payload.Roles}, nil
}

func (a *Authenticator) sealState(payload statePayload) (string, error) {
	expiresAt := a.now().Add(5 * time.Minute)
	token, err := a.codec.Seal(statePurpose, expiresAt, payload)
	if err != nil {
		return "", err
	}
	if err := a.stateStore.Put(token, expiresAt); err != nil {
		return "", fmt.Errorf("store OIDC state: %w", err)
	}
	return token, nil
}

func (a *Authenticator) openState(token string) (statePayload, error) {
	if !a.stateStore.Consume(token, a.now()) {
		return statePayload{}, errors.New("invalid OIDC state")
	}
	var payload statePayload
	if err := a.codec.Open(token, statePurpose, &payload); err != nil {
		return statePayload{}, errors.New("invalid OIDC state")
	}
	if payload.Nonce == "" || payload.Verifier == "" {
		return statePayload{}, errors.New("OIDC state is incomplete")
	}
	return payload, nil
}

func rolesFromClaims(claims map[string]any, claimName string) ([]string, error) {
	value, ok := claims[claimName]
	if !ok {
		return nil, fmt.Errorf("OIDC role claim %q is missing", claimName)
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("OIDC role claim %q must be an array", claimName)
	}
	roles := make([]string, 0, len(items))
	for _, item := range items {
		role, ok := item.(string)
		if !ok || strings.TrimSpace(role) == "" {
			return nil, fmt.Errorf("OIDC role claim %q contains a non-string role", claimName)
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func validateURL(name, raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%s must be an absolute URL without userinfo or fragment", name)
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return fmt.Errorf("%s must use HTTPS", name)
	}
	return nil
}

func randomValue(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
