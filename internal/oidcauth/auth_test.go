package oidcauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ksamaschke/matrix-agent-manager/internal/session"
)

func TestParseRolesRequiresConfiguredClaim(t *testing.T) {
	claims := map[string]any{
		"roles":  []any{"matrix-agent-viewer", "matrix-agent-admin"},
		"groups": []any{"other"},
	}

	roles, err := rolesFromClaims(claims, "roles")
	if err != nil {
		t.Fatalf("rolesFromClaims() error = %v", err)
	}
	if len(roles) != 2 || roles[1] != "matrix-agent-admin" {
		t.Fatalf("roles = %#v", roles)
	}
	if _, err := rolesFromClaims(claims, "missing"); err == nil {
		t.Fatal("expected missing configured role claim to fail")
	}
}

func TestParseRolesRejectsUnexpectedShape(t *testing.T) {
	if _, err := rolesFromClaims(map[string]any{"roles": "matrix-agent-admin"}, "roles"); err == nil {
		t.Fatal("expected scalar role claim to fail")
	}
}

func TestParseNestedKeycloakRealmRoles(t *testing.T) {
	roles, err := rolesFromClaims(map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"matrix-agent-admin"},
		},
	}, "realm_access.roles")
	if err != nil {
		t.Fatalf("rolesFromClaims() error = %v", err)
	}
	if len(roles) != 1 || roles[0] != "matrix-agent-admin" {
		t.Fatalf("roles = %#v", roles)
	}
}

func TestAuthenticatorStateIsOpaqueAndBoundToCallback(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	codec, err := session.NewKey(strings.Repeat("k", 32), func() time.Time { return clock })
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}

	auth, err := newTestAuthenticator(codec, clock)
	if err != nil {
		t.Fatalf("newTestAuthenticator() error = %v", err)
	}
	state, err := auth.sealState(statePayload{Nonce: "nonce", Verifier: "verifier"})
	if err != nil {
		t.Fatalf("sealState() error = %v", err)
	}
	if strings.Contains(state, "verifier") || strings.Contains(state, "nonce") {
		t.Fatal("OIDC state contains plaintext sensitive values")
	}

	payload, err := auth.openState(state)
	if err != nil {
		t.Fatalf("openState() error = %v", err)
	}
	if payload.Nonce != "nonce" || payload.Verifier != "verifier" {
		t.Fatalf("payload = %+v", payload)
	}
	if _, err := auth.openState(state); err == nil {
		t.Fatal("expected OIDC state to be single-use")
	}
}

func TestRequireAnyRole(t *testing.T) {
	identity := Identity{Subject: "synthetic-user", Roles: []string{"viewer"}}
	if err := identity.RequireAnyRole("admin", "viewer"); err != nil {
		t.Fatalf("RequireAnyRole() error = %v", err)
	}
	if err := identity.RequireAnyRole("admin"); err == nil {
		t.Fatal("expected missing role to fail")
	}
}

func TestOIDCConfigRejectsUnsafeProductionURL(t *testing.T) {
	_, err := New(context.Background(), Config{
		IssuerURL:        "http://idp.example.invalid",
		ClientID:         "synthetic-client",
		ClientSecretFile: "synthetic-client-secret",
		Audience:         "synthetic-client",
		RedirectURL:      "https://app.example.invalid/auth/callback",
		RolesClaim:       "roles",
		RequiredRoles:    []string{"admin"},
		Codec:            codecForTest(t),
		StateStore:       NewMemoryStateStore(),
		ReadSecret:       func(string) ([]byte, error) { return []byte("synthetic-secret"), nil },
		CookieSecure:     true,
		HTTPClient:       &http.Client{},
	})
	if err == nil {
		t.Fatal("expected insecure issuer URL to fail")
	}
}

func TestCallbackOriginMustBeConfigured(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	_, err := New(context.Background(), Config{
		IssuerURL:         server.URL,
		ClientID:          "synthetic-client",
		ClientSecretFile:  "synthetic-client-secret",
		Audience:          "synthetic-client",
		RedirectURL:       "http://app.example.invalid/auth/callback",
		RolesClaim:        "roles",
		RequiredRoles:     []string{"admin"},
		Codec:             codecForTest(t),
		StateStore:        NewMemoryStateStore(),
		ReadSecret:        func(string) ([]byte, error) { return []byte("synthetic-secret"), nil },
		AllowInsecureHTTP: true,
		HTTPClient:        server.Client(),
	})
	if err == nil {
		t.Fatal("expected discovery failure from invalid provider")
	}
}

func codecForTest(t *testing.T) *session.Codec {
	t.Helper()
	codec, err := session.NewKey(strings.Repeat("k", 32), time.Now)
	if err != nil {
		t.Fatalf("session codec: %v", err)
	}
	return codec
}

func newTestAuthenticator(codec *session.Codec, now time.Time) (*Authenticator, error) {
	return &Authenticator{
		codec:      codec,
		stateStore: NewMemoryStateStoreWithClock(4096, func() time.Time { return now }),
		now:        func() time.Time { return now },
		rolesClaim: "roles",
		sessionTTL: defaultSessionTTL,
	}, nil
}
