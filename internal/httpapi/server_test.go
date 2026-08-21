package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ksamaschke/matrix-agent-manager/internal/agents"
	"github.com/ksamaschke/matrix-agent-manager/internal/oidcauth"
)

type fakeAuth struct {
	identity oidcauth.Identity
}

func (f *fakeAuth) LoginURL() (string, error) { return "https://idp.example.invalid/auth", nil }
func (f *fakeAuth) Complete(context.Context, string, string) (oidcauth.Identity, *http.Cookie, error) {
	return f.identity, &http.Cookie{Name: "agent_manager_session", Value: "synthetic-session", HttpOnly: true}, nil
}
func (f *fakeAuth) IdentityFromRequest(*http.Request) (oidcauth.Identity, error) {
	if f.identity.Subject == "" {
		return oidcauth.Identity{}, context.Canceled
	}
	return f.identity, nil
}

type fakeAgentService struct {
	created []agents.CreateRequest
}

func (f *fakeAgentService) List(context.Context) ([]agents.Result, error) {
	return []agents.Result{{AgentName: "codex", DisplayName: "Codex", Status: agents.StatusActive, Generation: 1}}, nil
}
func (f *fakeAgentService) Create(_ context.Context, request agents.CreateRequest) (agents.Result, error) {
	f.created = append(f.created, request)
	return agents.Result{AgentName: request.AgentName, DisplayName: request.DisplayName, OneTimeToken: "synthetic-token", Generation: 1, Status: agents.StatusActive}, nil
}
func (f *fakeAgentService) Rotate(context.Context, string) (agents.Result, error) {
	return agents.Result{AgentName: "codex", OneTimeToken: "synthetic-rotated-token", Generation: 2, Status: agents.StatusActive}, nil
}
func (f *fakeAgentService) Deactivate(context.Context, string) (agents.Result, error) {
	return agents.Result{AgentName: "codex", Status: agents.StatusDeactivated}, nil
}
func (f *fakeAgentService) Revoke(context.Context, string) (agents.Result, error) {
	return agents.Result{AgentName: "codex", Status: agents.StatusRevoked}, nil
}
func (f *fakeAgentService) Remove(context.Context, string) (agents.Result, error) {
	return agents.Result{AgentName: "codex", Status: agents.StatusDeactivated}, nil
}

func newTestHTTPServer(t *testing.T, identity oidcauth.Identity) (*Server, *fakeAgentService) {
	t.Helper()
	service := &fakeAgentService{}
	server, err := NewServer(&fakeAuth{identity: identity}, service, ServerConfig{
		AdminRoles:  []string{"admin"},
		ViewerRoles: []string{"admin", "viewer"},
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	return server, service
}

func TestHTTPAuthAndRoleBoundaries(t *testing.T) {
	server, _ := newTestHTTPServer(t, oidcauth.Identity{Subject: "user", Roles: []string{"viewer"}})
	req := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	rec := httptest.NewRecorder()
	server.NewHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer GET status = %d", rec.Code)
	}

	body := strings.NewReader(`{"agent_name":"codex","display_name":"Codex"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/agents", body)
	rec = httptest.NewRecorder()
	server.NewHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST status = %d, want 403", rec.Code)
	}
}

func TestHTTPMutationRequiresCSRFAndReturnsTokenOnlyOnCreate(t *testing.T) {
	server, service := newTestHTTPServer(t, oidcauth.Identity{Subject: "admin", Roles: []string{"admin"}})
	req := httptest.NewRequest(http.MethodPost, "/api/agents", strings.NewReader(`{"agent_name":"codex","display_name":"Codex"}`))
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf"})
	rec := httptest.NewRecorder()
	server.NewHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF header status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/agents", strings.NewReader(`{"agent_name":"codex","display_name":"Codex"}`))
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf"})
	req.Header.Set("X-CSRF-Token", "csrf")
	rec = httptest.NewRecorder()
	server.NewHandler().ServeHTTP(rec, req)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var result agents.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.OneTimeToken != "synthetic-token" {
		t.Fatalf("token = %q", result.OneTimeToken)
	}
	if len(service.created) != 1 {
		t.Fatalf("created = %d", len(service.created))
	}

	req = httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	rec = httptest.NewRecorder()
	server.NewHandler().ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "synthetic-token") {
		t.Fatal("ordinary list leaked token")
	}
}

func TestHTTPRemoveRequiresCSRFAndAdmin(t *testing.T) {
	server, _ := newTestHTTPServer(t, oidcauth.Identity{Subject: "admin", Roles: []string{"admin"}})
	req := httptest.NewRequest(http.MethodDelete, "/api/agents/codex", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf"})
	req.Header.Set("X-CSRF-Token", "csrf")
	rec := httptest.NewRecorder()
	server.NewHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHealthEndpointDoesNotRequireAuth(t *testing.T) {
	server, _ := newTestHTTPServer(t, oidcauth.Identity{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	server.NewHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d", rec.Code)
	}
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
}
