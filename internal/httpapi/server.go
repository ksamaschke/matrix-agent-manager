package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/ksamaschke/matrix-agent-manager/internal/agents"
	"github.com/ksamaschke/matrix-agent-manager/internal/oidcauth"
)

const csrfCookieName = "agent_manager_csrf"

// Authenticator is the browser-facing subset of the generic OIDC boundary.
type Authenticator interface {
	LoginURL() (string, error)
	Complete(context.Context, string, string) (oidcauth.Identity, *http.Cookie, error)
	IdentityFromRequest(*http.Request) (oidcauth.Identity, error)
}

type AgentService interface {
	List(context.Context) ([]agents.Result, error)
	Create(context.Context, agents.CreateRequest) (agents.Result, error)
	Rotate(context.Context, string) (agents.Result, error)
	Deactivate(context.Context, string) (agents.Result, error)
}

// Server exposes the authenticated admin UI/API.
type Server struct {
	auth              Authenticator
	agents            AgentService
	adminRoles        []string
	viewerRoles       []string
	sessionCookieName string
}

// ServerConfig keeps deployment-specific authorization names outside handlers.
type ServerConfig struct {
	AdminRoles        []string
	ViewerRoles       []string
	SessionCookieName string
}

func NewServer(auth Authenticator, service AgentService, config ServerConfig) (*Server, error) {
	if auth == nil || service == nil {
		return nil, errors.New("authenticator and agent service are required")
	}
	if len(config.AdminRoles) == 0 || len(config.ViewerRoles) == 0 {
		return nil, errors.New("admin and viewer roles are required")
	}
	cookieName := strings.TrimSpace(config.SessionCookieName)
	if cookieName == "" {
		cookieName = "agent_manager_session"
	}
	return &Server{
		auth:              auth,
		agents:            service,
		adminRoles:        append([]string(nil), config.AdminRoles...),
		viewerRoles:       append([]string(nil), config.ViewerRoles...),
		sessionCookieName: cookieName,
	}, nil
}

// NewHandler returns the deployment-neutral HTTP handler for health and admin UI/API.
func (s *Server) NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.HandleFunc("GET /readyz", health)
	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /auth/logout", s.logout)
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /api/agents", s.listAgents)
	mux.HandleFunc("POST /api/agents", s.createAgent)
	mux.HandleFunc("POST /api/agents/{name}/rotate", s.rotateAgent)
	mux.HandleFunc("POST /api/agents/{name}/deactivate", s.deactivateAgent)
	return mux
}

func health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	url, err := s.auth.LoginURL()
	if err != nil {
		http.Error(w, "login unavailable", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		http.Error(w, "OIDC login denied", http.StatusUnauthorized)
		return
	}
	identity, cookie, err := s.auth.Complete(r.Context(), r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "OIDC login failed", http.StatusUnauthorized)
		return
	}
	if err := identity.RequireAnyRole(s.viewerRoles...); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	http.SetCookie(w, cookie)
	s.setCSRFCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	identity, err := s.auth.IdentityFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	if err := identity.RequireAnyRole(s.viewerRoles...); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	csrf := s.ensureCSRFCookie(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="csrf-token" content="%s"><title>Matrix Agent Manager</title></head><body><h1>Matrix Agent Manager</h1><p>Authenticated agent administration.</p><p>Use the JSON API with the CSRF token from this page.</p><form method="post" action="/auth/logout"><input type="hidden" name="csrf" value="%s"><button>Log out</button></form></body></html>`, template.HTMLEscapeString(csrf), template.HTMLEscapeString(csrf))
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireViewer(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	result, err := s.agents.List(r.Context())
	if err != nil {
		http.Error(w, "agent list failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) createAgent(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if _, err := s.requireAdmin(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var request agents.CreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	result, err := s.agents.Create(r.Context(), request)
	if err != nil {
		http.Error(w, "agent creation failed", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) rotateAgent(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if _, err := s.requireAdmin(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	result, err := s.agents.Rotate(r.Context(), r.PathValue("name"))
	if err != nil {
		http.Error(w, "agent rotation failed", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) deactivateAgent(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if _, err := s.requireAdmin(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	result, err := s.agents.Deactivate(r.Context(), r.PathValue("name"))
	if err != nil {
		http.Error(w, "agent deactivation failed", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) requireViewer(r *http.Request) (oidcauth.Identity, error) {
	identity, err := s.auth.IdentityFromRequest(r)
	if err != nil {
		return oidcauth.Identity{}, err
	}
	return identity, identity.RequireAnyRole(s.viewerRoles...)
}

func (s *Server) requireAdmin(r *http.Request) (oidcauth.Identity, error) {
	identity, err := s.auth.IdentityFromRequest(r)
	if err != nil {
		return oidcauth.Identity{}, err
	}
	return identity, identity.RequireAnyRole(s.adminRoles...)
}

func (s *Server) checkCSRF(r *http.Request) error {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return errors.New("CSRF cookie missing")
	}
	header := r.Header.Get("X-CSRF-Token")
	if header == "" {
		header = r.FormValue("csrf")
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
		return errors.New("invalid CSRF token")
	}
	return nil
}

func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(csrfCookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	return s.setCSRFCookie(w)
}

func (s *Server) setCSRFCookie(w http.ResponseWriter) string {
	valueBytes := make([]byte, 32)
	if _, err := rand.Read(valueBytes); err != nil {
		return ""
	}
	value := base64.RawURLEncoding.EncodeToString(valueBytes)
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: value, Path: "/", Secure: true, SameSite: http.SameSiteLaxMode})
	return value
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
