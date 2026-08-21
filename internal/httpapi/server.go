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

const defaultCSRFCookieName = "agent_manager_csrf"

// csrfCookieName is retained for package-level tests and defaults.
const csrfCookieName = defaultCSRFCookieName

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
	Revoke(context.Context, string) (agents.Result, error)
	Remove(context.Context, string) (agents.Result, error)
}

// Server exposes the authenticated admin UI/API.
type Server struct {
	auth              Authenticator
	agents            AgentService
	adminRoles        []string
	viewerRoles       []string
	sessionCookieName string
	csrfCookieName    string
	cookieSecure      bool
}

// ServerConfig keeps deployment-specific authorization names outside handlers.
type ServerConfig struct {
	AdminRoles        []string
	ViewerRoles       []string
	SessionCookieName string
	CSRFCookieName    string
	CookieSecure      bool
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
	csrfName := strings.TrimSpace(config.CSRFCookieName)
	if csrfName == "" {
		csrfName = defaultCSRFCookieName
	}
	return &Server{
		auth:              auth,
		agents:            service,
		adminRoles:        append([]string(nil), config.AdminRoles...),
		viewerRoles:       append([]string(nil), config.ViewerRoles...),
		sessionCookieName: cookieName,
		csrfCookieName:    csrfName,
		cookieSecure:      config.CookieSecure,
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
	mux.HandleFunc("POST /api/agents/{name}/revoke", s.revokeAgent)
	mux.HandleFunc("DELETE /api/agents/{name}", s.removeAgent)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		mux.ServeHTTP(w, r)
	})
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
	http.SetCookie(w, &http.Cookie{Name: s.sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: s.csrfCookieName, Value: "", Path: "/", MaxAge: -1, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode})
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
	// The page has inline JavaScript for the small deployment-neutral MVP. Bind it
	// to a fresh nonce instead of permitting arbitrary inline script execution.
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		http.Error(w, "page unavailable", http.StatusInternalServerError)
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Cache-Control", "no-store")
	csrf := s.ensureCSRFCookie(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="csrf-token" content="%s"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Matrix Agent Manager</title>
<style>body{font:16px system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#202124}form{display:flex;gap:.5rem;flex-wrap:wrap;margin:1rem 0}input,button{font:inherit;padding:.45rem .7rem}button{cursor:pointer}.agent{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:.7rem 0}.token{background:#fff4ce;border:1px solid #e0b400;padding:1rem;white-space:pre-wrap;overflow-wrap:anywhere}.muted{color:#666}</style></head>
<body><h1>Matrix Agent Manager</h1><p class="muted">Create and operate Matrix agent identities. Tokens are shown only immediately after creation or rotation.</p>
<form id="create"><input name="agent_name" required pattern="[a-z0-9][a-z0-9-]{0,63}" placeholder="agent name"><input name="display_name" required placeholder="display name"><button>Create agent</button></form>
<form method="post" action="/auth/logout"><input type="hidden" name="csrf" value="%s"><button>Log out</button></form>
<div id="message" aria-live="polite"></div><section id="agents"><p>Loading…</p></section>
<script nonce="%s">
const csrf=document.querySelector('meta[name="csrf-token"]').content;
const message=document.querySelector('#message');
const section=document.querySelector('#agents');
function showMessage(text,token){message.replaceChildren();const p=document.createElement('p');p.textContent=text;message.append(p);if(token){const pre=document.createElement('pre');pre.className='token';pre.textContent=token;message.append(pre);}}
async function api(path,options={}){options.headers={...(options.headers||{}),'X-CSRF-Token':csrf,'Content-Type':'application/json'};const response=await fetch(path,options);const text=await response.text();let data={};try{data=JSON.parse(text)}catch{}if(!response.ok)throw new Error(data.error||text||('HTTP '+response.status));return data;}
async function load(){try{const list=await api('/api/agents',{headers:{}});section.replaceChildren();if(!list.length){const p=document.createElement('p');p.textContent='No agents registered.';section.append(p);return;}for(const agent of list){const card=document.createElement('article');card.className='agent';const title=document.createElement('strong');title.textContent=agent.display_name+' ('+agent.agent_name+')';card.append(title);const meta=document.createElement('p');meta.textContent='Status: '+agent.status+' · Generation: '+agent.generation;card.append(meta);if(agent.status==='active'){const rotate=document.createElement('button');rotate.textContent='Rotate token';rotate.onclick=async()=>{try{const result=await api('/api/agents/'+encodeURIComponent(agent.agent_name)+'/rotate',{method:'POST',body:'{}'});showMessage('New token for '+result.agent_name+'. Store it now; it will not be shown again.',result.one_time_token);await load()}catch(e){showMessage(e.message)}};card.append(rotate);const revoke=document.createElement('button');revoke.textContent='Revoke token';revoke.onclick=async()=>{if(!confirm('Revoke '+agent.agent_name+' token?'))return;try{await api('/api/agents/'+encodeURIComponent(agent.agent_name)+'/revoke',{method:'POST',body:'{}'});showMessage('Agent token revoked.');await load()}catch(e){showMessage(e.message)}};card.append(revoke);const deactivate=document.createElement('button');deactivate.textContent='Deactivate';deactivate.onclick=async()=>{if(!confirm('Deactivate '+agent.agent_name+'?'))return;try{await api('/api/agents/'+encodeURIComponent(agent.agent_name)+'/deactivate',{method:'POST',body:'{}'});showMessage('Agent deactivated.');await load()}catch(e){showMessage(e.message)}};card.append(deactivate);const remove=document.createElement('button');remove.textContent='Remove';remove.onclick=async()=>{if(!confirm('Remove '+agent.agent_name+' permanently?'))return;try{await api('/api/agents/'+encodeURIComponent(agent.agent_name),{method:'DELETE'});showMessage('Agent removed.');await load()}catch(e){showMessage(e.message)}};card.append(remove)}else{const remove=document.createElement('button');remove.textContent='Remove';remove.onclick=async()=>{if(!confirm('Remove '+agent.agent_name+' permanently?'))return;try{await api('/api/agents/'+encodeURIComponent(agent.agent_name),{method:'DELETE'});showMessage('Agent removed.');await load()}catch(e){showMessage(e.message)}};card.append(remove)}section.append(card)}}catch(e){showMessage(e.message)}}
document.querySelector('#create').onsubmit=async(event)=>{event.preventDefault();const form=new FormData(event.target);try{const result=await api('/api/agents',{method:'POST',body:JSON.stringify({agent_name:form.get('agent_name'),display_name:form.get('display_name')})});showMessage('Agent created. Store this token now; it will not be shown again.',result.one_time_token);event.target.reset();await load()}catch(e){showMessage(e.message)}};
load();
</script></body></html>`, template.HTMLEscapeString(csrf), template.HTMLEscapeString(csrf), template.HTMLEscapeString(nonce))
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
	s.writeMutationJSON(w, http.StatusCreated, result)
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
	s.writeMutationJSON(w, http.StatusOK, result)
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
	s.writeMutationJSON(w, http.StatusOK, result)
}

func (s *Server) revokeAgent(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if _, err := s.requireAdmin(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	result, err := s.agents.Revoke(r.Context(), r.PathValue("name"))
	if err != nil {
		http.Error(w, "agent revoke failed", http.StatusBadRequest)
		return
	}
	s.writeMutationJSON(w, http.StatusOK, result)
}

func (s *Server) removeAgent(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if _, err := s.requireAdmin(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	result, err := s.agents.Remove(r.Context(), r.PathValue("name"))
	if err != nil {
		http.Error(w, "agent removal failed", http.StatusBadRequest)
		return
	}
	s.writeMutationJSON(w, http.StatusOK, result)
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
	cookie, err := r.Cookie(s.csrfCookieName)
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
	if cookie, err := r.Cookie(s.csrfCookieName); err == nil && cookie.Value != "" {
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
	http.SetCookie(w, &http.Cookie{Name: s.csrfCookieName, Value: value, Path: "/", Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode})
	return value
}

func (s *Server) writeMutationJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, value)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
