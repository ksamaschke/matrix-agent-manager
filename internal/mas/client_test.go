package mas

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientCreatesUserWithClientCredentials(t *testing.T) {
	var tokenRequests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			tokenRequests++
			if r.Method != http.MethodPost {
				t.Errorf("token method = %s, want POST", r.Method)
			}
			clientID, clientSecret, ok := r.BasicAuth()
			if !ok || clientID != "synthetic-admin-client" || clientSecret != "synthetic-admin-secret" {
				t.Errorf("unexpected basic auth: %q, %q, %v", clientID, clientSecret, ok)
			}
			body, _ := io.ReadAll(r.Body)
			form, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if form.Get("grant_type") != "client_credentials" {
				t.Errorf("grant_type = %q", form.Get("grant_type"))
			}
			if form.Get("scope") != AdminScope {
				t.Errorf("scope = %q, want %q", form.Get("scope"), AdminScope)
			}
			writeJSON(t, w, http.StatusOK, map[string]any{
				"access_token": "synthetic-mas-access-token",
				"token_type":   "Bearer",
				"expires_in":   300,
			})
		case "/api/admin/v1/users":
			if r.Method != http.MethodPost {
				t.Errorf("users method = %s, want POST", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer synthetic-mas-access-token" {
				t.Errorf("authorization = %q", got)
			}
			var request CreateUserRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode user request: %v", err)
			}
			if request.Username != "hermes-codex" || request.DisplayName == nil || *request.DisplayName != "Synthetic Agent" {
				t.Errorf("unexpected user request: %+v", request)
			}
			writeJSON(t, w, http.StatusCreated, singleResponse[UserAttributes]{
				Data: resource[UserAttributes]{
					Type: "user",
					ID:   "01J00000000000000000000000",
					Attributes: UserAttributes{
						Username: "hermes-codex",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		TokenURL:            server.URL + "/oauth2/token",
		UsersURL:            server.URL + "/api/admin/v1/users",
		PersonalSessionsURL: server.URL + "/api/admin/v1/personal-sessions",
		ClientID:            "synthetic-admin-client",
		ClientSecretFile:    "synthetic-secret-file",
		HTTPClient:          server.Client(),
	}, func(string) ([]byte, error) {
		return []byte("synthetic-admin-secret"), nil
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	name := "Synthetic Agent"
	user, err := client.CreateUser(context.Background(), CreateUserRequest{
		Username:    "hermes-codex",
		DisplayName: &name,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if user.ID != "01J00000000000000000000000" || user.Attributes.Username != "hermes-codex" {
		t.Fatalf("unexpected user: %+v", user)
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d, want 1", tokenRequests)
	}
}

func TestClientCreatesAndRevokesPersonalSession(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			writeJSON(t, w, http.StatusOK, map[string]any{
				"access_token": "synthetic-mas-access-token",
				"token_type":   "Bearer",
				"expires_in":   300,
			})
			return
		}
		if r.URL.Path == "/api/admin/v1/personal-sessions" && r.Method == http.MethodPost {
			var request CreatePersonalSessionRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode session request: %v", err)
			}
			if request.ActorUserID == "" || request.Scope != "openid" || request.HumanName != "Hermes Codex" {
				t.Errorf("unexpected session request: %+v", request)
			}
			writeJSON(t, w, http.StatusCreated, singleResponse[PersonalSessionAttributes]{
				Data: resource[PersonalSessionAttributes]{
					Type: "personal-session",
					ID:   "01J00000000000000000000001",
					Attributes: PersonalSessionAttributes{
						ActorUserID: "01J00000000000000000000000",
						HumanName:   "Hermes Codex",
						Scope:       "openid",
						AccessToken: "synthetic-agent-access-token",
					},
				},
			})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/regenerate") && r.Method == http.MethodPost {
			var request RegeneratePersonalSessionRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode regenerate request: %v", err)
			}
			if request.ExpiresIn == nil || *request.ExpiresIn != 3600 {
				t.Errorf("regenerate expiry = %#v", request.ExpiresIn)
			}
			writeJSON(t, w, http.StatusCreated, singleResponse[PersonalSessionAttributes]{
				Data: resource[PersonalSessionAttributes]{
					Type: "personal-session",
					ID:   "01J00000000000000000000001",
					Attributes: PersonalSessionAttributes{
						ActorUserID: "01J00000000000000000000000",
						HumanName:   "Hermes Codex",
						Scope:       "openid",
						AccessToken: "synthetic-regenerated-token",
					},
				},
			})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/revoke") && r.Method == http.MethodPost {
			if r.Header.Get("Authorization") != "Bearer synthetic-mas-access-token" {
				t.Errorf("missing admin authorization")
			}
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		TokenURL:            server.URL + "/oauth2/token",
		UsersURL:            server.URL + "/api/admin/v1/users",
		PersonalSessionsURL: server.URL + "/api/admin/v1/personal-sessions",
		ClientID:            "synthetic-admin-client",
		ClientSecretFile:    "synthetic-secret-file",
		HTTPClient:          server.Client(),
	}, func(string) ([]byte, error) {
		return []byte("synthetic-admin-secret"), nil
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	session, err := client.CreatePersonalSession(context.Background(), CreatePersonalSessionRequest{
		ActorUserID: "01J00000000000000000000000",
		HumanName:   "Hermes Codex",
		Scope:       "openid",
	})
	if err != nil {
		t.Fatalf("CreatePersonalSession() error = %v", err)
	}
	if session.ID != "01J00000000000000000000001" || session.Attributes.AccessToken != "synthetic-agent-access-token" {
		t.Fatalf("unexpected session: %+v", session)
	}
	expiresIn := uint32(3600)
	regenerated, err := client.RegeneratePersonalSession(context.Background(), session.ID, &expiresIn)
	if err != nil {
		t.Fatalf("RegeneratePersonalSession() error = %v", err)
	}
	if regenerated.ID != session.ID || regenerated.Attributes.AccessToken != "synthetic-regenerated-token" {
		t.Fatalf("unexpected regenerated session: %+v", regenerated)
	}
	if err := client.RevokePersonalSession(context.Background(), session.ID); err != nil {
		t.Fatalf("RevokePersonalSession() error = %v", err)
	}
}

func TestClientRejectsInvalidEndpointConfiguration(t *testing.T) {
	_, err := NewClient(ClientConfig{
		TokenURL:            "https://user:pass@example.invalid/token",
		UsersURL:            "https://mas.example.invalid/users",
		PersonalSessionsURL: "https://mas.example.invalid/sessions",
		ClientID:            "synthetic-client",
		ClientSecretFile:    "synthetic-secret-file",
	}, func(string) ([]byte, error) { return []byte("synthetic-secret"), nil })
	if err == nil {
		t.Fatal("expected endpoint validation to reject userinfo")
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("write JSON: %v", err)
	}
}
