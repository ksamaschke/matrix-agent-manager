package matrix

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRecoveryClientRejectsInvalidBaseURL(t *testing.T) {
	for _, raw := range []string{"", "not-a-url", "https://user:pass@example.test"} {
		if _, err := NewRecoveryClient(RecoveryClientConfig{HomeserverBaseURL: raw}, nil); err == nil {
			t.Fatalf("expected rejection of base URL %q", raw)
		}
	}
}

func TestCheckDeviceRequiresArguments(t *testing.T) {
	client, err := NewRecoveryClient(RecoveryClientConfig{HomeserverBaseURL: "https://homeserver.test"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := client.CheckDevice(context.Background(), "", "@agent:homeserver.test", "agent-codex"); err == nil {
		t.Fatal("expected error for empty access token")
	}
	if _, err := client.CheckDevice(context.Background(), "token", "", "agent-codex"); err == nil {
		t.Fatal("expected error for empty user ID")
	}
	if _, err := client.CheckDevice(context.Background(), "token", "@agent:homeserver.test", ""); err == nil {
		t.Fatal("expected error for empty device ID")
	}
}

func TestCheckDeviceReportsKnownDeviceWithKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer agent-token" {
			t.Errorf("unexpected authorization header %q", got)
		}
		if r.URL.Path != "/_matrix/client/v3/keys/query" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_keys": map[string]any{
				"@agent:homeserver.test": map[string]any{
					"agent-codex": map[string]any{
						"keys": map[string]string{
							"ed25519:agent-codex":    "ed-key",
							"curve25519:agent-codex": "curve-key",
						},
					},
				},
			},
		})
	}))
	defer server.Close()

	client, err := NewRecoveryClient(RecoveryClientConfig{HomeserverBaseURL: server.URL}, server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	status, err := client.CheckDevice(context.Background(), "agent-token", "@agent:homeserver.test", "agent-codex")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Known || !status.KeysMatch {
		t.Fatalf("expected known device with matching keys, got %+v", status)
	}
}

func TestCheckDeviceReportsMissingDevice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_keys": map[string]any{
				"@agent:homeserver.test": map[string]any{},
			},
		})
	}))
	defer server.Close()

	client, err := NewRecoveryClient(RecoveryClientConfig{HomeserverBaseURL: server.URL}, server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	status, err := client.CheckDevice(context.Background(), "agent-token", "@agent:homeserver.test", "agent-codex")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Known || status.KeysMatch {
		t.Fatalf("expected unknown device, got %+v", status)
	}
}

func TestCheckDeviceSurfacesHomeserverError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := NewRecoveryClient(RecoveryClientConfig{HomeserverBaseURL: server.URL}, server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := client.CheckDevice(context.Background(), "agent-token", "@agent:homeserver.test", "agent-codex"); err == nil {
		t.Fatal("expected error for non-200 homeserver response")
	}
}
