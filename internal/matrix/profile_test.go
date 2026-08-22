package matrix

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProfileClientSetsDisplayName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/profile/@agent:example.invalid/displayname" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
			t.Fatalf("authorization = %q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["displayname"] != "HEX" {
			t.Fatalf("displayname = %q", body["displayname"])
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewProfileClient(server.URL+"/profile/{user_id}/displayname", server.Client())
	if err != nil {
		t.Fatalf("NewProfileClient() error = %v", err)
	}
	if err := client.SetDisplayName(context.Background(), "access-token", "@agent:example.invalid", "HEX"); err != nil {
		t.Fatalf("SetDisplayName() error = %v", err)
	}
}

func TestNewProfileClientRejectsInvalidTemplate(t *testing.T) {
	for _, template := range []string{"", "https://example.invalid/profile/displayname", "https://example.invalid/profile/{user_id}/{user_id}"} {
		if _, err := NewProfileClient(template, nil); err == nil {
			t.Errorf("NewProfileClient(%q) accepted invalid template", template)
		}
	}
}
