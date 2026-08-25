package matrix

import (
	"context"
	"encoding/json"
	"io"
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

func TestProfileClientUploadsAndSetsAvatar(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/media/upload":
			if r.Method != http.MethodPost {
				t.Fatalf("upload method = %s", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
				t.Fatalf("upload authorization = %q", got)
			}
			if got := r.Header.Get("Content-Type"); got != "image/png" {
				t.Fatalf("upload content type = %q", got)
			}
			if got := r.URL.Query().Get("filename"); got != "avatar.png" {
				t.Fatalf("upload filename = %q", got)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read upload: %v", err)
			}
			if string(body) != "image-bytes" {
				t.Fatalf("upload body = %q", body)
			}
			writeJSON(t, w, http.StatusOK, map[string]string{"content_uri": "mxc://example.invalid/avatar-id"})
		case "/media/thumbnail/example.invalid/avatar-id":
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer access-token" {
				t.Fatalf("thumbnail request = %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
			}
			if r.URL.Query().Get("width") != "96" || r.URL.Query().Get("height") != "96" || r.URL.Query().Get("method") != "scale" {
				t.Fatalf("thumbnail query = %q", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("thumbnail"))
		case "/profile/@agent:example.invalid/avatar_url":
			if r.Method != http.MethodPut {
				t.Fatalf("avatar method = %s", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
				t.Fatalf("avatar authorization = %q", got)
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode avatar request: %v", err)
			}
			if body["avatar_url"] != "mxc://example.invalid/avatar-id" {
				t.Fatalf("avatar URL = %q", body["avatar_url"])
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewProfileClientWithConfig(ProfileClientConfig{
		DisplayNameURLTemplate:    server.URL + "/profile/{user_id}/displayname",
		AvatarURLTemplate:         server.URL + "/profile/{user_id}/avatar_url",
		MediaUploadURL:            server.URL + "/media/upload",
		MediaThumbnailURLTemplate: server.URL + "/media/thumbnail/{server_name}/{media_id}",
	}, server.Client())
	if err != nil {
		t.Fatalf("NewProfileClientWithConfig() error = %v", err)
	}
	avatarURL, err := client.UploadAvatar(context.Background(), "access-token", "avatar.png", "image/png", []byte("image-bytes"))
	if err != nil {
		t.Fatalf("UploadAvatar() error = %v", err)
	}
	if avatarURL != "mxc://example.invalid/avatar-id" {
		t.Fatalf("avatar URL = %q", avatarURL)
	}
	if err := client.SetAvatarURL(context.Background(), "access-token", "@agent:example.invalid", avatarURL); err != nil {
		t.Fatalf("SetAvatarURL() error = %v", err)
	}
	thumbnail, contentType, err := client.FetchAvatar(context.Background(), "access-token", avatarURL)
	if err != nil {
		t.Fatalf("FetchAvatar() error = %v", err)
	}
	if string(thumbnail) != "thumbnail" || contentType != "image/png" {
		t.Fatalf("thumbnail = %q content type = %q", thumbnail, contentType)
	}
}

func TestNewProfileClientRejectsInvalidTemplate(t *testing.T) {
	for _, template := range []string{"", "https://example.invalid/profile/displayname", "https://example.invalid/profile/{user_id}/{user_id}"} {
		if _, err := NewProfileClient(template, nil); err == nil {
			t.Errorf("NewProfileClient(%q) accepted invalid template", template)
		}
	}
}

func TestNewProfileClientRejectsInvalidAvatarConfiguration(t *testing.T) {
	base := ProfileClientConfig{DisplayNameURLTemplate: "https://example.invalid/profile/{user_id}/displayname"}
	for _, config := range []ProfileClientConfig{
		{DisplayNameURLTemplate: base.DisplayNameURLTemplate, AvatarURLTemplate: "https://example.invalid/profile/{user_id}/avatar_url"},
		{DisplayNameURLTemplate: base.DisplayNameURLTemplate, MediaUploadURL: "https://example.invalid/_matrix/media/v3/upload"},
		{DisplayNameURLTemplate: base.DisplayNameURLTemplate, AvatarURLTemplate: "https://other.invalid/profile/{user_id}/avatar_url", MediaUploadURL: "https://example.invalid/_matrix/media/v3/upload", MediaThumbnailURLTemplate: "https://example.invalid/_matrix/client/v1/media/thumbnail/{server_name}/{media_id}"},
	} {
		if _, err := NewProfileClientWithConfig(config, nil); err == nil {
			t.Errorf("NewProfileClientWithConfig(%+v) accepted incomplete avatar configuration", config)
		}
	}
}

func TestProfileClientRejectsInvalidAvatarURI(t *testing.T) {
	for _, value := range []string{"", "https://example.invalid/avatar", "mxc://", "mxc://example.invalid/a/b"} {
		if err := validateMXCURI(value); err == nil {
			t.Errorf("validateMXCURI(%q) accepted invalid URI", value)
		}
	}
}

func TestProfileClientValidatesConfiguredMXCServerName(t *testing.T) {
	if err := validateMXCURIForServer("mxc://example.invalid/avatar-id", "example.invalid"); err != nil {
		t.Fatalf("valid server name rejected: %v", err)
	}
	if err := validateMXCURIForServer("mxc://other.invalid/avatar-id", "example.invalid"); err == nil {
		t.Fatal("foreign server name accepted")
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
