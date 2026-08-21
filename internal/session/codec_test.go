package session

import (
	"strings"
	"testing"
	"time"
)

func TestCodecRoundTripAndPurposeSeparation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	codec, err := NewKey(strings.Repeat("k", 32), func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}

	token, err := codec.Seal("oidc-state", now.Add(5*time.Minute), map[string]string{
		"state": "synthetic-state",
	})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if strings.Contains(token, "synthetic-state") {
		t.Fatal("sealed token contains plaintext payload")
	}

	var payload map[string]string
	if err := codec.Open(token, "oidc-state", &payload); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if payload["state"] != "synthetic-state" {
		t.Fatalf("state = %q, want synthetic-state", payload["state"])
	}
	if err := codec.Open(token, "session", &payload); err == nil {
		t.Fatal("expected purpose mismatch to fail")
	}
}

func TestCodecRejectsExpiryAndTampering(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	current := now
	codec, err := NewKey(strings.Repeat("k", 32), func() time.Time { return current })
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}

	expiring, err := codec.Seal("session", now.Add(time.Minute), map[string]string{"sub": "user"})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	current = now.Add(2 * time.Minute)
	if err := codec.Open(expiring, "session", &map[string]string{}); err == nil {
		t.Fatal("expected expired token to fail")
	}

	current = now
	valid, err := codec.Seal("session", now.Add(time.Minute), map[string]string{"sub": "user"})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	last := valid[len(valid)-1]
	replacement := byte('A')
	if last == replacement {
		replacement = 'B'
	}
	tampered := valid[:len(valid)-1] + string(replacement)
	if err := codec.Open(tampered, "session", &map[string]string{}); err == nil {
		t.Fatal("expected tampering to fail")
	}
}

func TestNewKeyRequiresExactly32Bytes(t *testing.T) {
	if _, err := NewKey("short", time.Now); err == nil {
		t.Fatal("expected short key to fail")
	}
}

func TestCodecAcceptsBinaryKeyMaterial(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := string([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31})
	codec, err := NewKey(raw, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
	token, err := codec.Seal("test", now.Add(time.Minute), map[string]string{"ok": "yes"})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	var payload map[string]string
	if err := codec.Open(token, "test", &payload); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if payload["ok"] != "yes" {
		t.Fatalf("payload = %#v", payload)
	}
}
