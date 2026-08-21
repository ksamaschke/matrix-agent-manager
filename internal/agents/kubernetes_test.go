package agents

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestKubernetesBackendRoundTripAndListScope(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "agent-manager", Labels: map[string]string{"other": "true"}},
	})
	backend, err := NewKubernetesBackend(client, "agent-manager", "matrix-agent")
	if err != nil {
		t.Fatalf("NewKubernetesBackend() error = %v", err)
	}
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	record := SecretRecord{
		AgentName:   "codex",
		DisplayName: "Codex",
		MASUserID:   "user-codex",
		SessionID:   "session-codex",
		AccessToken: "synthetic-token",
		Generation:  1,
		Status:      StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := backend.CreateAgent(context.Background(), record); err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	got, err := backend.GetAgent(context.Background(), "codex")
	if err != nil {
		t.Fatalf("GetAgent() error = %v", err)
	}
	if got.AccessToken != record.AccessToken || got.Generation != 1 {
		t.Fatalf("got = %+v", got)
	}
	list, err := backend.ListAgents(context.Background())
	if err != nil {
		t.Fatalf("ListAgents() error = %v", err)
	}
	if len(list) != 1 || list[0].AgentName != "codex" {
		t.Fatalf("list = %+v", list)
	}
}

func TestKubernetesBackendRejectsMalformedRecord(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "matrix-agent-codex",
			Namespace: "agent-manager",
			Labels: map[string]string{
				secretPartOfLabel: "matrix-agent-manager",
				agentLabel:        "codex",
			},
		},
		Data: map[string][]byte{"generation": []byte("bad")},
	})
	backend, err := NewKubernetesBackend(client, "agent-manager", "matrix-agent")
	if err != nil {
		t.Fatalf("NewKubernetesBackend() error = %v", err)
	}
	if _, err := backend.GetAgent(context.Background(), "codex"); err == nil {
		t.Fatal("expected malformed Secret to fail")
	}
}

func TestKubernetesBackendDeleteAgent(t *testing.T) {
	client := fake.NewSimpleClientset()
	backend, err := NewKubernetesBackend(client, "agent-manager", "matrix-agent")
	if err != nil {
		t.Fatalf("NewKubernetesBackend() error = %v", err)
	}
	record := SecretRecord{AgentName: "codex", DisplayName: "Codex", MASUserID: "user-codex", SessionID: "session-codex", AccessToken: "token", Generation: 1, Status: StatusActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := backend.CreateAgent(context.Background(), record); err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	if err := backend.DeleteAgent(context.Background(), "codex"); err != nil {
		t.Fatalf("DeleteAgent() error = %v", err)
	}
	if _, err := backend.GetAgent(context.Background(), "codex"); err != ErrNotFound {
		t.Fatalf("GetAgent() after delete = %v, want ErrNotFound", err)
	}
	if err := backend.DeleteAgent(context.Background(), "codex"); err != ErrNotFound {
		t.Fatalf("second DeleteAgent() = %v, want ErrNotFound", err)
	}
}

func TestKubernetesBackendRoundTripsInactiveRecordWithoutTokenMaterial(t *testing.T) {
	client := fake.NewSimpleClientset()
	backend, err := NewKubernetesBackend(client, "agent-manager", "matrix-agent")
	if err != nil {
		t.Fatalf("NewKubernetesBackend() error = %v", err)
	}
	now := time.Now().UTC()
	record := SecretRecord{
		AgentName: "codex", DisplayName: "Codex", MASUserID: "user-codex",
		Generation: 2, Status: StatusRevoked, CreatedAt: now, UpdatedAt: now,
	}
	if err := backend.CreateAgent(context.Background(), record); err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	got, err := backend.GetAgent(context.Background(), "codex")
	if err != nil {
		t.Fatalf("GetAgent() error = %v", err)
	}
	if got.Status != StatusRevoked || got.AccessToken != "" || got.SessionID != "" {
		t.Fatalf("inactive record = %+v", got)
	}
}

func TestMarshalMetadataDoesNotContainToken(t *testing.T) {
	payload, err := MarshalMetadata(SecretRecord{AgentName: "codex", AccessToken: "synthetic-token", Status: StatusActive, Generation: 1})
	if err != nil {
		t.Fatalf("MarshalMetadata() error = %v", err)
	}
	if string(payload) == "" || contains(string(payload), "synthetic-token") {
		t.Fatalf("metadata contains token: %s", payload)
	}
}

func contains(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

var _ = metav1.NamespaceDefault
var _ = corev1.SecretTypeOpaque
