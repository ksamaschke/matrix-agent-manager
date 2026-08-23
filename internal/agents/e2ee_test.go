package agents

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

func TestKubernetesBackendRoundTripsE2EESecretWithoutTokenMaterial(t *testing.T) {
	backend, err := NewKubernetesBackend(fake.NewSimpleClientset(), "matrix-agents", "matrix-agent")
	if err != nil {
		t.Fatalf("NewKubernetesBackend() error = %v", err)
	}
	now := time.Now().UTC()
	pending := E2EERecord{
		AgentName: "hex-work",
		DeviceID:  "agent-hex-work",
		Status:    E2EEStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := backend.EnsureE2EE(context.Background(), pending); err != nil {
		t.Fatalf("EnsureE2EE() error = %v", err)
	}
	got, err := backend.GetE2EE(context.Background(), "hex-work")
	if err != nil {
		t.Fatalf("GetE2EE() error = %v", err)
	}
	if got.DeviceID != pending.DeviceID || got.Status != E2EEStatusPending || got.RecoveryKey != "" {
		t.Fatalf("pending E2EE record = %+v", got)
	}

	got.RecoveryKey = "agent-recovery-key"
	got.Status = E2EEStatusReady
	got.UpdatedAt = now.Add(time.Minute)
	if err := backend.UpdateE2EE(context.Background(), got); err != nil {
		t.Fatalf("UpdateE2EE() error = %v", err)
	}
	ready, err := backend.GetE2EE(context.Background(), "hex-work")
	if err != nil {
		t.Fatalf("GetE2EE() after update error = %v", err)
	}
	if ready.Status != E2EEStatusReady || ready.RecoveryKey != "agent-recovery-key" {
		t.Fatalf("ready E2EE record = %+v", ready)
	}

	metadata, err := MarshalMetadata(SecretRecord{AgentName: "hex-work", DisplayName: "HEX", MASUserID: "user", Generation: 1, Status: StatusActive})
	if err != nil {
		t.Fatalf("MarshalMetadata() error = %v", err)
	}
	if string(metadata) == "" || string(metadata) == "agent-recovery-key" {
		t.Fatalf("metadata unexpectedly contains recovery material: %s", metadata)
	}
}

func TestKubernetesBackendRefusesRecoveryKeyReplacement(t *testing.T) {
	backend, err := NewKubernetesBackend(fake.NewSimpleClientset(), "matrix-agents", "matrix-agent")
	if err != nil {
		t.Fatalf("NewKubernetesBackend() error = %v", err)
	}
	now := time.Now().UTC()
	if err := backend.EnsureE2EE(context.Background(), E2EERecord{AgentName: "hex-work", DeviceID: "agent-hex-work", Status: E2EEStatusPending, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("EnsureE2EE() error = %v", err)
	}
	ready := E2EERecord{AgentName: "hex-work", DeviceID: "agent-hex-work", RecoveryKey: "first-key", Status: E2EEStatusReady, CreatedAt: now, UpdatedAt: now}
	if err := backend.UpdateE2EE(context.Background(), ready); err != nil {
		t.Fatalf("first UpdateE2EE() error = %v", err)
	}
	ready.RecoveryKey = "second-key"
	if err := backend.UpdateE2EE(context.Background(), ready); err == nil {
		t.Fatal("UpdateE2EE() unexpectedly replaced an existing recovery key")
	}
	got, err := backend.GetE2EE(context.Background(), "hex-work")
	if err != nil {
		t.Fatalf("GetE2EE() error = %v", err)
	}
	if got.RecoveryKey != "first-key" {
		t.Fatalf("recovery key was replaced: %+v", got)
	}
}

func TestInitializeE2EEIsIdempotentAndDoesNotReturnRecoveryKey(t *testing.T) {
	service, _, secrets := newTestService()
	if _, err := service.Create(context.Background(), CreateRequest{AgentName: "hex-work", DisplayName: "HEX"}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	first, err := service.InitializeE2EE(context.Background(), "hex-work")
	if err != nil {
		t.Fatalf("first InitializeE2EE() error = %v", err)
	}
	second, err := service.InitializeE2EE(context.Background(), "hex-work")
	if err != nil {
		t.Fatalf("second InitializeE2EE() error = %v", err)
	}
	if first.E2EEStatus != E2EEStatusPending || second.E2EEStatus != E2EEStatusPending || first.E2EEDeviceID != "agent-hex-work" {
		t.Fatalf("initialization results = %+v / %+v", first, second)
	}
	if _, err := secrets.GetE2EE(context.Background(), "hex-work"); err != nil {
		t.Fatalf("E2EE Secret missing after initialization: %v", err)
	}
	if first.OneTimeToken != "" {
		t.Fatalf("initialization unexpectedly returned token material: %+v", first)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), "agent-recovery-key") {
		t.Fatalf("initialization result leaked recovery material: %s", encoded)
	}
}
