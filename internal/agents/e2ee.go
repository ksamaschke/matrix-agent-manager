package agents

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	e2eeSecretType      = "matrix-agent-manager.io/e2ee"
	e2eeAgentLabel      = "matrix-agent-manager.io/e2ee"
	e2eeRecoveryKeyData = "recovery-key"
	e2eeDeviceIDData    = "device-id"
	e2eeStatusData      = "status"
	e2eeAgentNameData   = "agent-name"
	e2eeCreatedAtData   = "created-at"
	e2eeUpdatedAtData   = "updated-at"
)

type E2EEStatus string

const (
	E2EEStatusUninitialized E2EEStatus = "uninitialized"
	E2EEStatusPending       E2EEStatus = "pending"
	E2EEStatusReady         E2EEStatus = "ready"
)

// E2EERecord is deliberately separate from SecretRecord. Recovery material is
// cross-signing state, not an MAS access token, and must never enter ordinary
// agent mutation responses.
type E2EERecord struct {
	AgentName       string
	DeviceID        string
	RecoveryKey     string
	ResourceVersion string
	Status          E2EEStatus
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// E2EEBackend owns the separate per-agent recovery-key Secret lifecycle.
// Implementations must preserve an existing non-empty RecoveryKey unless an
// explicit destructive operation is added later.
type E2EEBackend interface {
	GetE2EE(context.Context, string) (E2EERecord, error)
	EnsureE2EE(context.Context, E2EERecord) error
	UpdateE2EE(context.Context, E2EERecord) error
	DeleteE2EE(context.Context, string) error
}

func (b *KubernetesBackend) e2eeSecretName(agentName string) string {
	return b.prefix + "-" + agentName + "-e2ee"
}

func (b *KubernetesBackend) GetE2EE(ctx context.Context, name string) (E2EERecord, error) {
	if _, err := validateAgentName(name); err != nil {
		return E2EERecord{}, err
	}
	secret, err := b.client.CoreV1().Secrets(b.namespace).Get(ctx, b.e2eeSecretName(name), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return E2EERecord{}, ErrNotFound
	}
	if err != nil {
		return E2EERecord{}, fmt.Errorf("get agent E2EE Secret: %w", err)
	}
	return e2eeRecordFromSecret(secret)
}

func (b *KubernetesBackend) EnsureE2EE(ctx context.Context, record E2EERecord) error {
	if err := validateE2EERecord(record); err != nil {
		return err
	}
	secrets := b.client.CoreV1().Secrets(b.namespace)
	current, err := secrets.Get(ctx, b.e2eeSecretName(record.AgentName), metav1.GetOptions{})
	if err == nil {
		existing, parseErr := e2eeRecordFromSecret(current)
		if parseErr != nil {
			return parseErr
		}
		if existing.DeviceID != record.DeviceID {
			return fmt.Errorf("agent E2EE device ID changed from %q to %q", existing.DeviceID, record.DeviceID)
		}
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("get agent E2EE Secret: %w", err)
	}
	secret, err := e2eeSecretFromRecord(record)
	if err != nil {
		return err
	}
	secret.Name = b.e2eeSecretName(record.AgentName)
	secret.Namespace = b.namespace
	_, err = secrets.Create(ctx, secret, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("create agent E2EE Secret: %w", err)
	}
	return nil
}

func (b *KubernetesBackend) UpdateE2EE(ctx context.Context, record E2EERecord) error {
	if err := validateE2EERecord(record); err != nil {
		return err
	}
	secrets := b.client.CoreV1().Secrets(b.namespace)
	current, err := secrets.Get(ctx, b.e2eeSecretName(record.AgentName), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("get agent E2EE Secret for update: %w", err)
	}
	existing, err := e2eeRecordFromSecret(current)
	if err != nil {
		return err
	}
	if record.ResourceVersion != "" && current.ResourceVersion != record.ResourceVersion {
		return ErrConflict
	}
	if existing.DeviceID != record.DeviceID {
		return fmt.Errorf("agent E2EE device ID changed from %q to %q", existing.DeviceID, record.DeviceID)
	}
	if existing.RecoveryKey != "" && existing.RecoveryKey != record.RecoveryKey {
		return errors.New("agent E2EE recovery key already exists")
	}
	updated, err := e2eeSecretFromRecord(record)
	if err != nil {
		return err
	}
	updated.Name = b.e2eeSecretName(record.AgentName)
	updated.Namespace = b.namespace
	updated.ResourceVersion = current.ResourceVersion
	if _, err := secrets.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update agent E2EE Secret: %w", err)
	}
	return nil
}

func (b *KubernetesBackend) DeleteE2EE(ctx context.Context, name string) error {
	if _, err := validateAgentName(name); err != nil {
		return err
	}
	err := b.client.CoreV1().Secrets(b.namespace).Delete(ctx, b.e2eeSecretName(name), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("delete agent E2EE Secret: %w", err)
	}
	return nil
}

func validateE2EERecord(record E2EERecord) error {
	if _, err := validateAgentName(record.AgentName); err != nil {
		return err
	}
	if strings.TrimSpace(record.DeviceID) == "" || len(record.DeviceID) > 255 || strings.ContainsAny(record.DeviceID, "\x00\r\n") {
		return errors.New("agent E2EE device ID is invalid")
	}
	if record.Status != E2EEStatusPending && record.Status != E2EEStatusReady {
		return errors.New("agent E2EE status is invalid")
	}
	if record.Status == E2EEStatusReady && strings.TrimSpace(record.RecoveryKey) == "" {
		return errors.New("ready agent E2EE record requires a recovery key")
	}
	if len(record.RecoveryKey) > 4096 || strings.ContainsRune(record.RecoveryKey, '\x00') {
		return errors.New("agent E2EE recovery key is invalid")
	}
	if record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() {
		return errors.New("agent E2EE record requires timestamps")
	}
	return nil
}

func e2eeSecretFromRecord(record E2EERecord) (*corev1.Secret, error) {
	if err := validateE2EERecord(record); err != nil {
		return nil, err
	}
	data := map[string][]byte{
		e2eeAgentNameData: []byte(record.AgentName),
		e2eeDeviceIDData:  []byte(record.DeviceID),
		e2eeStatusData:    []byte(record.Status),
		e2eeCreatedAtData: []byte(record.CreatedAt.UTC().Format(time.RFC3339Nano)),
		e2eeUpdatedAtData: []byte(record.UpdatedAt.UTC().Format(time.RFC3339Nano)),
	}
	if record.RecoveryKey != "" {
		data[e2eeRecoveryKeyData] = []byte(record.RecoveryKey)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      record.AgentName,
			Namespace: "",
			Labels: map[string]string{
				secretPartOfLabel:                     "matrix-agent-manager",
				e2eeAgentLabel:                        record.AgentName,
				"matrix-agent-manager.io/e2ee-status": string(record.Status),
			},
		},
		Type: corev1.SecretType(e2eeSecretType),
		Data: data,
	}, nil
}

func e2eeRecordFromSecret(secret *corev1.Secret) (E2EERecord, error) {
	if secret == nil || secret.Type != corev1.SecretType(e2eeSecretType) || secret.Labels[secretPartOfLabel] != "matrix-agent-manager" || secret.Labels[e2eeAgentLabel] == "" {
		return E2EERecord{}, errors.New("Secret is not a Matrix Agent Manager E2EE record")
	}
	data := secret.Data
	createdAt, err := time.Parse(time.RFC3339Nano, string(data[e2eeCreatedAtData]))
	if err != nil {
		return E2EERecord{}, errors.New("agent E2EE Secret has invalid created-at")
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, string(data[e2eeUpdatedAtData]))
	if err != nil {
		return E2EERecord{}, errors.New("agent E2EE Secret has invalid updated-at")
	}
	record := E2EERecord{
		AgentName:       string(data[e2eeAgentNameData]),
		DeviceID:        string(data[e2eeDeviceIDData]),
		RecoveryKey:     string(data[e2eeRecoveryKeyData]),
		ResourceVersion: secret.ResourceVersion,
		Status:          E2EEStatus(string(data[e2eeStatusData])),
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}
	if secret.Labels[e2eeAgentLabel] != record.AgentName {
		return E2EERecord{}, errors.New("agent E2EE Secret has inconsistent agent name")
	}
	if err := validateE2EERecord(record); err != nil {
		return E2EERecord{}, err
	}
	return record, nil
}
