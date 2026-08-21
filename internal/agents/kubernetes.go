package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/kubernetes"
)

const (
	secretPartOfLabel = "app.kubernetes.io/part-of"
	agentLabel        = "matrix-agent-manager.io/agent"
	secretType        = "matrix-agent-manager.io/agent"
)

// KubernetesBackend persists agent metadata and token material in namespaced
// Secrets. The caller's RBAC must limit access to this namespace.
type KubernetesBackend struct {
	client    kubernetes.Interface
	namespace string
	prefix    string
	now       func() time.Time
}

func NewKubernetesBackend(client kubernetes.Interface, namespace, prefix string) (*KubernetesBackend, error) {
	if client == nil {
		return nil, errors.New("Kubernetes client is required")
	}
	if strings.TrimSpace(namespace) == "" {
		return nil, errors.New("Kubernetes Secret namespace is required")
	}
	prefix = strings.Trim(strings.TrimSpace(prefix), "-")
	if prefix == "" {
		return nil, errors.New("Kubernetes Secret name prefix is required")
	}
	return &KubernetesBackend{client: client, namespace: namespace, prefix: prefix, now: time.Now}, nil
}

func (b *KubernetesBackend) GetAgent(ctx context.Context, name string) (SecretRecord, error) {
	secret, err := b.client.CoreV1().Secrets(b.namespace).Get(ctx, b.secretName(name), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return SecretRecord{}, ErrNotFound
	}
	if err != nil {
		return SecretRecord{}, fmt.Errorf("get agent Secret: %w", err)
	}
	return recordFromSecret(secret)
}

func (b *KubernetesBackend) CreateAgent(ctx context.Context, record SecretRecord) error {
	secret, err := b.secretFromRecord(record)
	if err != nil {
		return err
	}
	_, err = b.client.CoreV1().Secrets(b.namespace).Create(ctx, secret, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return errors.New("agent already exists")
	}
	if err != nil {
		return fmt.Errorf("create agent Secret: %w", err)
	}
	return nil
}

func (b *KubernetesBackend) UpdateAgent(ctx context.Context, record SecretRecord) error {
	secrets := b.client.CoreV1().Secrets(b.namespace)
	current, err := secrets.Get(ctx, b.secretName(record.AgentName), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("get agent Secret for update: %w", err)
	}
	updated, err := b.secretFromRecord(record)
	if err != nil {
		return err
	}
	updated.ResourceVersion = current.ResourceVersion
	_, err = secrets.Update(ctx, updated, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update agent Secret: %w", err)
	}
	return nil
}

func (b *KubernetesBackend) ListAgents(ctx context.Context) ([]SecretRecord, error) {
	req, err := labels.NewRequirement(agentLabel, selection.Exists, nil)
	if err != nil {
		return nil, fmt.Errorf("build agent Secret selector: %w", err)
	}
	list, err := b.client.CoreV1().Secrets(b.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set{secretPartOfLabel: "matrix-agent-manager"}.String() + "," + req.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("list agent Secrets: %w", err)
	}
	result := make([]SecretRecord, 0, len(list.Items))
	for i := range list.Items {
		record, err := recordFromSecret(&list.Items[i])
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, nil
}

func (b *KubernetesBackend) secretName(agentName string) string {
	return b.prefix + "-" + agentName
}

func (b *KubernetesBackend) secretFromRecord(record SecretRecord) (*corev1.Secret, error) {
	if record.AgentName == "" || record.MASUserID == "" || record.SessionID == "" {
		return nil, errors.New("agent Secret requires agent, MAS user, and session IDs")
	}
	if record.Generation < 1 {
		return nil, errors.New("agent Secret generation must be positive")
	}
	metadata := map[string]string{
		secretPartOfLabel:                "matrix-agent-manager",
		agentLabel:                       record.AgentName,
		"matrix-agent-manager.io/status": string(record.Status),
	}
	data := map[string][]byte{}
	if record.AccessToken != "" {
		data["access-token"] = []byte(record.AccessToken)
	}
	data["agent-name"] = []byte(record.AgentName)
	data["display-name"] = []byte(record.DisplayName)
	data["mas-user-id"] = []byte(record.MASUserID)
	data["session-id"] = []byte(record.SessionID)
	data["generation"] = []byte(strconv.Itoa(record.Generation))
	data["status"] = []byte(record.Status)
	data["created-at"] = []byte(record.CreatedAt.UTC().Format(time.RFC3339Nano))
	data["updated-at"] = []byte(record.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: b.secretName(record.AgentName), Namespace: b.namespace, Labels: metadata},
		Type:       corev1.SecretType(secretType),
		Data:       data,
	}, nil
}

func recordFromSecret(secret *corev1.Secret) (SecretRecord, error) {
	if secret == nil || secret.Labels[secretPartOfLabel] != "matrix-agent-manager" || secret.Labels[agentLabel] == "" {
		return SecretRecord{}, errors.New("Secret is not a Matrix Agent Manager record")
	}
	data := secret.Data
	generation, err := strconv.Atoi(string(data["generation"]))
	if err != nil || generation < 1 {
		return SecretRecord{}, errors.New("agent Secret has invalid generation")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, string(data["created-at"]))
	if err != nil {
		return SecretRecord{}, errors.New("agent Secret has invalid created-at")
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, string(data["updated-at"]))
	if err != nil {
		return SecretRecord{}, errors.New("agent Secret has invalid updated-at")
	}
	status := Status(string(data["status"]))
	if status != StatusActive && status != StatusDeactivated {
		return SecretRecord{}, errors.New("agent Secret has invalid status")
	}
	return SecretRecord{
		AgentName:   string(data["agent-name"]),
		DisplayName: string(data["display-name"]),
		MASUserID:   string(data["mas-user-id"]),
		SessionID:   string(data["session-id"]),
		AccessToken: string(data["access-token"]),
		Generation:  generation,
		Status:      status,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}, nil
}

// MarshalMetadata is used by audit/UI layers and deliberately excludes token data.
func MarshalMetadata(record SecretRecord) ([]byte, error) {
	return json.Marshal(Result{AgentName: record.AgentName, DisplayName: record.DisplayName, MASUserID: record.MASUserID, SessionID: record.SessionID, Generation: record.Generation, Status: record.Status})
}
