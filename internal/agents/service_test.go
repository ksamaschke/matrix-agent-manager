package agents

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ksamaschke/matrix-agent-manager/internal/mas"
)

type fakeMAS struct {
	users            []mas.User
	sessions         []mas.PersonalSession
	revoked          []string
	deactivated      []string
	failCreateSecret bool
}

func (f *fakeMAS) CreateUser(_ context.Context, request mas.CreateUserRequest) (mas.User, error) {
	user := mas.User{Type: "user", ID: "user-" + request.Username, Attributes: mas.UserAttributes{Username: request.Username}}
	f.users = append(f.users, user)
	return user, nil
}

func (f *fakeMAS) CreatePersonalSession(_ context.Context, request mas.CreatePersonalSessionRequest) (mas.PersonalSession, error) {
	id := "session-" + request.ActorUserID + "-" + string(rune('0'+len(f.sessions)))
	session := mas.PersonalSession{Type: "personal-session", ID: id, Attributes: mas.PersonalSessionAttributes{
		ActorUserID: request.ActorUserID,
		HumanName:   request.HumanName,
		Scope:       request.Scope,
		AccessToken: "token-" + id,
	}}
	f.sessions = append(f.sessions, session)
	return session, nil
}

func (f *fakeMAS) RevokePersonalSession(_ context.Context, id string) error {
	f.revoked = append(f.revoked, id)
	return nil
}

func (f *fakeMAS) DeactivateUser(_ context.Context, id string, _ bool) (mas.User, error) {
	f.deactivated = append(f.deactivated, id)
	return mas.User{Type: "user", ID: id}, nil
}

type memorySecrets struct {
	agents     map[string]SecretRecord
	failUpdate bool
}

func newMemorySecrets() *memorySecrets { return &memorySecrets{agents: make(map[string]SecretRecord)} }
func (m *memorySecrets) GetAgent(_ context.Context, name string) (SecretRecord, error) {
	record, ok := m.agents[name]
	if !ok {
		return SecretRecord{}, ErrNotFound
	}
	return record, nil
}
func (m *memorySecrets) CreateAgent(_ context.Context, record SecretRecord) error {
	if _, ok := m.agents[record.AgentName]; ok {
		return errors.New("already exists")
	}
	if record.AccessToken == "" && record.Status == StatusActive {
		return errors.New("missing token")
	}
	if len(m.agents) > 0 && record.AgentName == "fail" {
		return errors.New("synthetic create failure")
	}
	m.agents[record.AgentName] = record
	return nil
}
func (m *memorySecrets) UpdateAgent(_ context.Context, record SecretRecord) error {
	if m.failUpdate {
		return errors.New("synthetic update failure")
	}
	if _, ok := m.agents[record.AgentName]; !ok {
		return ErrNotFound
	}
	m.agents[record.AgentName] = record
	return nil
}
func (m *memorySecrets) ListAgents(_ context.Context) ([]SecretRecord, error) {
	out := make([]SecretRecord, 0, len(m.agents))
	for _, record := range m.agents {
		out = append(out, record)
	}
	return out, nil
}

func newTestService() (*Service, *fakeMAS, *memorySecrets) {
	masClient := &fakeMAS{}
	secrets := newMemorySecrets()
	return NewService(masClient, secrets, ServiceConfig{
		SecretNamePrefix: "synthetic-agent",
		TokenScope:       "openid urn:matrix:client:api:*",
		TokenExpiry:      time.Hour,
	}), masClient, secrets
}

func TestCreatePersistsBeforeReturningToken(t *testing.T) {
	service, fake, secrets := newTestService()
	result, err := service.Create(context.Background(), CreateRequest{AgentName: "codex", DisplayName: "Codex"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.OneTimeToken != "token-session-user-codex-0" {
		t.Fatalf("token = %q", result.OneTimeToken)
	}
	stored, err := secrets.GetAgent(context.Background(), "codex")
	if err != nil {
		t.Fatalf("GetAgent() error = %v", err)
	}
	if stored.AccessToken != result.OneTimeToken || stored.Generation != 1 {
		t.Fatalf("stored = %+v", stored)
	}
	if len(fake.sessions) != 1 {
		t.Fatalf("sessions = %d", len(fake.sessions))
	}
}

func TestRotateStoresNewTokenBeforeRevokingOld(t *testing.T) {
	service, fake, secrets := newTestService()
	created, err := service.Create(context.Background(), CreateRequest{AgentName: "codex", DisplayName: "Codex"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	rotated, err := service.Rotate(context.Background(), "codex")
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if rotated.Generation != 2 || rotated.OneTimeToken == created.OneTimeToken {
		t.Fatalf("rotated = %+v", rotated)
	}
	if len(fake.revoked) != 1 || fake.revoked[0] != created.SessionID {
		t.Fatalf("revoked = %#v", fake.revoked)
	}
	stored, _ := secrets.GetAgent(context.Background(), "codex")
	if stored.AccessToken != rotated.OneTimeToken || stored.SessionID != rotated.SessionID {
		t.Fatalf("stored = %+v", stored)
	}
}

func TestRotateLeavesOldTokenWhenPersistenceFails(t *testing.T) {
	service, fake, secrets := newTestService()
	created, err := service.Create(context.Background(), CreateRequest{AgentName: "codex", DisplayName: "Codex"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	secrets.failUpdate = true
	if _, err := service.Rotate(context.Background(), "codex"); err == nil {
		t.Fatal("expected rotate failure")
	}
	if len(fake.revoked) != 1 || fake.revoked[0] != "session-user-codex-1" {
		t.Fatalf("new session cleanup = %#v", fake.revoked)
	}
	stored, _ := secrets.GetAgent(context.Background(), "codex")
	if stored.AccessToken != created.OneTimeToken {
		t.Fatalf("old token was not retained: %+v", stored)
	}
}

func TestDeactivateRevokesThenRemovesTokenMaterial(t *testing.T) {
	service, fake, secrets := newTestService()
	created, err := service.Create(context.Background(), CreateRequest{AgentName: "codex", DisplayName: "Codex"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	result, err := service.Deactivate(context.Background(), "codex")
	if err != nil {
		t.Fatalf("Deactivate() error = %v", err)
	}
	if result.Status != StatusDeactivated || result.OneTimeToken != "" {
		t.Fatalf("result = %+v", result)
	}
	if len(fake.revoked) != 1 || fake.revoked[0] != created.SessionID {
		t.Fatalf("revoked = %#v", fake.revoked)
	}
	if len(fake.deactivated) != 1 || fake.deactivated[0] != created.MASUserID {
		t.Fatalf("deactivated = %#v", fake.deactivated)
	}
	stored, _ := secrets.GetAgent(context.Background(), "codex")
	if stored.AccessToken != "" {
		t.Fatal("token material remains after deactivation")
	}
}
