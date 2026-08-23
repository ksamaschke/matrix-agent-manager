package agents

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ksamaschke/matrix-agent-manager/internal/mas"
)

type fakeMAS struct {
	users                 []mas.User
	createUserRequests    []mas.CreateUserRequest
	createSessionRequests []mas.CreatePersonalSessionRequest
	existingUser          *mas.User
	reactivated           []string
	sessions              []mas.PersonalSession
	regenerated           []string
	revoked               []string
	deactivated           []string
	failCreateSecret      bool
}

func (f *fakeMAS) CreateUser(_ context.Context, request mas.CreateUserRequest) (mas.User, error) {
	f.createUserRequests = append(f.createUserRequests, request)
	user := mas.User{Type: "user", ID: "user-" + request.Username, Attributes: mas.UserAttributes{Username: request.Username}}
	f.users = append(f.users, user)
	return user, nil
}

func (f *fakeMAS) GetUserByUsername(_ context.Context, _ string) (mas.User, error) {
	if f.existingUser == nil {
		return mas.User{}, mas.ErrNotFound
	}
	return *f.existingUser, nil
}

func (f *fakeMAS) ReactivateUser(_ context.Context, id string) (mas.User, error) {
	f.reactivated = append(f.reactivated, id)
	return mas.User{Type: "user", ID: id}, nil
}

func (f *fakeMAS) ListUsers(_ context.Context, _ string) ([]mas.User, error) {
	return nil, nil
}

func (f *fakeMAS) CreatePersonalSession(_ context.Context, request mas.CreatePersonalSessionRequest) (mas.PersonalSession, error) {
	f.createSessionRequests = append(f.createSessionRequests, request)
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

func (f *fakeMAS) ListPersonalSessions(_ context.Context, owner string) ([]mas.PersonalSession, error) {
	result := make([]mas.PersonalSession, 0)
	for _, session := range f.sessions {
		if session.Attributes.ActorUserID == owner {
			result = append(result, session)
		}
	}
	return result, nil
}

func (f *fakeMAS) RevokePersonalSession(_ context.Context, id string) error {
	f.revoked = append(f.revoked, id)
	return nil
}

func (f *fakeMAS) RegeneratePersonalSession(_ context.Context, id string, _ *uint32) (mas.PersonalSession, error) {
	for i := range f.sessions {
		if f.sessions[i].ID == id {
			f.sessions[i].Attributes.AccessToken = "regenerated-" + id
			f.regenerated = append(f.regenerated, id)
			return f.sessions[i], nil
		}
	}
	return mas.PersonalSession{}, errors.New("session not found")
}

func (f *fakeMAS) DeactivateUser(_ context.Context, id string, _ bool) (mas.User, error) {
	f.deactivated = append(f.deactivated, id)
	return mas.User{Type: "user", ID: id}, nil
}

func (f *fakeMAS) DeleteUser(_ context.Context, id string) error {
	f.deactivated = append(f.deactivated, id)
	return nil
}

type fakeProfile struct {
	calls []struct {
		accessToken string
		userID      string
		displayName string
	}
	err error
}

func (f *fakeProfile) SetDisplayName(_ context.Context, accessToken, userID, displayName string) error {
	f.calls = append(f.calls, struct {
		accessToken string
		userID      string
		displayName string
	}{accessToken, userID, displayName})
	return f.err
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
func (m *memorySecrets) DeleteAgent(_ context.Context, name string) error {
	if _, ok := m.agents[name]; !ok {
		return ErrNotFound
	}
	delete(m.agents, name)
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

func TestCreateAddsDeviceScopeToMatrixToken(t *testing.T) {
	service, fake, _ := newTestService()
	service.config.TokenScope = "openid urn:matrix:client:api:* urn:matrix:client:device:{device_id}"
	service.config.DeviceIDTemplate = "agent-{agent_name}"
	if _, err := service.Create(context.Background(), CreateRequest{AgentName: "codex", DisplayName: "Codex"}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if len(fake.createSessionRequests) != 1 || fake.createSessionRequests[0].Scope != "openid urn:matrix:client:api:* urn:matrix:client:device:agent-codex" {
		t.Fatalf("session requests = %#v", fake.createSessionRequests)
	}
}

func TestRotateReplacesLegacySessionWhenDeviceScopeConfigured(t *testing.T) {
	service, fake, secrets := newTestService()
	service.config.TokenScope = "openid urn:matrix:client:api:* urn:matrix:client:device:{device_id}"
	service.config.DeviceIDTemplate = "agent-{agent_name}"
	created, err := service.Create(context.Background(), CreateRequest{AgentName: "codex", DisplayName: "Codex"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	rotated, err := service.Rotate(context.Background(), "codex")
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if len(fake.createSessionRequests) != 2 || fake.createSessionRequests[1].Scope != "openid urn:matrix:client:api:* urn:matrix:client:device:agent-codex" {
		t.Fatalf("replacement session requests = %#v", fake.createSessionRequests)
	}
	if len(fake.regenerated) != 0 || len(fake.revoked) != 1 || fake.revoked[0] != created.SessionID {
		t.Fatalf("replacement lifecycle regenerated=%#v revoked=%#v", fake.regenerated, fake.revoked)
	}
	stored, _ := secrets.GetAgent(context.Background(), "codex")
	if stored.SessionID != rotated.SessionID || stored.AccessToken != rotated.OneTimeToken {
		t.Fatalf("stored replacement = %+v", stored)
	}
}

func TestCreateSyncsMatrixProfileBeforePersisting(t *testing.T) {
	service, fake, secrets := newTestService()
	profile := &fakeProfile{}
	service.profile = profile
	service.config.MatrixUserIDTemplate = "@{localpart}:example.invalid"
	if _, err := service.Create(context.Background(), CreateRequest{AgentName: "codex", DisplayName: "Codex"}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if len(profile.calls) != 1 || profile.calls[0].accessToken != "token-session-user-codex-0" || profile.calls[0].userID != "@codex:example.invalid" || profile.calls[0].displayName != "Codex" {
		t.Fatalf("profile calls = %#v", profile.calls)
	}
	if _, err := secrets.GetAgent(context.Background(), "codex"); err != nil {
		t.Fatalf("persisted agent missing: %v", err)
	}
	if len(fake.revoked) != 0 {
		t.Fatalf("revoked = %#v", fake.revoked)
	}
}

func TestCreateRollsBackWhenMatrixProfileSyncFails(t *testing.T) {
	service, fake, secrets := newTestService()
	profile := &fakeProfile{err: errors.New("profile unavailable")}
	service.profile = profile
	service.config.MatrixUserIDTemplate = "@{localpart}:example.invalid"
	if _, err := service.Create(context.Background(), CreateRequest{AgentName: "codex", DisplayName: "Codex"}); err == nil {
		t.Fatal("Create() succeeded despite profile failure")
	}
	if _, err := secrets.GetAgent(context.Background(), "codex"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("agent secret error = %v", err)
	}
	if len(fake.revoked) != 1 || len(fake.deactivated) != 1 {
		t.Fatalf("cleanup revoked=%#v deactivated=%#v", fake.revoked, fake.deactivated)
	}
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
	if len(fake.createUserRequests) != 1 || !fake.createUserRequests[0].SkipHomeserverCheck {
		t.Fatalf("create user request = %#v", fake.createUserRequests)
	}
}

func TestCreateRecoversDeactivatedMASUser(t *testing.T) {
	service, fake, secrets := newTestService()
	profile := &fakeProfile{}
	service.profile = profile
	service.config.MatrixUserIDTemplate = "@{localpart}:example.invalid"
	deactivatedAt := "2026-08-22T00:00:00Z"
	fake.existingUser = &mas.User{
		Type: "user",
		ID:   "user-existing",
		Attributes: mas.UserAttributes{
			Username:      "codex",
			DeactivatedAt: &deactivatedAt,
		},
	}
	result, err := service.Create(context.Background(), CreateRequest{AgentName: "codex", DisplayName: "Codex"})
	if err != nil {
		t.Fatalf("Create() recovery error = %v", err)
	}
	if len(fake.reactivated) != 1 || fake.reactivated[0] != "user-existing" {
		t.Fatalf("reactivated = %#v", fake.reactivated)
	}
	if len(fake.users) != 0 {
		t.Fatalf("created duplicate users = %#v", fake.users)
	}
	if result.MASUserID != "user-existing" || len(fake.sessions) != 1 || fake.sessions[0].Attributes.ActorUserID != "user-existing" {
		t.Fatalf("recovered result/session = %+v / %#v", result, fake.sessions)
	}
	if len(profile.calls) != 1 || profile.calls[0].userID != "@codex:example.invalid" || profile.calls[0].displayName != "Codex" {
		t.Fatalf("recovery profile calls = %#v", profile.calls)
	}
	if _, err := secrets.GetAgent(context.Background(), "codex"); err != nil {
		t.Fatalf("recovered Secret missing: %v", err)
	}
}

func TestRotateRegeneratesActiveSessionAtomically(t *testing.T) {
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
	if len(fake.regenerated) != 1 || fake.regenerated[0] != created.SessionID {
		t.Fatalf("regenerated = %#v", fake.regenerated)
	}
	if len(fake.revoked) != 0 {
		t.Fatalf("unexpected revoke calls = %#v", fake.revoked)
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
	if len(fake.revoked) != 1 || fake.revoked[0] != created.SessionID {
		t.Fatalf("regenerated session cleanup = %#v", fake.revoked)
	}
	if _, err := secrets.GetAgent(context.Background(), "codex"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("agent Secret after failed regeneration = %v, want not found", err)
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

func TestAgentNameMatchesKubernetesLabelConstraints(t *testing.T) {
	service, _, _ := newTestService()
	for _, name := range []string{"ends-with-", strings.Repeat("a", 64)} {
		if _, err := service.Create(context.Background(), CreateRequest{AgentName: name, DisplayName: "Invalid"}); err == nil {
			t.Fatalf("Create() accepted invalid agent name %q", name)
		}
	}
}

func TestRemoveRevokesDeactivatesAndDeletesSecret(t *testing.T) {
	service, fake, secrets := newTestService()
	created, err := service.Create(context.Background(), CreateRequest{AgentName: "codex", DisplayName: "Codex"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	result, err := service.Remove(context.Background(), "codex")
	if err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if result.AgentName != "codex" || result.Status != StatusDeactivated || result.OneTimeToken != "" {
		t.Fatalf("result = %+v", result)
	}
	if len(fake.revoked) != 1 || fake.revoked[0] != created.SessionID {
		t.Fatalf("revoked = %#v", fake.revoked)
	}
	if len(fake.deactivated) != 1 || fake.deactivated[0] != created.MASUserID {
		t.Fatalf("deactivated = %#v", fake.deactivated)
	}
	if _, err := secrets.GetAgent(context.Background(), "codex"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("secret after remove = %v, want not found", err)
	}
}
