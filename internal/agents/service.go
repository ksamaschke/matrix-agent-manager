package agents

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ksamaschke/matrix-agent-manager/internal/mas"
)

var ErrNotFound = errors.New("agent not found")

type Status string

const (
	StatusActive      Status = "active"
	StatusDeactivated Status = "deactivated"
)

// MASClient is the narrow lifecycle subset used by the manager.
type MASClient interface {
	CreateUser(context.Context, mas.CreateUserRequest) (mas.User, error)
	CreatePersonalSession(context.Context, mas.CreatePersonalSessionRequest) (mas.PersonalSession, error)
	RevokePersonalSession(context.Context, string) error
	DeactivateUser(context.Context, string, bool) (mas.User, error)
}

// SecretRecord is metadata plus one token value held only by the secret backend
// and the immediate create/rotate result. Ordinary list/detail APIs omit it.
type SecretRecord struct {
	AgentName   string
	DisplayName string
	MASUserID   string
	SessionID   string
	AccessToken string
	Generation  int
	Status      Status
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// SecretBackend stores agent metadata and token material.
type SecretBackend interface {
	GetAgent(context.Context, string) (SecretRecord, error)
	CreateAgent(context.Context, SecretRecord) error
	UpdateAgent(context.Context, SecretRecord) error
	ListAgents(context.Context) ([]SecretRecord, error)
}

type ServiceConfig struct {
	SecretNamePrefix string
	TokenScope       string
	TokenExpiry      time.Duration
}

type Service struct {
	mas     MASClient
	secrets SecretBackend
	config  ServiceConfig
	now     func() time.Time
}

type CreateRequest struct {
	AgentName   string
	DisplayName string
}

type Result struct {
	AgentName    string
	DisplayName  string
	MASUserID    string
	SessionID    string
	OneTimeToken string
	Generation   int
	Status       Status
}

func NewService(client MASClient, secrets SecretBackend, config ServiceConfig) *Service {
	return &Service{mas: client, secrets: secrets, config: config, now: time.Now}
}

func (s *Service) Create(ctx context.Context, request CreateRequest) (Result, error) {
	name, err := validateAgentName(request.AgentName)
	if err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(request.DisplayName) == "" {
		return Result{}, errors.New("display name is required")
	}
	if _, err := s.secrets.GetAgent(ctx, name); err == nil {
		return Result{}, errors.New("agent already exists")
	} else if !errors.Is(err, ErrNotFound) {
		return Result{}, fmt.Errorf("check existing agent: %w", err)
	}
	displayName := request.DisplayName
	user, err := s.mas.CreateUser(ctx, mas.CreateUserRequest{Username: name, DisplayName: &displayName})
	if err != nil {
		return Result{}, fmt.Errorf("create MAS user: %w", err)
	}
	session, err := s.mas.CreatePersonalSession(ctx, mas.CreatePersonalSessionRequest{
		ActorUserID: user.ID,
		HumanName:   request.DisplayName,
		Scope:       s.config.TokenScope,
		ExpiresIn:   durationPointer(s.config.TokenExpiry),
	})
	if err != nil {
		return Result{}, fmt.Errorf("create MAS personal session: %w", err)
	}
	if session.Attributes.AccessToken == "" {
		return Result{}, errors.New("MAS returned no access token")
	}
	now := s.now()
	record := SecretRecord{AgentName: name, DisplayName: request.DisplayName, MASUserID: user.ID, SessionID: session.ID, AccessToken: session.Attributes.AccessToken, Generation: 1, Status: StatusActive, CreatedAt: now, UpdatedAt: now}
	if err := s.secrets.CreateAgent(ctx, record); err != nil {
		_ = s.mas.RevokePersonalSession(ctx, session.ID)
		return Result{}, fmt.Errorf("persist agent secret: %w", err)
	}
	return resultFromRecord(record, true), nil
}

func (s *Service) Rotate(ctx context.Context, name string) (Result, error) {
	record, err := s.secrets.GetAgent(ctx, name)
	if err != nil {
		return Result{}, err
	}
	if record.Status != StatusActive {
		return Result{}, errors.New("agent is not active")
	}
	session, err := s.mas.CreatePersonalSession(ctx, mas.CreatePersonalSessionRequest{ActorUserID: record.MASUserID, HumanName: record.DisplayName, Scope: s.config.TokenScope, ExpiresIn: durationPointer(s.config.TokenExpiry)})
	if err != nil {
		return Result{}, fmt.Errorf("create replacement MAS session: %w", err)
	}
	if session.Attributes.AccessToken == "" {
		return Result{}, errors.New("MAS returned no replacement access token")
	}
	oldSessionID := record.SessionID
	record.SessionID = session.ID
	record.AccessToken = session.Attributes.AccessToken
	record.Generation++
	record.UpdatedAt = s.now()
	if err := s.secrets.UpdateAgent(ctx, record); err != nil {
		_ = s.mas.RevokePersonalSession(ctx, session.ID)
		return Result{}, fmt.Errorf("persist replacement agent secret: %w", err)
	}
	if err := s.mas.RevokePersonalSession(ctx, oldSessionID); err != nil {
		return Result{}, fmt.Errorf("revoke previous MAS session: %w", err)
	}
	return resultFromRecord(record, true), nil
}

func (s *Service) Deactivate(ctx context.Context, name string) (Result, error) {
	record, err := s.secrets.GetAgent(ctx, name)
	if err != nil {
		return Result{}, err
	}
	if record.Status == StatusDeactivated {
		return resultFromRecord(record, false), nil
	}
	if record.SessionID != "" {
		if err := s.mas.RevokePersonalSession(ctx, record.SessionID); err != nil {
			return Result{}, fmt.Errorf("revoke agent session: %w", err)
		}
	}
	if _, err := s.mas.DeactivateUser(ctx, record.MASUserID, false); err != nil {
		return Result{}, fmt.Errorf("deactivate MAS user: %w", err)
	}
	record.AccessToken = ""
	record.Status = StatusDeactivated
	record.UpdatedAt = s.now()
	if err := s.secrets.UpdateAgent(ctx, record); err != nil {
		return Result{}, fmt.Errorf("persist deactivated agent: %w", err)
	}
	return resultFromRecord(record, false), nil
}

func (s *Service) List(ctx context.Context) ([]Result, error) {
	records, err := s.secrets.ListAgents(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(records))
	for _, record := range records {
		results = append(results, resultFromRecord(record, false))
	}
	return results, nil
}

func resultFromRecord(record SecretRecord, includeToken bool) Result {
	result := Result{AgentName: record.AgentName, DisplayName: record.DisplayName, MASUserID: record.MASUserID, SessionID: record.SessionID, Generation: record.Generation, Status: record.Status}
	if includeToken {
		result.OneTimeToken = record.AccessToken
	}
	return result
}

func validateAgentName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", errors.New("agent name must be 1-64 characters")
	}
	for i, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			if i == 0 && r == '-' {
				return "", errors.New("agent name must start with a letter or digit")
			}
			continue
		}
		return "", errors.New("agent name may contain only lowercase letters, digits, and hyphens")
	}
	return name, nil
}

func durationPointer(value time.Duration) *uint32 {
	if value <= 0 {
		return nil
	}
	seconds := uint64(value / time.Second)
	if seconds == 0 || seconds > ^uint64(0xffffffff) {
		return nil
	}
	result := uint32(seconds)
	return &result
}
