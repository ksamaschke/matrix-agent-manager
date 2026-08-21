package agents

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ksamaschke/matrix-agent-manager/internal/mas"
)

var ErrNotFound = errors.New("agent not found")

type Status string

const (
	StatusActive      Status = "active"
	StatusRevoked     Status = "revoked"
	StatusDeactivated Status = "deactivated"
)

// MASClient is the narrow lifecycle subset used by the manager.
type MASClient interface {
	CreateUser(context.Context, mas.CreateUserRequest) (mas.User, error)
	CreatePersonalSession(context.Context, mas.CreatePersonalSessionRequest) (mas.PersonalSession, error)
	ListPersonalSessions(context.Context, string) ([]mas.PersonalSession, error)
	RevokePersonalSession(context.Context, string) error
	DeactivateUser(context.Context, string, bool) (mas.User, error)
	DeleteUser(context.Context, string) error
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
	DeleteAgent(context.Context, string) error
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
	locks   sync.Map
}

type CreateRequest struct {
	AgentName   string
	DisplayName string
}

type Result struct {
	AgentName    string `json:"agent_name"`
	DisplayName  string `json:"display_name"`
	MASUserID    string `json:"mas_user_id"`
	SessionID    string `json:"session_id"`
	OneTimeToken string `json:"one_time_token,omitempty"`
	Generation   int    `json:"generation"`
	Status       Status `json:"status"`
}

func NewService(client MASClient, secrets SecretBackend, config ServiceConfig) *Service {
	return &Service{mas: client, secrets: secrets, config: config, now: time.Now}
}

func (s *Service) withAgentLock(name string, fn func() (Result, error)) (Result, error) {
	value, _ := s.locks.LoadOrStore(name, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	return fn()
}

func (s *Service) Create(ctx context.Context, request CreateRequest) (Result, error) {
	name, err := validateAgentName(request.AgentName)
	if err != nil {
		return Result{}, err
	}
	displayName := strings.TrimSpace(request.DisplayName)
	if displayName == "" {
		return Result{}, errors.New("display name is required")
	}
	if len(displayName) > 256 {
		return Result{}, errors.New("display name must be at most 256 characters")
	}
	return s.withAgentLock(name, func() (Result, error) {
		if _, err := s.secrets.GetAgent(ctx, name); err == nil {
			return Result{}, errors.New("agent already exists")
		} else if !errors.Is(err, ErrNotFound) {
			return Result{}, fmt.Errorf("check existing agent: %w", err)
		}
		user, err := s.mas.CreateUser(ctx, mas.CreateUserRequest{Username: name, DisplayName: &displayName})
		if err != nil {
			return Result{}, fmt.Errorf("create MAS user: %w", err)
		}
		session, err := s.mas.CreatePersonalSession(ctx, mas.CreatePersonalSessionRequest{
			ActorUserID: user.ID,
			HumanName:   displayName,
			Scope:       s.config.TokenScope,
			ExpiresIn:   durationPointer(s.config.TokenExpiry),
		})
		if err != nil {
			_ = s.mas.DeleteUser(ctx, user.ID)
			return Result{}, fmt.Errorf("create MAS personal session: %w", err)
		}
		if session.Attributes.AccessToken == "" {
			_ = s.mas.DeleteUser(ctx, user.ID)
			return Result{}, errors.New("MAS returned no access token")
		}
		now := s.now()
		record := SecretRecord{AgentName: name, DisplayName: displayName, MASUserID: user.ID, SessionID: session.ID, AccessToken: session.Attributes.AccessToken, Generation: 1, Status: StatusActive, CreatedAt: now, UpdatedAt: now}
		if err := s.secrets.CreateAgent(ctx, record); err != nil {
			_ = s.mas.RevokePersonalSession(ctx, session.ID)
			_ = s.mas.DeleteUser(ctx, user.ID)
			return Result{}, fmt.Errorf("persist agent secret: %w", err)
		}
		return resultFromRecord(record, true), nil
	})
}

func (s *Service) Rotate(ctx context.Context, name string) (Result, error) {
	if _, err := validateAgentName(name); err != nil {
		return Result{}, err
	}
	return s.withAgentLock(name, func() (Result, error) {
		record, err := s.secrets.GetAgent(ctx, name)
		if err != nil {
			return Result{}, err
		}
		if record.Status == StatusDeactivated {
			return Result{}, errors.New("agent is deactivated")
		}
		session, err := s.mas.CreatePersonalSession(ctx, mas.CreatePersonalSessionRequest{ActorUserID: record.MASUserID, HumanName: record.DisplayName, Scope: s.config.TokenScope, ExpiresIn: durationPointer(s.config.TokenExpiry)})
		if err != nil {
			return Result{}, fmt.Errorf("create replacement MAS session: %w", err)
		}
		if session.Attributes.AccessToken == "" {
			return Result{}, errors.New("MAS returned no replacement access token")
		}
		oldSessionID := record.SessionID
		oldStatus := record.Status
		record.SessionID = session.ID
		record.AccessToken = session.Attributes.AccessToken
		record.Generation++
		record.Status = StatusActive
		record.UpdatedAt = s.now()
		if err := s.secrets.UpdateAgent(ctx, record); err != nil {
			_ = s.mas.RevokePersonalSession(ctx, session.ID)
			return Result{}, fmt.Errorf("persist replacement agent secret: %w", err)
		}
		if oldStatus == StatusActive && oldSessionID != "" {
			if err := s.mas.RevokePersonalSession(ctx, oldSessionID); err != nil {
				return Result{}, fmt.Errorf("revoke previous MAS session: %w", err)
			}
		}
		return resultFromRecord(record, true), nil
	})
}

// Revoke invalidates every active personal session but keeps the MAS account and
// metadata. A later Rotate can issue a fresh token for the same named agent.
func (s *Service) Revoke(ctx context.Context, name string) (Result, error) {
	if _, err := validateAgentName(name); err != nil {
		return Result{}, err
	}
	return s.withAgentLock(name, func() (Result, error) {
		record, err := s.secrets.GetAgent(ctx, name)
		if err != nil {
			return Result{}, err
		}
		if record.Status == StatusDeactivated {
			return Result{}, errors.New("agent is deactivated")
		}
		if err := s.revokeActiveSessions(ctx, record); err != nil {
			return Result{}, err
		}
		record.SessionID = ""
		record.AccessToken = ""
		record.Status = StatusRevoked
		record.UpdatedAt = s.now()
		if err := s.secrets.UpdateAgent(ctx, record); err != nil {
			// MAS has already revoked the sessions. Do not retain the old token
			// locally when the status write cannot be persisted.
			_ = s.secrets.DeleteAgent(ctx, name)
			return Result{}, fmt.Errorf("persist revoked agent: %w", err)
		}
		return resultFromRecord(record, false), nil
	})
}

func (s *Service) Deactivate(ctx context.Context, name string) (Result, error) {
	if _, err := validateAgentName(name); err != nil {
		return Result{}, err
	}
	return s.withAgentLock(name, func() (Result, error) {
		record, err := s.secrets.GetAgent(ctx, name)
		if err != nil {
			return Result{}, err
		}
		if record.Status == StatusDeactivated {
			return resultFromRecord(record, false), nil
		}
		if err := s.revokeActiveSessions(ctx, record); err != nil {
			return Result{}, err
		}
		if _, err := s.mas.DeactivateUser(ctx, record.MASUserID, false); err != nil {
			return Result{}, fmt.Errorf("deactivate MAS user: %w", err)
		}
		record.SessionID = ""
		record.AccessToken = ""
		record.Status = StatusDeactivated
		record.UpdatedAt = s.now()
		if err := s.secrets.UpdateAgent(ctx, record); err != nil {
			// MAS has already accepted deactivation. Prefer removing local token
			// material over retaining a stale credential after a write failure.
			_ = s.secrets.DeleteAgent(ctx, name)
			return Result{}, fmt.Errorf("persist deactivated agent: %w", err)
		}
		return resultFromRecord(record, false), nil
	})
}

// Remove revokes every active personal session, deactivates the MAS user, and
// deletes local token material. Local deletion happens only after MAS succeeds.
func (s *Service) Remove(ctx context.Context, name string) (Result, error) {
	if _, err := validateAgentName(name); err != nil {
		return Result{}, err
	}
	return s.withAgentLock(name, func() (Result, error) {
		record, err := s.secrets.GetAgent(ctx, name)
		if err != nil {
			return Result{}, err
		}
		if record.Status == StatusDeactivated {
			if err := s.secrets.DeleteAgent(ctx, name); err != nil {
				return Result{}, fmt.Errorf("delete agent Secret: %w", err)
			}
			return resultFromRecord(record, false), nil
		}
		if err := s.revokeActiveSessions(ctx, record); err != nil {
			return Result{}, err
		}
		if _, err := s.mas.DeactivateUser(ctx, record.MASUserID, false); err != nil {
			return Result{}, fmt.Errorf("deactivate MAS user: %w", err)
		}
		if err := s.secrets.DeleteAgent(ctx, name); err != nil {
			return Result{}, fmt.Errorf("delete agent Secret: %w", err)
		}
		record.SessionID = ""
		record.AccessToken = ""
		record.Status = StatusDeactivated
		return resultFromRecord(record, false), nil
	})
}

func (s *Service) revokeActiveSessions(ctx context.Context, record SecretRecord) error {
	sessions, err := s.mas.ListPersonalSessions(ctx, record.MASUserID)
	if err != nil {
		return fmt.Errorf("list agent MAS sessions: %w", err)
	}
	seen := make(map[string]struct{}, len(sessions)+1)
	for _, session := range sessions {
		if session.ID == "" {
			continue
		}
		seen[session.ID] = struct{}{}
		if session.Attributes.RevokedAt != nil {
			continue
		}
		if err := s.mas.RevokePersonalSession(ctx, session.ID); err != nil {
			return fmt.Errorf("revoke agent session: %w", err)
		}
	}
	if record.Status == StatusActive && record.SessionID != "" {
		if _, ok := seen[record.SessionID]; !ok {
			if err := s.mas.RevokePersonalSession(ctx, record.SessionID); err != nil {
				return fmt.Errorf("revoke recorded agent session: %w", err)
			}
		}
	}
	return nil
}

func (s *Service) List(ctx context.Context) ([]Result, error) {
	records, err := s.secrets.ListAgents(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].AgentName < records[j].AgentName })
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
	if name == "" || len(name) > 63 {
		return "", errors.New("agent name must be 1-63 characters")
	}
	for i, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			if (i == 0 || i == len(name)-1) && r == '-' {
				return "", errors.New("agent name must start and end with a letter or digit")
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
