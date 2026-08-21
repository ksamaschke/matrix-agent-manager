package oidcauth

import (
	"errors"
	"sync"
	"time"
)

// StateStore makes OIDC state single-use. Production deployments should inject
// a shared store when the manager runs more than one replica.
type StateStore interface {
	Put(key string, expiresAt time.Time) error
	Consume(key string, now time.Time) bool
}

// MemoryStateStore is intended for tests and single-process development only.
type MemoryStateStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{entries: make(map[string]time.Time)}
}

func (s *MemoryStateStore) Put(key string, expiresAt time.Time) error {
	if key == "" {
		return errors.New("state key is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = expiresAt
	return nil
}

func (s *MemoryStateStore) Consume(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiresAt, ok := s.entries[key]
	if !ok {
		return false
	}
	delete(s.entries, key)
	return expiresAt.After(now)
}
