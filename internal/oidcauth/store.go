package oidcauth

import (
	"errors"
	"sync"
	"time"
)

const defaultStateStoreMaxEntries = 4096

// StateStore makes OIDC state single-use. Production deployments should inject
// a shared store when the manager runs more than one replica.
type StateStore interface {
	Put(key string, expiresAt time.Time) error
	Consume(key string, now time.Time) bool
}

// MemoryStateStore is intended for tests and single-process development only.
// It is bounded and opportunistically removes expired entries so abandoned
// unauthenticated login attempts cannot grow it without limit.
type MemoryStateStore struct {
	mu         sync.Mutex
	entries    map[string]time.Time
	maxEntries int
	now        func() time.Time
}

func NewMemoryStateStore() *MemoryStateStore {
	return NewMemoryStateStoreWithClock(defaultStateStoreMaxEntries, time.Now)
}

func NewMemoryStateStoreWithLimit(maxEntries int) *MemoryStateStore {
	return NewMemoryStateStoreWithClock(maxEntries, time.Now)
}

func NewMemoryStateStoreWithClock(maxEntries int, now func() time.Time) *MemoryStateStore {
	if maxEntries < 1 {
		maxEntries = defaultStateStoreMaxEntries
	}
	if now == nil {
		now = time.Now
	}
	return &MemoryStateStore{entries: make(map[string]time.Time), maxEntries: maxEntries, now: now}
}

func (s *MemoryStateStore) Put(key string, expiresAt time.Time) error {
	if key == "" {
		return errors.New("state key is required")
	}
	now := s.now()
	if !expiresAt.After(now) {
		return errors.New("state expiry must be in the future")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpired(now)
	if _, exists := s.entries[key]; !exists && len(s.entries) >= s.maxEntries {
		return errors.New("OIDC state store capacity reached")
	}
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

func (s *MemoryStateStore) pruneExpired(now time.Time) {
	for key, expiresAt := range s.entries {
		if !expiresAt.After(now) {
			delete(s.entries, key)
		}
	}
}

var _ StateStore = (*MemoryStateStore)(nil)
