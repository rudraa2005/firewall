package firewall

import (
	"context"
	"time"
)

// memoryBackend implements StateBackend using the in-process stores. This is
// the default backend and requires no external dependencies.
type memoryBackend struct {
	reputation *ReputationStore
	canaries   *CanaryStore
	limiter    *RateLimiter
}

func newMemoryBackend(halfLife time.Duration) *memoryBackend {
	return &memoryBackend{
		reputation: NewReputationStore(halfLife),
		canaries:   NewCanaryStore(),
		limiter:    NewRateLimiter(),
	}
}

func (m *memoryBackend) start(ctx context.Context) {
	m.canaries.Start(ctx)
}

func (m *memoryBackend) ReputationScore(clientID string, now time.Time) float64 {
	return m.reputation.Score(clientID, now)
}

func (m *memoryBackend) ReputationAdd(clientID string, delta, floor float64, now time.Time) float64 {
	return m.reputation.Add(clientID, delta, floor, now)
}

func (m *memoryBackend) CanaryPut(record CanaryRecord) {
	m.canaries.Put(record)
}

func (m *memoryBackend) CanaryTake(correlationID string) (CanaryRecord, bool) {
	return m.canaries.Take(correlationID)
}

func (m *memoryBackend) CanaryDelete(correlationID string) {
	m.canaries.Delete(correlationID)
}

func (m *memoryBackend) RateAllow(clientID string, limit int, now time.Time) bool {
	return m.limiter.Allow(clientID, limit, now)
}
