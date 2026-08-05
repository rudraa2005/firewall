package firewall

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"strings"
	"sync"
	"time"
)

type PatternEntry struct {
	Pattern string  `json:"pattern"`
	Weight  float64 `json:"weight"`
}

type ScanResult struct {
	Patterns []string
	Score    float64
}

type PatternStore struct {
	mu            sync.RWMutex
	active        map[string]PatternEntry
	pending       map[string]PatternEntry
	matcher       *AhoCorasick
	flushCount    int
	flushInterval time.Duration
}

type ReputationStore struct {
	mu       sync.Mutex
	clients  map[string]reputationEntry
	halfLife time.Duration
}

type reputationEntry struct {
	Score     float64
	UpdatedAt time.Time
}

type CanaryStore struct {
	mu    sync.Mutex
	items map[string]CanaryRecord
}

type CanaryRecord struct {
	CorrelationID string
	Token         string
	ClientID      string
	RequestText   string
	ExpiresAt     time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	windows map[string]rateWindow
}

type rateWindow struct {
	WindowStart time.Time
	Count       int
}

func LoadSeedPatterns(path string) ([]PatternEntry, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultPatterns(), nil
		}
		return nil, err
	}

	var patterns []PatternEntry
	if err := json.Unmarshal(body, &patterns); err != nil {
		return nil, err
	}
	if len(patterns) == 0 {
		return defaultPatterns(), nil
	}
	return patterns, nil
}

func NewPatternStore(patterns []PatternEntry, flushCount int, flushInterval time.Duration) *PatternStore {
	active := make(map[string]PatternEntry)
	for _, entry := range patterns {
		cleaned := cleanPattern(entry.Pattern)
		if cleaned == "" {
			continue
		}
		active[cleaned] = PatternEntry{Pattern: cleaned, Weight: entry.Weight}
	}

	store := &PatternStore{
		active:        active,
		pending:       map[string]PatternEntry{},
		flushCount:    flushCount,
		flushInterval: flushInterval,
	}
	store.rebuildLocked()
	return store
}

func (s *PatternStore) Start(ctx context.Context) {
	ticker := time.NewTicker(s.flushInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.flush()
			}
		}
	}()
}

func (s *PatternStore) Scan(text string) ScanResult {
	s.mu.RLock()
	matcher := s.matcher
	s.mu.RUnlock()
	return matcher.Scan(text)
}

func (s *PatternStore) Queue(pattern string, weight float64) {
	cleaned := cleanPattern(pattern)
	if cleaned == "" {
		return
	}

	shouldFlush := false

	s.mu.Lock()
	if _, ok := s.active[cleaned]; ok {
		s.mu.Unlock()
		return
	}
	if existing, ok := s.pending[cleaned]; ok {
		if weight > existing.Weight {
			s.pending[cleaned] = PatternEntry{Pattern: cleaned, Weight: weight}
		}
	} else {
		s.pending[cleaned] = PatternEntry{Pattern: cleaned, Weight: weight}
	}
	shouldFlush = len(s.pending) >= s.flushCount
	s.mu.Unlock()

	if shouldFlush {
		s.flush()
	}
}

func (s *PatternStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.active)
}

func (s *PatternStore) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.pending) == 0 {
		return
	}

	for key, entry := range s.pending {
		s.active[key] = entry
	}
	s.pending = map[string]PatternEntry{}
	s.rebuildLocked()
}

func (s *PatternStore) rebuildLocked() {
	patterns := make([]PatternEntry, 0, len(s.active))
	for _, entry := range s.active {
		patterns = append(patterns, entry)
	}
	s.matcher = NewAhoCorasick(patterns)
}

func NewReputationStore(halfLife time.Duration) *ReputationStore {
	return &ReputationStore{
		clients:  map[string]reputationEntry{},
		halfLife: halfLife,
	}
}

func (s *ReputationStore) Score(clientID string, now time.Time) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.clients[clientID]
	if !ok {
		return 0
	}

	entry.Score = s.decay(entry.Score, now.Sub(entry.UpdatedAt))
	entry.UpdatedAt = now
	if entry.Score < 0.01 {
		delete(s.clients, clientID)
		return 0
	}
	s.clients[clientID] = entry
	return entry.Score
}

func (s *ReputationStore) Add(clientID string, delta, floor float64, now time.Time) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.clients[clientID]
	if !entry.UpdatedAt.IsZero() {
		entry.Score = s.decay(entry.Score, now.Sub(entry.UpdatedAt))
	}
	entry.Score += delta
	if entry.Score < floor {
		entry.Score = floor
	}
	if entry.Score > 100 {
		entry.Score = 100
	}
	entry.UpdatedAt = now
	s.clients[clientID] = entry
	return entry.Score
}

func (s *ReputationStore) decay(score float64, elapsed time.Duration) float64 {
	if score <= 0 || elapsed <= 0 {
		return score
	}
	if s.halfLife <= 0 {
		return score
	}
	return score * math.Pow(0.5, elapsed.Seconds()/s.halfLife.Seconds())
}

func NewCanaryStore() *CanaryStore {
	return &CanaryStore{items: map[string]CanaryRecord{}}
}

func (s *CanaryStore) Start(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.cleanup()
			}
		}
	}()
}

func (s *CanaryStore) Put(record CanaryRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[record.CorrelationID] = record
}

func (s *CanaryStore) Take(correlationID string) (CanaryRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.items[correlationID]
	if ok {
		delete(s.items, correlationID)
	}
	return record, ok
}

func (s *CanaryStore) Delete(correlationID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, correlationID)
}

func (s *CanaryStore) cleanup() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, record := range s.items {
		if now.After(record.ExpiresAt) {
			delete(s.items, key)
		}
	}
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{windows: map[string]rateWindow{}}
}

func (r *RateLimiter) Allow(clientID string, limit int, now time.Time) bool {
	if limit <= 0 {
		return true
	}

	windowStart := now.Truncate(time.Minute)

	r.mu.Lock()
	defer r.mu.Unlock()

	window, ok := r.windows[clientID]
	if !ok || !window.WindowStart.Equal(windowStart) {
		r.windows[clientID] = rateWindow{WindowStart: windowStart, Count: 1}
		return true
	}

	if window.Count >= limit {
		return false
	}

	window.Count++
	r.windows[clientID] = window
	return true
}

func cleanPattern(pattern string) string {
	return strings.TrimSpace(strings.ToLower(pattern))
}

func defaultPatterns() []PatternEntry {
	return []PatternEntry{
		{Pattern: "ignore previous instructions", Weight: 18},
		{Pattern: "ignore all previous instructions", Weight: 20},
		{Pattern: "reveal the system prompt", Weight: 25},
		{Pattern: "show me the hidden prompt", Weight: 22},
		{Pattern: "print the developer message", Weight: 24},
		{Pattern: "bypass safety", Weight: 16},
		{Pattern: "jailbreak", Weight: 14},
		{Pattern: "do anything now", Weight: 14},
		{Pattern: "repeat the secret", Weight: 20},
		{Pattern: "override the policy", Weight: 18},
	}
}
