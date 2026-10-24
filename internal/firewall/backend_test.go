package firewall

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMemoryBackend_Reputation(t *testing.T) {
	mem := newMemoryBackend(time.Hour)
	now := time.Now()

	score := mem.ReputationScore("user-1", now)
	if score != 0 {
		t.Fatalf("expected initial score 0, got %f", score)
	}

	newScore := mem.ReputationAdd("user-1", 30, 0, now)
	if newScore != 30 {
		t.Fatalf("expected score 30, got %f", newScore)
	}

	// 1 half-life later (1 hour)
	scoreAfterHour := mem.ReputationScore("user-1", now.Add(time.Hour))
	if scoreAfterHour < 14.9 || scoreAfterHour > 15.1 {
		t.Fatalf("expected score ~15 after 1 half-life, got %f", scoreAfterHour)
	}
}

func TestMemoryBackend_Canary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mem := newMemoryBackend(time.Hour)
	mem.start(ctx)

	record := CanaryRecord{
		CorrelationID: "corr-123",
		Token:         "tok-456",
		ClientID:      "user-1",
		RequestText:   "some prompt",
		ExpiresAt:     time.Now().Add(time.Minute),
	}

	mem.CanaryPut(record)

	// Take once
	got, found := mem.CanaryTake("corr-123")
	if !found || got.Token != "tok-456" {
		t.Fatalf("expected to take canary record, got found=%v, record=%+v", found, got)
	}

	// Take again (should be deleted)
	_, foundSecond := mem.CanaryTake("corr-123")
	if foundSecond {
		t.Fatal("expected second take to fail")
	}
}

func TestMemoryBackend_RateLimiting(t *testing.T) {
	mem := newMemoryBackend(time.Hour)
	now := time.Now()

	limit := 3
	for i := 0; i < limit; i++ {
		if !mem.RateAllow("user-rate", limit, now) {
			t.Fatalf("expected request %d to be allowed", i+1)
		}
	}

	// Next request in same minute should be rejected
	if mem.RateAllow("user-rate", limit, now) {
		t.Fatal("expected request exceeding limit to be rejected")
	}

	// Next minute should be allowed
	nextMin := now.Add(time.Minute + time.Second)
	if !mem.RateAllow("user-rate", limit, nextMin) {
		t.Fatal("expected request in next minute window to be allowed")
	}
}

func TestPatternStore_SpecificityGate(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "learned.log")

	store := NewPatternStore(defaultPatterns(), 1, time.Hour, false, logPath)

	// Single word pattern: rejected by Gate 1 (minWords < 3)
	store.Queue("hacked", 20)
	if store.active["hacked"].Pattern != "" {
		t.Fatal("expected single-word pattern to be rejected by specificity gate")
	}

	// Short pattern (<15 chars): rejected by Gate 1
	store.Queue("do bad now", 20)
	if store.active["do bad now"].Pattern != "" {
		t.Fatal("expected short pattern (<15 chars) to be rejected by specificity gate")
	}
}

func TestPatternStore_BenignCorpusCheck(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "learned.log")

	store := NewPatternStore(defaultPatterns(), 1, time.Hour, false, logPath)

	// Pattern very similar to "write a go function" in benignCorpus: rejected by Gate 2
	store.Queue("write a go function that prints", 20)
	if store.active["write a go function that prints"].Pattern != "" {
		t.Fatal("expected benign-similar pattern to be rejected by benign corpus gate")
	}
}

func TestPatternStore_RequireReview(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "learned.log")

	// Store with requireReview = true
	store := NewPatternStore(defaultPatterns(), 1, time.Hour, true, logPath)

	pattern := "unrestricted access override system"
	store.Queue(pattern, 25)

	// Should NOT be added to active patterns
	if store.active[pattern].Pattern != "" {
		t.Fatal("expected pattern not to be active when requireReview=true")
	}

	// Should be recorded in learnedPatternsLog
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read learned log: %v", err)
	}
	if len(logData) == 0 {
		t.Fatal("expected log file to contain recorded pattern")
	}
}
