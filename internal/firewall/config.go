package firewall

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr           string
	UpstreamURL          string
	ClientIDHeader       string
	PatternFile          string
	TightenThreshold     float64
	BlockThreshold       float64
	TightenedBlock       float64
	PatternPenalty       float64
	CanaryLeakPenalty    float64
	ReputationHalfLife   time.Duration
	CanaryTTL            time.Duration
	PendingFlushCount    int
	PendingFlushInterval time.Duration
	RateLimitPerMinute   int
	CanarySampleRate     float64
	NormalizationDepth   int
	DeepNormalization    int

	// Redis (optional). When set, all mutable state is stored in Redis so
	// multiple firewall instances share reputation, canary, and rate-limit
	// state. When empty the in-memory backend is used (default).
	RedisURL string

	// SmartLearning controls the pattern-learning gates.
	//
	// RequireReview: when true, learned patterns are written to
	// LearnedPatternsLog but are never auto-promoted to active. An operator
	// must promote them by adding them to the seed pattern file. Default false.
	RequireReview bool

	// LearnedPatternsLog is the path to an append-only JSON-lines file where
	// new candidate patterns are recorded for operator review. Empty = no log.
	LearnedPatternsLog string
}

func LoadConfig() (Config, error) {
	cfg := Config{
		ListenAddr:           envString("LISTEN_ADDR", ":8080"),
		UpstreamURL:          envString("UPSTREAM_URL", "http://127.0.0.1:8081"),
		ClientIDHeader:       envString("CLIENT_ID_HEADER", "X-Client-ID"),
		PatternFile:          envString("PATTERN_FILE", "patterns.json"),
		TightenThreshold:     envFloat("TIGHTEN_THRESHOLD", 40),
		BlockThreshold:       envFloat("BLOCK_THRESHOLD", 80),
		TightenedBlock:       envFloat("TIGHTENED_BLOCK_THRESHOLD", 50),
		PatternPenalty:       envFloat("PATTERN_PENALTY", 25),
		CanaryLeakPenalty:    envFloat("CANARY_LEAK_PENALTY", 60),
		ReputationHalfLife:   envDuration("REPUTATION_HALF_LIFE", 30*time.Minute),
		CanaryTTL:            envDuration("CANARY_TTL", 5*time.Minute),
		PendingFlushCount:    envInt("PENDING_FLUSH_COUNT", 25),
		PendingFlushInterval: envDuration("PENDING_FLUSH_INTERVAL", time.Hour),
		RateLimitPerMinute:   envInt("RATE_LIMIT_PER_MINUTE", 60),
		CanarySampleRate:     envFloat("CANARY_SAMPLE_RATE", 1),
		NormalizationDepth:   envInt("NORMALIZATION_DEPTH", 1),
		DeepNormalization:    envInt("DEEP_NORMALIZATION_DEPTH", 3),
		RedisURL:             envString("REDIS_URL", ""),
		RequireReview:        envBool("REQUIRE_PATTERN_REVIEW", false),
		LearnedPatternsLog:   envString("LEARNED_PATTERNS_LOG", ""),
	}

	if cfg.UpstreamURL == "" {
		return Config{}, errors.New("UPSTREAM_URL cannot be empty")
	}
	if cfg.TightenThreshold <= 0 || cfg.BlockThreshold <= 0 || cfg.TightenedBlock <= 0 {
		return Config{}, errors.New("thresholds must be positive")
	}
	if cfg.TightenThreshold >= cfg.BlockThreshold {
		return Config{}, errors.New("TIGHTEN_THRESHOLD must be lower than BLOCK_THRESHOLD")
	}
	if cfg.TightenedBlock < cfg.TightenThreshold || cfg.TightenedBlock > cfg.BlockThreshold {
		return Config{}, errors.New("TIGHTENED_BLOCK_THRESHOLD must be between TIGHTEN_THRESHOLD and BLOCK_THRESHOLD")
	}
	if cfg.CanarySampleRate < 0 || cfg.CanarySampleRate > 1 {
		return Config{}, errors.New("CANARY_SAMPLE_RATE must be between 0 and 1")
	}
	if cfg.PendingFlushCount < 1 {
		return Config{}, errors.New("PENDING_FLUSH_COUNT must be at least 1")
	}
	if cfg.RateLimitPerMinute < 1 {
		return Config{}, errors.New("RATE_LIMIT_PER_MINUTE must be at least 1")
	}
	if cfg.NormalizationDepth < 1 {
		cfg.NormalizationDepth = 1
	}
	if cfg.DeepNormalization < cfg.NormalizationDepth {
		cfg.DeepNormalization = cfg.NormalizationDepth
	}

	return cfg, nil
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envFloat(key string, fallback float64) float64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
