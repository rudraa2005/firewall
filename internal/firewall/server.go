package firewall

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"time"
)

type contextKey string

const requestMetaKey contextKey = "requestMeta"

type requestMeta struct {
	CorrelationID string
	ClientID      string
}

// Server is the LLM firewall proxy. It inspects both the inbound request and
// the upstream response, enforcing pattern-matching, canary-based exfiltration
// detection, reputation scoring, and per-client rate limiting.
type Server struct {
	cfg      Config
	target   *url.URL
	patterns *PatternStore
	state    StateBackend // reputation, canary, rate-limiter (memory or Redis)
	proxy    *httputil.ReverseProxy
	handler  http.Handler
	logger   *log.Logger
	cancel   context.CancelFunc

	// reputation and canaries are exposed for tests that set state directly.
	reputation *ReputationStore
	canaries   *CanaryStore
	limiter    *RateLimiter
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

// preEncoded holds JSON error bodies that are computed once at startup to avoid
// per-request marshal allocations on the hot error paths.
var preEncoded struct {
	blocked         []byte
	blockedLen      string
	responseBlocked []byte
	responseBlocLen string
}

func init() {
	preEncoded.blocked, _ = json.Marshal(map[string]any{"error": "request blocked by firewall"})
	preEncoded.blockedLen = strconv.Itoa(len(preEncoded.blocked))
	preEncoded.responseBlocked, _ = json.Marshal(map[string]any{"error": "response blocked by firewall"})
	preEncoded.responseBlocLen = strconv.Itoa(len(preEncoded.responseBlocked))
}

func New(cfg Config) (*Server, error) {
	target, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return nil, err
	}

	patterns, err := LoadSeedPatterns(cfg.PatternFile)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Build the in-memory stores. These are always created so that tests and
	// the memory backend can reference them directly.
	mem := newMemoryBackend(cfg.ReputationHalfLife)
	mem.start(ctx)

	server := &Server{
		cfg:        cfg,
		target:     target,
		patterns:   NewPatternStore(patterns, cfg.PendingFlushCount, cfg.PendingFlushInterval, cfg.RequireReview, cfg.LearnedPatternsLog),
		state:      mem,
		reputation: mem.reputation,
		canaries:   mem.canaries,
		limiter:    mem.limiter,
		logger:     log.New(os.Stdout, "", log.LstdFlags),
		cancel:     cancel,
	}

	// If REDIS_URL is configured, upgrade the state backend to Redis.
	if cfg.RedisURL != "" {
		rb, err := newRedisBackend(cfg.RedisURL, cfg.ReputationHalfLife)
		if err != nil {
			cancel()
			return nil, err
		}
		server.state = rb
	}

	server.patterns.Start(ctx)

	// Build the reverse proxy. We use a custom RoundTripper (streamingTransport)
	// that pipes the upstream body through the rolling-window canary detector,
	// enabling true streaming without buffering the whole response.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &streamingTransport{
		inner:  transport,
		server: server,
	}
	proxy.ModifyResponse = nil // streaming transport handles response inspection
	proxy.ErrorHandler = server.handleProxyError
	server.proxy = proxy

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.healthz)
	mux.HandleFunc("/", server.handleProxy)
	server.handler = mux

	return server, nil
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) Close() {
	s.cancel()
}

// SetUpstreamTransport replaces the inner transport used by the reverse proxy's
// streaming transport.
func (s *Server) SetUpstreamTransport(rt http.RoundTripper) {
	s.proxy.Transport = &streamingTransport{
		inner:  rt,
		server: s,
	}
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	response := map[string]any{
		"status":          "ok",
		"upstream":        s.target.String(),
		"active_patterns": s.patterns.Size(),
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	cid := r.Header.Get("X-Correlation-ID")
	if cid == "" {
		cid = randomHex(10)
	}
	meta := requestMeta{
		CorrelationID: cid,
		ClientID:      s.resolveClientID(r),
	}
	w.Header().Set("X-Correlation-ID", meta.CorrelationID)

	now := time.Now()
	currentScore := s.state.ReputationScore(meta.ClientID, now)
	if s.isBlocked(currentScore) {
		s.logRequest(meta, r, http.StatusForbidden, "blocked_reputation", start, currentScore)
		writeBlockedRequest(w, meta.CorrelationID)
		return
	}

	limit := s.cfg.RateLimitPerMinute
	if s.isTightened(currentScore) {
		limit = maxInt(1, limit/2)
	}
	if !s.state.RateAllow(meta.ClientID, limit, now) {
		s.logRequest(meta, r, http.StatusTooManyRequests, "rate_limited", start, currentScore)
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":          "client rate limited",
			"correlation_id": meta.CorrelationID,
		})
		return
	}

	// Read the request body into a pooled buffer to reduce allocations.
	bufPtr := bodyPool.Get().(*[]byte)
	*bufPtr = (*bufPtr)[:0]
	*bufPtr, _ = io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10 MiB cap
	_ = r.Body.Close()
	body := make([]byte, len(*bufPtr))
	copy(body, *bufPtr)
	bodyPool.Put(bufPtr)

	depth := s.cfg.NormalizationDepth
	if s.isTightened(currentScore) {
		depth = s.cfg.DeepNormalization
	}

	normalizedText := Normalize(ExtractText(body, r.Header.Get("Content-Type")), depth)
	scan := s.patterns.Scan(normalizedText)
	if scan.Score > 0 {
		updatedScore := s.state.ReputationAdd(meta.ClientID, scan.Score, 0, now)
		s.logRequest(meta, r, http.StatusForbidden, "pattern_block", start, updatedScore)
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":          "request blocked by firewall",
			"correlation_id": meta.CorrelationID,
			"matches":        scan.Patterns,
		})
		return
	}

	if s.isBlocked(currentScore) {
		s.logRequest(meta, r, http.StatusForbidden, "blocked_reputation", start, currentScore)
		writeBlockedRequest(w, meta.CorrelationID)
		return
	}

	modifiedBody := body
	if s.shouldInjectCanary(currentScore) {
		token := randomHex(12)
		injected, ok := InjectCanary(body, r.Header.Get("Content-Type"), token)
		if ok {
			modifiedBody = injected
			s.state.CanaryPut(CanaryRecord{
				CorrelationID: meta.CorrelationID,
				Token:         token,
				ClientID:      meta.ClientID,
				RequestText:   normalizedText,
				ExpiresAt:     now.Add(s.cfg.CanaryTTL),
			})
		}
	}

	ctx := context.WithValue(r.Context(), requestMetaKey, meta)
	r = r.WithContext(ctx)
	r.Body = io.NopCloser(bytes.NewReader(modifiedBody))
	r.ContentLength = int64(len(modifiedBody))
	if len(modifiedBody) > 0 {
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(modifiedBody)), nil
		}
		r.Header.Set("Content-Length", strconv.Itoa(len(modifiedBody)))
	} else {
		r.GetBody = nil
		r.Header.Del("Content-Length")
	}
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set("X-Correlation-ID", meta.CorrelationID)

	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	s.proxy.ServeHTTP(recorder, r)
	scoreAfter := s.state.ReputationScore(meta.ClientID, time.Now())
	s.logRequest(meta, r, recorder.status, "forwarded", start, scoreAfter)
}

func (s *Server) handleProxyError(w http.ResponseWriter, r *http.Request, err error) {
	if meta, ok := metaFromContext(r.Context()); ok {
		s.state.CanaryDelete(meta.CorrelationID)
	}

	status := http.StatusBadGateway
	if errors.Is(err, context.DeadlineExceeded) {
		status = http.StatusGatewayTimeout
	}

	writeJSON(w, status, map[string]any{
		"error": "upstream request failed",
	})
}

func (s *Server) resolveClientID(r *http.Request) string {
	if value := r.Header.Get(s.cfg.ClientIDHeader); value != "" {
		return value
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		sum := sha256.Sum256([]byte(auth))
		return hex.EncodeToString(sum[:8])
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "anonymous"
}

func (s *Server) isTightened(score float64) bool {
	if s.cfg.TightenThreshold <= 0 {
		return false
	}
	return score >= s.cfg.TightenThreshold
}

func (s *Server) isBlocked(score float64) bool {
	thresh := s.effectiveBlockThreshold(score)
	if thresh <= 0 {
		return false
	}
	return score >= thresh
}

func (s *Server) effectiveBlockThreshold(score float64) float64 {
	if s.isTightened(score) {
		return s.cfg.TightenedBlock
	}
	return s.cfg.BlockThreshold
}

func (s *Server) shouldInjectCanary(score float64) bool {
	if s.isTightened(score) {
		return true
	}
	if s.cfg.CanarySampleRate >= 1 {
		return true
	}
	return mathrand.Float64() < s.cfg.CanarySampleRate
}

func (s *Server) logRequest(meta requestMeta, r *http.Request, status int, reason string, start time.Time, score float64) {
	s.logger.Printf(
		"correlation_id=%s client_id=%s method=%s path=%s status=%d reason=%s score=%.2f duration_ms=%d",
		meta.CorrelationID,
		meta.ClientID,
		r.Method,
		r.URL.Path,
		status,
		reason,
		score,
		time.Since(start).Milliseconds(),
	)
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func metaFromContext(ctx context.Context) (requestMeta, bool) {
	meta, ok := ctx.Value(requestMetaKey).(requestMeta)
	return meta, ok
}

func randomHex(size int) string {
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// writeBlockedRequest writes a pre-encoded 403 response without correlation_id
// to avoid a per-request json.Marshal call.
func writeBlockedRequest(w http.ResponseWriter, correlationID string) {
	// We need the correlation_id in the body; build it efficiently.
	body, _ := json.Marshal(map[string]any{
		"error":          "request blocked by firewall",
		"correlation_id": correlationID,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(body)
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	body, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
