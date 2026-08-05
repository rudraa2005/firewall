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

type Server struct {
	cfg        Config
	target     *url.URL
	patterns   *PatternStore
	reputation *ReputationStore
	canaries   *CanaryStore
	limiter    *RateLimiter
	proxy      *httputil.ReverseProxy
	handler    http.Handler
	logger     *log.Logger
	cancel     context.CancelFunc
}

type statusRecorder struct {
	http.ResponseWriter
	status int
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

	server := &Server{
		cfg:        cfg,
		target:     target,
		patterns:   NewPatternStore(patterns, cfg.PendingFlushCount, cfg.PendingFlushInterval),
		reputation: NewReputationStore(cfg.ReputationHalfLife),
		canaries:   NewCanaryStore(),
		limiter:    NewRateLimiter(),
		logger:     log.New(os.Stdout, "", log.LstdFlags),
		cancel:     cancel,
	}

	server.patterns.Start(ctx)
	server.canaries.Start(ctx)

	proxy := httputil.NewSingleHostReverseProxy(target)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	proxy.Transport = transport
	proxy.ModifyResponse = server.inspectResponse
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
	meta := requestMeta{
		CorrelationID: randomHex(10),
		ClientID:      s.resolveClientID(r),
	}
	w.Header().Set("X-Correlation-ID", meta.CorrelationID)

	now := time.Now()
	currentScore := s.reputation.Score(meta.ClientID, now)
	if s.isBlocked(currentScore) {
		s.logRequest(meta, r, http.StatusForbidden, "blocked_reputation", start, currentScore)
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":          "request blocked by firewall",
			"correlation_id": meta.CorrelationID,
		})
		return
	}

	limit := s.cfg.RateLimitPerMinute
	if s.isTightened(currentScore) {
		limit = maxInt(1, limit/2)
	}
	if !s.limiter.Allow(meta.ClientID, limit, now) {
		s.logRequest(meta, r, http.StatusTooManyRequests, "rate_limited", start, currentScore)
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":          "client rate limited",
			"correlation_id": meta.CorrelationID,
		})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logRequest(meta, r, http.StatusBadRequest, "read_failed", start, currentScore)
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":          "invalid request body",
			"correlation_id": meta.CorrelationID,
		})
		return
	}
	_ = r.Body.Close()

	depth := s.cfg.NormalizationDepth
	if s.isTightened(currentScore) {
		depth = s.cfg.DeepNormalization
	}

	normalizedText := Normalize(ExtractText(body, r.Header.Get("Content-Type")), depth)
	scan := s.patterns.Scan(normalizedText)
	if scan.Score > 0 {
		updatedScore := s.reputation.Add(meta.ClientID, scan.Score, 0, now)
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
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":          "request blocked by firewall",
			"correlation_id": meta.CorrelationID,
		})
		return
	}

	modifiedBody := body
	if s.shouldInjectCanary(currentScore) {
		token := randomHex(12)
		injected, ok := InjectCanary(body, r.Header.Get("Content-Type"), token)
		if ok {
			modifiedBody = injected
			s.canaries.Put(CanaryRecord{
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
	scoreAfter := s.reputation.Score(meta.ClientID, time.Now())
	s.logRequest(meta, r, recorder.status, "forwarded", start, scoreAfter)
}

func (s *Server) inspectResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if meta, ok := metaFromContext(resp.Request.Context()); ok {
			s.canaries.Delete(meta.CorrelationID)
		}
		return err
	}
	_ = resp.Body.Close()

	meta, ok := metaFromContext(resp.Request.Context())
	if ok {
		resp.Header.Set("X-Correlation-ID", meta.CorrelationID)
		record, found := s.canaries.Take(meta.CorrelationID)
		if found && bytes.Contains(body, []byte(record.Token)) {
			s.reputation.Add(record.ClientID, s.cfg.CanaryLeakPenalty, s.cfg.BlockThreshold, time.Now())
			for _, fragment := range ExtractSuspiciousFragments(record.RequestText) {
				s.patterns.Queue(fragment, s.cfg.PatternPenalty)
			}

			replacement, _ := json.Marshal(map[string]any{
				"error":          "response blocked by firewall",
				"correlation_id": meta.CorrelationID,
			})
			resp.StatusCode = http.StatusForbidden
			resp.Status = http.StatusText(http.StatusForbidden)
			resp.Header.Set("Content-Type", "application/json")
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Transfer-Encoding")
			resp.Header.Set("Content-Length", strconv.Itoa(len(replacement)))
			resp.ContentLength = int64(len(replacement))
			resp.Body = io.NopCloser(bytes.NewReader(replacement))
			return nil
		}
	}

	resp.Header.Del("Content-Encoding")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.ContentLength = int64(len(body))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

func (s *Server) handleProxyError(w http.ResponseWriter, r *http.Request, err error) {
	if meta, ok := metaFromContext(r.Context()); ok {
		s.canaries.Delete(meta.CorrelationID)
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
	return score >= s.cfg.TightenThreshold
}

func (s *Server) isBlocked(score float64) bool {
	return score >= s.effectiveBlockThreshold(score)
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
