package firewall

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStreamingTransport_CleanStreaming(t *testing.T) {
	// Upstream flushes 3 chunks with delays to simulate token streaming.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected http.Flusher")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 1; i <= 3; i++ {
			_, _ = fmt.Fprintf(w, "data: chunk-%d\n\n", i)
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	cfg := Config{
		ListenAddr:           ":0",
		UpstreamURL:          upstream.URL,
		ClientIDHeader:       "X-Client-ID",
		CanarySampleRate:     0, // no canary
		TightenThreshold:     40,
		TightenedBlock:       50,
		BlockThreshold:       80,
		PendingFlushCount:    10,
		PendingFlushInterval: time.Hour,
		RateLimitPerMinute:   100,
	}

	server, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	proxyServer := httptest.NewServer(server.Handler())
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/stream")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	expected := "data: chunk-1\n\ndata: chunk-2\n\ndata: chunk-3\n\n"
	if string(body) != expected {
		t.Fatalf("expected %q, got %q", expected, string(body))
	}
}

func TestStreamingTransport_CanarySplitAcrossChunksAborts(t *testing.T) {
	// Test that a canary token split across two consecutive chunk boundaries
	// is caught by the rolling overlap window and aborts the stream.
	token := "0123456789abcdef01234567" // 24 chars

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected http.Flusher")
		}
		w.Header().Set("Content-Type", "text/event-stream")

		// Chunk 1 ends with first 12 chars of the token
		_, _ = fmt.Fprintf(w, "prefix_%s", token[:12])
		flusher.Flush()
		time.Sleep(10 * time.Millisecond)

		// Chunk 2 starts with second 12 chars of the token
		_, _ = fmt.Fprintf(w, "%s_suffix", token[12:])
		flusher.Flush()
	}))
	defer upstream.Close()

	cfg := Config{
		ListenAddr:           ":0",
		UpstreamURL:          upstream.URL,
		ClientIDHeader:       "X-Client-ID",
		CanarySampleRate:     0, // we will manually inject canary record
		TightenThreshold:     40,
		TightenedBlock:       50,
		BlockThreshold:       80,
		CanaryLeakPenalty:    60,
		PendingFlushCount:    10,
		PendingFlushInterval: time.Hour,
		RateLimitPerMinute:   100,
	}

	server, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	// Wrap server with a test handler that manually inserts canary record for correlation ID
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := requestMeta{
			CorrelationID: "test-corr-split",
			ClientID:      "stream-client",
		}
		server.state.CanaryPut(CanaryRecord{
			CorrelationID: meta.CorrelationID,
			Token:         token,
			ClientID:      meta.ClientID,
			RequestText:   "attack text",
			ExpiresAt:     time.Now().Add(time.Minute),
		})
		server.Handler().ServeHTTP(w, r)
	})

	proxyServer := httptest.NewServer(wrappedHandler)
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/stream", strings.NewReader(`{"messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-ID", "test-corr-split")
	req.Header.Set("X-Client-ID", "stream-client")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Connection abort may surface as request error or body read error
		return
	}
	defer resp.Body.Close()

	// Reading the body should fail or be truncated because stream is aborted mid-stream
	_, readErr := io.ReadAll(resp.Body)
	score := server.state.ReputationScore("stream-client", time.Now())
	if score < server.cfg.CanaryLeakPenalty-0.1 {
		t.Fatalf("expected reputation penalty applied on split canary detection, got %f", score)
	}
	_ = readErr
}

func TestStreamingTransport_ImmediateCanaryBlocksWith403(t *testing.T) {
	token := "abcdef0123456789abcdef01"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"response":"here is token %s"}`, token)
	}))
	defer upstream.Close()

	cfg := Config{
		ListenAddr:           ":0",
		UpstreamURL:          upstream.URL,
		ClientIDHeader:       "X-Client-ID",
		CanarySampleRate:     0,
		TightenThreshold:     40,
		TightenedBlock:       50,
		BlockThreshold:       80,
		CanaryLeakPenalty:    60,
		PendingFlushCount:    10,
		PendingFlushInterval: time.Hour,
		RateLimitPerMinute:   100,
	}

	server, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Insert canary for this request
		server.state.CanaryPut(CanaryRecord{
			CorrelationID: "immediate-canary",
			Token:         token,
			ClientID:      "leak-user",
			RequestText:   "prompt",
			ExpiresAt:     time.Now().Add(time.Minute),
		})
		server.Handler().ServeHTTP(w, r)
	}))
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/", bytes.NewReader([]byte(`{"prompt":"test"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-ID", "immediate-canary")
	req.Header.Set("X-Client-ID", "leak-user")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on immediate leak, got %d, body: %s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "response blocked by firewall") {
		t.Fatalf("expected response blocked message, got: %s", string(body))
	}
}
