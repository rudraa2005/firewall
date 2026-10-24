package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// bodyPool recycles byte slices used when reading request bodies to reduce
// per-request allocations on the clean path.
var bodyPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 64*1024)
		return &b
	},
}

// streamingTransport wraps an inner RoundTripper. For requests whose canary
// token is registered in the StateBackend it pipes the upstream body through a
// rolling-window scanner. The window is len(token)-1 bytes wide so a token
// split across two consecutive reads is always caught.
//
// On early detection (before response headers are sent), an HTTP 403 Forbidden
// response is returned. On late detection (mid-stream), the stream is aborted
// immediately. Requests without a canary pass through untouched with full,
// zero-copy streaming.
type streamingTransport struct {
	inner  http.RoundTripper
	server *Server
}

func (t *streamingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	meta, hasMeta := metaFromContext(req.Context())
	if !hasMeta {
		return resp, nil
	}

	resp.Header.Set("X-Correlation-ID", meta.CorrelationID)

	record, found := t.server.state.CanaryTake(meta.CorrelationID)
	if !found {
		// No canary – stream freely, no buffering needed.
		return resp, nil
	}

	tokenBytes := []byte(record.Token)

	// Read the first chunk to catch immediate leaks before sending headers.
	buf := make([]byte, 4096)
	n, readErr := resp.Body.Read(buf)
	firstChunk := buf[:n]

	if bytes.Contains(firstChunk, tokenBytes) {
		_ = resp.Body.Close()
		t.server.onCanaryLeak(record)

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
		return resp, nil
	}

	// Prepare streaming detector. We remove Content-Length / Transfer-Encoding
	// because late detection may terminate the stream prematurely.
	resp.Header.Del("Content-Length")
	resp.Header.Del("Transfer-Encoding")
	resp.ContentLength = -1

	win := len(tokenBytes) - 1
	var initialOverlap []byte
	if win > 0 && len(firstChunk) > 0 {
		if len(firstChunk) >= win {
			initialOverlap = append([]byte(nil), firstChunk[len(firstChunk)-win:]...)
		} else {
			initialOverlap = append([]byte(nil), firstChunk...)
		}
	}

	resp.Body = &canaryDetectorBody{
		src:      resp.Body,
		token:    tokenBytes,
		server:   t.server,
		record:   record,
		initial:  firstChunk,
		buf:      initialOverlap,
		firstErr: readErr,
	}
	return resp, nil
}

// canaryDetectorBody is an io.ReadCloser that scans the upstream byte stream
// for a canary token using an overlap-safe rolling window.
type canaryDetectorBody struct {
	src      io.ReadCloser
	token    []byte
	server   *Server
	record   CanaryRecord
	initial  []byte // buffered bytes from the initial chunk
	buf      []byte // overlap window from previous Read
	detected bool
	firstErr error // error (if any) from reading the initial chunk
}

func (b *canaryDetectorBody) Read(p []byte) (int, error) {
	if b.detected {
		return 0, errors.New("firewall: canary token detected in response stream")
	}

	// Serve any remaining bytes from the initial chunk.
	if len(b.initial) > 0 {
		n := copy(p, b.initial)
		b.initial = b.initial[n:]
		if len(b.initial) == 0 && b.firstErr != nil {
			return n, b.firstErr
		}
		return n, nil
	}

	if b.firstErr != nil {
		return 0, b.firstErr
	}

	n, readErr := b.src.Read(p)
	if n == 0 {
		return 0, readErr
	}

	chunk := p[:n]

	// Prepend the overlap window so tokens split across chunks are detected.
	var haystack []byte
	if len(b.buf) > 0 {
		haystack = append(append([]byte(nil), b.buf...), chunk...)
	} else {
		haystack = chunk
	}

	if bytes.Contains(haystack, b.token) {
		b.detected = true
		b.server.onCanaryLeak(b.record)
		_ = b.src.Close()
		return 0, errors.New("firewall: canary token detected in response stream")
	}

	// Keep the trailing window for the next Read.
	win := len(b.token) - 1
	if win <= 0 {
		b.buf = b.buf[:0]
	} else if len(haystack) >= win {
		b.buf = append(b.buf[:0], haystack[len(haystack)-win:]...)
	} else {
		b.buf = append(b.buf[:0], haystack...)
	}

	return n, readErr
}

func (b *canaryDetectorBody) Close() error {
	return b.src.Close()
}

// onCanaryLeak is invoked when the canary detector finds the canary token
// in the upstream response. It applies the reputation penalty and queues
// the suspicious fragments for pattern learning.
func (s *Server) onCanaryLeak(record CanaryRecord) {
	s.state.ReputationAdd(record.ClientID, s.cfg.CanaryLeakPenalty, s.cfg.BlockThreshold, time.Now())
	for _, fragment := range ExtractSuspiciousFragments(record.RequestText) {
		s.patterns.Queue(fragment, s.cfg.PatternPenalty)
	}
	s.logger.Printf(
		"canary_leak client_id=%s correlation_id=%s",
		record.ClientID, record.CorrelationID,
	)
}
