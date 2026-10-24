# Prompt Injection Firewall — Architecture Reference

**Scope:** L7 reverse proxy, text/HTTP LLM security firewall. Sits between client applications and upstream LLM APIs (e.g., OpenAI, Anthropic, local vLLM/Ollama endpoints), inspecting and enforcing controls in both directions with true streaming support.

---

## 1. Boundary & Threat Model

- **Input:** HTTP request from client — JSON payload (`messages`, `prompt`, `system`, etc.), HTTP headers, client identifier (`X-Client-ID`, `Authorization` bearer token hash, or Remote IP).
- **Output:** Forwarded-and-relayed LLM response (streamed in real-time or returned as a single response), or a firewall rejection (`403 Forbidden` / `429 Too Many Requests`).
- **Trust Boundaries:**
  1. **Client → Proxy (Untrusted Input):** Prompt injection, jailbreak attempts, homoglyph obfuscation, multi-layer base64 encoding, zero-width steganography, token smuggling, and denial-of-service bursts.
  2. **Proxy → LLM API (Controlled Outbound Rewriting):** The proxy injects unique canary tokens into system or instruction contexts without disrupting the client payload schema.
  3. **LLM API → Proxy (Untrusted Upstream Output):** Responses may leak canaries, echo poisoned instructions, or execute indirect prompt exfiltration.
  4. **Proxy → Client (Sanitized Egress):** Real-time rolling-window canary detection aborts compromised streams or returns generic 403 responses before leaked data reaches the client.

```
+--------+   (1) Untrusted Prompt   +----------+   (2) Canary Injected   +---------+
| Client | -----------------------> | Firewall | ----------------------> | LLM API |
|        | <----------------------- |  Proxy   | <---------------------- |         |
+--------+   (4) Clean / Aborted    +----------+   (3) Streamed Tokens   +---------+
```

---

## 2. Request & Response Pipeline

```
[Inbound Request Pipeline]
1. Inbound HTTP request arrives.
2. Resolve Client ID (X-Client-ID header -> Authorization hash -> Remote IP -> anonymous).
3. Extract/Generate Correlation ID (X-Correlation-ID header or 20-hex random string).
4. Check Client Reputation Score S against Block Threshold:
     -> S >= T_block => Immediate BLOCK (HTTP 403), audit log, return.
5. Check Rate Limiter (sliding 1-minute window, halved if client in tightened mode):
     -> Limit exceeded => Immediate BLOCK (HTTP 429 Too Many Requests), return.
6. Pooled Body Read: Read body once into a sync.Pool byte buffer (capped at 10 MiB).
7. Schema-Aware Text Extraction (streaming JSON token walk, zero map allocations):
     -> Walks only text-bearing keys ("content", "prompt", "text", "input", etc.).
8. Multi-Layer Normalization:
     -> Homoglyph & confusable replacement (Cyrillic, Greek, lookalikes).
     -> Zero-width character removal (ZWSP, ZWNJ, ZWJ, soft hyphens).
     -> Recursive base64 decoding (up to NormalizationDepth or DeepNormalization).
     -> Whitespace canonicalization and case-folding.
9. Fast Aho-Corasick Matcher Scan:
     -> Exact match found => BLOCK (HTTP 403), add score penalty to reputation, return.
10. Canary Injection (Schema-Aware In-Place Splice):
     -> Sampled or forced (100% in tightened mode).
     -> Prepends system message to "messages" array or string prefix with zero unmarshal.
     -> Registers CanaryRecord (CorrelationID, Token, ClientID, RequestText, TTL) in StateBackend.
11. Forward modified request to upstream LLM API via streaming transport.

[Outbound Response Pipeline — Streaming & Rolling Window]
12. Upstream responds via streamingTransport (custom http.RoundTripper):
     -> No canary registered for Correlation ID => Stream upstream response directly.
     -> Canary registered => Pipe through rolling-window canary detector.
13. Rolling Window Inspection:
     -> Window size: len(token) - 1 (23 bytes for 24-char hex token).
     -> Preserves trailing overlap window across consecutive network reads.
     -> Early detection (in initial chunk before headers written):
          => Replace response with HTTP 403 Forbidden ("response blocked by firewall").
          => Call onCanaryLeak: penalize reputation, queue suspicious fragments.
     -> Late detection (mid-stream after headers/bytes flushed):
          => Abort stream immediately (close connection, return error to ReverseProxy).
          => Call onCanaryLeak: penalize reputation, queue suspicious fragments.
     -> Clean stream completion (EOF without token):
          => Transparently flush remaining window bytes to client.
```

---

## 3. Detection Layers

| Layer | Type | Catches | Latency / Overhead | Update Mechanism |
|---|---|---|---|---|
| **Aho-Corasick Automaton** | Inbound deterministic exact-match automaton | Known jailbreak phrases, role overrides, prompt leakage keywords | Sub-millisecond (single-pass linear time $O(n)$) | Batch-rebuilt periodically or when pending queue reaches limit; never rebuilt per-request. |
| **Normalization Pipeline** | Inbound decoding & de-obfuscation | Homoglyphs, zero-width chars, nested base64 (single, double, triple) | 15–35 µs per request | Deterministic rune-mapping & regex base64 unwrapper. |
| **Canary Leak Detection** | Outbound rolling-window stream scanner | Confirmed successful prompt exfiltration & indirect injection | Near zero (23-byte rolling overlap, zero-copy buffer slicing) | Per-request ephemeral tokens in StateBackend with 1-minute TTL. |
| **Adaptive Reputation** | Stateful client threat tracking | Slow-drip probing, distributed attacks, repeated infractions | $O(1)$ memory/Redis read with exponential time decay | Atomic score adjustments on pattern match, canary leak, or rate violation. |

---

## 4. State Management: In-Memory vs. Redis Backend

The proxy abstracts all mutable runtime state behind the `StateBackend` interface:

```go
type StateBackend interface {
    ReputationScore(clientID string, now time.Time) float64
    ReputationAdd(clientID string, delta, floor float64, now time.Time) float64
    CanaryPut(record CanaryRecord)
    CanaryTake(correlationID string) (CanaryRecord, bool)
    CanaryDelete(correlationID string)
    RateAllow(clientID string, limit int, now time.Time) bool
}
```

### In-Memory Backend (`memoryBackend`)
- **Default mode** (`REDIS_URL` unset). Requires zero external dependencies.
- Reputation stored in synchronized maps with background half-life decay.
- Canaries stored with lock protection and periodic sweep goroutines.
- Rate limits tracked using minute-bucketed in-memory counters.

### Redis Backend (`redisBackend`)
- **Multi-instance mode** (activated when `REDIS_URL` is set, e.g. `redis://localhost:6379`).
- **Reputation (`rep:{clientID}`):** Redis `HASH` storing `score` and `updated_at` (unix nanoseconds as `int64` string). Exponential half-life decay computed client-side upon read and cached back. Keys expire after 10 half-lives.
- **Canary (`canary:{correlationID}`):** JSON-serialized `CanaryRecord` stored with Redis TTL matching `CanaryTTL`. Atomically retrieved and deleted using a Lua script:
  ```lua
  local val = redis.call('get', KEYS[1])
  if val then redis.call('del', KEYS[1]) end
  return val
  ```
- **Rate Limiting (`rate:{clientID}:{minute}`):** Redis `INCR` counter with automatic `EXPIREAT` scheduled for the next minute boundary.

---

## 5. Streaming Architecture (`streamingTransport`)

Previous implementations buffered the full response body using `io.ReadAll` inside `httputil.ReverseProxy.ModifyResponse`, destroying streaming performance and adding seconds of time-to-first-token (TTFT) latency.

The new streaming architecture replaces `ModifyResponse` with `streamingTransport`:

1. **Custom `RoundTripper` Wrapper:** Wraps the standard HTTP transport.
2. **Zero-Copy Pass-Through:** If no canary was registered for the correlation ID, the response streams directly with zero interception.
3. **Rolling Overlap Window (`canaryDetectorBody`):**
   - Buffers only `len(token) - 1` bytes (23 bytes) across chunk boundaries.
   - For an incoming chunk of $N$ bytes, checks `haystack = append(buf, chunk...)`.
   - **Early detection:** If the canary is present in the first chunk, returns HTTP 403 with `{"error": "response blocked by firewall"}` before client headers are written.
   - **Late detection:** If the canary appears mid-stream, immediately terminates the stream (`io.Closer`), triggering a connection reset or HTTP/2 stream cancellation.
   - **Clean stream:** Window bytes are flushed transparently upon `io.EOF`.

---

## 6. Allocation Reduction & Schema-Aware Extraction

To minimize GC pressure under high-throughput LLM workloads:

1. **`bodyPool` (`sync.Pool`):** Inbound request bodies are read into pooled 64 KiB buffers rather than repeatedly allocating fresh slices.
2. **Zero-Unmarshal `ExtractText`:** Instead of `json.Unmarshal` into `map[string]any`, `extractJSONStrings` uses `encoding/json.Decoder` to walk the token stream. It only collects strings whose keys are in `textBearingKeys`:
   - `content`, `text`, `prompt`, `input`, `instructions`, `system`, `message`, `query`, `user`, `assistant`, `description`, `messages`, `prompts`.
   - Numeric, boolean, and non-text tokens are skipped without allocation.
3. **In-Place Canary Splice (`injectCanaryJSON`):**
   - For OpenAI-style `{"messages":[...]}` schemas, splices `{"role":"system","content":"..."}` directly after the opening `[` bracket without re-encoding the entire JSON structure.
   - For single-field payloads (`system`, `prompt`, `input`), splices the canary message directly into the existing string value.
   - Falls back to unmarshal/marshal only for unrecognized custom schemas.
4. **Pre-Encoded Static Responses:** Fixed error payloads (`request blocked by firewall`, `response blocked by firewall`) are pre-marshaled into immutable byte slices at startup.

---

## 7. Smarter Pattern Learning & Safety Gates

When a canary leak occurs, `ExtractSuspiciousFragments` identifies candidate phrases containing attack keywords. To prevent false positives or poisonings from entering the active detection automaton, candidates must pass three gates:

1. **Gate 1: Minimum Specificity:**
   - Must have at least **3 words** and **15 characters** (`meetsSpecificity`). Single words (e.g., "ignore", "bypass") are rejected to avoid blocking normal English text.
2. **Gate 2: Benign Corpus Similarity Check:**
   - Evaluated against a built-in 23-phrase benign reference corpus (`benignCorpus`).
   - If Jaccard word-set similarity $\ge 0.50$ against any benign phrase, the candidate is discarded.
3. **Gate 3: Optional Review Mode (`RequireReview` / `LearnedPatternsLog`):**
   - If `REQUIRE_PATTERN_REVIEW=true`, learned candidates are appended to an operator audit log (JSON-lines) and excluded from the active matcher until manually approved.

---

## 8. Adaptive Reputation & Tightening Mechanics

- **Reputation Band:** $S \in [0, 100]$.
- **Thresholds:**
  - Standard Mode: Normal operation ($0 \le S < T_{\text{tighten}}$).
  - Tightened Mode: $T_{\text{tighten}} \le S < T_{\text{block}}$ (default: $40 \le S < 80$).
  - Blocked Mode: $S \ge T_{\text{block}}$ (default: $S \ge 80$).
- **Behaviors in Tightened Mode:**
  1. Effective block threshold drops from 80 to 50 (`TightenedBlock`).
  2. Canary injection sample rate forced to 100%.
  3. Base64 normalization depth increases from 1 to 3 (`DeepNormalization`).
  4. Per-minute rate limit is halved.
- **Decay:** Time-based exponential decay:
  $$S(t) = S_0 \cdot 0.5^{\Delta t / t_{\text{half-life}}}$$
  Clean requests do **not** reduce score, eliminating clean-request padding attacks.
