# Firewall Test and Benchmark Report

Run date: August 5, 2026

## Environment

- OS: Darwin 25.4.0
- Architecture: arm64
- CPU reported by Go: Apple M1
- Logical CPUs: 8
- Go version: go1.24.6

## Method

- Functional suite: `go test ./internal/firewall`
- Race check: `go test -race ./internal/firewall`
- Core benchmarks: `go test -run '^$' -bench 'Benchmark(NormalizeComplexPayload|PatternScanLargeCorpus|ProxyCleanRequest|ProxyObfuscatedAttackBlocked|ProxyCanaryLeak)$' -benchmem -count=3 -benchtime=2s ./internal/firewall`
- Parallel mixed-load benchmark: `go test -run '^$' -bench BenchmarkProxyParallelMixedTraffic -benchmem -count=3 -benchtime=2s -cpu=1,4,8 ./internal/firewall`

The first benchmark attempt used localhost `httptest` servers over TCP. After repeated runs, the machine started returning `dial tcp 127.0.0.1:...: connect: can't assign requested address`, which made the socket-based measurements unstable. The final benchmark harness uses an in-memory upstream round tripper, so the numbers below measure firewall overhead cleanly without local socket noise or real upstream network latency.

## Functional Results

- `go test ./internal/firewall`: PASS in `1.546s`
- `go test -race ./internal/firewall`: PASS in `1.630s`

### Scenario coverage that passed

1. Normalization catches base64, zero-width, and homoglyph-obfuscated prompt injection strings.
2. Exact pattern matches are blocked before any upstream call.
3. Clean requests are forwarded and receive a correlation ID.
4. Canary injection happens on forwarded JSON requests.
5. Leaked canaries are blocked on the response path and never relayed raw.
6. A leaked canary raises client reputation to the blocking threshold.
7. Tightened-mode clients get deeper decoding and block triple-encoded attack payloads.
8. Tightened-mode clients get the lower rate limit and hit `429` after 10 requests per minute with the current test config.
9. A client that leaks a canary is blocked on the next request even if that next request is clean.
10. Leak-driven corpus growth works: one client can trigger learning, and the same payload from a new client is then blocked before upstream forwarding.

## Benchmark Results

Median values are shown from 3 runs.

| Benchmark | Median ns/op | Approx ops/sec | Median B/op | Median allocs/op |
|---|---:|---:|---:|---:|
| `BenchmarkNormalizeComplexPayload` | 15,088 | 66,278 | 3,259 | 36 |
| `BenchmarkPatternScanLargeCorpus` | 30,221 | 33,089 | 16 | 1 |
| `BenchmarkProxyCleanRequest` | 18,697 | 53,484 | 49,898 | 176 |
| `BenchmarkProxyObfuscatedAttackBlocked` | 23,114 | 43,264 | 13,436 | 119 |
| `BenchmarkProxyCanaryLeak` | 7,811 | 128,025 | 10,212 | 92 |

### Parallel mixed-load benchmark

Traffic mix:

- 1/3 clean requests
- 1/3 deep-obfuscated blocked attacks
- 1/3 canary-leak responses

| CPU setting | Median ns/op | Approx ops/sec | Median B/op | Median allocs/op |
|---|---:|---:|---:|---:|
| `1` | 19,019 | 52,579 | 24,563 | 127 |
| `4` | 6,164 | 162,232 | 24,524 | 127 |
| `8` | 5,869 | 170,387 | 24,537 | 127 |

## What Worked Well

- The request pipeline is behaving in the right order: normalize, match, score, tighten, inject, forward, inspect.
- The fast block path is cheaper than the clean proxy path, which is correct for a firewall.
- Reputation and adaptive tightening are observable and testable, not just configured.
- Leak detection is high-confidence and immediately changes both client reputation and the literal pattern corpus.
- The code stayed small enough to explain in an interview without hand-waving.

## Findings and Fixes Made During Testing

- I found a real correctness bug in JSON text extraction: map iteration order made normalized text nondeterministic, which could make leak-driven learning inconsistent across equivalent requests.
- I fixed that by making JSON extraction deterministic and skipping the `role` field during extracted text assembly.
- I also replaced the benchmark/test upstream transport with an in-memory harness after localhost socket reuse started failing under repeated runs.

## Current Limitations

1. Reputation, canary state, and learned patterns are still in-memory. The architecture document calls for Redis-backed atomic updates and TTL behavior.
2. Response handling buffers the entire upstream response in `ModifyResponse`, so this implementation does not preserve streaming behavior yet.
3. The clean path still allocates about `49.9 KB` and `176` allocations per request in the benchmark harness, which is high for a proxy.
4. There is no full false-positive/false-negative evaluation yet against HackAPrompt or garak corpora.
5. Output-side detection is only canary-based right now. Secret-shaped output scanning and echoed-attack detection are not implemented yet.
6. Pattern learning is literal and useful, but still naive. It grows the corpus with verified strings, not clustered variants or canonicalized templates.

## Best Next Improvements

1. Replace the in-memory stores with Redis-backed reputation and canary storage so the implementation matches the architecture and works across multiple instances.
2. Reduce allocations on the clean path by cutting repeated body copies and JSON re-marshalling where possible.
3. Add true streaming proxy support and move response-side checks to a streaming-safe design for non-buffered flows.
4. Add a corpus evaluation job against HackAPrompt and garak so the project can report detection rate and false-positive rate, not just microbenchmarks.
5. Add schema-aware extraction for common LLM request formats so scanning focuses on text-bearing fields instead of generic JSON walking.
6. Persist learned literal patterns and batch rebuild metadata so the trie survives restarts.

## Bottom Line

The project now has passing functional coverage, a clean race pass, measurable performance numbers, and a written record of both strengths and missing pieces. As a student-project level firewall, it is solid and explainable. To make it interview-strong against production questions, the next biggest upgrades are Redis-backed state, streaming support, and a real adversarial evaluation dataset.
