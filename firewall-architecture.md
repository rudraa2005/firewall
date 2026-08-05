# Prompt Injection Firewall — Architecture Reference

Scope: L7 reverse proxy, text/HTTP only (multimodal explicitly deferred to a
follow-on project). Sits between client and LLM API, controls both directions.

## 1. Boundary

- **Input:** HTTP request from client — JSON body (prompt/messages), headers,
  client identifier (session/IP/API key).
- **Output:** either the forwarded-and-relayed LLM response, or a rejection
  (`403`/`429`) — decided by the proxy, never passed through blindly.
- **Trust boundaries in play:**
  1. client → proxy (untrusted input)
  2. proxy → LLM API (proxy may rewrite the outbound request — this is what
     makes canary injection possible)
  3. LLM API → proxy (response may contain a leaked canary or otherwise be
     compromised)
  4. proxy → client (final sanitization point before untrusted output leaves
     your system)

## 2. Request pipeline (sequence, not components)

```
1. Request arrives at proxy
2. Generate correlation ID (keys the canary + all per-request state)
3. Normalize input:
     - decode base64 / recursive unwrap
     - resolve homoglyphs / confusables
     - strip zero-width characters
4. Run normalized text through Aho-Corasick pattern set
     -> match found?  => BLOCK, return 403, done. (no forward)
     -> no match       => continue
5. Compute request-level score from matched-pattern weights (0 if no matches)
6. Update client's rolling reputation score S in Redis (atomic INCRBY/Lua)
     -> S >= T_block?  => BLOCK, return 403/429, done.
     -> S in [T_tighten, T_block)? => enter tightened mode for this client
7. Inject unique canary token into outbound request
     (bound to correlation ID, TTL'd)
8. Forward request to LLM API
9. Response arrives
10. Scan response for canary leak
      -> leaked => confirmed attack:
           - do NOT relay the raw response to client (strip/replace with
             generic rejection)
           - add offending literal pattern to pending Aho-Corasick corpus
           - hard-set/boost client's S (independent of decay path)
      -> not leaked => proceed
11. Relay response to client
```

## 3. Detection layers (why two, not one merged into the other)

| Layer | Type | Catches | Update mechanism |
|---|---|---|---|
| Aho-Corasick | exact-match automaton | known literal attack strings/patterns | corpus grows; trie rebuilt in **batches**, never per-request |
| Canary token | leak detection | confirmed *successful* injections (high confidence, but after-the-fact — this is detection, not prevention) | per-request, no state needed beyond TTL |

These are separate, parallel mechanisms. Do not try to "merge" them into one
data structure — Aho-Corasick is deterministic pattern matching; a vector-DB/
embedding layer (if added later) would be a third, independent similarity-based
layer, not an upgrade path for Aho-Corasick itself.

**Rejected design:** caching "safe" verdicts by similarity to skip
re-checking. This creates a whitelist-poisoning attack surface (attacker
seeds a borderline-benign request into the "safe" cache, then sends the real
payload worded to land in the same cluster). Cut for this week's scope.

## 4. Trie rebuild policy

- **Never** rebuild per-request or per-single-failure (O(Σ|p_i|) cost +
  requires atomic pointer swap / double-buffering for a lock-free live path —
  too expensive to pay constantly, and a trivial DoS lever for an attacker
  who deliberately trips checks rapidly).
- Batch triggers, whichever fires first:
  - **Count:** pending verified new patterns reach N (e.g. 100)
  - **Time:** scheduled flush interval (e.g. every 6h) if queue is non-empty

## 5. Adaptive client reputation (the "dynamic tightening" requirement)

- State: `S ∈ [0,100]` per client ID, in Redis, atomic updates only
  (Lua script / `INCRBY`+`EXPIRE` — never Go-side GET→modify→SET, which races
  under concurrent burst traffic).
- **Thresholds:** `0 < T_tighten < T_block` (e.g. tighten @ 40, block @ 80)
- **On match/leak:** S increases (weighted by confidence — canary leak >
  pattern match)
- **Decay:** exponential only, time-based. Clean requests do **not**
  actively reduce S (prevents an attacker padding attacks with throwaway
  clean requests to wash their score down cheaply).
- **In tightened band** (`T_tighten ≤ S < T_block`), for that client only:
  1. client-specific `T_block` drops (e.g. 80 → 50)
  2. canary check sampling → 100% (if normally sampled below 100%)
  3. normalization pipeline goes deeper (higher base64-unwrap depth, full
     homoglyph resolution forced on)
  4. rate limit halved
- **At/above `T_block`:** hard reject, no forwarding.

## 6. Explicit failure-mode answers (don't skip these when building)

- **LLM API timeout/no response:** correlation-ID entry must be TTL'd —
  decide the cleanup path now, not as an afterthought, or it leaks memory.
- **Response containing a leaked canary:** never relayed raw to the client —
  decide the replacement response now.
- **Canary injection point:** must land in the actual outbound instruction
  context the proxy controls (system prompt / message the proxy itself
  constructs) — not an assumption that one will always exist in the client's
  payload.

## 7. Build order (this week)

1. Transparent passthrough proxy (prove byte-identical response via `curl`,
   prove streaming works if applicable) — **today's only goal**
2. Logging seam (Director/middleware hook logging req+resp) — the plug-in
   point for everything below
3. Normalization + Aho-Corasick block layer
4. Scoring + Redis reputation layer
5. Canary injection + correlation ID + leak detection
6. Adaptive tightening behaviors
7. Output-side scan (secret-shaped strings in response, echoed-attack
   detection)
8. Adversarial self-test against HackAPrompt corpus + garak probes — measure
   true-positive / false-positive rate. **This number is the deliverable.**
9. Structured logging / observability pass + written note on the
   false-positive vs. DoS tradeoff made in step 6

## Explicitly out of scope this week

- Multimodal / image-embedded injection (deferred — legitimate follow-on
  project, not a replacement for this one)
- Vector-DB similarity layer / "safe" response caching
