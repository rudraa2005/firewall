package firewall

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisBackend implements StateBackend using Redis, enabling correct behaviour
// across multiple firewall instances. It is activated when REDIS_URL is set.
//
// Key layout
//   rep:{clientID}          HASH  score / updated_at (unix seconds float)
//   canary:{correlationID}  STRING  JSON-encoded CanaryRecord (with TTL)
//   rate:{clientID}:{min}   STRING  integer counter (expires at next minute)
type redisBackend struct {
	rdb      *redis.Client
	halfLife time.Duration
}

// newRedisBackend dials Redis and returns a backend. Call close() when done.
func newRedisBackend(url string, halfLife time.Duration) (*redisBackend, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	rdb := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return &redisBackend{rdb: rdb, halfLife: halfLife}, nil
}

var canaryTakeScript = redis.NewScript(`
local val = redis.call('get', KEYS[1])
if val then
    redis.call('del', KEYS[1])
end
return val
`)

func (r *redisBackend) close() { _ = r.rdb.Close() }

// ---------- Reputation ----------

func (r *redisBackend) ReputationScore(clientID string, now time.Time) float64 {
	ctx := context.Background()
	key := "rep:" + clientID
	vals, err := r.rdb.HMGet(ctx, key, "score", "updated_at").Result()
	if err != nil || vals[0] == nil || vals[1] == nil {
		return 0
	}
	score, _ := strconv.ParseFloat(vals[0].(string), 64)
	ns, _ := strconv.ParseInt(vals[1].(string), 10, 64)
	elapsed := now.Sub(time.Unix(0, ns))
	if elapsed < 0 {
		elapsed = 0
	}
	score = r.decay(score, elapsed)
	if score < 0.01 {
		r.rdb.Del(ctx, key)
		return 0
	}
	// Update the cached decayed value.
	r.rdb.HSet(ctx, key, "score", strconv.FormatFloat(score, 'f', -1, 64),
		"updated_at", strconv.FormatInt(now.UnixNano(), 10))
	return score
}

func (r *redisBackend) ReputationAdd(clientID string, delta, floor float64, now time.Time) float64 {
	ctx := context.Background()
	key := "rep:" + clientID
	vals, _ := r.rdb.HMGet(ctx, key, "score", "updated_at").Result()

	var score float64
	if vals != nil && len(vals) >= 2 && vals[0] != nil && vals[1] != nil {
		score, _ = strconv.ParseFloat(vals[0].(string), 64)
		ns, _ := strconv.ParseInt(vals[1].(string), 10, 64)
		elapsed := now.Sub(time.Unix(0, ns))
		if elapsed < 0 {
			elapsed = 0
		}
		score = r.decay(score, elapsed)
	}
	score += delta
	if score < floor {
		score = floor
	}
	if score > 100 {
		score = 100
	}
	r.rdb.HSet(ctx, key, "score", strconv.FormatFloat(score, 'f', -1, 64), "updated_at", strconv.FormatInt(now.UnixNano(), 10))
	// Expire key after ~10 half-lives (score will be negligible).
	if r.halfLife > 0 {
		r.rdb.Expire(ctx, key, 10*r.halfLife)
	}
	return score
}

func (r *redisBackend) decay(score float64, elapsed time.Duration) float64 {
	if score <= 0 || elapsed <= 0 || r.halfLife <= 0 {
		return score
	}
	return score * math.Pow(0.5, elapsed.Seconds()/r.halfLife.Seconds())
}

// ---------- Canary ----------

func (r *redisBackend) CanaryPut(record CanaryRecord) {
	ctx := context.Background()
	key := "canary:" + record.CorrelationID
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	ttl := time.Until(record.ExpiresAt)
	if ttl <= 0 {
		return
	}
	r.rdb.Set(ctx, key, data, ttl)
}

func (r *redisBackend) CanaryTake(correlationID string) (CanaryRecord, bool) {
	ctx := context.Background()
	key := "canary:" + correlationID

	res, err := canaryTakeScript.Run(ctx, r.rdb, []string{key}).Text()
	if err != nil || res == "" {
		return CanaryRecord{}, false
	}
	var record CanaryRecord
	if err := json.Unmarshal([]byte(res), &record); err != nil {
		return CanaryRecord{}, false
	}
	return record, true
}

func (r *redisBackend) CanaryDelete(correlationID string) {
	r.rdb.Del(context.Background(), "canary:"+correlationID)
}

// ---------- Rate limiting ----------

// RateAllow uses a per-minute counter key. The key expires at the top of the
// next minute so counters are automatically cleaned up.
func (r *redisBackend) RateAllow(clientID string, limit int, now time.Time) bool {
	if limit <= 0 {
		return true
	}
	ctx := context.Background()
	minute := now.Truncate(time.Minute).Unix()
	key := "rate:" + clientID + ":" + strconv.FormatInt(minute, 10)

	// INCR returns the value after increment. If it's 1 (first request this
	// minute) set the TTL so the key auto-expires.
	val, err := r.rdb.Incr(ctx, key).Result()
	if err != nil {
		// On Redis error, fail open.
		return true
	}
	if val == 1 {
		// Key just created; expire at the next minute boundary + 1s buffer.
		nextMinute := now.Truncate(time.Minute).Add(time.Minute + time.Second)
		r.rdb.ExpireAt(ctx, key, nextMinute)
	}
	return val <= int64(limit)
}
