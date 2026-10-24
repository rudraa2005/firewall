package firewall

import "time"

// StateBackend abstracts the shared state stores (reputation, canary, rate
// limiter) so that both the in-memory and Redis implementations satisfy the
// same interface. The server calls only these methods; stores remain internal
// implementation details of each backend.
type StateBackend interface {
	// Reputation returns the current decayed reputation score for clientID.
	ReputationScore(clientID string, now time.Time) float64
	// ReputationAdd applies delta to the score (with floor) and returns the
	// new value after decay.
	ReputationAdd(clientID string, delta, floor float64, now time.Time) float64

	// CanaryPut registers a canary record keyed by CorrelationID.
	CanaryPut(record CanaryRecord)
	// CanaryTake atomically retrieves and removes a canary record. Returns
	// (record, true) if found.
	CanaryTake(correlationID string) (CanaryRecord, bool)
	// CanaryDelete removes a canary record without returning it.
	CanaryDelete(correlationID string)

	// RateAllow returns true if clientID is within the rate limit for the
	// current minute window, and increments the counter if allowed.
	RateAllow(clientID string, limit int, now time.Time) bool
}
