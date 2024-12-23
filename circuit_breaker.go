package resty

import (
	"errors"
	"net/http"
	"sync/atomic"
	"time"
)

// CircuitBreaker can be in one of three states: Closed, Open, or Half-Open.
//   - When the CircuitBreaker is Closed, requests are allowed to pass through.
//   - If a failure count threshold is reached within a specified time-frame,
//     the CircuitBreaker transitions to the Open state.
//   - When the CircuitBreaker is Open, requests are blocked.
//   - After a specified timeout, the CircuitBreaker transitions to the Half-Open state.
//   - When the CircuitBreaker is Half-Open, a single request is allowed to pass through.
//   - If that request fails, the CircuitBreaker returns to the Open state.
//   - If the number of successes reaches a specified threshold,
//     the CircuitBreaker transitions to the Closed state.
type CircuitBreaker struct {
	policies                        []CircuitBreakerPolicy
	timeout                         time.Duration
	failThreshold, successThreshold uint32

	state                   atomic.Value // circuitBreakerState
	failCount, successCount atomic.Uint32
	lastFail                time.Time
}

// NewCircuitBreaker creates a new [CircuitBreaker] with default settings.
// The default settings are:
// - Timeout: 10 seconds
// - FailThreshold: 3
// - SuccessThreshold: 1
// - Policies: CircuitBreaker5xxPolicy
func NewCircuitBreaker() *CircuitBreaker {
	cb := &CircuitBreaker{
		policies:         []CircuitBreakerPolicy{CircuitBreaker5xxPolicy},
		timeout:          10 * time.Second,
		failThreshold:    3,
		successThreshold: 1,
	}
	cb.state.Store(circuitBreakerStateClosed)
	return cb
}

// SetPolicies sets the CircuitBreakerPolicy's that the [CircuitBreaker] will use to determine whether a response is a failure.
func (cb *CircuitBreaker) SetPolicies(policies []CircuitBreakerPolicy) *CircuitBreaker {
	cb.policies = policies
	return cb
}

// SetTimeout sets the timeout duration for the [CircuitBreaker].
func (cb *CircuitBreaker) SetTimeout(timeout time.Duration) *CircuitBreaker {
	cb.timeout = timeout
	return cb
}

// SetFailThreshold sets the number of failures that must occur within the timeout duration for the [CircuitBreaker] to
// transition to the Open state.
func (cb *CircuitBreaker) SetFailThreshold(threshold uint32) *CircuitBreaker {
	cb.failThreshold = threshold
	return cb
}

// SetSuccessThreshold sets the number of successes that must occur to transition the [CircuitBreaker] from the Half-Open state
// to the Closed state.
func (cb *CircuitBreaker) SetSuccessThreshold(threshold uint32) *CircuitBreaker {
	cb.successThreshold = threshold
	return cb
}

// CircuitBreakerPolicy is a function that determines whether a response should trip the [CircuitBreaker].
type CircuitBreakerPolicy func(resp *http.Response) bool

// CircuitBreaker5xxPolicy is a [CircuitBreakerPolicy] that trips the [CircuitBreaker] if the response status code is 500 or greater.
func CircuitBreaker5xxPolicy(resp *http.Response) bool {
	return resp.StatusCode > 499
}

var ErrCircuitBreakerOpen = errors.New("resty: circuit breaker open")

type circuitBreakerState uint32

const (
	circuitBreakerStateClosed circuitBreakerState = iota
	circuitBreakerStateOpen
	circuitBreakerStateHalfOpen
)

func (cb *CircuitBreaker) getState() circuitBreakerState {
	return cb.state.Load().(circuitBreakerState)
}

func (cb *CircuitBreaker) allow() error {
	if cb == nil {
		return nil
	}

	if cb.getState() == circuitBreakerStateOpen {
		return ErrCircuitBreakerOpen
	}

	return nil
}

func (cb *CircuitBreaker) applyPolicies(resp *http.Response) {
	if cb == nil {
		return
	}

	failed := false
	for _, policy := range cb.policies {
		if policy(resp) {
			failed = true
			break
		}
	}

	if failed {
		if cb.failCount.Load() > 0 && time.Since(cb.lastFail) > cb.timeout {
			cb.failCount.Store(0)
		}

		switch cb.getState() {
		case circuitBreakerStateClosed:
			failCount := cb.failCount.Add(1)
			if failCount >= cb.failThreshold {
				cb.open()
			} else {
				cb.lastFail = time.Now()
			}
		case circuitBreakerStateHalfOpen:
			cb.open()
		}
	} else {
		switch cb.getState() {
		case circuitBreakerStateClosed:
			return
		case circuitBreakerStateHalfOpen:
			successCount := cb.successCount.Add(1)
			if successCount >= cb.successThreshold {
				cb.changeState(circuitBreakerStateClosed)
			}
		}
	}

	return
}

func (cb *CircuitBreaker) open() {
	cb.changeState(circuitBreakerStateOpen)
	go func() {
		time.Sleep(cb.timeout)
		cb.changeState(circuitBreakerStateHalfOpen)
	}()
}

func (cb *CircuitBreaker) changeState(state circuitBreakerState) {
	cb.failCount.Store(0)
	cb.successCount.Store(0)
	cb.state.Store(state)
}
