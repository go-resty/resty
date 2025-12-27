// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"errors"
	"net/http"
	"sync/atomic"
	"time"
)

// ErrCircuitBreakerOpen is returned when the circuit breaker is open.
var ErrCircuitBreakerOpen = errors.New("resty: circuit breaker open")

type circuitBreakerState uint32

const (
	circuitBreakerStateClosed circuitBreakerState = iota
	circuitBreakerStateOpen
	circuitBreakerStateHalfOpen
)

// CircuitBreaker struct implements a state machine to monitor and manage the
// states of circuit breakers. The three states are:
//   - Closed: requests are allowed
//   - Open: requests are blocked
//   - Half-Open: a single request is allowed to determine
//
// Transitions
//   - To Closed State: when the success count reaches the success threshold.
//   - To Open State: when the failure count reaches the failure threshold.
//   - Half-Open Check: when the specified timeout reaches, a single request is allowed
//     to determine the transition state; if failed, it goes back to the open state.
//
// Use [NewCircuitBreakerWithCount] or [NewCircuitBreakerWithRatio] to create a new [CircuitBreaker]
// instance accordingly.
type CircuitBreaker struct {
	policies      []CircuitBreakerPolicy
	resetTimeout  time.Duration
	state         atomic.Value // circuitBreakerState
	failureCount  atomic.Uint64
	successCount  atomic.Uint64
	lastFailureAt atomic.Value // time.Time

	// Count based
	failureThreshold uint64
	successThreshold uint64

	// Ratio based
	isRatioBased bool
	failureRatio float64 // Threshold, e.g., 0.5 for 50% failure
	minRequests  uint64  // Minimum number of requests to consider failure ratio
	totalCount   atomic.Uint64
}

// NewCircuitBreakerWithCount method creates a new [CircuitBreaker] instance with Count settings.
//
// The default settings are:
//   - Policies: CircuitBreaker5xxPolicy
func NewCircuitBreakerWithCount(failureThreshold uint64, successThreshold uint64,
	resetTimeout time.Duration, policies ...CircuitBreakerPolicy) *CircuitBreaker {
	cb := newCircuitBreaker(resetTimeout, policies...)
	cb.failureThreshold = failureThreshold
	cb.successThreshold = successThreshold
	return cb
}

// NewCircuitBreakerWithRatio method creates a new [CircuitBreaker] instance with Ratio settings.
//
// The default settings are:
//   - Policies: CircuitBreaker5xxPolicy
func NewCircuitBreakerWithRatio(failureRatio float64, minRequests uint64,
	resetTimeout time.Duration, policies ...CircuitBreakerPolicy) *CircuitBreaker {
	cb := newCircuitBreaker(resetTimeout, policies...)
	cb.failureRatio = failureRatio
	cb.minRequests = minRequests
	cb.isRatioBased = true
	return cb
}

func newCircuitBreaker(resetTimeout time.Duration, policies ...CircuitBreakerPolicy) *CircuitBreaker {
	cb := &CircuitBreaker{
		resetTimeout: resetTimeout,
		policies:     []CircuitBreakerPolicy{CircuitBreaker5xxPolicy},
	}
	cb.state.Store(circuitBreakerStateClosed)
	if len(policies) > 0 {
		cb.policies = policies
	}
	return cb
}

// CircuitBreakerPolicy is a function type that determines whether a response should
// trip the [CircuitBreaker].
type CircuitBreakerPolicy func(resp *http.Response) bool

// CircuitBreaker5xxPolicy is a [CircuitBreakerPolicy] that trips the [CircuitBreaker] if
// the response status code is 500 or greater.
func CircuitBreaker5xxPolicy(resp *http.Response) bool {
	return resp.StatusCode > 499
}

func (cb *CircuitBreaker) getState() circuitBreakerState {
	return cb.state.Load().(circuitBreakerState)
}

func (cb *CircuitBreaker) allow() error {
	if cb.getState() == circuitBreakerStateOpen {
		return ErrCircuitBreakerOpen
	}

	return nil
}

func (cb *CircuitBreaker) applyPolicies(resp *http.Response) {
	failed := false
	for _, policy := range cb.policies {
		if policy(resp) {
			failed = true
			break
		}
	}

	if cb.isRatioBased {
		cb.totalCount.Add(1)
	}

	if failed {
		if cb.failureCount.Load() > 0 && time.Since(cb.lastFailureAt.Load().(time.Time)) > cb.resetTimeout {
			cb.failureCount.Store(0)
		}

		switch cb.getState() {
		case circuitBreakerStateClosed:
			failureCount := cb.failureCount.Add(1)
			cb.lastFailureAt.Store(time.Now())

			if cb.isRatioBased {
				totalCount := cb.totalCount.Load()
				if totalCount >= cb.minRequests {
					currentFailureRatio := float64(failureCount) / float64(totalCount)
					if currentFailureRatio >= cb.failureRatio {
						cb.open()
					}
				}
			} else {
				if failureCount >= cb.failureThreshold {
					cb.open()
				}
			}
		case circuitBreakerStateHalfOpen:
			cb.open()
		}

		return
	}

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

func (cb *CircuitBreaker) open() {
	cb.changeState(circuitBreakerStateOpen)
	if cb.isRatioBased {
		cb.totalCount.Store(0)
	}
	go func() {
		time.Sleep(cb.resetTimeout)
		cb.changeState(circuitBreakerStateHalfOpen)
	}()
}

func (cb *CircuitBreaker) changeState(state circuitBreakerState) {
	cb.failureCount.Store(0)
	cb.successCount.Store(0)
	cb.state.Store(state)
}
