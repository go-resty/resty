// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ErrCircuitBreakerOpen is returned when the circuit breaker is open.
var ErrCircuitBreakerOpen = errors.New("resty: circuit breaker open")

type (
	// CircuitBreakerTriggerHook type is for reacting to circuit breaker trigger hooks.
	CircuitBreakerTriggerHook func(*Request, error)

	// CircuitBreakerStateChangeHook type is for reacting to circuit breaker state change hooks.
	CircuitBreakerStateChangeHook func(oldState, newState CircuitBreakerState)

	// CircuitBreakerState type represents the state of the circuit breaker.
	CircuitBreakerState uint32
)

const (
	// CircuitBreakerStateClosed represents the closed state of the circuit breaker.
	CircuitBreakerStateClosed CircuitBreakerState = iota

	// CircuitBreakerStateOpen represents the open state of the circuit breaker.
	CircuitBreakerStateOpen

	// CircuitBreakerStateHalfOpen represents the half-open state of the circuit breaker.
	CircuitBreakerStateHalfOpen
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
	lock          *sync.RWMutex
	policies      []CircuitBreakerPolicy
	resetTimeout  time.Duration
	state         atomic.Value // circuitBreakerState
	failureCount  atomic.Uint64
	successCount  atomic.Uint64
	lastFailureAt atomic.Value // time.Time

	// Hooks
	triggerHooks     []CircuitBreakerTriggerHook
	stateChangeHooks []CircuitBreakerStateChangeHook

	// Count-based
	failureThreshold uint64
	successThreshold uint64

	// Ratio-based
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
		lock:         &sync.RWMutex{},
		resetTimeout: resetTimeout,
		policies:     []CircuitBreakerPolicy{CircuitBreaker5xxPolicy},
	}
	cb.state.Store(CircuitBreakerStateClosed)
	if len(policies) > 0 {
		cb.policies = policies
	}
	return cb
}

// OnTrigger method adds a [CircuitBreakerTriggerHook] to the [CircuitBreaker] instance.
func (cb *CircuitBreaker) OnTrigger(hooks ...CircuitBreakerTriggerHook) *CircuitBreaker {
	cb.lock.Lock()
	defer cb.lock.Unlock()
	cb.triggerHooks = append(cb.triggerHooks, hooks...)
	return cb
}

// onTriggerHooks method executes all registered trigger hooks.
func (cb *CircuitBreaker) onTriggerHooks(req *Request, err error) {
	cb.lock.RLock()
	defer cb.lock.RUnlock()
	for _, h := range cb.triggerHooks {
		h(req, err)
	}
}

// OnStateChange method adds a [CircuitBreakerStateChangeHook] to the [CircuitBreaker] instance.
func (cb *CircuitBreaker) OnStateChange(hooks ...CircuitBreakerStateChangeHook) *CircuitBreaker {
	cb.lock.Lock()
	defer cb.lock.Unlock()
	cb.stateChangeHooks = append(cb.stateChangeHooks, hooks...)
	return cb
}

// onStateChangeHooks method executes all registered state change hooks.
func (cb *CircuitBreaker) onStateChangeHooks(oldState, newState CircuitBreakerState) {
	cb.lock.RLock()
	defer cb.lock.RUnlock()
	for _, h := range cb.stateChangeHooks {
		h(oldState, newState)
	}
}

// CircuitBreakerPolicy is a function type that determines whether a response should
// trip the [CircuitBreaker].
type CircuitBreakerPolicy func(resp *http.Response) bool

// CircuitBreaker5xxPolicy is a [CircuitBreakerPolicy] that trips the [CircuitBreaker] if
// the response status code is 500 or greater.
func CircuitBreaker5xxPolicy(resp *http.Response) bool {
	return resp.StatusCode > 499
}

func (cb *CircuitBreaker) getState() CircuitBreakerState {
	return cb.state.Load().(CircuitBreakerState)
}

func (cb *CircuitBreaker) allow() error {
	if cb.getState() == CircuitBreakerStateOpen {
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
		case CircuitBreakerStateClosed:
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
		case CircuitBreakerStateHalfOpen:
			cb.open()
		}

		return
	}

	switch cb.getState() {
	case CircuitBreakerStateClosed:
		return
	case CircuitBreakerStateHalfOpen:
		successCount := cb.successCount.Add(1)
		if successCount >= cb.successThreshold {
			cb.changeState(CircuitBreakerStateClosed)
		}
	}
}

func (cb *CircuitBreaker) open() {
	cb.changeState(CircuitBreakerStateOpen)
	if cb.isRatioBased {
		cb.totalCount.Store(0)
	}
	go func() {
		time.Sleep(cb.resetTimeout)
		cb.changeState(CircuitBreakerStateHalfOpen)
	}()
}

func (cb *CircuitBreaker) changeState(state CircuitBreakerState) {
	cb.failureCount.Store(0)
	cb.successCount.Store(0)

	oldState := cb.getState()
	cb.state.Store(state)
	if oldState != state {
		cb.onStateChangeHooks(oldState, state)
	}
}
