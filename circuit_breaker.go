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
type CircuitBreaker struct {
	policies         []CircuitBreakerPolicy
	timeout          time.Duration
	failureThreshold uint32
	successThreshold uint32
	state            atomic.Value // circuitBreakerState
	failureCount     atomic.Uint32
	successCount     atomic.Uint32
	lastFailureAt    time.Time
}

// NewCircuitBreaker method creates a new [CircuitBreaker] with default settings.
//
// The default settings are:
//   - Timeout: 10 seconds
//   - FailThreshold: 3
//   - SuccessThreshold: 1
//   - Policies: CircuitBreaker5xxPolicy
func NewCircuitBreaker() *CircuitBreaker {
	cb := &CircuitBreaker{
		policies:         []CircuitBreakerPolicy{CircuitBreaker5xxPolicy},
		timeout:          10 * time.Second,
		failureThreshold: 3,
		successThreshold: 1,
	}
	cb.state.Store(circuitBreakerStateClosed)
	return cb
}

// SetPolicies method sets the one or more given CircuitBreakerPolicy(s) into
// [CircuitBreaker], which will be used to determine whether a request is failed
// or successful by evaluating the response instance.
//
//	// set one policy
//	cb.SetPolicies(CircuitBreaker5xxPolicy)
//
//	// set multiple polices
//	cb.SetPolicies(policy1, policy2, policy3)
//
//	// if you have slice, do
//	cb.SetPolicies(policies...)
//
// NOTE: This method overwrites the policies with the given new ones. See [CircuitBreaker.AddPolicies]
func (cb *CircuitBreaker) SetPolicies(policies ...CircuitBreakerPolicy) *CircuitBreaker {
	cb.policies = policies
	return cb
}

// SetTimeout method sets the timeout duration for the [CircuitBreaker]. When the
// timeout reaches, a single request is allowed to determine the state.
func (cb *CircuitBreaker) SetTimeout(timeout time.Duration) *CircuitBreaker {
	cb.timeout = timeout
	return cb
}

// SetFailureThreshold method sets the number of failures that must occur within the
// timeout duration for the [CircuitBreaker] to transition to the Open state.
func (cb *CircuitBreaker) SetFailureThreshold(threshold uint32) *CircuitBreaker {
	cb.failureThreshold = threshold
	return cb
}

// SetSuccessThreshold method sets the number of successes that must occur to transition
// the [CircuitBreaker] from the Half-Open state to the Closed state.
func (cb *CircuitBreaker) SetSuccessThreshold(threshold uint32) *CircuitBreaker {
	cb.successThreshold = threshold
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
		if cb.failureCount.Load() > 0 && time.Since(cb.lastFailureAt) > cb.timeout {
			cb.failureCount.Store(0)
		}

		switch cb.getState() {
		case circuitBreakerStateClosed:
			failCount := cb.failureCount.Add(1)
			if failCount >= cb.failureThreshold {
				cb.open()
			} else {
				cb.lastFailureAt = time.Now()
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
}

func (cb *CircuitBreaker) open() {
	cb.changeState(circuitBreakerStateOpen)
	go func() {
		time.Sleep(cb.timeout)
		cb.changeState(circuitBreakerStateHalfOpen)
	}()
}

func (cb *CircuitBreaker) changeState(state circuitBreakerState) {
	cb.failureCount.Store(0)
	cb.successCount.Store(0)
	cb.state.Store(state)
}
