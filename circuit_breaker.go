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
	openStartAt      atomic.Value // time.Time
	sw               *tfsw
}

// NewCircuitBreaker method creates a new [CircuitBreaker] with default settings.
//
// The default settings are:
//   - Timeout: 10 seconds
//   - SlidingWindowBucketSize: 10
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
	cb.sw = newSlidingWindow(
		func() totalAndFailures { return totalAndFailures{} },
		cb.timeout,
		10,
	)
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
	cb.sw.SetInterval(timeout)
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
		cb.sw.Add(totalAndFailures{total: 1, failures: 1})
	} else {
		cb.sw.Add(totalAndFailures{total: 1, failures: 0})
	}
	switch cb.getState() {
	case circuitBreakerStateClosed:
		if cb.sw.Get().failures >= int(cb.failureThreshold) {
			cb.open()
		}
	case circuitBreakerStateHalfOpen:
		totalAndFailure := cb.sw.Get()
		if totalAndFailure.total-totalAndFailure.failures >= int(cb.successThreshold) {
			cb.changeState(circuitBreakerStateClosed)
		} else {
			cb.open()
		}
	case circuitBreakerStateOpen:
		if time.Since(cb.openStartAt.Load().(time.Time)) >= cb.timeout {
			cb.changeState(circuitBreakerStateHalfOpen)
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
	cb.state.Store(state)
	cb.openStartAt.Store(time.Now())
}

type tfsw = slidingWindow[totalAndFailures]

func newSlidingWindow[G group[G]](
	newEmpty func() G,
	interval time.Duration,
	bucketSize int,
) *slidingWindow[G] {
	values := make([]G, 0, bucketSize)
	for i := 0; i < bucketSize; i++ {
		values = append(values, newEmpty())
	}
	return &slidingWindow[G]{
		total:     newEmpty(),
		values:    values,
		lastStart: time.Now(),
		interval:  interval / time.Duration(bucketSize),
	}
}

type slidingWindow[G group[G]] struct {
	mutex  sync.RWMutex
	total  G
	values []G

	idx       int
	lastStart time.Time
	interval  time.Duration
}

// group is a mathematical concept. The values in the sliding window adhere to group properties.
type group[T any] interface {
	op(T) T
	empty() T
	inverse() T
}

func (sw *slidingWindow[G]) Add(val G) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	for elapsed := time.Since(sw.lastStart); elapsed > sw.interval; elapsed -= sw.interval {
		sw.idx++
		if sw.idx >= len(sw.values) {
			sw.idx = 0
		}
		sw.lastStart = sw.lastStart.Add(sw.interval)
		sw.total = sw.total.op(sw.values[sw.idx].inverse())
		sw.values[sw.idx] = sw.values[sw.idx].empty()
	}
	sw.total = sw.total.op(val)
	sw.values[sw.idx] = sw.values[sw.idx].op(val)
}

func (sw *slidingWindow[G]) Get() G {
	sw.mutex.RLock()
	defer sw.mutex.RUnlock()
	return sw.total
}
func (sw *slidingWindow[G]) SetInterval(interval time.Duration) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	sw.interval = interval / time.Duration(len(sw.values))
}

type totalAndFailures struct {
	total    int
	failures int
}

func (tf totalAndFailures) op(g totalAndFailures) totalAndFailures {
	tf.total += g.total
	tf.failures += g.failures
	return tf
}

func (tf totalAndFailures) empty() totalAndFailures {
	return totalAndFailures{}
}

func (tf totalAndFailures) inverse() totalAndFailures {
	tf.total = -tf.total
	tf.failures = -tf.failures
	return tf
}
