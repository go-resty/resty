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

// group is an interface for types that can be combined and inverted
type group[T any] interface {
	op(T) T
	empty() T
	inverse() T
}

// totalAndFailures tracks total requests and failures
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

// slidingWindow implements a time-based sliding window for tracking values
type slidingWindow[G group[G]] struct {
	mutex     sync.RWMutex
	total     G
	values    []G
	idx       int
	lastStart time.Time
	interval  time.Duration
}

func newSlidingWindow[G group[G]](empty func() G, interval time.Duration, buckets int) *slidingWindow[G] {
	return &slidingWindow[G]{
		total:     empty(),
		values:    make([]G, buckets),
		idx:       0,
		lastStart: time.Now(),
		interval:  interval,
	}
}

func (sw *slidingWindow[G]) Add(val G) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(sw.lastStart)
	bucketDuration := sw.interval / time.Duration(len(sw.values))

	// Advance window if needed
	if elapsed >= bucketDuration {
		bucketsToAdvance := int(elapsed / bucketDuration)
		if bucketsToAdvance >= len(sw.values) {
			// Reset all buckets
			for i := range sw.values {
				sw.values[i] = sw.total.empty()
			}
			sw.total = sw.total.empty()
			sw.idx = 0
		} else {
			// Remove old buckets
			for i := 0; i < bucketsToAdvance; i++ {
				sw.idx = (sw.idx + 1) % len(sw.values)
				sw.total = sw.total.op(sw.values[sw.idx].inverse())
				sw.values[sw.idx] = sw.total.empty()
			}
		}
		sw.lastStart = now
	}

	// Add to current bucket
	sw.values[sw.idx] = sw.values[sw.idx].op(val)
	sw.total = sw.total.op(val)
}

func (sw *slidingWindow[G]) Get() G {
	sw.mutex.RLock()
	defer sw.mutex.RUnlock()
	return sw.total
}

func (sw *slidingWindow[G]) SetInterval(interval time.Duration) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	sw.interval = interval
}

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
	lock         *sync.RWMutex
	policies     []CircuitBreakerPolicy
	resetTimeout time.Duration
	state        atomic.Value // CircuitBreakerState
	sw           *slidingWindow[totalAndFailures]

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
	cb.sw = newSlidingWindow(
		func() totalAndFailures { return totalAndFailures{} },
		resetTimeout,
		10,
	)
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

	if failed {
		cb.sw.Add(totalAndFailures{total: 1, failures: 1})

		switch cb.getState() {
		case CircuitBreakerStateClosed:
			tf := cb.sw.Get()

			if cb.isRatioBased {
				if tf.total >= int(cb.minRequests) {
					currentFailureRatio := float64(tf.failures) / float64(tf.total)
					if currentFailureRatio >= cb.failureRatio {
						cb.open()
					}
				}
			} else {
				if tf.failures >= int(cb.failureThreshold) {
					cb.open()
				}
			}
		case CircuitBreakerStateHalfOpen:
			cb.open()
		}

		return
	}

	cb.sw.Add(totalAndFailures{total: 1, failures: 0})

	switch cb.getState() {
	case CircuitBreakerStateClosed:
		return
	case CircuitBreakerStateHalfOpen:
		tf := cb.sw.Get()
		if tf.total-tf.failures >= int(cb.successThreshold) {
			cb.changeState(CircuitBreakerStateClosed)
		}
	}
}

func (cb *CircuitBreaker) open() {
	cb.changeState(CircuitBreakerStateOpen)
	go func() {
		time.Sleep(cb.resetTimeout)
		cb.changeState(CircuitBreakerStateHalfOpen)
	}()
}

func (cb *CircuitBreaker) changeState(state CircuitBreakerState) {
	oldState := cb.getState()
	cb.sw = newSlidingWindow(
		func() totalAndFailures { return totalAndFailures{} },
		cb.resetTimeout,
		10,
	)
	cb.state.Store(state)
	if oldState != state {
		cb.onStateChangeHooks(oldState, state)
	}
}
