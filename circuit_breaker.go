// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ErrCircuitBreakerOpen is returned by [Client] execute method when the circuit breaker
// is in the open state and a request is blocked.
var ErrCircuitBreakerOpen = errors.New("resty: circuit breaker open")

type (
	// CircuitBreakerTriggerHook is called each time the circuit breaker blocks a
	// request because it is in the open state. The hook receives the blocked
	// [Request] and [ErrCircuitBreakerOpen] as the error.
	CircuitBreakerTriggerHook func(*Request, error)

	// CircuitBreakerStateChangeHook is called whenever the circuit breaker
	// transitions between states (Closed → Open, Open → Half-Open, Half-Open → Closed, etc.).
	// It receives the previous and the new [CircuitBreakerState].
	CircuitBreakerStateChangeHook func(oldState, newState CircuitBreakerState)

	// CircuitBreakerState is the type for the three circuit breaker states:
	// [CircuitBreakerStateClosed], [CircuitBreakerStateOpen], and [CircuitBreakerStateHalfOpen].
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
	// CircuitBreakerStateClosed is the normal operating state: all requests are
	// forwarded and failures are tracked against the configured threshold.
	CircuitBreakerStateClosed CircuitBreakerState = iota

	// CircuitBreakerStateOpen is the tripped state: all requests are blocked and
	// return [ErrCircuitBreakerOpen] immediately. After the reset timeout the
	// breaker transitions to [CircuitBreakerStateHalfOpen].
	CircuitBreakerStateOpen

	// CircuitBreakerStateHalfOpen is the recovery probe state: a single request
	// is allowed through. A success transitions to [CircuitBreakerStateClosed];
	// a failure transitions back to [CircuitBreakerStateOpen].
	CircuitBreakerStateHalfOpen
)

// CircuitBreaker implements a three-state state machine that protects downstream
// services from cascading failures.
//
// States:
//   - [CircuitBreakerStateClosed]: requests pass through; failures are recorded.
//   - [CircuitBreakerStateOpen]: all requests are rejected with [ErrCircuitBreakerOpen].
//   - [CircuitBreakerStateHalfOpen]: one probe request is allowed to test recovery.
//
// State transitions:
//   - Closed → Open: when the failure count (or ratio) reaches the configured threshold.
//   - Open → Half-Open: automatically after the reset timeout elapses.
//   - Half-Open → Closed: when the probe success count reaches the success threshold.
//   - Half-Open → Open: when the probe request is classified as a failure by any policy.
//
// Use [NewCircuitBreakerWithCount] for absolute failure count thresholds, or
// [NewCircuitBreakerWithRatio] for failure-ratio thresholds.
// Register the instance via [Client.SetCircuitBreaker].
type CircuitBreaker struct {
	lock         *sync.RWMutex
	policies     []CircuitBreakerPolicy
	resetTimeout time.Duration
	resetCtx     context.Context
	resetCancel  context.CancelFunc
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

// NewCircuitBreakerWithCount creates a [CircuitBreaker] that trips when the absolute
// number of request failures within the sliding window reaches failureThreshold.
// Once open, it recovers after resetTimeout and closes again when successThreshold
// consecutive probe successes are observed.
//
// The optional policies override the detection logic used to classify a response as
// a failure. When no policies are provided, [CircuitBreaker5xxPolicy] is used by default.
func NewCircuitBreakerWithCount(failureThreshold uint64, successThreshold uint64,
	resetTimeout time.Duration, policies ...CircuitBreakerPolicy) *CircuitBreaker {
	cb := newCircuitBreaker(resetTimeout, policies...)
	cb.failureThreshold = failureThreshold
	cb.successThreshold = successThreshold
	return cb
}

// NewCircuitBreakerWithRatio creates a [CircuitBreaker] that trips when the ratio of
// failures to total requests within the sliding window reaches failureRatio (0.0–1.0),
// provided at least minRequests have been observed. Once open, it recovers after
// resetTimeout. The half-open probe closes the breaker after one successful request.
//
// The optional policies override the detection logic used to classify a response as
// a failure. When no policies are provided, [CircuitBreaker5xxPolicy] is used by default.
func NewCircuitBreakerWithRatio(failureRatio float64, minRequests uint64,
	resetTimeout time.Duration, policies ...CircuitBreakerPolicy) *CircuitBreaker {
	cb := newCircuitBreaker(resetTimeout, policies...)
	cb.failureRatio = failureRatio
	cb.minRequests = minRequests
	cb.isRatioBased = true
	return cb
}

func newCircuitBreaker(resetTimeout time.Duration, policies ...CircuitBreakerPolicy) *CircuitBreaker {
	ctx, cancel := context.WithCancel(context.Background())
	cb := &CircuitBreaker{
		lock:         &sync.RWMutex{},
		resetTimeout: resetTimeout,
		resetCtx:     ctx,
		resetCancel:  cancel,
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

// OnTrigger registers one or more [CircuitBreakerTriggerHook] functions that are invoked
// each time the circuit breaker rejects a request in the open state.
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

// OnStateChange registers one or more [CircuitBreakerStateChangeHook] functions that are
// invoked whenever the circuit breaker transitions between states.
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

// CircuitBreakerPolicy is a function that inspects a raw [http.Response] and returns
// true when that response should be counted as a failure and potentially trip the
// [CircuitBreaker]. Multiple policies can be registered; the breaker trips if any
// policy returns true.
type CircuitBreakerPolicy func(resp *http.Response) bool

// CircuitBreaker5xxPolicy is the default [CircuitBreakerPolicy]. It classifies a
// response as a failure when the HTTP status code is greater than or equal to 500.
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

	cb.lock.Lock()
	// Cancel previous reset goroutine if any
	cb.resetCancel()
	ctx, cancel := context.WithCancel(context.Background())
	cb.resetCtx = ctx
	cb.resetCancel = cancel
	resetCtx := ctx
	resetTimeout := cb.resetTimeout
	cb.lock.Unlock()

	go func(resetCtx context.Context, resetTimeout time.Duration) {
		select {
		case <-time.After(resetTimeout):
			if cb.getState() == CircuitBreakerStateOpen {
				cb.changeState(CircuitBreakerStateHalfOpen)
			}
		case <-resetCtx.Done():
			// Cancelled, exit gracefully
		}
	}(resetCtx, resetTimeout)
}

func (cb *CircuitBreaker) changeState(state CircuitBreakerState) {
	oldState := cb.getState()
	cb.lock.Lock()
	cb.sw = newSlidingWindow(
		func() totalAndFailures { return totalAndFailures{} },
		cb.resetTimeout,
		10,
	)
	cb.lock.Unlock()
	cb.state.Store(state)
	if oldState != state {
		cb.onStateChangeHooks(oldState, state)
	}
}
