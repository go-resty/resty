// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrCircuitBreakerOpen is returned by [Client] execute method when the circuit breaker
// is in the open state and a request is blocked.
var ErrCircuitBreakerOpen = errors.New("resty: circuit breaker open")

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

type (
	// CircuitBreaker is an interface for implementing a circuit breaker pattern to protect
	// downstream services from cascading failures. It provides methods to check if a request is allowed
	// and apply policies to classify responses as failures.
	CircuitBreaker interface {
		// Allow checks if a request is allowed to proceed based on the current state of the circuit breaker.
		// It returns [ErrCircuitBreakerOpen] when the breaker is open or when a half-open
		// probe request is already in flight.
		Allow() error

		// ApplyPolicies inspects the given HTTP response against the registered policies to determine
		// if it should be classified as a failure. It updates the sliding window counts and
		// manages state transitions accordingly.
		ApplyPolicies(*Response)
	}

	// CircuitBreakerObserver is an interface for observing circuit breaker events via hooks.
	// It provides methods to register hooks for trigger and state change events, and to
	// execute those hooks.
	CircuitBreakerObserver interface {
		// OnTrigger registers one or more [CircuitBreakerTriggerHook] functions that are invoked
		// each time the circuit breaker rejects a request in the open state.
		OnTrigger(...CircuitBreakerTriggerHook) CircuitBreakerObserver

		// RunOnTriggerHooks executes all registered trigger hooks with the given request and error.
		RunOnTriggerHooks(*Request, error)

		// OnStateChange registers one or more [CircuitBreakerStateChangeHook] functions that are
		// invoked whenever the circuit breaker transitions between states.
		OnStateChange(...CircuitBreakerStateChangeHook) CircuitBreakerObserver

		// RunOnStateChangeHooks executes all registered state change hooks with the given old and new states.
		RunOnStateChangeHooks(oldState, newState CircuitBreakerState)
	}

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

	circuitBreakerMode interface {
		shouldOpenOnClosed(totalAndFailures) bool
		halfOpenSuccessThreshold() uint64
	}
)

var _ CircuitBreakerObserver = (*CircuitBreakerCount)(nil)
var _ CircuitBreaker = (*CircuitBreakerCount)(nil)

// CircuitBreakerCount implements a count-based circuit breaker. It trips when the
// absolute number of request failures within the sliding window reaches the
// configured failureThreshold. Once open, it recovers after resetTimeout and closes
// again when successThreshold consecutive probe successes are observed.
//
// Create via [NewCircuitBreakerCount] and register via [Client.SetCircuitBreaker].
type CircuitBreakerCount struct {
	*circuitBreakerBase
	failureThreshold uint64
	successThreshold uint64
}

func (cb *CircuitBreakerCount) shouldOpenOnClosed(tf totalAndFailures) bool {
	return tf.failures >= int(cb.failureThreshold)
}

func (cb *CircuitBreakerCount) halfOpenSuccessThreshold() uint64 {
	return cb.successThreshold
}

// ApplyPolicies inspects the given HTTP response against the registered policies to
// determine if it should be classified as a failure. It updates the sliding window
// counts and manages state transitions accordingly.
func (cb *CircuitBreakerCount) ApplyPolicies(resp *Response) {
	cb.applyPolicies(resp, cb)
}

var _ CircuitBreakerObserver = (*CircuitBreakerRatio)(nil)
var _ CircuitBreaker = (*CircuitBreakerRatio)(nil)

// CircuitBreakerRatio implements a ratio-based circuit breaker. It trips when the
// ratio of failures to total requests within the sliding window reaches the configured
// failureRatio, provided at least minRequests have been observed. Once open, it
// recovers after resetTimeout. The half-open probe closes the breaker after one
// successful request.
//
// Create via [NewCircuitBreakerRatio] and register via [Client.SetCircuitBreaker].
type CircuitBreakerRatio struct {
	*circuitBreakerBase
	failureRatio float64
	minRequests  uint64
}

func (cb *CircuitBreakerRatio) shouldOpenOnClosed(tf totalAndFailures) bool {
	if tf.total < int(cb.minRequests) {
		return false
	}
	currentFailureRatio := float64(tf.failures) / float64(tf.total)
	return currentFailureRatio >= cb.failureRatio
}

func (cb *CircuitBreakerRatio) halfOpenSuccessThreshold() uint64 {
	// Ratio mode intentionally uses a single probe request to recover.
	return 1
}

// ApplyPolicies inspects the given HTTP response against the registered policies to
// determine if it should be classified as a failure. It updates the sliding window
// counts and manages state transitions accordingly.
func (cb *CircuitBreakerRatio) ApplyPolicies(resp *Response) {
	cb.applyPolicies(resp, cb)
}

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

func newSlidingWindow[G group[G]](interval time.Duration, buckets int) *slidingWindow[G] {
	var zero G
	return &slidingWindow[G]{
		total:     zero.empty(),
		values:    make([]G, buckets),
		lastStart: time.Now(),
		interval:  interval,
	}
}

func (sw *slidingWindow[G]) Add(val G) {
	_ = sw.AddAndGet(val)
}

func (sw *slidingWindow[G]) AddAndGet(val G) G {
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
			for range bucketsToAdvance {
				sw.idx = (sw.idx + 1) % len(sw.values)
				sw.total = sw.total.op(sw.values[sw.idx].inverse())
				sw.values[sw.idx] = sw.total.empty()
			}
		}
		sw.lastStart = sw.lastStart.Add(time.Duration(bucketsToAdvance) * bucketDuration)
	}

	// Add to current bucket
	sw.values[sw.idx] = sw.values[sw.idx].op(val)
	sw.total = sw.total.op(val)

	return sw.total
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

type cbRequestErrorObserver interface {
	onRequestError()
}

var _ cbRequestErrorObserver = (*circuitBreakerBase)(nil)

// circuitBreakerBase holds the common state and logic shared by [CircuitBreakerCount]
// and [CircuitBreakerRatio]. It is embedded by pointer in each concrete type.
type circuitBreakerBase struct {
	lock                  sync.RWMutex
	policies              []CircuitBreakerPolicy
	resetTimeout          time.Duration
	resetTimerMu          sync.Mutex
	resetTimer            *time.Timer
	resetDeadlineUnixNano atomic.Int64
	state                 atomic.Value // CircuitBreakerState
	halfOpenProbeInFlight atomic.Uint32
	sw                    atomic.Pointer[slidingWindow[totalAndFailures]]

	// Hooks
	triggerHooks     []CircuitBreakerTriggerHook
	stateChangeHooks []CircuitBreakerStateChangeHook
}

// NewCircuitBreakerCount creates a circuit breaker that trips when the absolute
// number of request failures within the sliding window reaches failureThreshold.
// Once open, it recovers after resetTimeout and closes again when successThreshold
// consecutive probe successes are observed.
//
// The optional policies override the detection logic used to classify a response as
// a failure. When no policies are provided, [CircuitBreaker5xxPolicy] is used by default.
func NewCircuitBreakerCount(failureThreshold uint64, successThreshold uint64,
	resetTimeout time.Duration, policies ...CircuitBreakerPolicy) CircuitBreaker {
	return &CircuitBreakerCount{
		circuitBreakerBase: newCircuitBreakerBase(resetTimeout, policies...),
		failureThreshold:   failureThreshold,
		successThreshold:   successThreshold,
	}
}

// NewCircuitBreakerRatio creates a circuit breaker that trips when the ratio of
// failures to total requests within the sliding window reaches failureRatio (0.0–1.0),
// provided at least minRequests have been observed. Once open, it recovers after
// resetTimeout. The half-open probe closes the breaker after one successful request.
//
// The optional policies override the detection logic used to classify a response as
// a failure. When no policies are provided, [CircuitBreaker5xxPolicy] is used by default.
func NewCircuitBreakerRatio(failureRatio float64, minRequests uint64,
	resetTimeout time.Duration, policies ...CircuitBreakerPolicy) CircuitBreaker {
	return &CircuitBreakerRatio{
		circuitBreakerBase: newCircuitBreakerBase(resetTimeout, policies...),
		failureRatio:       failureRatio,
		minRequests:        minRequests,
	}
}

func newCircuitBreakerBase(resetTimeout time.Duration, policies ...CircuitBreakerPolicy) *circuitBreakerBase {
	cb := &circuitBreakerBase{
		resetTimeout: resetTimeout,
		policies:     []CircuitBreakerPolicy{CircuitBreaker5xxPolicy},
	}
	cb.state.Store(CircuitBreakerStateClosed)
	cb.sw.Store(newSlidingWindow[totalAndFailures](resetTimeout, 10))
	if len(policies) > 0 {
		cb.policies = policies
	}
	return cb
}

// Allow checks if a request is allowed to proceed based on the current
// state of the circuit breaker.
func (cb *circuitBreakerBase) Allow() error {
	switch cb.getState() {
	case CircuitBreakerStateOpen:
		return ErrCircuitBreakerOpen
	case CircuitBreakerStateHalfOpen:
		if !cb.halfOpenProbeInFlight.CompareAndSwap(0, 1) {
			return ErrCircuitBreakerOpen
		}
	}

	return nil
}

// applyPolicies is the shared implementation used by [CircuitBreakerCount.ApplyPolicies]
// and [CircuitBreakerRatio.ApplyPolicies].
func (cb *circuitBreakerBase) applyPolicies(resp *Response, mode circuitBreakerMode) {
	failed := false
	for _, policy := range cb.policies {
		if policy(resp) {
			failed = true
			break
		}
	}

	sw := cb.sw.Load()
	if failed {
		tf := sw.AddAndGet(totalAndFailures{total: 1, failures: 1})

		switch cb.getState() {
		case CircuitBreakerStateClosed:
			if mode.shouldOpenOnClosed(tf) {
				cb.open()
			}
		case CircuitBreakerStateHalfOpen:
			cb.halfOpenProbeInFlight.Store(0)
			cb.open()
		}

		return
	}

	tf := sw.AddAndGet(totalAndFailures{total: 1, failures: 0})

	switch cb.getState() {
	case CircuitBreakerStateClosed:
		return
	case CircuitBreakerStateHalfOpen:
		cb.halfOpenProbeInFlight.Store(0)
		if tf.total-tf.failures >= int(mode.halfOpenSuccessThreshold()) {
			cb.changeState(CircuitBreakerStateClosed)
		}
	}
}

// OnTrigger registers one or more [CircuitBreakerTriggerHook] functions that are invoked
// each time the circuit breaker rejects a request in the open state.
func (cb *circuitBreakerBase) OnTrigger(hooks ...CircuitBreakerTriggerHook) CircuitBreakerObserver {
	cb.lock.Lock()
	defer cb.lock.Unlock()
	cb.triggerHooks = append(cb.triggerHooks, hooks...)
	return cb
}

// RunOnTriggerHooks method executes all registered trigger hooks with the given request and error.
func (cb *circuitBreakerBase) RunOnTriggerHooks(req *Request, err error) {
	cb.lock.RLock()
	defer cb.lock.RUnlock()
	for _, h := range cb.triggerHooks {
		h(req, err)
	}
}

// OnStateChange registers one or more [CircuitBreakerStateChangeHook] functions that are
// invoked whenever the circuit breaker transitions between states.
func (cb *circuitBreakerBase) OnStateChange(hooks ...CircuitBreakerStateChangeHook) CircuitBreakerObserver {
	cb.lock.Lock()
	defer cb.lock.Unlock()
	cb.stateChangeHooks = append(cb.stateChangeHooks, hooks...)
	return cb
}

// RunOnStateChangeHooks method executes all registered state change hooks with the given old and new states.
func (cb *circuitBreakerBase) RunOnStateChangeHooks(oldState, newState CircuitBreakerState) {
	cb.lock.RLock()
	defer cb.lock.RUnlock()
	for _, h := range cb.stateChangeHooks {
		h(oldState, newState)
	}
}

// CircuitBreakerPolicy is a function that inspects a [Response] and returns
// true when that response should be counted as a failure and potentially trip the
// circuit breaker. Multiple policies can be registered; the breaker trips if any
// policy returns true.
type CircuitBreakerPolicy func(resp *Response) bool

// CircuitBreaker5xxPolicy is the default [CircuitBreakerPolicy]. It classifies a
// response as a failure when the HTTP status code is greater than or equal to 500.
func CircuitBreaker5xxPolicy(resp *Response) bool {
	return resp.StatusCode() > 499
}

func (cb *circuitBreakerBase) getState() CircuitBreakerState {
	return cb.state.Load().(CircuitBreakerState)
}

func (cb *circuitBreakerBase) open() {
	cb.changeState(CircuitBreakerStateOpen)
	cb.resetDeadlineUnixNano.Store(time.Now().Add(cb.resetTimeout).UnixNano())

	cb.resetTimerMu.Lock()
	defer cb.resetTimerMu.Unlock()

	if cb.resetTimer == nil {
		cb.resetTimer = time.AfterFunc(cb.resetTimeout, cb.onResetTimeout)
		return
	}

	cb.resetTimer.Stop()
	cb.resetTimer.Reset(cb.resetTimeout)
}

func (cb *circuitBreakerBase) onResetTimeout() {
	if cb.getState() != CircuitBreakerStateOpen {
		return
	}

	deadline := cb.resetDeadlineUnixNano.Load()
	remaining := time.Until(time.Unix(0, deadline))
	if remaining > 0 {
		cb.resetTimerMu.Lock()
		if cb.resetTimer != nil {
			cb.resetTimer.Reset(remaining)
		}
		cb.resetTimerMu.Unlock()
		return
	}

	cb.changeState(CircuitBreakerStateHalfOpen)
}

func (cb *circuitBreakerBase) changeState(state CircuitBreakerState) {
	oldState := cb.getState()
	cb.state.Store(state)
	cb.halfOpenProbeInFlight.Store(0)
	cb.sw.Store(newSlidingWindow[totalAndFailures](cb.resetTimeout, 10))
	if oldState != state {
		cb.RunOnStateChangeHooks(oldState, state)
	}
}

func (cb *circuitBreakerBase) onRequestError() {
	if cb.getState() == CircuitBreakerStateHalfOpen {
		cb.halfOpenProbeInFlight.Store(0)
		cb.open()
	}
}
