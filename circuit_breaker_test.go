// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var _ CircuitBreakerPolicy = CircuitBreaker5xxPolicy

func TestCircuitBreakerCountBased(t *testing.T) {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)

		switch r.URL.Path {
		case "/200":
			w.WriteHeader(http.StatusOK)
			return
		case "/500":
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})
	defer ts.Close()

	failThreshold := uint64(2)
	successThreshold := uint64(1)
	resetTimeout := 100 * time.Millisecond

	cb := NewCircuitBreakerWithCount(failThreshold, successThreshold, resetTimeout)

	c := dcnl().SetCircuitBreaker(cb)

	for i := uint64(0); i < failThreshold; i++ {
		_, err := c.R().Get(ts.URL + "/500")
		assertNil(t, err)
	}
	resp, err := c.R().Get(ts.URL + "/500")
	assertErrorIs(t, ErrCircuitBreakerOpen, err)
	assertNil(t, resp)
	assertEqual(t, CircuitBreakerStateOpen, c.circuitBreaker.getState())

	time.Sleep(resetTimeout + 50*time.Millisecond)
	assertEqual(t, CircuitBreakerStateHalfOpen, c.circuitBreaker.getState())

	_, err = c.R().Get(ts.URL + "/500")
	assertError(t, err)
	assertEqual(t, CircuitBreakerStateOpen, c.circuitBreaker.getState())

	time.Sleep(resetTimeout + 50*time.Millisecond)
	assertEqual(t, CircuitBreakerStateHalfOpen, c.circuitBreaker.getState())

	for i := uint64(0); i < successThreshold; i++ {
		_, err := c.R().Get(ts.URL + "/200")
		assertNil(t, err)
	}
	assertEqual(t, CircuitBreakerStateClosed, c.circuitBreaker.getState())

	resp, err = c.R().Get(ts.URL + "/200")
	assertNil(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	_, err = c.R().Get(ts.URL + "/500")
	assertError(t, err)
	assertEqual(t, 1, c.circuitBreaker.sw.Get().failures)

	time.Sleep(resetTimeout)

	_, err = c.R().Get(ts.URL + "/500")
	assertError(t, err)
	assertEqual(t, 1, c.circuitBreaker.sw.Get().failures)
}

func TestCircuitBreaker5xxPolicy(t *testing.T) {
	res1 := CircuitBreaker5xxPolicy(&http.Response{StatusCode: 500})
	assertEqual(t, true, res1)

	res2 := CircuitBreaker5xxPolicy(&http.Response{StatusCode: 200})
	assertEqual(t, false, res2)
}

func TestCircuitBreakerCountBasedOpensAndAllow(t *testing.T) {
	cb := NewCircuitBreakerWithCount(2, 1, 20*time.Millisecond)
	fail := &http.Response{StatusCode: 500}

	// expected allow when state is closed
	err1 := cb.allow()
	assertNil(t, err1)
	assertEqual(t, 0, cb.sw.Get().failures)

	// expected still closed after 1 failure
	cb.applyPolicies(fail)
	err2 := cb.allow()
	assertNil(t, err2)
	assertEqual(t, 1, cb.sw.Get().failures)

	// expected open after reaching failure threshold
	cb.applyPolicies(fail)
	err3 := cb.allow()
	assertErrorIs(t, ErrCircuitBreakerOpen, err3)

	// time.Sleep to half-open state
	time.Sleep(25 * time.Millisecond)
	assertEqual(t, CircuitBreakerStateHalfOpen, cb.getState())

	// expected still half-open after a failure
	cb.applyPolicies(fail)
	assertEqual(t, CircuitBreakerStateOpen, cb.getState())

	// expected open state on allow
	err4 := cb.allow()
	assertErrorIs(t, ErrCircuitBreakerOpen, err4)
}

func TestCircuitBreakerCountBasedHalfOpenToClosedOnSuccess(t *testing.T) {
	cb := NewCircuitBreakerWithCount(1, 1, 30*time.Millisecond)
	fail := &http.Response{StatusCode: 500}
	ok := &http.Response{StatusCode: 200}

	// expected open after failing threshold
	cb.applyPolicies(fail)
	err1 := cb.allow()
	assertErrorIs(t, ErrCircuitBreakerOpen, err1)

	// wait for resetTimeout to transition to half-open
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if cb.getState() == CircuitBreakerStateHalfOpen {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// expected half-open state after reset timeout
	assertEqual(t, CircuitBreakerStateHalfOpen, cb.getState())

	// on success in half-open, should move to closed
	cb.applyPolicies(ok)
	assertEqual(t, CircuitBreakerStateClosed, cb.getState())

	// expected allow when closed
	err := cb.allow()
	assertNil(t, err)
}

func TestCircuitBreakerRatioBasedOpenToClosed(t *testing.T) {
	cb := NewCircuitBreakerWithRatio(0.5, 2, 20*time.Millisecond)
	fail := &http.Response{StatusCode: 500}
	ok := &http.Response{StatusCode: 200}

	// two failures should open (2/2 = 1.0 >= 0.5)
	cb.applyPolicies(fail)
	err1 := cb.allow()
	assertNil(t, err1)
	if err1 == ErrCircuitBreakerOpen {
		t.Errorf("expected still closed after 1 failure (minRequests not met)")
	}

	// expected open after failures exceed ratio threshold
	cb.applyPolicies(fail)
	err2 := cb.allow()
	assertErrorIs(t, ErrCircuitBreakerOpen, err2)
	// if err := cb.allow(); err != ErrCircuitBreakerOpen {
	// 	t.Fatalf("expected open after failures exceed ratio threshold, got %v", err)
	// }
	time.Sleep(25 * time.Millisecond)

	// expected half-open state after reset timeout
	assertEqual(t, CircuitBreakerStateHalfOpen, cb.getState())

	// on success in half-open, should move to closed
	cb.applyPolicies(ok)
	assertEqual(t, CircuitBreakerStateClosed, cb.getState())
}

func TestCircuitBreakerNewStateAndPolicies(t *testing.T) {
	cb := NewCircuitBreakerWithCount(3, 2, 10*time.Millisecond, CircuitBreaker5xxPolicy)
	assertEqual(t, CircuitBreakerStateClosed, cb.getState())
	assertEqual(t, uint64(3), cb.failureThreshold)
	assertEqual(t, uint64(2), cb.successThreshold)
	assertEqual(t, 10*time.Millisecond, cb.resetTimeout)
	assertEqual(t, 1, len(cb.policies))
}

func TestCircuitBreakerChangeStateClearsCounts(t *testing.T) {
	cb := NewCircuitBreakerWithCount(2, 1, 10*time.Millisecond)
	fail := &http.Response{StatusCode: 500}

	cb.applyPolicies(fail)
	assertEqual(t, 1, cb.sw.Get().failures)

	cb.changeState(CircuitBreakerStateHalfOpen)
	assertEqual(t, CircuitBreakerStateHalfOpen, cb.getState())
	assertEqual(t, 0, cb.sw.Get().failures)
	assertEqual(t, 0, cb.sw.Get().total)
}

func TestCircuitBreakerAllowDuringHalfOpen(t *testing.T) {
	cb := NewCircuitBreakerWithCount(1, 1, 20*time.Millisecond)
	fail := &http.Response{StatusCode: 500}

	cb.applyPolicies(fail) // opens
	assertErrorIs(t, ErrCircuitBreakerOpen, cb.allow())

	time.Sleep(25 * time.Millisecond) // wait to transition to half-open
	assertEqual(t, CircuitBreakerStateHalfOpen, cb.getState())
	assertNil(t, cb.allow())
}

func TestCircuitBreakerOnTriggerHooks(t *testing.T) {
	cb := NewCircuitBreakerWithCount(1, 1, 10*time.Millisecond)

	called := false
	var gotErr error
	cb.OnTrigger(func(r *Request, e error) {
		called = true
		gotErr = e
	})

	cb.onTriggerHooks(nil, ErrCircuitBreakerOpen)

	assertEqual(t, true, called)
	assertEqual(t, ErrCircuitBreakerOpen, gotErr)
}

func TestCircuitBreakerOnStateChangeHooks(t *testing.T) {
	cb := NewCircuitBreakerWithCount(1, 1, 10*time.Millisecond)

	called := false
	var oldState, newState CircuitBreakerState
	cb.OnStateChange(func(o, n CircuitBreakerState) {
		called = true
		oldState = o
		newState = n
	})

	cb.onStateChangeHooks(CircuitBreakerStateClosed, CircuitBreakerStateOpen)

	assertEqual(t, true, called)
	assertEqual(t, CircuitBreakerStateClosed, oldState)
	assertEqual(t, CircuitBreakerStateOpen, newState)
}

func TestCircuitBreakerMultipleHooksAreCalled(t *testing.T) {
	cb := NewCircuitBreakerWithCount(1, 1, 10*time.Millisecond)

	triggerCount := 0
	cb.OnTrigger(func(_ *Request, _ error) { triggerCount++ })
	cb.OnTrigger(func(_ *Request, _ error) { triggerCount++ })

	cb.onTriggerHooks(nil, ErrCircuitBreakerOpen)
	assertEqual(t, 2, triggerCount)

	stateCount := 0
	cb.OnStateChange(func(_, _ CircuitBreakerState) { stateCount++ })
	cb.OnStateChange(func(_, _ CircuitBreakerState) { stateCount++ })

	cb.onStateChangeHooks(CircuitBreakerStateClosed, CircuitBreakerStateHalfOpen)
	assertEqual(t, 2, stateCount)
}

func TestCircuitBreakerConcurrentOnTriggerRegistration(t *testing.T) {
	cb := NewCircuitBreakerWithCount(1, 1, 10*time.Millisecond)
	var wg sync.WaitGroup
	var cnt int32
	n := 100

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			cb.OnTrigger(func(_ *Request, _ error) {
				atomic.AddInt32(&cnt, 1)
			})
			wg.Done()
		}()
	}
	wg.Wait()

	cb.onTriggerHooks(nil, ErrCircuitBreakerOpen)
	got := atomic.LoadInt32(&cnt)
	assertEqual(t, int32(n), got) // expected N hooks executed
}

func TestCircuitBreakerConcurrentOnStateChangeRegistration(t *testing.T) {
	cb := NewCircuitBreakerWithCount(1, 1, 10*time.Millisecond)
	var wg sync.WaitGroup
	var cnt int32
	n := 100

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			cb.OnStateChange(func(_, _ CircuitBreakerState) {
				atomic.AddInt32(&cnt, 1)
			})
			wg.Done()
		}()
	}
	wg.Wait()

	cb.onStateChangeHooks(CircuitBreakerStateClosed, CircuitBreakerStateOpen)
	got := atomic.LoadInt32(&cnt)
	assertEqual(t, int32(n), got) // expected N state change hooks executed
}

func TestCircuitBreakerSlidingWindowSetInterval(t *testing.T) {
	cb := NewCircuitBreakerWithCount(2, 1, 100*time.Millisecond)

	// Verify initial interval
	assertEqual(t, 100*time.Millisecond, cb.sw.interval)

	// Change interval to a longer duration
	cb.sw.SetInterval(200 * time.Millisecond)

	// Verify interval was changed
	assertEqual(t, 200*time.Millisecond, cb.sw.interval)
}
