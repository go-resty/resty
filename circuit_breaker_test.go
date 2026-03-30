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

	cb := NewCircuitBreakerCount(failThreshold, successThreshold, resetTimeout)
	cbc := cb.circuitBreakerBase

	c := dcnl().SetCircuitBreaker(cb)

	for i := uint64(0); i < failThreshold; i++ {
		_, err := c.R().Get(ts.URL + "/500")
		assertNil(t, err)
	}
	resp, err := c.R().Get(ts.URL + "/500")
	assertErrorIs(t, ErrCircuitBreakerOpen, err)
	assertNil(t, resp)
	assertEqual(t, CircuitBreakerStateOpen, cbc.getState(), "expected open state after reaching failure threshold")

	time.Sleep(resetTimeout + 50*time.Millisecond)
	assertEqual(t, CircuitBreakerStateHalfOpen, cbc.getState(), "expected half-open state")

	_, err = c.R().Get(ts.URL + "/500")
	assertError(t, err)
	assertEqual(t, CircuitBreakerStateOpen, cbc.getState(), "expected open state after failure in half-open")

	time.Sleep(resetTimeout + 50*time.Millisecond)
	assertEqual(t, CircuitBreakerStateHalfOpen, cbc.getState(), "expected half-open state")

	for i := uint64(0); i < successThreshold; i++ {
		_, err := c.R().Get(ts.URL + "/200")
		assertNil(t, err)
	}
	assertEqual(t, CircuitBreakerStateClosed, cbc.getState(), "expected closed state after success threshold")

	resp, err = c.R().Get(ts.URL + "/200")
	assertNil(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	_, err = c.R().Get(ts.URL + "/500")
	assertError(t, err)
	assertEqual(t, 1, cbc.sw.Load().Get().failures, "expected failure count to be 1 after single failure in closed state")

	time.Sleep(resetTimeout)

	_, err = c.R().Get(ts.URL + "/500")
	assertError(t, err)
	assertEqual(t, 1, cbc.sw.Load().Get().failures, "expected failure count to be 1 after single failure in closed state")
}

func TestCircuitBreaker5xxPolicy(t *testing.T) {
	res1 := CircuitBreaker5xxPolicy(&Response{RawResponse: &http.Response{StatusCode: 500}})
	assertTrue(t, res1, "expected true for 5xx status code")

	res2 := CircuitBreaker5xxPolicy(&Response{RawResponse: &http.Response{StatusCode: 200}})
	assertFalse(t, res2, "expected false for non-5xx status code")
}

func TestCircuitBreakerCountBasedOpensAndAllow(t *testing.T) {
	cb := NewCircuitBreakerCount(2, 1, 20*time.Millisecond)
	cbc := cb.circuitBreakerBase
	fail := &Response{RawResponse: &http.Response{StatusCode: 500}}

	// expected allow when state is closed
	err1 := cb.Allow()
	assertNil(t, err1)
	assertEqual(t, 0, cbc.sw.Load().Get().failures, "expected allow when no failures initially")

	// expected still closed after 1 failure
	cb.ApplyPolicies(fail)
	err2 := cb.Allow()
	assertNil(t, err2)
	assertEqual(t, 1, cbc.sw.Load().Get().failures, "expected still closed after 1 failure")

	// expected open after reaching failure threshold
	cb.ApplyPolicies(fail)
	err3 := cb.Allow()
	assertErrorIs(t, ErrCircuitBreakerOpen, err3, "expected open after reaching failure threshold")

	// time.Sleep to half-open state
	time.Sleep(25 * time.Millisecond)
	assertEqual(t, CircuitBreakerStateHalfOpen, cbc.getState(), "expected half-open state after reset timeout")

	// expected still half-open after a failure
	cb.ApplyPolicies(fail)
	assertEqual(t, CircuitBreakerStateOpen, cbc.getState(), "expected open state after failure in half-open")

	// expected open state on allow
	err4 := cb.Allow()
	assertErrorIs(t, ErrCircuitBreakerOpen, err4, "expected open state on allow after failure in half-open")
}

func TestCircuitBreakerCountBasedHalfOpenToClosedOnSuccess(t *testing.T) {
	cb := NewCircuitBreakerCount(1, 1, 30*time.Millisecond)
	cbc := cb.circuitBreakerBase
	fail := &Response{RawResponse: &http.Response{StatusCode: 500}}
	ok := &Response{RawResponse: &http.Response{StatusCode: 200}}

	// expected open after failing threshold
	cb.ApplyPolicies(fail)
	err1 := cb.Allow()
	assertErrorIs(t, ErrCircuitBreakerOpen, err1, "expected open after failing threshold")

	// wait for resetTimeout to transition to half-open
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if cbc.getState() == CircuitBreakerStateHalfOpen {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// expected half-open state after reset timeout
	assertEqual(t, CircuitBreakerStateHalfOpen, cbc.getState(), "expected half-open state after reset timeout")

	// on success in half-open, should move to closed
	cb.ApplyPolicies(ok)
	assertEqual(t, CircuitBreakerStateClosed, cbc.getState(), "expected closed state after success in half-open")

	// expected allow when closed
	err := cb.Allow()
	assertNil(t, err)
}

func TestCircuitBreakerRatioBasedOpenToClosed(t *testing.T) {
	cb := NewCircuitBreakerRatio(0.5, 2, 20*time.Millisecond)
	cbc := cb.circuitBreakerBase
	fail := &Response{RawResponse: &http.Response{StatusCode: 500}}
	ok := &Response{RawResponse: &http.Response{StatusCode: 200}}

	// two failures should open (2/2 = 1.0 >= 0.5)
	cb.ApplyPolicies(fail)
	err1 := cb.Allow()
	assertNil(t, err1)
	if err1 == ErrCircuitBreakerOpen {
		t.Errorf("expected still closed after 1 failure (minRequests not met)")
	}

	// expected open after failures exceed ratio threshold
	cb.ApplyPolicies(fail)
	err2 := cb.Allow()
	assertErrorIs(t, ErrCircuitBreakerOpen, err2, "expected open after failures exceed ratio threshold")

	time.Sleep(25 * time.Millisecond)

	// expected half-open state after reset timeout
	assertEqual(t, CircuitBreakerStateHalfOpen, cbc.getState(), "expected half-open state after reset timeout")

	// on success in half-open, should move to closed
	cb.ApplyPolicies(ok)
	assertEqual(t, CircuitBreakerStateClosed, cbc.getState(), "expected closed state after success in half-open")
}

func TestCircuitBreakerNewStateAndPolicies(t *testing.T) {
	cb := NewCircuitBreakerCount(3, 2, 10*time.Millisecond, CircuitBreaker5xxPolicy)
	cbc := cb.circuitBreakerBase
	assertEqual(t, CircuitBreakerStateClosed, cbc.getState())
	assertEqual(t, uint64(3), cb.failureThreshold)
	assertEqual(t, uint64(2), cb.successThreshold)
	assertEqual(t, 10*time.Millisecond, cbc.resetTimeout)
	assertEqual(t, 1, len(cbc.policies))
}

func TestCircuitBreakerChangeStateClearsCounts(t *testing.T) {
	cb := NewCircuitBreakerCount(2, 1, 10*time.Millisecond)
	cbc := cb.circuitBreakerBase
	fail := &Response{RawResponse: &http.Response{StatusCode: 500}}

	cb.ApplyPolicies(fail)
	assertEqual(t, 1, cbc.sw.Load().Get().failures)

	cbc.changeState(CircuitBreakerStateHalfOpen)
	assertEqual(t, CircuitBreakerStateHalfOpen, cbc.getState())
	assertEqual(t, 0, cbc.sw.Load().Get().failures)
	assertEqual(t, 0, cbc.sw.Load().Get().total)
}

func TestCircuitBreakerAllowDuringHalfOpen(t *testing.T) {
	cb := NewCircuitBreakerCount(1, 1, 20*time.Millisecond)
	cbc := cb.circuitBreakerBase
	fail := &Response{RawResponse: &http.Response{StatusCode: 500}}
	ok := &Response{RawResponse: &http.Response{StatusCode: 200}}

	cb.ApplyPolicies(fail) // opens
	assertErrorIs(t, ErrCircuitBreakerOpen, cb.Allow(), "expected open state")

	time.Sleep(25 * time.Millisecond) // wait to transition to half-open
	assertEqual(t, CircuitBreakerStateHalfOpen, cbc.getState(), "expected half-open state")
	assertNil(t, cb.Allow(), "expected first probe request to be allowed in half-open state")
	assertErrorIs(t, ErrCircuitBreakerOpen, cb.Allow(), "expected only one in-flight probe request in half-open state")

	cb.ApplyPolicies(ok)
	assertEqual(t, CircuitBreakerStateClosed, cbc.getState(), "expected closed state after successful half-open probe")
}

func TestCircuitBreakerHalfOpenToOpenOnError(t *testing.T) {
	t.Run("request error", func(t *testing.T) {
		cb := NewCircuitBreakerCount(1, 1, 20*time.Millisecond)
		cbc := cb.circuitBreakerBase
		fail := &Response{RawResponse: &http.Response{StatusCode: 500}}

		cb.ApplyPolicies(fail)
		assertErrorIs(t, ErrCircuitBreakerOpen, cb.Allow(), "expected open state")

		time.Sleep(25 * time.Millisecond)
		assertEqual(t, CircuitBreakerStateHalfOpen, cbc.getState(), "expected half-open state")
		assertNil(t, cb.Allow(), "expected probe request to be allowed")

		cbc.onRequestError()
		assertEqual(t, CircuitBreakerStateOpen, cbc.getState(), "expected open state after probe request error")
		assertErrorIs(t, ErrCircuitBreakerOpen, cb.Allow(), "expected open state on allow after request error")
	})

	t.Run("middleware error", func(t *testing.T) {
		cb := NewCircuitBreakerCount(1, 1, 20*time.Millisecond)
		cbc := cb.circuitBreakerBase
		fail := &Response{RawResponse: &http.Response{StatusCode: 500}}
		mwErr := errors.New("middleware failure")

		c := dcnl().SetCircuitBreaker(cb)
		c.AddRequestMiddleware(func(_ *Client, _ *Request) error {
			return mwErr
		})

		cb.ApplyPolicies(fail)
		assertErrorIs(t, ErrCircuitBreakerOpen, cb.Allow(), "expected open state")

		time.Sleep(25 * time.Millisecond)
		assertEqual(t, CircuitBreakerStateHalfOpen, cbc.getState(), "expected half-open state")

		_, err := c.R().Get("http://localhost")
		assertErrorIs(t, mwErr, err, "expected middleware error")
		assertEqual(t, CircuitBreakerStateOpen, cbc.getState(), "expected open state after half-open middleware error")

		assertErrorIs(t, ErrCircuitBreakerOpen, cb.Allow(), "expected open state on allow after middleware error")
	})
}

func TestCircuitBreakerOpenCancelsPreviousResetTimer(t *testing.T) {
	resetTimeout := 60 * time.Millisecond
	cb := NewCircuitBreakerCount(1, 1, resetTimeout)
	cbc := cb.circuitBreakerBase

	var halfOpenTransitions int32
	cbc.OnStateChange(func(oldState, newState CircuitBreakerState) {
		if oldState == CircuitBreakerStateOpen && newState == CircuitBreakerStateHalfOpen {
			atomic.AddInt32(&halfOpenTransitions, 1)
		}
	})

	cbc.open()
	time.Sleep(40 * time.Millisecond)
	cbc.open()

	// If the previous timer was not canceled, it would flip to half-open soon.
	time.Sleep(30 * time.Millisecond)
	assertEqual(t, CircuitBreakerStateOpen, cbc.getState(), "expected open state while waiting for latest timer")

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if cbc.getState() == CircuitBreakerStateHalfOpen {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	assertEqual(t, CircuitBreakerStateHalfOpen, cbc.getState(), "expected half-open transition from latest timer")
	assertEqual(t, int32(1), atomic.LoadInt32(&halfOpenTransitions), "expected exactly one open-to-half-open transition")
}

func TestCircuitBreakerOnResetTimeout(t *testing.T) {
	t.Run("no transition when is not open", func(t *testing.T) {
		cb := NewCircuitBreakerCount(1, 1, 50*time.Millisecond)
		cbc := cb.circuitBreakerBase

		cbc.changeState(CircuitBreakerStateClosed)
		cbc.resetDeadlineUnixNano.Store(time.Now().Add(-10 * time.Millisecond).UnixNano())

		cbc.onResetTimeout()

		assertEqual(t, CircuitBreakerStateClosed, cbc.getState(), "expected no state transition when breaker is not open")
	})

	t.Run("reset timer when deadline in future", func(t *testing.T) {
		cb := NewCircuitBreakerCount(1, 1, 200*time.Millisecond)
		cbc := cb.circuitBreakerBase

		cbc.changeState(CircuitBreakerStateOpen)
		cbc.resetDeadlineUnixNano.Store(time.Now().Add(30 * time.Millisecond).UnixNano())

		cbc.resetTimerMu.Lock()
		cbc.resetTimer = time.AfterFunc(time.Hour, cbc.onResetTimeout)
		cbc.resetTimerMu.Unlock()

		cbc.onResetTimeout()

		deadline := time.Now().Add(300 * time.Millisecond)
		for time.Now().Before(deadline) {
			if cbc.getState() == CircuitBreakerStateHalfOpen {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}

		assertEqual(t, CircuitBreakerStateHalfOpen, cbc.getState(), "expected timer to be reset to remaining deadline and transition to half-open")
	})

	t.Run("half-open transition when reset deadline has elapsed", func(t *testing.T) {
		cb := NewCircuitBreakerCount(1, 1, 50*time.Millisecond)
		cbc := cb.circuitBreakerBase

		cbc.changeState(CircuitBreakerStateOpen)
		cbc.resetDeadlineUnixNano.Store(time.Now().Add(-10 * time.Millisecond).UnixNano())

		cbc.onResetTimeout()

		assertEqual(t, CircuitBreakerStateHalfOpen, cbc.getState(), "expected half-open transition when reset deadline has elapsed")
	})

}

func TestCircuitBreakerOnTriggerHooks(t *testing.T) {
	cb := NewCircuitBreakerCount(1, 1, 10*time.Millisecond)
	cbc := cb.circuitBreakerBase

	called := false
	var gotErr error
	cbc.OnTrigger(func(r *Request, e error) {
		called = true
		gotErr = e
	})

	cbc.RunOnTriggerHooks(nil, ErrCircuitBreakerOpen)

	assertTrue(t, called, "expected onTrigger hook to be called")
	assertEqual(t, ErrCircuitBreakerOpen, gotErr, "expected error to be passed to onTrigger hook")
}

func TestCircuitBreakerOnStateChangeHooks(t *testing.T) {
	cb := NewCircuitBreakerCount(1, 1, 10*time.Millisecond)
	cbc := cb.circuitBreakerBase

	called := false
	var oldState, newState CircuitBreakerState
	cbc.OnStateChange(func(o, n CircuitBreakerState) {
		called = true
		oldState = o
		newState = n
	})

	cbc.RunOnStateChangeHooks(CircuitBreakerStateClosed, CircuitBreakerStateOpen)

	assertTrue(t, called)
	assertEqual(t, CircuitBreakerStateClosed, oldState, "expected old state to be passed to onStateChange hook")
	assertEqual(t, CircuitBreakerStateOpen, newState, "expected new state to be passed to onStateChange hook")
}

func TestCircuitBreakerMultipleHooksAreCalled(t *testing.T) {
	cb := NewCircuitBreakerCount(1, 1, 10*time.Millisecond)
	cbc := cb.circuitBreakerBase

	triggerCount := 0
	cbc.OnTrigger(func(_ *Request, _ error) { triggerCount++ })
	cbc.OnTrigger(func(_ *Request, _ error) { triggerCount++ })

	cbc.RunOnTriggerHooks(nil, ErrCircuitBreakerOpen)
	assertEqual(t, 2, triggerCount, "expected both trigger hooks to be called")

	stateCount := 0
	cbc.OnStateChange(func(_, _ CircuitBreakerState) { stateCount++ })
	cbc.OnStateChange(func(_, _ CircuitBreakerState) { stateCount++ })

	cbc.RunOnStateChangeHooks(CircuitBreakerStateClosed, CircuitBreakerStateHalfOpen)
	assertEqual(t, 2, stateCount, "expected both state change hooks to be called")
}

func TestCircuitBreakerConcurrentOnTriggerRegistration(t *testing.T) {
	cb := NewCircuitBreakerCount(1, 1, 10*time.Millisecond)
	cbc := cb.circuitBreakerBase
	var wg sync.WaitGroup
	var cnt int32
	n := 100

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			cbc.OnTrigger(func(_ *Request, _ error) {
				atomic.AddInt32(&cnt, 1)
			})
			wg.Done()
		}()
	}
	wg.Wait()

	cbc.RunOnTriggerHooks(nil, ErrCircuitBreakerOpen)
	got := atomic.LoadInt32(&cnt)
	assertEqual(t, int32(n), got, "expected N hooks executed")
}

func TestCircuitBreakerConcurrentOnStateChangeRegistration(t *testing.T) {
	cb := NewCircuitBreakerCount(1, 1, 10*time.Millisecond)
	cbc := cb.circuitBreakerBase
	var wg sync.WaitGroup
	var cnt int32
	n := 100

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			cbc.OnStateChange(func(_, _ CircuitBreakerState) {
				atomic.AddInt32(&cnt, 1)
			})
			wg.Done()
		}()
	}
	wg.Wait()

	cbc.RunOnStateChangeHooks(CircuitBreakerStateClosed, CircuitBreakerStateOpen)
	got := atomic.LoadInt32(&cnt)
	assertEqual(t, int32(n), got, "expected N state change hooks executed")
}

func TestCircuitBreakerSlidingWindow1SetInterval(t *testing.T) {
	cb := NewCircuitBreakerCount(2, 1, 100*time.Millisecond)
	cbc := cb.circuitBreakerBase

	// Verify initial interval
	assertEqual(t, 100*time.Millisecond, cbc.sw.Load().interval, "initial interval mismatch")

	// Change interval to a longer duration
	cbc.sw.Load().SetInterval(200 * time.Millisecond)

	// Verify interval was changed
	assertEqual(t, 200*time.Millisecond, cbc.sw.Load().interval, "interval not updated correctly")
}

func TestCircuitBreakerSlidingWindow2SetInterval(t *testing.T) {
	sw := newSlidingWindow[totalAndFailures](100*time.Millisecond, 5)
	assertEqual(t, 100*time.Millisecond, sw.interval, "initial interval mismatch")

	sw.SetInterval(250 * time.Millisecond)
	assertEqual(t, 250*time.Millisecond, sw.interval, "interval not updated correctly")
}

func TestCircuitBreakerSlidingWindowConcurrentAddGet(t *testing.T) {
	sw := newSlidingWindow[totalAndFailures](200*time.Millisecond, 10)

	var wg sync.WaitGroup
	n := 200
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			sw.Add(totalAndFailures{total: 1, failures: 0})
			wg.Done()
		}()
	}
	wg.Wait()

	got := sw.Get()
	assertEqual(t, n, got.total, "concurrent adds: expected total count mismatch")
}

func TestCircuitBreakerTotalAndFailuresOperations(t *testing.T) {
	a := totalAndFailures{total: 2, failures: 1}
	b := totalAndFailures{total: 3, failures: 2}

	c := a.op(b)
	assertEqual(t, 5, c.total, "op result incorrect, want total 5")
	assertEqual(t, 3, c.failures, "op result incorrect, want failures 3")

	inv := c.inverse()
	assertEqual(t, -5, inv.total, "inverse result incorrect, want total -5")
	assertEqual(t, -3, inv.failures, "inverse result incorrect, want failures -3")

	empty := c.empty()
	assertEqual(t, 0, empty.total, "empty result incorrect, want total 0")
	assertEqual(t, 0, empty.failures, "empty result incorrect, want failures 0")
}

func TestCircuitBreakerSlidingWindowResetWhenElapsedExceedsBuckets(t *testing.T) {
	interval := 100 * time.Millisecond
	sw := newSlidingWindow[totalAndFailures](interval, 4)

	// Pre-populate total and buckets to non-zero values
	sw.values[0] = totalAndFailures{total: 5, failures: 2}
	sw.values[1] = totalAndFailures{total: 3, failures: 1}
	sw.total = sw.values[0].op(sw.values[1]).op(sw.total)

	// Force lastStart far in the past so bucketsToAdvance >= len(values) path is taken
	sw.lastStart = sw.lastStart.Add(-time.Duration(10) * interval)

	// Add a new value; should reset buckets and only this value remains
	sw.Add(totalAndFailures{total: 1, failures: 1})

	got := sw.Get()
	assertEqual(t, 1, got.total, "after reset expected total=1")
	assertEqual(t, 1, got.failures, "after reset expected failures=1")
	assertEqual(t, 0, sw.idx, "expected idx reset to 0")
}
