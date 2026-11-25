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

func TestCircuitBreakerHooksRegisterDuringDispatch(t *testing.T) {
	for _, kind := range []string{"count", "ratio"} {
		for _, hook := range []string{"trigger", "state-change"} {
			t.Run(kind+"/"+hook, func(t *testing.T) {
				var cb *circuitBreakerBase
				if kind == "count" {
					cb = NewCircuitBreakerCount(1, 1, time.Second).circuitBreakerBase
				} else {
					cb = NewCircuitBreakerRatio(0.5, 1, time.Second).circuitBreakerBase
				}
				calls := make([]int, 0, 5)
				registered := false
				var dispatch func()
				if hook == "trigger" {
					cb.OnTrigger(func(*Request, error) {
						calls = append(calls, 1)
						if !registered {
							registered = true
							cb.OnTrigger(func(*Request, error) { calls = append(calls, 3) })
						}
					}, func(*Request, error) { calls = append(calls, 2) })
					dispatch = func() { cb.RunOnTriggerHooks(nil, ErrCircuitBreakerOpen) }
				} else {
					cb.OnStateChange(func(CircuitBreakerState, CircuitBreakerState) {
						calls = append(calls, 1)
						if !registered {
							registered = true
							cb.OnStateChange(func(CircuitBreakerState, CircuitBreakerState) { calls = append(calls, 3) })
						}
					}, func(CircuitBreakerState, CircuitBreakerState) { calls = append(calls, 2) })
					dispatch = func() { cb.RunOnStateChangeHooks(CircuitBreakerStateClosed, CircuitBreakerStateOpen) }
				}
				done := make(chan struct{})
				go func() { dispatch(); close(done) }()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("hook registration deadlocked during callback dispatch")
				}
				assertEqual(t, []int{1, 2}, calls)
				calls = calls[:0]
				dispatch()
				assertEqual(t, []int{1, 2, 3}, calls)
			})
		}
	}
}

func TestCircuitBreakerHooksConcurrentRegistration(t *testing.T) {
	cb := NewCircuitBreakerCount(1, 1, time.Second)
	var calls atomic.Int64
	cb.OnTrigger(func(*Request, error) { calls.Add(1) })
	cb.OnStateChange(func(CircuitBreakerState, CircuitBreakerState) { calls.Add(1) })
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cb.OnTrigger(func(*Request, error) { calls.Add(1) })
				cb.OnStateChange(func(CircuitBreakerState, CircuitBreakerState) { calls.Add(1) })
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cb.RunOnTriggerHooks(nil, ErrCircuitBreakerOpen)
				cb.RunOnStateChangeHooks(CircuitBreakerStateClosed, CircuitBreakerStateOpen)
			}
		}()
	}
	wg.Wait()
	before := calls.Load()
	cb.RunOnTriggerHooks(nil, ErrCircuitBreakerOpen)
	cb.RunOnStateChangeHooks(CircuitBreakerStateClosed, CircuitBreakerStateOpen)
	assertEqual(t, int64(802), calls.Load()-before)
}

func TestCircuitBreakerStateChangeHookRegistersTriggerHook(t *testing.T) {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer ts.Close()
	cb := NewCircuitBreakerCount(1, 1, time.Hour)
	var calls atomic.Int64
	cb.OnStateChange(func(_, next CircuitBreakerState) {
		if next == CircuitBreakerStateOpen {
			cb.OnTrigger(func(*Request, error) { calls.Add(1) })
		}
	})
	c := dcnl().SetCircuitBreaker(cb)
	defer c.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.R().Get(ts.URL)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("request blocked while its state-change hook registered a trigger hook")
	}
	_, err := c.R().Get(ts.URL)
	assertErrorIs(t, ErrCircuitBreakerOpen, err)
	assertEqual(t, int64(1), calls.Load())
}
