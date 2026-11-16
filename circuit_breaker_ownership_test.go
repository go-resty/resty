// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"resty.dev/v3"
)

func TestIgnoredStaleAttemptCannotReleaseCurrentProbe(t *testing.T) {
	for _, mode := range []string{"count", "ratio"} {
		for _, admittedIn := range []string{"closed", "previous half-open"} {
			t.Run(mode+"/"+admittedIn, func(t *testing.T) {
				staleEntered, reopenEntered, currentEntered := make(chan struct{}), make(chan struct{}), make(chan struct{})
				reopenRelease, currentRelease := make(chan struct{}), make(chan struct{})
				var nextRequests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/stale":
						close(staleEntered)
						<-r.Context().Done()
					case "/reopen":
						close(reopenEntered)
						select {
						case <-reopenRelease:
							w.WriteHeader(http.StatusServiceUnavailable)
						case <-r.Context().Done():
						}
					case "/trip":
						w.WriteHeader(http.StatusServiceUnavailable)
					case "/current":
						close(currentEntered)
						select {
						case <-currentRelease:
							_, _ = io.WriteString(w, "recovered")
						case <-r.Context().Done():
						}
					default:
						nextRequests.Add(1)
						_, _ = io.WriteString(w, "recovered")
					}
				}))
				defer server.Close()
				closeSignal := func(signal chan struct{}) {
					select {
					case <-signal:
					default:
						close(signal)
					}
				}
				defer closeSignal(reopenRelease)
				defer closeSignal(currentRelease)

				var breaker resty.CircuitBreaker
				var observer resty.CircuitBreakerObserver
				if mode == "count" {
					cb := resty.NewCircuitBreakerCount(1, 1, 20*time.Millisecond)
					breaker, observer = cb, cb
				} else {
					cb := resty.NewCircuitBreakerRatio(0.5, 1, 20*time.Millisecond)
					breaker, observer = cb, cb
				}
				halfOpen := make(chan struct{}, 2)
				observer.OnStateChange(func(_, next resty.CircuitBreakerState) {
					if next == resty.CircuitBreakerStateHalfOpen {
						halfOpen <- struct{}{}
					}
				})
				client := resty.New().SetTimeout(3 * time.Second).SetCircuitBreaker(breaker)
				defer client.Close()
				wait := func(signal <-chan struct{}) {
					t.Helper()
					select {
					case <-signal:
					case <-time.After(5 * time.Second):
						t.Fatal("HTTP request/state barrier timed out")
					}
				}
				waitResult := func(result <-chan error) error {
					t.Helper()
					select {
					case err := <-result:
						return err
					case <-time.After(5 * time.Second):
						t.Fatal("HTTP request did not finish")
						return nil
					}
				}
				start := func(ctx context.Context, path string) <-chan error {
					result := make(chan error, 1)
					go func() {
						_, err := client.R().SetContext(ctx).Get(server.URL + path)
						result <- err
					}()
					return result
				}

				// A response admitted while closed can reopen the breaker during its first probe.
				var reopenResult <-chan error
				if admittedIn == "previous half-open" {
					reopenResult = start(context.Background(), "/reopen")
					wait(reopenEntered)
				}
				staleContext, cancelStale := context.WithCancel(context.Background())
				defer cancelStale()
				var staleResult <-chan error
				if admittedIn == "closed" {
					staleResult = start(staleContext, "/stale")
					wait(staleEntered)
				}
				if _, err := client.R().Get(server.URL + "/trip"); err != nil {
					t.Fatal(err)
				}
				wait(halfOpen)
				if admittedIn == "previous half-open" {
					staleResult = start(staleContext, "/stale")
					wait(staleEntered)
					closeSignal(reopenRelease)
					if err := waitResult(reopenResult); err != nil {
						t.Fatal(err)
					}
					wait(halfOpen)
				}
				currentContext, cancelCurrent := context.WithCancel(context.Background())
				defer cancelCurrent()
				currentResult := start(currentContext, "/current")
				wait(currentEntered)
				cancelStale()
				if err := waitResult(staleResult); !errors.Is(err, context.Canceled) {
					t.Fatalf("stale request error = %v, want context.Canceled", err)
				}
				if _, err := client.R().Get(server.URL + "/next"); !errors.Is(err, resty.ErrCircuitBreakerOpen) {
					t.Fatalf("another probe was admitted while the current probe is still in flight: %v", err)
				}
				if got := nextRequests.Load(); got != 0 {
					t.Fatalf("rejected probe reached the server %d times", got)
				}
				closeSignal(currentRelease)
				if err := waitResult(currentResult); err != nil {
					t.Fatal(err)
				}
				response, err := client.R().Get(server.URL + "/next")
				if err != nil || response.String() != "recovered" {
					t.Fatalf("successful probe did not restore requests: response=%v error=%v", response, err)
				}
			})
		}
	}
}

type externalCircuitBreaker struct {
	err         error
	policyCalls int
}

func (cb *externalCircuitBreaker) Allow() error { return cb.err }
func (cb *externalCircuitBreaker) ApplyPolicies(*resty.Response) {
	cb.policyCalls++
}

func TestExternalCircuitBreakerAdmission(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(map[bool]string{false: "allowed", true: "rejected"}[rejected], func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			breaker := &externalCircuitBreaker{}
			if rejected {
				breaker.err = resty.ErrCircuitBreakerOpen
			}
			client := resty.New().SetCircuitBreaker(breaker)
			defer client.Close()
			response, err := client.R().Get(server.URL)
			if rejected {
				if !errors.Is(err, resty.ErrCircuitBreakerOpen) || requests.Load() != 0 || breaker.policyCalls != 0 {
					t.Fatalf("custom breaker rejection not preserved: err=%v requests=%d policies=%d", err, requests.Load(), breaker.policyCalls)
				}
			} else if err != nil || response.StatusCode() != http.StatusOK || requests.Load() != 1 || breaker.policyCalls != 1 {
				t.Fatalf("custom breaker admission not preserved: err=%v requests=%d policies=%d", err, requests.Load(), breaker.policyCalls)
			}
		})
	}
}

type embeddedCountCircuitBreaker struct {
	*resty.CircuitBreakerCount
	err        error
	allowCalls int
}

func (cb *embeddedCountCircuitBreaker) Allow() error {
	cb.allowCalls++
	return cb.err
}

type embeddedRatioCircuitBreaker struct {
	*resty.CircuitBreakerRatio
	err        error
	allowCalls int
}

func (cb *embeddedRatioCircuitBreaker) Allow() error {
	cb.allowCalls++
	return cb.err
}

func TestEmbeddedCircuitBreakerAdmission(t *testing.T) {
	for _, mode := range []string{"count", "ratio"} {
		for _, rejected := range []bool{false, true} {
			t.Run(mode+"/"+map[bool]string{false: "allowed", true: "rejected"}[rejected], func(t *testing.T) {
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()
				var admissionError error
				if rejected {
					admissionError = resty.ErrCircuitBreakerOpen
				}
				var breaker resty.CircuitBreaker
				var allowCalls *int
				if mode == "count" {
					cb := &embeddedCountCircuitBreaker{
						CircuitBreakerCount: resty.NewCircuitBreakerCount(1, 1, time.Second),
						err:                 admissionError,
					}
					breaker, allowCalls = cb, &cb.allowCalls
				} else {
					cb := &embeddedRatioCircuitBreaker{
						CircuitBreakerRatio: resty.NewCircuitBreakerRatio(0.5, 1, time.Second),
						err:                 admissionError,
					}
					breaker, allowCalls = cb, &cb.allowCalls
				}
				client := resty.New().SetCircuitBreaker(breaker)
				defer client.Close()
				response, err := client.R().Get(server.URL)
				if *allowCalls != 1 {
					t.Fatalf("embedded breaker Allow called %d times, want 1", *allowCalls)
				}
				if rejected {
					if !errors.Is(err, resty.ErrCircuitBreakerOpen) || requests.Load() != 0 {
						t.Fatalf("embedded breaker rejection not preserved: err=%v requests=%d", err, requests.Load())
					}
				} else if err != nil || response.StatusCode() != http.StatusOK || requests.Load() != 1 {
					t.Fatalf("embedded breaker admission not preserved: err=%v requests=%d", err, requests.Load())
				}
			})
		}
	}
}
