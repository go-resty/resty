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

func TestCircuitBreakerIgnoredHalfOpenProbe(t *testing.T) {
	for _, mode := range []string{"count", "ratio"} {
		for _, ignored := range []string{"cancellation", "custom EOF policy"} {
			t.Run(mode+"/"+ignored, func(t *testing.T) {
				entered := make(chan struct{}, 1)
				var okRequests atomic.Int32
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/trip":
						w.Header().Set("Connection", "close")
						w.WriteHeader(http.StatusServiceUnavailable)
					case "/cancel":
						entered <- struct{}{}
						<-r.Context().Done()
					case "/disconnect":
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = conn.Close()
					default:
						okRequests.Add(1)
						_, _ = io.WriteString(w, "recovered")
					}
				}))
				defer ts.Close()

				var breaker resty.CircuitBreaker
				var observer resty.CircuitBreakerObserver
				var errorPolicy resty.CircuitBreakerErrorPolicy
				if ignored == "custom EOF policy" {
					errorPolicy = func(err error) bool {
						return resty.CircuitBreakerTransportErrorPolicy(err) && !errors.Is(err, io.EOF)
					}
				}
				if mode == "count" {
					cb := resty.NewCircuitBreakerCount(1, 2, 50*time.Millisecond).SetErrorPolicy(errorPolicy)
					breaker, observer = cb, cb
				} else {
					cb := resty.NewCircuitBreakerRatio(0.5, 1, 50*time.Millisecond).SetErrorPolicy(errorPolicy)
					breaker, observer = cb, cb
				}
				var state atomic.Uint32
				halfOpen := make(chan struct{}, 1)
				observer.OnStateChange(func(_, next resty.CircuitBreakerState) {
					state.Store(uint32(next))
					if next == resty.CircuitBreakerStateHalfOpen {
						halfOpen <- struct{}{}
					}
				})
				client := resty.New().SetTimeout(3 * time.Second).SetCircuitBreaker(breaker)
				defer client.Close()
				if _, err := client.R().Get(ts.URL + "/trip"); err != nil {
					t.Fatal(err)
				}
				select {
				case <-halfOpen:
				case <-time.After(5 * time.Second):
					t.Fatal("breaker did not enter half-open state")
				}

				if ignored == "cancellation" {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					done := make(chan error, 1)
					go func() {
						_, err := client.R().SetContext(ctx).Get(ts.URL + "/cancel")
						done <- err
					}()
					select {
					case <-entered:
					case <-time.After(5 * time.Second):
						t.Fatal("probe did not reach the HTTP server")
					}
					if _, err := client.R().Get(ts.URL + "/ok"); !errors.Is(err, resty.ErrCircuitBreakerOpen) {
						t.Fatalf("concurrent probe error = %v, want ErrCircuitBreakerOpen", err)
					}
					if okRequests.Load() != 0 {
						t.Fatal("concurrent recovery request reached the server while a probe was in flight")
					}
					cancel()
					select {
					case err := <-done:
						if !errors.Is(err, context.Canceled) {
							t.Fatalf("probe error = %v, want context.Canceled", err)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("canceled HTTP probe did not return")
					}
				} else if _, err := client.R().Get(ts.URL + "/disconnect"); !errors.Is(err, io.EOF) {
					t.Fatalf("probe error = %v, want EOF", err)
				}
				if got := resty.CircuitBreakerState(state.Load()); got != resty.CircuitBreakerStateHalfOpen {
					t.Fatalf("state after ignored error = %v, want half-open", got)
				}
				response, err := client.R().Get(ts.URL + "/ok")
				if err != nil {
					t.Fatalf("next recovery probe was rejected: %v", err)
				}
				if response.String() != "recovered" {
					t.Fatalf("recovery response = %q", response.String())
				}
				if mode == "count" {
					if resty.CircuitBreakerState(state.Load()) != resty.CircuitBreakerStateHalfOpen {
						t.Fatal("ignored probe must not count toward the success threshold")
					}
					if _, err := client.R().Get(ts.URL + "/ok"); err != nil {
						t.Fatal(err)
					}
				}
				if resty.CircuitBreakerState(state.Load()) != resty.CircuitBreakerStateClosed {
					t.Fatal("successful recovery probes did not close the breaker")
				}
			})
		}
	}
}
