// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func createHedgingTestServer(t *testing.T, attemptCount *int32, r1, r2 int32) *httptest.Server {
	return createTestServer(func(w http.ResponseWriter, r *http.Request) {
		attempt := atomic.AddInt32(attemptCount, 1)
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)

		delay1 := r1
		if delay1 == 0 {
			delay1 = 200
		}

		delay2 := r2
		if delay2 == 0 {
			delay2 = 50
		}

		switch r.URL.Path {
		case "/", "/hedging-slow-first":
			w.Header().Set("X-Attempt", fmt.Sprintf("%d", attempt))
			if attempt == 1 {
				time.Sleep(time.Duration(rand.Int31n(delay1)) * time.Millisecond)
			} else {
				time.Sleep(time.Duration(rand.Int31n(delay2)) * time.Millisecond)
			}
			_, _ = fmt.Fprintf(w, "Attempt %d", attempt)
		case "/hedging-slow-all":
			w.Header().Set("X-Attempt", fmt.Sprintf("%d", attempt))
			time.Sleep(time.Duration(rand.Int31n(delay1)) * time.Millisecond)
			_, _ = fmt.Fprintf(w, "Attempt %d", attempt)
		}
	})
}

func TestHedgingBasic(t *testing.T) {
	var attemptCount int32
	ts := createHedgingTestServer(t, &attemptCount, 0, 0)
	defer ts.Close()

	c := dcnl()
	c.EnableHedging(20*time.Millisecond, 3, 0)

	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	count := atomic.LoadInt32(&attemptCount)
	if count < 2 {
		t.Errorf("Expected at least 2 requests, got %d", count)
	}
}

func TestHedgingFirstWins(t *testing.T) {
	var attemptCount int32
	firstAttempt := atomic.Int32{}

	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		attempt := atomic.AddInt32(&attemptCount, 1)
		if attempt == 1 {
			time.Sleep(200 * time.Millisecond)
		} else {
			time.Sleep(50 * time.Millisecond)
		}
		firstAttempt.CompareAndSwap(0, attempt)

		w.Header().Set("X-Attempt", fmt.Sprintf("%d", attempt))
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Attempt %d", attempt)
	})
	defer ts.Close()

	c := dcnl()
	c.EnableHedging(30*time.Millisecond, 2, 0)

	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)

	winner := firstAttempt.Load()
	if winner != 2 {
		t.Errorf("Expected second request to win, got attempt %d", winner)
	}

	totalAttempts := atomic.LoadInt32(&attemptCount)
	if totalAttempts < 2 {
		t.Errorf("Expected at least 2 hedged requests, got %d", totalAttempts)
	}
}

func TestHedgingTimeout(t *testing.T) {
	var attemptCount int32
	requestTimes := make([]time.Time, 0, 3)
	var timesLock atomic.Value
	timesLock.Store(requestTimes)

	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		attempt := atomic.AddInt32(&attemptCount, 1)
		now := time.Now()

		times := timesLock.Load().([]time.Time)
		times = append(times, now)
		timesLock.Store(times)

		if attempt == 1 {
			time.Sleep(300 * time.Millisecond)
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Attempt %d", attempt)
	})
	defer ts.Close()

	c := dcnl()
	delay := 50 * time.Millisecond
	c.EnableHedging(delay, 3, 0)

	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(200 * time.Millisecond)

	times := timesLock.Load().([]time.Time)
	if len(times) >= 2 {
		diff := times[1].Sub(times[0])
		if diff < delay || diff > delay+30*time.Millisecond {
			t.Logf("Expected delay between requests to be ~%v, got %v", delay, diff)
		}
	}
}

func TestHedgingReadOnlyMethodsOnly(t *testing.T) {
	var attemptCount int32

	ts := createHedgingTestServer(t, &attemptCount, 0, 0)
	defer ts.Close()

	c := dcnl()
	c.EnableHedging(20*time.Millisecond, 3, 0)

	testCases := []struct {
		method        string
		expectHedging bool
		requestFunc   func(*Client, string) (*Response, error)
	}{
		{MethodGet, true, func(c *Client, url string) (*Response, error) { return c.R().Get(url) }},
		{MethodHead, true, func(c *Client, url string) (*Response, error) { return c.R().Head(url) }},
		{MethodOptions, true, func(c *Client, url string) (*Response, error) { return c.R().Options(url) }},
		{MethodPost, false, func(c *Client, url string) (*Response, error) { return c.R().Post(url) }},
		{MethodPut, false, func(c *Client, url string) (*Response, error) { return c.R().Put(url) }},
		{MethodPatch, false, func(c *Client, url string) (*Response, error) { return c.R().Patch(url) }},
		{MethodDelete, false, func(c *Client, url string) (*Response, error) { return c.R().Delete(url) }},
	}

	for _, tc := range testCases {
		t.Run(tc.method, func(t *testing.T) {
			atomic.StoreInt32(&attemptCount, 0)

			resp, err := tc.requestFunc(c, ts.URL+"/")
			assertError(t, err)
			assertEqual(t, http.StatusOK, resp.StatusCode())

			time.Sleep(100 * time.Millisecond)

			count := atomic.LoadInt32(&attemptCount)
			if tc.expectHedging {
				if count < 2 {
					t.Logf("%s: Expected hedging (multiple requests), got %d request(s)", tc.method, count)
				}
			} else {
				if count != 1 {
					t.Errorf("%s: Expected no hedging (1 request), got %d request(s)", tc.method, count)
				}
			}
		})
	}
}

func TestHedgingRateLimit(t *testing.T) {
	var attemptCount int32

	ts := createHedgingTestServer(t, &attemptCount, 500, 0)
	defer ts.Close()

	c := dcnl()
	c.EnableHedging(10*time.Millisecond, 10, 5.0)

	start := time.Now()
	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	duration := time.Since(start)

	if duration < 200*time.Millisecond {
		t.Logf("Rate limiting may have limited hedged requests. Duration: %v, Attempts: %d", duration, atomic.LoadInt32(&attemptCount))
	}
}

func TestHedgingWithRetryFallback(t *testing.T) {
	c := dcnl()

	// Set retry first
	c.SetRetryCount(2)
	assertEqual(t, 2, c.RetryCount())

	// Enable hedging should disable retry by default
	c.EnableHedging(50*time.Millisecond, 3, 0)
	assertEqual(t, 0, c.RetryCount())

	// But user can re-enable retry as fallback
	c.SetRetryCount(1)
	assertEqual(t, 1, c.RetryCount())
	assertEqual(t, true, c.IsHedgingEnabled())

	// Disable hedging
	c.DisableHedging()
	assertEqual(t, false, c.IsHedgingEnabled())
	assertEqual(t, 1, c.RetryCount()) // Retry count should remain
}

func TestHedgingDisable(t *testing.T) {
	var attemptCount int32

	ts := createHedgingTestServer(t, &attemptCount, 0, 0)
	defer ts.Close()

	c := dcnl()
	c.EnableHedging(20*time.Millisecond, 3, 0)
	assertEqual(t, true, c.IsHedgingEnabled())

	c.DisableHedging()
	assertEqual(t, false, c.IsHedgingEnabled())

	atomic.StoreInt32(&attemptCount, 0)
	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)

	assertEqual(t, int32(1), atomic.LoadInt32(&attemptCount))
}

func TestHedgingContextCancellation(t *testing.T) {
	attemptCount := atomic.Int32{}
	startedCount := atomic.Int32{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedCount.Add(1)
		time.Sleep(200 * time.Millisecond)
		attemptCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := dcnl()
	c.EnableHedging(20*time.Millisecond, 3, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.R().SetContext(ctx).Get(ts.URL + "/")
	if err == nil {
		t.Error("Expected context cancellation error")
	}

	time.Sleep(100 * time.Millisecond)

	started := startedCount.Load()
	completed := attemptCount.Load()

	if started < 2 {
		t.Logf("Expected multiple hedged requests to start, got %d", started)
	}

	if completed > 0 {
		t.Logf("Context cancellation should have prevented completion, but %d completed", completed)
	}
}

func TestHedgingConfiguration(t *testing.T) {
	c := dcnl()

	// Setters require hedging to be enabled first
	assertEqual(t, false, c.IsHedgingEnabled())

	c.EnableHedging(50*time.Millisecond, 3, 10.0)

	assertEqual(t, true, c.IsHedgingEnabled())
	assertEqual(t, 50*time.Millisecond, c.HedgingDelay())
	assertEqual(t, 3, c.HedgingUpTo())
	assertEqual(t, 10.0, c.HedgingMaxPerSecond())

	// Now we can update individual settings
	c.SetHedgingDelay(100 * time.Millisecond)
	assertEqual(t, 100*time.Millisecond, c.HedgingDelay())

	c.SetHedgingUpTo(5)
	assertEqual(t, 5, c.HedgingUpTo())

	c.SetHedgingMaxPerSecond(20.0)
	assertEqual(t, 20.0, c.HedgingMaxPerSecond())
}

func TestHedgingWithCustomTransport(t *testing.T) {
	var attemptCount int32

	ts := createHedgingTestServer(t, &attemptCount, 0, 0)
	defer ts.Close()

	customTransport := &http.Transport{}
	c := NewWithClient(&http.Client{Transport: customTransport})

	c.EnableHedging(20*time.Millisecond, 3, 0)

	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)

	count := atomic.LoadInt32(&attemptCount)
	if count < 2 {
		t.Errorf("Expected hedging with custom transport, got %d request(s)", count)
	}

	c.DisableHedging()

	ht, ok := c.httpClient.Transport.(*hedgingTransport)
	if ok {
		t.Error("Transport should be unwrapped after DisableHedging")
	}
	_ = ht
}

func TestHedgingSingleRequest(t *testing.T) {
	var attemptCount int32

	ts := createHedgingTestServer(t, &attemptCount, 0, 0)
	defer ts.Close()

	c := dcnl()
	c.EnableHedging(20*time.Millisecond, 1, 0)

	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)

	assertEqual(t, int32(1), atomic.LoadInt32(&attemptCount))
}

func TestHedgingSettersWhenDisabled(t *testing.T) {
	c := dcnl()

	// Verify hedging is not enabled
	assertEqual(t, false, c.IsHedgingEnabled())

	// Test setters when hedging is disabled - they should log errors but not panic
	c.SetHedgingDelay(100 * time.Millisecond)
	c.SetHedgingUpTo(5)
	c.SetHedgingMaxPerSecond(20.0)
	c.SetHedgingAllowNonReadOnly(true)

	// Verify hedging is still not enabled
	assertEqual(t, false, c.IsHedgingEnabled())
}

func TestHedgingGettersWhenDisabled(t *testing.T) {
	c := dcnl()

	// Verify hedging is not enabled
	assertEqual(t, false, c.IsHedgingEnabled())

	// Test getters when hedging is disabled - they should return defaults
	assertEqual(t, time.Duration(0), c.HedgingDelay())
	assertEqual(t, 0, c.HedgingUpTo())
	assertEqual(t, 0.0, c.HedgingMaxPerSecond())
	assertEqual(t, false, c.IsHedgingAllowNonReadOnly())
}

func TestHedgingAllowNonReadOnly(t *testing.T) {
	var attemptCount int32

	ts := createHedgingTestServer(t, &attemptCount, 0, 0)
	defer ts.Close()

	c := dcnl()
	c.EnableHedging(20*time.Millisecond, 3, 0)

	// By default, non-read-only methods should not be hedged
	assertEqual(t, false, c.IsHedgingAllowNonReadOnly())

	// Test POST without allowing non-read-only
	atomic.StoreInt32(&attemptCount, 0)
	resp, err := c.R().Post(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)
	count := atomic.LoadInt32(&attemptCount)
	if count != 1 {
		t.Errorf("Expected no hedging for POST without allow flag, got %d request(s)", count)
	}

	// Enable non-read-only methods
	c.SetHedgingAllowNonReadOnly(true)
	assertEqual(t, true, c.IsHedgingAllowNonReadOnly())

	// Test POST with allowing non-read-only
	atomic.StoreInt32(&attemptCount, 0)
	resp, err = c.R().Post(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)
	count = atomic.LoadInt32(&attemptCount)
	if count < 2 {
		t.Errorf("Expected hedging for POST with allow flag, got %d request(s)", count)
	}
}

func TestHedgingWithNilTransport(t *testing.T) {
	var attemptCount int32

	ts := createHedgingTestServer(t, &attemptCount, 0, 0)
	defer ts.Close()

	// Create client with nil transport
	c := NewWithClient(&http.Client{Transport: nil})

	c.EnableHedging(20*time.Millisecond, 3, 0)

	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)

	count := atomic.LoadInt32(&attemptCount)
	if count < 2 {
		t.Errorf("Expected hedging with nil transport, got %d request(s)", count)
	}
}

func TestHedgingEnableMultipleTimes(t *testing.T) {
	var attemptCount int32

	ts := createHedgingTestServer(t, &attemptCount, 0, 0)
	defer ts.Close()

	c := dcnl()

	// Enable hedging first time
	c.EnableHedging(20*time.Millisecond, 3, 0)
	assertEqual(t, true, c.IsHedgingEnabled())

	// Enable hedging again without disabling - should handle already wrapped transport
	c.EnableHedging(30*time.Millisecond, 5, 10.0)
	assertEqual(t, true, c.IsHedgingEnabled())
	assertEqual(t, 30*time.Millisecond, c.HedgingDelay())
	assertEqual(t, 5, c.HedgingUpTo())
	assertEqual(t, 10.0, c.HedgingMaxPerSecond())

	// Verify hedging still works
	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)

	count := atomic.LoadInt32(&attemptCount)
	if count < 2 {
		t.Errorf("Expected hedging after re-enabling, got %d request(s)", count)
	}
}

func TestHedgingWrapWithDisabledHedging(t *testing.T) {
	c := dcnl()

	// Enable and then disable hedging
	c.EnableHedging(20*time.Millisecond, 3, 0)
	c.DisableHedging()

	assertEqual(t, false, c.IsHedgingEnabled())

	// Verify transport is not a hedgingTransport
	_, ok := c.httpClient.Transport.(*hedgingTransport)
	if ok {
		t.Error("Transport should not be hedgingTransport after DisableHedging")
	}

	// Now try SetHedgingAllowNonReadOnly when hedging is disabled
	// This should trigger the error path and NOT call wrapTransportWithHedging
	c.SetHedgingAllowNonReadOnly(true)
	assertEqual(t, false, c.IsHedgingEnabled())
}

func TestHedgingWrapAlreadyWrapped(t *testing.T) {
	var attemptCount int32

	ts := createHedgingTestServer(t, &attemptCount, 0, 0)
	defer ts.Close()

	c := dcnl()

	// Enable hedging first time - wraps transport
	c.EnableHedging(20*time.Millisecond, 3, 0)

	// Get the current transport (should be hedgingTransport)
	_, ok := c.httpClient.Transport.(*hedgingTransport)
	if !ok {
		t.Error("Transport should be hedgingTransport after EnableHedging")
	}

	// Manually re-enable hedging without disabling first
	// This should detect transport is already hedgingTransport and return early (line 1604)
	c.EnableHedging(30*time.Millisecond, 5, 10.0)

	// Verify it still works
	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)

	count := atomic.LoadInt32(&attemptCount)
	if count < 2 {
		t.Errorf("Expected hedging to still work, got %d request(s)", count)
	}
}

func TestHedgingRateDelayBetweenRequests(t *testing.T) {
	requestTimes := make([]time.Time, 0, 3)
	var mu sync.Mutex

	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestTimes = append(requestTimes, time.Now())
		mu.Unlock()

		// Slow response to ensure multiple hedged requests are sent
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	c := dcnl()
	// delay=10ms, upTo=3, maxPerSecond=5.0 (rateDelay = 200ms)
	// Expected timing: req1 at 0, req2 at ~10ms + 200ms = ~210ms, req3 at ~420ms
	c.EnableHedging(10*time.Millisecond, 3, 5.0)

	_, err := c.R().Get(ts.URL + "/")
	assertError(t, err)

	// Wait for all requests to be recorded
	time.Sleep(600 * time.Millisecond)

	mu.Lock()
	times := make([]time.Time, len(requestTimes))
	copy(times, requestTimes)
	mu.Unlock()

	if len(times) < 2 {
		t.Fatalf("Expected at least 2 hedged requests, got %d", len(times))
	}

	// Verify rate delay was applied between requests
	// With maxPerSecond=5.0, rateDelay should be 200ms
	// The gap between requests should be at least rateDelay (200ms)
	expectedRateDelay := 200 * time.Millisecond
	tolerance := 50 * time.Millisecond

	for i := 1; i < len(times); i++ {
		gap := times[i].Sub(times[i-1])
		// Gap should be >= (delay + rateDelay) - tolerance
		minExpectedGap := expectedRateDelay - tolerance
		if gap < minExpectedGap {
			t.Errorf("Gap between request %d and %d was %v, expected at least %v (rate delay should be ~%v)",
				i-1, i, gap, minExpectedGap, expectedRateDelay)
		}
	}
}
