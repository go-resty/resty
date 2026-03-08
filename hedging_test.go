// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func createHedgingTestServer(t *testing.T, attemptCount *int32) *httptest.Server {
	timeouts := [5]time.Duration{800 * time.Millisecond, 400 * time.Millisecond, 10 * time.Millisecond, 5 * time.Millisecond, 1 * time.Millisecond}
	return createTestServer(func(w http.ResponseWriter, r *http.Request) {
		attempt := atomic.AddInt32(attemptCount, 1)
		time.Sleep(timeouts[attempt-1])
		w.Header().Set("X-Attempt", fmt.Sprintf("%d", attempt))
		_, _ = fmt.Fprintf(w, "Attempt %d", attempt)
	})
}

func TestHedgingBasic(t *testing.T) {
	var attemptCount int32
	ts := createHedgingTestServer(t, &attemptCount)
	defer ts.Close()

	const maxRequests = 3
	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(0)

	c := dcnl().SetHedging(h)

	resp, err := c.R().Get(ts.URL)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int32(maxRequests), atomic.LoadInt32(&attemptCount), "total attempts should match max requests")
}

func TestHedgingSecondWins(t *testing.T) {
	var attemptCount int32
	winnerAttempt := atomic.Int32{}
	timeouts := [2]time.Duration{400 * time.Millisecond, 20 * time.Millisecond}
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		attempt := atomic.AddInt32(&attemptCount, 1)
		time.Sleep(timeouts[attempt-1])
		winnerAttempt.CompareAndSwap(0, attempt)

		w.Header().Set("X-Attempt", fmt.Sprintf("%d", attempt))
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Attempt %d", attempt)
	})
	defer ts.Close()

	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(2).
		SetMaxRequestPerSecond(0)

	c := dcnl().SetHedging(h)

	resp, err := c.R().Get(ts.URL)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	winnerRequest := winnerAttempt.Load()
	assertEqual(t, fmt.Sprintf("Attempt %d", winnerRequest), resp.String(), "expected second attempt to win")
	assertEqual(t, int32(2), winnerRequest, "expected second request to win")
	assertEqual(t, int32(2), atomic.LoadInt32(&attemptCount), "total attempts should be 2")
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

	delay := 50 * time.Millisecond
	h := NewHedging().
		SetDelay(delay).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(0)

	c := dcnl().SetHedging(h)

	resp, err := c.R().Get(ts.URL)
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
	ts := createHedgingTestServer(t, &attemptCount)
	defer ts.Close()

	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(0)

	c := dcnl().SetHedging(h)

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

			resp, err := tc.requestFunc(c, ts.URL)
			assertError(t, err)
			assertEqual(t, http.StatusOK, resp.StatusCode())

			time.Sleep(20 * time.Millisecond)

			count := atomic.LoadInt32(&attemptCount)
			if tc.expectHedging {
				assertNotEqual(t, 1, count, fmt.Sprintf("%s: expected hedging with multiple requests, got %d request(s)", tc.method, count))
			} else {
				assertEqual(t, int32(1), count, fmt.Sprintf("%s: no hedging 1 request only", tc.method))
			}
		})
	}
}

func TestHedgingRateLimit(t *testing.T) {
	var attemptCount int32
	ts := createHedgingTestServer(t, &attemptCount)
	defer ts.Close()

	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(10).
		SetMaxRequestPerSecond(5.0)

	c := dcnl().SetHedging(h)

	start := time.Now()
	resp, err := c.R().Get(ts.URL)
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

	h := NewHedging().
		SetDelay(50 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(0)

	// Enable hedging should disable retry by default
	c.SetHedging(h)
	assertEqual(t, 0, c.RetryCount())

	// But user can re-enable retry as fallback
	c.SetRetryCount(1)
	assertEqual(t, 1, c.RetryCount())
	assertEqual(t, true, c.isHedgingEnabled())

	// Disable hedging
	c.SetHedging(nil)
	assertEqual(t, false, c.isHedgingEnabled())
	assertEqual(t, 1, c.RetryCount()) // Retry count should remain
}

func TestHedgingDisable(t *testing.T) {
	var attemptCount int32
	ts := createHedgingTestServer(t, &attemptCount)
	defer ts.Close()

	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(0)

	c := dcnl()
	c.SetHedging(h)
	assertEqual(t, true, c.isHedgingEnabled())

	c.SetHedging(nil)
	assertEqual(t, false, c.isHedgingEnabled())

	atomic.StoreInt32(&attemptCount, 0)
	resp, err := c.R().Get(ts.URL)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(50 * time.Millisecond)

	assertEqual(t, int32(1), atomic.LoadInt32(&attemptCount))
}

func TestHedgingContextCancellation(t *testing.T) {
	attemptCount := atomic.Int32{}
	startedCount := atomic.Int32{}

	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		startedCount.Add(1)
		time.Sleep(200 * time.Millisecond)
		attemptCount.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(0)

	c := dcnl().SetHedging(h)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := c.R().SetContext(ctx).Get(ts.URL)
	assertErrorIs(t, context.DeadlineExceeded, err)

	time.Sleep(50 * time.Millisecond)

	started := startedCount.Load()
	completed := attemptCount.Load()
	assertTrue(t, started > 1, "expected multiple hedged request to start")
	assertEqual(t, int32(0), completed, "context cancellation should have prevented completion")
}

func TestHedgingConfiguration(t *testing.T) {
	h := NewHedging().
		SetDelay(50 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(10.0)
	assertEqual(t, 50*time.Millisecond, h.Delay())
	assertEqual(t, 3, h.MaxRequest())
	assertEqual(t, 10.0, h.MaxRequestPerSecond())

	// Now we can update individual settings
	h.SetDelay(100 * time.Millisecond)
	assertEqual(t, 100*time.Millisecond, h.Delay())

	h.SetMaxRequest(5)
	assertEqual(t, 5, h.MaxRequest())

	h.SetMaxRequestPerSecond(20.0)
	assertEqual(t, 20.0, h.MaxRequestPerSecond())
}

func TestHedgingConfigurationViaClient(t *testing.T) {
	c := dcnl()

	// Setters require hedging to be enabled first
	assertEqual(t, false, c.isHedgingEnabled())

	h := NewHedging().
		SetDelay(50 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(10.0)
	c.SetHedging(h)

	assertEqual(t, true, c.isHedgingEnabled())
	assertEqual(t, 50*time.Millisecond, c.Hedging().Delay())
	assertEqual(t, 3, c.Hedging().MaxRequest())
	assertEqual(t, 10.0, c.Hedging().MaxRequestPerSecond())

	// Now we can update individual settings
	c.Hedging().SetDelay(100 * time.Millisecond)
	assertEqual(t, 100*time.Millisecond, c.Hedging().Delay())

	c.Hedging().SetMaxRequest(5)
	assertEqual(t, 5, c.Hedging().MaxRequest())

	c.Hedging().SetMaxRequestPerSecond(20.0)
	assertEqual(t, 20.0, c.Hedging().MaxRequestPerSecond())
}

func TestHedgingWithCustomTransport(t *testing.T) {
	var attemptCount int32
	ts := createHedgingTestServer(t, &attemptCount)
	defer ts.Close()

	customTransport := &http.Transport{}
	c := NewWithClient(&http.Client{Transport: customTransport})

	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(0)
	c.SetHedging(h)

	resp, err := c.R().Get(ts.URL)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int32(3), atomic.LoadInt32(&attemptCount), "Expected 3 attempts with hedging enabled")

	// disable hedging and verify transport is unwrapped
	c.SetHedging(nil)
	_, ok := c.httpClient.Transport.(*Hedging)
	assertFalse(t, ok, "transport should be unwrapped after disabling hedging")
}

func TestHedgingSingleRequest(t *testing.T) {
	var attemptCount int32
	ts := createHedgingTestServer(t, &attemptCount)
	defer ts.Close()

	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(1).
		SetMaxRequestPerSecond(0)

	c := dcnl().SetHedging(h)

	resp, err := c.R().Get(ts.URL)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int32(1), atomic.LoadInt32(&attemptCount))
}

func TestHedgingAllowNonReadOnly(t *testing.T) {
	var attemptCount int32
	ts := createHedgingTestServer(t, &attemptCount)
	defer ts.Close()

	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(0)

	c := dcnl().SetHedging(h)

	// By default, non-read-only methods should not be hedged
	assertEqual(t, false, c.Hedging().IsNonReadOnlyAllowed())

	// Test POST without allowing non-read-only
	atomic.StoreInt32(&attemptCount, 0)
	resp, err := c.R().Post(ts.URL)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int32(1), atomic.LoadInt32(&attemptCount), "no hedging for POST without allow flag")

	// Enable non-read-only methods
	c.Hedging().SetNonReadOnlyAllowed(true)
	assertEqual(t, true, c.Hedging().IsNonReadOnlyAllowed())

	// Test POST with allowing non-read-only
	atomic.StoreInt32(&attemptCount, 0)
	resp, err = c.R().Post(ts.URL)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int32(3), atomic.LoadInt32(&attemptCount), "hedging for POST with allow flag")
}

func TestHedgingWithNilTransport(t *testing.T) {
	var attemptCount int32
	ts := createHedgingTestServer(t, &attemptCount)
	defer ts.Close()

	// Create client with nil transport
	c := NewWithClient(&http.Client{Transport: nil})

	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(0)
	c.SetHedging(h)

	resp, err := c.R().Get(ts.URL)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int32(3), atomic.LoadInt32(&attemptCount), "hedging with nil transport should still work")
}

func TestHedgingEnableMultipleTimes(t *testing.T) {
	var attemptCount int32
	ts := createHedgingTestServer(t, &attemptCount)
	defer ts.Close()

	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(0)

	c := dcnl()

	// Enable hedging first time
	c.SetHedging(h)
	assertEqual(t, true, c.isHedgingEnabled())

	// Enable hedging again without disabling - should handle already wrapped transport
	nh := NewHedging().
		SetDelay(30 * time.Millisecond).
		SetMaxRequest(5).
		SetMaxRequestPerSecond(10.0)
	c.SetHedging(nh)
	assertEqual(t, true, c.isHedgingEnabled())
	assertEqual(t, 30*time.Millisecond, c.Hedging().Delay())
	assertEqual(t, 5, c.Hedging().MaxRequest())
	assertEqual(t, 10.0, c.Hedging().MaxRequestPerSecond())

	// Verify hedging still works
	resp, err := c.R().Get(ts.URL)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int32(3), atomic.LoadInt32(&attemptCount), "expected hedging after re-enabling")
}

func TestHedgingWrapWithDisabledHedging(t *testing.T) {
	c := dcnl()

	h := NewHedging().
		SetDelay(20 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(0)
	// Enable and then disable hedging
	c.SetHedging(h)
	assertEqual(t, true, c.isHedgingEnabled())

	c.SetHedging(nil)
	assertEqual(t, false, c.isHedgingEnabled())

	// Verify transport is not a hedgingTransport
	_, ok := c.httpClient.Transport.(*Hedging)
	assertFalse(t, ok, "transport should not be hedging transport")
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
	// delay=10ms, maxRequest=3, maxRequestPerSecond=5.0 (rateDelay = 200ms)
	// Expected timing: req1 at 0, req2 at ~10ms + 200ms = ~210ms, req3 at ~420ms
	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(5.0)
	c.SetHedging(h)

	_, err := c.R().Get(ts.URL)
	assertError(t, err)

	// Wait for all requests to be recorded
	time.Sleep(600 * time.Millisecond)

	mu.Lock()
	times := make([]time.Time, len(requestTimes))
	copy(times, requestTimes)
	mu.Unlock()

	assertEqual(t, 3, len(times), "expected 3 hedged requests to be sent")

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

func TestHedgingNoDoubleWrap(t *testing.T) {
	h1 := NewHedging().SetDelay(50 * time.Millisecond)
	h2 := NewHedging().SetDelay(100 * time.Millisecond)

	c := dcnl()

	// Enable hedging first time
	c.SetHedging(h1)
	_, ok := c.httpClient.Transport.(*Hedging)
	assertTrue(t, ok, "Hedging transport")

	// Enable different hedging without disabling first
	c.SetHedging(h2)

	// Both should be Hedging
	hedging2, ok := c.httpClient.Transport.(*Hedging)
	assertTrue(t, ok, "Hedging transport")

	// The wrapped transport should NOT be another Hedging
	_, isHedging := hedging2.transport.(*Hedging)
	assertFalse(t, isHedging, "Double-wrapped hedging detected - transport should be unwrapped")

	// Verify transport chain depth, should only have one Hedging layer
	if hedging, ok := c.httpClient.Transport.(*Hedging); ok {
		_, isHedging := hedging.transport.(*Hedging)
		assertFalse(t, isHedging, "Double-wrapped hedging detected")
	}

	// Verify the configuration is the new one
	assertEqual(t, hedging2.Delay(), 100*time.Millisecond, "Expected 100ms delay")
}

func TestHedgingRoundTripDeadlineExpired(t *testing.T) {
	var attemptCount int32
	ts := createHedgingTestServer(t, &attemptCount)
	defer ts.Close()

	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(0)

	c := dcnl().SetHedging(h)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Millisecond))
	defer cancel()

	_, err := c.R().SetContext(ctx).Get(ts.URL)
	assertErrorIs(t, context.DeadlineExceeded, err, "Expected context deadline expired error")

	time.Sleep(50 * time.Millisecond)
	assertEqual(t, int32(0), atomic.LoadInt32(&attemptCount))
}
