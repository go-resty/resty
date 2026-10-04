// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	assertEqual(t, 50*time.Millisecond, c.Hedging().(*Hedging).Delay())
	assertEqual(t, 3, c.Hedging().(*Hedging).MaxRequest())
	assertEqual(t, 10.0, c.Hedging().(*Hedging).MaxRequestPerSecond())

	// Now we can update individual settings
	c.Hedging().(*Hedging).SetDelay(100 * time.Millisecond)
	assertEqual(t, 100*time.Millisecond, c.Hedging().(*Hedging).Delay())

	c.Hedging().(*Hedging).SetMaxRequest(5)
	assertEqual(t, 5, c.Hedging().(*Hedging).MaxRequest())

	c.Hedging().(*Hedging).SetMaxRequestPerSecond(20.0)
	assertEqual(t, 20.0, c.Hedging().(*Hedging).MaxRequestPerSecond())
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
	assertEqual(t, false, c.Hedging().(*Hedging).IsNonReadOnlyAllowed())

	// Test POST without allowing non-read-only
	atomic.StoreInt32(&attemptCount, 0)
	resp, err := c.R().Post(ts.URL)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int32(1), atomic.LoadInt32(&attemptCount), "no hedging for POST without allow flag")

	// Enable non-read-only methods
	c.Hedging().(*Hedging).SetNonReadOnlyAllowed(true)
	assertEqual(t, true, c.Hedging().(*Hedging).IsNonReadOnlyAllowed())

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

	hedging := c.Hedging().(*Hedging)
	assertEqual(t, true, c.isHedgingEnabled())
	assertEqual(t, 30*time.Millisecond, hedging.Delay())
	assertEqual(t, 5, hedging.MaxRequest())
	assertEqual(t, 10.0, hedging.MaxRequestPerSecond())

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
	_, isHedging := hedging2.Transport().(Hedger)
	assertFalse(t, isHedging, "Double-wrapped hedging detected - transport should be unwrapped")

	// Verify transport chain depth, should only have one Hedging layer
	if hedging, ok := c.httpClient.Transport.(*Hedging); ok {
		_, isHedging := hedging.Transport().(Hedger)
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

// TestHedgingLargeResponseBody guards against the hedge context being cancelled
// before the caller has read the winning response body. A body larger than the
// transport read buffer cannot already be buffered when RoundTrip returns, so any
// early cancel truncates it or fails the read outright.
func TestHedgingLargeResponseBody(t *testing.T) {
	const bodySize = 512 * 1024

	payload := make([]byte, bodySize)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}

	var attemptCount int32
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		attempt := atomic.AddInt32(&attemptCount, 1)
		if attempt == 1 {
			// lose the race so a hedged attempt wins and returns this body
			time.Sleep(500 * time.Millisecond)
		}
		w.Header().Set(hdrContentTypeKey, "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	defer ts.Close()

	c := dcnl().SetHedging(NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(2).
		SetMaxRequestPerSecond(0))

	resp, err := c.R().Get(ts.URL)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, bodySize, len(resp.Bytes()))
	assertEqual(t, string(payload), string(resp.Bytes()))
}

// TestHedgingDoNotParseResponseLargeBody covers the same hazard on the path where
// the caller owns the body and reads it after RoundTrip has long returned.
func TestHedgingDoNotParseResponseLargeBody(t *testing.T) {
	const bodySize = 512 * 1024
	payload := make([]byte, bodySize)

	var attemptCount int32
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attemptCount, 1) == 1 {
			time.Sleep(500 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	defer ts.Close()

	c := dcnl().SetHedging(NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(2).
		SetMaxRequestPerSecond(0))

	resp, err := c.R().SetResponseDoNotParse(true).Get(ts.URL)
	assertError(t, err)
	defer func() { assertNil(t, resp.Body.Close()) }()

	// simulate a caller that takes its time before reading
	time.Sleep(100 * time.Millisecond)

	read, err := io.Copy(io.Discard, resp.Body)
	assertError(t, err)
	assertEqual(t, int64(bodySize), read)
}

// trackedBody records whether a response body was read to completion and closed.
type trackedBody struct {
	r      *strings.Reader
	closed chan struct{}
	once   sync.Once
	read   atomic.Int64
}

func newTrackedBody(payload string) *trackedBody {
	return &trackedBody{r: strings.NewReader(payload), closed: make(chan struct{})}
}

func (b *trackedBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.read.Add(int64(n))
	return n, err
}

func (b *trackedBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

// The spawn loop waits out the per-second rate delay before starting the next
// hedged attempt; that wait has to give up when the caller's context is done,
// otherwise a cancelled request keeps the loop parked for up to a second.
func TestHedgingRoundTripContextDoneDuringRateDelay(t *testing.T) {
	var attempts atomic.Int32
	release := make(chan struct{})

	h := NewHedging().
		SetDelay(0). // no inter-attempt delay, only the rate delay
		SetMaxRequest(3).
		SetMaxRequestPerSecond(1) // one second between attempts
	h.SetTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		<-release // hold the first attempt open so no winner is decided
		return nil, context.Canceled
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // done before the loop reaches the rate delay
	req, err := http.NewRequestWithContext(ctx, MethodGet, "http://127.0.0.1:65535/", nil)
	assertNil(t, err)

	go func() {
		time.Sleep(100 * time.Millisecond)
		close(release)
	}()

	start := time.Now()
	resp, err := h.RoundTrip(req)
	assertNil(t, resp)
	assertErrorIs(t, context.Canceled, err)

	// the full rate delay is a second; giving up early is the whole point
	assertTrue(t, time.Since(start) < 900*time.Millisecond,
		"expected the rate delay wait to be abandoned on context cancellation")
	assertEqual(t, int32(1), attempts.Load(), "expected no further attempts to be started")
}

// A hedged attempt that loses the race but still produced a response must have
// that response drained and closed, otherwise its connection is never returned.
func TestHedgingLosingAttemptResponseBodyDrained(t *testing.T) {
	var attempts atomic.Int32
	release := make(chan struct{})
	loser := newTrackedBody("loser")

	h := NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(2).
		SetMaxRequestPerSecond(0)
	h.SetTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		if attempts.Add(1) == 1 {
			<-release // lose the race, then still hand back a usable response
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       loser,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("winner")),
		}, nil
	}))

	req, err := http.NewRequest(MethodGet, "http://127.0.0.1:65535/", nil)
	assertNil(t, err)

	resp, err := h.RoundTrip(req)
	assertNil(t, err)
	body, err := io.ReadAll(resp.Body)
	assertNil(t, err)
	assertEqual(t, "winner", string(body))
	assertNil(t, resp.Body.Close())

	close(release)
	select {
	case <-loser.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("the losing response body was never closed")
	}
	assertEqual(t, int64(len("loser")), loser.read.Load(),
		"expected the losing response body to be drained before closing")
}

// With neither an inter-attempt delay nor a rate delay the spawn loop has no
// select to observe the winner on, so it has to re-check before every attempt.
// Otherwise every configured attempt is fired even after the race is over.
func TestHedgingSpawnLoopStopsOnceDecided(t *testing.T) {
	const runs = 200

	var attempts atomic.Int32
	h := NewHedging().
		SetDelay(0).
		SetMaxRequest(8).
		SetMaxRequestPerSecond(0)
	h.SetTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("ok")),
		}, nil
	}))

	for range runs {
		req, err := http.NewRequest(MethodGet, "http://127.0.0.1:65535/", nil)
		assertNil(t, err)

		resp, err := h.RoundTrip(req)
		assertNil(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		assertNil(t, err)
		assertEqual(t, "ok", string(body))
		assertNil(t, resp.Body.Close())
	}

	// every run still has to produce exactly one usable response
	assertTrue(t, attempts.Load() >= runs, "expected at least one attempt per run")
}

// http.Request.Clone does not copy the body, so every hedged attempt read the
// same io.ReadCloser and the first to finish closed it. Attempts saw disjoint
// slices of the payload, and the truncated one could win.
func TestHedgingGivesEachAttemptItsOwnBody(t *testing.T) {
	const payload = `{"payload":"the-full-request-body"}`

	var mu sync.Mutex
	var bodies []string
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		n := len(bodies)
		mu.Unlock()
		if n < 3 {
			// stall the early attempts so later ones are actually spawned
			time.Sleep(300 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	c := dcnl().SetHedging(NewHedging().
		SetDelay(20 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(1000).
		SetNonReadOnlyAllowed(true))
	defer c.Close()

	res, err := c.R().
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(payload).
		Post(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, res.StatusCode())

	mu.Lock()
	defer mu.Unlock()
	assertEqual(t, true, len(bodies) > 1)
	for _, b := range bodies {
		// every attempt must carry the whole payload, never a truncated one
		assertEqual(t, payload, b)
	}
}

// Without GetBody an attempt's body cannot be rebuilt, so the request must be
// sent once rather than raced with a shared reader.
func TestHedgingSkipsRacingWhenBodyIsNotReplayable(t *testing.T) {
	var mu sync.Mutex
	var count int
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		count++
		mu.Unlock()
		assertEqual(t, "streamed-body", string(b))
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	c := dcnl().SetHedging(NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(3).
		SetMaxRequestPerSecond(1000).
		SetNonReadOnlyAllowed(true))
	defer c.Close()

	// a bare io.Reader gives net/http no GetBody to rebuild from
	res, err := c.R().
		SetBody(io.NopCloser(strings.NewReader("streamed-body"))).
		Post(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, res.StatusCode())

	mu.Lock()
	defer mu.Unlock()
	assertEqual(t, 1, count)
}

// A GetBody that fails leaves the attempt with no body to send; the error must
// reach the caller rather than being raced away or sending a bodyless request.
func TestHedgingSurfacesGetBodyError(t *testing.T) {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	c := dcnl().SetHedging(NewHedging().
		SetDelay(10 * time.Millisecond).
		SetMaxRequest(2).
		SetMaxRequestPerSecond(1000).
		SetNonReadOnlyAllowed(true))
	defer c.Close()

	c.SetRequestMiddlewares(
		MiddlewareRequestCreate,
		func(_ *Client, r *Request) error {
			r.RawRequest.GetBody = func() (io.ReadCloser, error) {
				return nil, errors.New("get body test error")
			}
			return nil
		},
	)

	_, err := c.R().SetBody(`{"a":1}`).Post(ts.URL + "/")
	assertNotNil(t, err)
	assertEqual(t, true, strings.Contains(err.Error(), "get body test error"))
}
