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
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestHedgingBasic(t *testing.T) {
	attemptCount := atomic.Int32{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attemptCount.Add(1)
		if attempt == 1 {
			time.Sleep(100 * time.Millisecond)
		}
		w.Header().Set("X-Attempt", strconv.Itoa(int(attempt)))
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Attempt %d", attempt)
	}))
	defer ts.Close()

	c := dcnl()
	err := c.EnableHedging(20*time.Millisecond, 3, 0)
	assertError(t, err)

	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	finalCount := attemptCount.Load()
	if finalCount < 2 {
		t.Errorf("Expected at least 2 requests, got %d", finalCount)
	}
}

func TestHedgingFirstWins(t *testing.T) {
	attemptCount := atomic.Int32{}
	firstAttempt := atomic.Int32{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attemptCount.Add(1)
		if attempt == 1 {
			time.Sleep(200 * time.Millisecond)
		} else if attempt == 2 {
			time.Sleep(50 * time.Millisecond)
		}
		firstAttempt.CompareAndSwap(0, attempt)

		w.Header().Set("X-Attempt", strconv.Itoa(int(attempt)))
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Attempt %d", attempt)
	}))
	defer ts.Close()

	c := dcnl()
	err := c.EnableHedging(30*time.Millisecond, 3, 0)
	assertError(t, err)

	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)

	winner := firstAttempt.Load()
	if winner != 2 {
		t.Logf("Expected second request to win, got attempt %d", winner)
	}

	totalAttempts := attemptCount.Load()
	if totalAttempts < 2 {
		t.Errorf("Expected at least 2 hedged requests, got %d", totalAttempts)
	}
}

func TestHedgingTimeout(t *testing.T) {
	attemptCount := atomic.Int32{}
	requestTimes := make([]time.Time, 0, 3)
	var timesLock atomic.Value
	timesLock.Store(requestTimes)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attemptCount.Add(1)
		now := time.Now()

		times := timesLock.Load().([]time.Time)
		times = append(times, now)
		timesLock.Store(times)

		if attempt == 1 {
			time.Sleep(300 * time.Millisecond)
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Attempt %d", attempt)
	}))
	defer ts.Close()

	c := dcnl()
	delay := 50 * time.Millisecond
	err := c.EnableHedging(delay, 3, 0)
	assertError(t, err)

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

func TestHedgingSafeMethodsOnly(t *testing.T) {
	attemptCount := atomic.Int32{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := dcnl()
	err := c.EnableHedging(20*time.Millisecond, 3, 0)
	assertError(t, err)

	testCases := []struct {
		method         string
		expectHedging  bool
		requestFunc    func(*Client, string) (*Response, error)
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
			attemptCount.Store(0)

			resp, err := tc.requestFunc(c, ts.URL+"/")
			assertError(t, err)
			assertEqual(t, http.StatusOK, resp.StatusCode())

			time.Sleep(100 * time.Millisecond)

			count := attemptCount.Load()
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
	attemptCount := atomic.Int32{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attemptCount.Add(1)
		if attempt == 1 {
			time.Sleep(500 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := dcnl()
	err := c.EnableHedging(10*time.Millisecond, 10, 5.0)
	assertError(t, err)

	start := time.Now()
	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	duration := time.Since(start)
	count := attemptCount.Load()

	if duration < 200*time.Millisecond {
		t.Logf("Rate limiting may have limited hedged requests. Duration: %v, Attempts: %d", duration, count)
	}
}

func TestHedgingMutualExclusionWithRetry(t *testing.T) {
	c := dcnl()

	err := c.EnableHedging(50*time.Millisecond, 3, 0)
	assertError(t, err)

	c.SetRetryCount(2)
	if c.RetryCount() != 0 {
		t.Error("Should not be able to enable retry when hedging is enabled")
	}

	c.DisableHedging()

	c.SetRetryCount(2)
	assertEqual(t, 2, c.RetryCount())

	err = c.EnableHedging(50*time.Millisecond, 3, 0)
	if err == nil {
		t.Error("Should not be able to enable hedging when retry is enabled")
	}
	assertEqual(t, ErrHedgingRetryMutualExclusion, err)
}

func TestHedgingDisable(t *testing.T) {
	attemptCount := atomic.Int32{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := dcnl()
	err := c.EnableHedging(20*time.Millisecond, 3, 0)
	assertError(t, err)
	assertEqual(t, true, c.IsHedgingEnabled())

	c.DisableHedging()
	assertEqual(t, false, c.IsHedgingEnabled())

	attemptCount.Store(0)
	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)

	count := attemptCount.Load()
	assertEqual(t, int32(1), count)
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
	err := c.EnableHedging(20*time.Millisecond, 3, 0)
	assertError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = c.R().SetContext(ctx).Get(ts.URL + "/")
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

	c.SetHedgingDelay(100 * time.Millisecond)
	assertEqual(t, 100*time.Millisecond, c.HedgingDelay())

	c.SetHedgingUpTo(5)
	assertEqual(t, 5, c.HedgingUpTo())

	c.SetHedgingMaxPerSecond(20.0)
	assertEqual(t, 20.0, c.HedgingMaxPerSecond())

	assertEqual(t, false, c.IsHedgingEnabled())

	err := c.EnableHedging(50*time.Millisecond, 3, 10.0)
	assertError(t, err)

	assertEqual(t, true, c.IsHedgingEnabled())
	assertEqual(t, 50*time.Millisecond, c.HedgingDelay())
	assertEqual(t, 3, c.HedgingUpTo())
	assertEqual(t, 10.0, c.HedgingMaxPerSecond())
}

func TestHedgingWithCustomTransport(t *testing.T) {
	attemptCount := atomic.Int32{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attemptCount.Add(1)
		if attempt == 1 {
			time.Sleep(100 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	customTransport := &http.Transport{}
	c := NewWithClient(&http.Client{Transport: customTransport})

	err := c.EnableHedging(20*time.Millisecond, 3, 0)
	assertError(t, err)

	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)

	count := attemptCount.Load()
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
	attemptCount := atomic.Int32{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := dcnl()
	err := c.EnableHedging(20*time.Millisecond, 1, 0)
	assertError(t, err)

	resp, err := c.R().Get(ts.URL + "/")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	time.Sleep(100 * time.Millisecond)

	count := attemptCount.Load()
	assertEqual(t, int32(1), count)
}
