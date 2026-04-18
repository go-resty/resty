// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimiterTokenBucket(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		l := NewRateLimitTokenBucket(100, 5)
		for i := range 5 {
			err := l.Allow(context.Background())
			assertNil(t, err, fmt.Sprintf("unexpected error on iteration %d", i))
		}
	})

	t.Run("burst depletes tokens", func(t *testing.T) {
		// 1 token/s, burst 1 -> after 1 call tokens are 0
		l := NewRateLimitTokenBucket(1, 1)

		// First call should succeed immediately (burst token available).
		err := l.Allow(context.Background())
		assertNil(t, err)

		// Second call: no token available, context with very short deadline should time out.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		err = l.Allow(ctx)
		assertErrorIs(t, ErrRateLimitExceeded, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		// rate=1/s, burst=1 -> drain burst first, then cancel
		l := NewRateLimitTokenBucket(1, 1)
		_ = l.Allow(context.Background()) // drain the single burst token

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // already cancelled

		err := l.Allow(ctx)
		assertErrorIs(t, ErrRateLimitExceeded, err)
	})

	t.Run("refills over time", func(t *testing.T) {
		// 10 requests/s -> 1 token every 100 ms
		l := NewRateLimitTokenBucket(10, 1)

		// Drain burst.
		err := l.Allow(context.Background())
		assertNil(t, err)

		// Wait for one token to refill, then allow should succeed.
		time.Sleep(120 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		err = l.Allow(ctx)
		assertNil(t, err, "expected token to be available after refill interval")
	})
}

func TestRateLimiterTokenBucketConfig(t *testing.T) {
	t.Run("rate and burst accessors", func(t *testing.T) {
		l := NewRateLimitTokenBucket(42.5, 7)
		assertEqual(t, 42.5, l.Rate(), "unexpected rate value")
		assertEqual(t, 7, l.Burst(), "unexpected burst")
	})

	t.Run("defaults on invalid rate", func(t *testing.T) {
		l := NewRateLimitTokenBucket(0, 3)
		assertEqual(t, 5.0, l.Rate(), "unexpected default rate")
		assertEqual(t, 3, l.Burst(), "unexpected burst")
	})

	t.Run("defaults on invalid burst", func(t *testing.T) {
		l := NewRateLimitTokenBucket(10, 0)
		assertEqual(t, 10.0, l.Rate(), "unexpected rate")
		assertEqual(t, 1, l.Burst(), "unexpected default burst")
	})
}

func TestClientRateLimiterTokenBucket(t *testing.T) {
	t.Run("set/get/clear rate limiter", func(t *testing.T) {
		c := dcnl()
		assertNil(t, c.RateLimiter(), "expected nil rate limiter initially")

		l := NewRateLimitTokenBucket(50, 5)
		c.SetRateLimiter(l)
		assertEqual(t, l, c.RateLimiter(), "expected rate limiter to be set")

		c.SetRateLimiter(nil)
		assertNil(t, c.RateLimiter(), "expected nil after clearing rate limiter")
	})

	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	t.Run("throttles requests", func(t *testing.T) {
		// rate=1/s, burst=1 -> only 1 instant request allowed
		l := NewRateLimitTokenBucket(1, 1)
		c := dcnl().SetBaseURL(ts.URL).SetRateLimiter(l)

		// First request: burst token available, should succeed.
		resp, err := c.R().Get(ts.URL)
		assertNil(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())

		// Second request with a short-deadline context: burst exhausted, must be rejected.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		resp2, err2 := c.R().SetContext(ctx).Get(ts.URL)
		assertErrorIs(t, ErrRateLimitExceeded, err2)
		assertNil(t, resp2)
	})

	t.Run("allows after refill", func(t *testing.T) {
		// 10 req/s -> 1 token every 100 ms, burst 1
		l := NewRateLimitTokenBucket(10, 1)
		c := dcnl().SetBaseURL(ts.URL).SetRateLimiter(l)

		// Drain burst.
		_, err := c.R().Get(ts.URL)
		assertNil(t, err)

		// Wait for one token to refill.
		time.Sleep(120 * time.Millisecond)

		resp, err := c.R().Get(ts.URL)
		assertNil(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
	})

	t.Run("custom implementation", func(t *testing.T) {
		var allowCalls atomic.Int32
		cl := &customTestLimiter{allow: true, calls: &allowCalls}
		c := dcnl().SetBaseURL(ts.URL).SetRateLimiter(cl)

		_, err := c.R().Get(ts.URL)
		assertNil(t, err)
		assertEqual(t, int32(1), allowCalls.Load(), "expected Allow to be called once")

		// Now reject all requests.
		cl.allow = false
		_, err = c.R().Get(ts.URL)
		assertErrorIs(t, ErrRateLimitExceeded, err)
		assertEqual(t, int32(2), allowCalls.Load(), "expected Allow to be called twice")
	})
}

type customTestLimiter struct {
	allow bool
	calls *atomic.Int32
}

func (l *customTestLimiter) Allow(_ context.Context) error {
	l.calls.Add(1)
	if !l.allow {
		return ErrRateLimitExceeded
	}
	return nil
}

func TestRateLimiterSlidingWindow(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		l := NewRateLimitSlidingWindow(5, time.Second)
		for i := range 5 {
			err := l.Allow(context.Background())
			assertNil(t, err, fmt.Sprintf("unexpected error on iteration %d: %v", i, err))
		}
	})

	t.Run("limit exhausted", func(t *testing.T) {
		// 2 requests per second window; drain both slots immediately.
		l := NewRateLimitSlidingWindow(2, time.Second)
		assertNil(t, l.Allow(context.Background()))
		assertNil(t, l.Allow(context.Background()))

		// Third request: window is full, short deadline must be rejected.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		err := l.Allow(ctx)
		assertErrorIs(t, ErrRateLimitExceeded, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		l := NewRateLimitSlidingWindow(1, time.Second)
		assertNil(t, l.Allow(context.Background())) // drain the single slot

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // already cancelled
		err := l.Allow(ctx)
		assertErrorIs(t, ErrRateLimitExceeded, err)
	})

	t.Run("slides over time", func(t *testing.T) {
		// Window of 100 ms, limit 1: after the first request, wait >100 ms and
		// the slot should become available again.
		l := NewRateLimitSlidingWindow(1, 100*time.Millisecond)
		assertNil(t, l.Allow(context.Background()))

		time.Sleep(120 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		err := l.Allow(ctx)
		assertNil(t, err, "expected slot to be available after window slides")
	})

	t.Run("throttles", func(t *testing.T) {
		ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		defer ts.Close()

		// limit=1, window=1s → only 1 instant request allowed
		l := NewRateLimitSlidingWindow(1, time.Second)
		c := dcnl().SetBaseURL(ts.URL).SetRateLimiter(l)

		resp, err := c.R().Get(ts.URL)
		assertNil(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		resp2, err2 := c.R().SetContext(ctx).Get(ts.URL)
		assertErrorIs(t, ErrRateLimitExceeded, err2)
		assertNil(t, resp2)
	})
}

func TestRateLimiterSlidingWindowConfig(t *testing.T) {
	t.Run("accessors", func(t *testing.T) {
		l := NewRateLimitSlidingWindow(42, 5*time.Second)
		assertEqual(t, 42, l.Limit(), "unexpected limit value")
		assertEqual(t, 5*time.Second, l.WindowSize(), "unexpected window size")
	})

	t.Run("defaults", func(t *testing.T) {
		l := NewRateLimitSlidingWindow(0, 0)
		assertEqual(t, 5, l.Limit(), "expected default limit of 5")
		assertEqual(t, time.Second, l.WindowSize(), "expected default window of 1s")
	})
}
