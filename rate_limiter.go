// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrRateLimitExceeded is returned by [Client] execute method when the rate limiter
// rejects a request. This occurs when the context is cancelled or the deadline
// expires before a token becomes available, or immediately if the rate limiter
// implementation rejects the request for any other reason.
var ErrRateLimitExceeded = errors.New("resty: rate limit exceeded")

// RateLimiter is the interface that wraps the rate limiting behavior used by
// [Client]. Implement this interface to provide custom rate limiting strategies.
// The [Client] calls [RateLimiter.Allow] before every request; if it returns
// an error the request is aborted with that error.
//
// The context passed to [RateLimiter.Allow] is the request context, so
// cancellation or deadline expiry is respected automatically. Implementations
// must be safe for concurrent use.
type RateLimiter interface {
	// Allow blocks until the rate limiter permits the next request or the
	// context is done. It returns [ErrRateLimitExceeded] if the context expires
	// or is cancelled before a token is available, and nil when the request may
	// proceed. Implementations must be goroutine-safe.
	Allow(ctx context.Context) error
}

// NewRateLimitTokenBucket creates a new token-bucket [RateLimiter] that permits at most
// requests per second with a burst capacity of burst tokens.
//
// The burst value controls how many requests can be issued instantly; after the
// burst is exhausted, tokens refill at the rate of request tokens per second.
//
// For example, to allow 100 requests per second with a burst of 10:
//
//	rateLimiter := resty.NewRateLimitTokenBucket(100, 10)
//	client := resty.New().SetRateLimiter(rateLimiter)
//
// A burst of 1 enforces strict rate limiting with no burstiness.
//
// If requestsPerSecond <= 0, NewRateLimitTokenBucket defaults to 5 requests per second.
// If burst <= 0, NewRateLimitTokenBucket defaults to a burst of 1.
func NewRateLimitTokenBucket(requestsPerSecond float64, burst int) *RateLimitTokenBucket {
	if requestsPerSecond <= 0 {
		// Default to 5 requests per second if invalid rate is provided.
		requestsPerSecond = 5
	}
	if burst <= 0 {
		// Default to a burst of 1 if invalid burst is provided.
		burst = 1
	}

	l := &RateLimitTokenBucket{
		rate:   requestsPerSecond,
		burst:  burst,
		tokens: float64(burst),
	}
	l.lastRefill = time.Now()
	return l
}

var _ RateLimiter = (*RateLimitTokenBucket)(nil)

// RateLimitTokenBucket is a token-bucket based implementation of [RateLimiter].
// It implements the standard token-bucket algorithm: tokens refill at a
// constant rate and each request consumes one token. When no tokens are
// available, [RateLimitTokenBucket.Allow] blocks until either a token becomes
// available or the context expires.
//
// This implementation is safe for concurrent use from multiple goroutines.
// The token count is internally synchronized; access the rate and burst
// separately through [RateLimitTokenBucket.Rate] and [RateLimitTokenBucket.Burst].
//
// Create instances with [NewRateLimitTokenBucket]; do not use the zero value directly.
type RateLimitTokenBucket struct {
	mu         sync.Mutex
	rate       float64   // tokens per second
	burst      int       // max token capacity
	tokens     float64   // current token count
	lastRefill time.Time // last refill timestamp
}

// Rate method returns the token refill rate in requests per second.
func (l *RateLimitTokenBucket) Rate() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rate
}

// Burst method returns the maximum burst capacity (maximum token count).
func (l *RateLimitTokenBucket) Burst() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.burst
}

// Allow blocks until the rate limiter grants a token or the context is done.
// It returns [ErrRateLimitExceeded] if the context is cancelled or times out
// before a token is available.
//
// Performance note: Timer allocations occur only when tokens are exhausted and
// waiting is necessary. When tokens are available (the common case), Allow
// returns immediately without allocating timers. Context deadline and
// cancellation checks are performed on every iteration,
// respecting cancellation immediately even during token waits.
func (l *RateLimitTokenBucket) Allow(ctx context.Context) error {
	for {
		// Check context first to avoid acquiring the lock unnecessarily.
		select {
		case <-ctx.Done():
			return ErrRateLimitExceeded
		default:
		}

		l.mu.Lock()
		l.refill()
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}

		// Calculate time needed for the missing fractional token amount.
		missingTokens := 1 - l.tokens
		wait := max(time.Duration((missingTokens/l.rate)*float64(time.Second)), time.Nanosecond)
		l.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrRateLimitExceeded
		case <-timer.C:
		}
	}
}

// refill adds tokens based on the elapsed time since the last refill.
// Must be called with l.mu held.
func (l *RateLimitTokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	l.tokens = min(float64(l.burst), l.tokens+elapsed*l.rate)
	l.lastRefill = now
}

// NewRateLimitSlidingWindow creates a new sliding-window [RateLimiter] that
// allows at most limit requests within any rolling window of windowSize duration.
//
// Unlike the token-bucket limiter which refills tokens at a constant rate, the
// sliding window continuously tracks when requests were made and permits a new
// request only when fewer than limit requests occurred in the past windowSize
// duration.
//
// For example, to allow 100 requests per 10 seconds:
//
//	rateLimiter := resty.NewRateLimitSlidingWindow(100, 10*time.Second)
//	client := resty.New().SetRateLimiter(rateLimiter)
//
// If limit <= 0, it defaults to 5. If windowSize <= 0, it defaults to 1 second.
func NewRateLimitSlidingWindow(limit int, windowSize time.Duration) *RateLimitSlidingWindow {
	if limit <= 0 {
		limit = 5
	}
	if windowSize <= 0 {
		windowSize = time.Second
	}
	return &RateLimitSlidingWindow{
		limit:      limit,
		windowSize: windowSize,
		timestamps: make([]time.Time, 0, limit),
	}
}

var _ RateLimiter = (*RateLimitSlidingWindow)(nil)

// RateLimitSlidingWindow is a sliding-window based implementation of [RateLimiter].
// It tracks request timestamps and allows a new request only when the number of
// requests within the past windowSize is below the configured limit.
//
// This implementation is safe for concurrent use from multiple goroutines.
// Memory usage is proportional to (limit * average_request_rate * windowSize);
// old timestamps are automatically evicted as they slide out of the window.
// Access rate and window size through [RateLimitSlidingWindow.Limit] and
// [RateLimitSlidingWindow.WindowSize].
//
// Compared to token-bucket: sliding window provides stricter enforcement of the
// request limit within discrete time windows, while token-bucket focuses on
// average rate with burst tolerance.
//
// Create instances with [NewRateLimitSlidingWindow]; do not use the zero value directly.
type RateLimitSlidingWindow struct {
	mu         sync.Mutex
	limit      int           // max requests per window
	windowSize time.Duration // duration of the sliding window
	timestamps []time.Time   // ordered slice of in-window request timestamps
}

// Limit returns the maximum number of requests allowed per window.
func (l *RateLimitSlidingWindow) Limit() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit
}

// WindowSize returns the duration of the sliding window.
func (l *RateLimitSlidingWindow) WindowSize() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.windowSize
}

// Allow blocks until the sliding window permits the next request or the context
// is done. It returns [ErrRateLimitExceeded] if the context is cancelled or
// times out before a slot becomes available.
//
// Performance note: When a slot is available (the common case), Allow returns
// immediately after evicting out-of-window timestamps. The eviction is O(n)
// where n is the number of out-of-window timestamps, but typically small due
// to sliding window semantics. Context cancellation is checked before and during
// any wait period, respecting cancellation immediately.
func (l *RateLimitSlidingWindow) Allow(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ErrRateLimitExceeded
		default:
		}

		l.mu.Lock()
		now := time.Now()
		windowStart := now.Add(-l.windowSize)

		// Evict timestamps that have slid out of the window.
		i := 0
		for i < len(l.timestamps) && l.timestamps[i].Before(windowStart) {
			i++
		}
		if i > 0 {
			// Use copy() to clear old elements and allow GC to reclaim memory.
			copy(l.timestamps, l.timestamps[i:])
			l.timestamps = l.timestamps[:len(l.timestamps)-i]
		}

		if len(l.timestamps) < l.limit {
			l.timestamps = append(l.timestamps, now)
			l.mu.Unlock()
			return nil
		}

		// Wait until the oldest in-window timestamp slides out.
		wait := l.timestamps[0].Add(l.windowSize).Sub(now)
		if wait <= 0 {
			wait = time.Nanosecond
		}
		l.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrRateLimitExceeded
		case <-timer.C:
		}
	}
}
