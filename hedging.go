// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// 2025 Ahmet Demir (https://github.com/ahmet2mir)
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

// This hedging implementation draws inspiration from the reference provided here: https://github.com/cristalhq/hedgedhttp.

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// NewHedging creates a new Hedging instance with default configuration.
// By default values are:
//   - 50ms delay between requests
//   - Maximum 3 requests
//   - Maximum 3 requests per second
//   - Only read-only methods are hedged
//
// You can customize these settings using the corresponding setter methods.
// For example:
//
//	hedging := NewHedging().
//		SetDelay(100 * time.Millisecond).
//		SetMaxRequest(5).
//		SetMaxRequestPerSecond(10)
//
//	// Assign the hedging instance to the Resty client
//	client := resty.New().
//		SetHedging(hedging)
//
//	defer c.Close()
func NewHedging() *Hedging {
	h := &Hedging{
		lock:                 new(sync.RWMutex),
		delay:                50 * time.Millisecond, // delay between requests
		maxRequest:           3,                     // max requests
		maxRequestPerSecond:  3,                     // max requests per second
		isNonReadOnlyAllowed: false,                 // only hedge read-only methods by default
	}
	h.calculateRateDelay()
	return h
}

// Hedging struct implements the http.RoundTripper interface to perform hedged HTTP requests.
// It sends multiple requests in parallel with a specified delay and returns the first successful
// response. Hedging is particularly useful for improving latency and reliability in scenarios
// where requests may occasionally fail or experience high latency.
//
// By default only read-only HTTP methods (GET, HEAD, OPTIONS, TRACE) are hedged to avoid unintended
// side effects on the server. Unless SetHedgingAllowNonReadOnly is used to allow non-read-only methods,
// in which case all HTTP methods will be hedged.
//
// NOTE:
//   - Hedging should be used with caution, especially for non-read-only methods, as it can lead to
//     unintended consequences if multiple requests are processed by the server.
//   - Ensure that the server can safely handle multiple concurrent requests when using hedging,
//     as otherwise, hedging requests can overwhelm the server.
//
// For more information on hedging and its use cases, refer to the following resources:
//   - [The Tail at Scale]
//
// [The Tail at Scale]: https://research.google/pubs/the-tail-at-scale/
type Hedging struct {
	lock                 *sync.RWMutex
	transport            http.RoundTripper
	delay                time.Duration
	maxRequest           int
	maxRequestPerSecond  float64
	rateDelay            time.Duration // delay between requests based on maxPerSecond
	isNonReadOnlyAllowed bool
}

// Delay method returns the configured hedging delay.
func (h *Hedging) Delay() time.Duration {
	h.lock.RLock()
	defer h.lock.RUnlock()
	return h.delay
}

// SetDelay method sets the delay between hedged requests.
func (h *Hedging) SetDelay(delay time.Duration) *Hedging {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.delay = delay
	return h
}

// MaxRequest method returns the maximum concurrent requests.
func (h *Hedging) MaxRequest() int {
	h.lock.RLock()
	defer h.lock.RUnlock()
	return h.maxRequest
}

// SetMaxRequest method sets maximum concurrent hedged requests.
func (h *Hedging) SetMaxRequest(count int) *Hedging {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.maxRequest = count
	return h
}

// MaxRequestPerSecond method returns the hedging rate limit.
func (h *Hedging) MaxRequestPerSecond() float64 {
	h.lock.RLock()
	defer h.lock.RUnlock()
	return h.maxRequestPerSecond
}

// SetMaxRequestPerSecond method sets rate limit for hedged requests.
func (h *Hedging) SetMaxRequestPerSecond(count float64) *Hedging {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.maxRequestPerSecond = count
	h.calculateRateDelay()
	return h
}

// IsNonReadOnlyAllowed method returns true if hedging is enabled for non-read-only
// HTTP methods.
func (h *Hedging) IsNonReadOnlyAllowed() bool {
	h.lock.RLock()
	defer h.lock.RUnlock()
	return h.isNonReadOnlyAllowed
}

// SetNonReadOnlyAllowed method allows hedging for non-read-only HTTP methods.
// By default, only read-only methods (GET, HEAD, OPTIONS, TRACE) are hedged.
//
// NOTE:
//   - Use this with caution as hedging write operations can lead to duplicates.
func (h *Hedging) SetNonReadOnlyAllowed(allow bool) *Hedging {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.isNonReadOnlyAllowed = allow
	return h
}

// calculateRateDelay method calculates the delay between requests based on the maxPerSecond setting.
// If maxPerSecond is greater than 0, it sets rateDelay to 1 second divided by maxPerSecond.
// Otherwise, it sets rateDelay to 0 (no delay).
//
// NOTE: It should be called within lock region.
func (h *Hedging) calculateRateDelay() {
	if h.maxRequestPerSecond > 0 {
		// Calculate rate delay: if maxPerSecond is 10, delay is 100ms (1s / 10)
		h.rateDelay = time.Duration(float64(time.Second) / h.maxRequestPerSecond)
	} else {
		h.rateDelay = 0 // no delay if maxPerSecond is 0 or negative
	}
}

func (ht *Hedging) RoundTrip(req *http.Request) (*http.Response, error) {
	if !ht.isNonReadOnlyAllowed && !isReadOnlyMethod(req.Method) {
		return ht.transport.RoundTrip(req)
	}

	if ht.MaxRequest() <= 1 {
		return ht.transport.RoundTrip(req)
	}

	ctx := req.Context()
	deadline, hasDeadline := ctx.Deadline()

	// Derive hedgeCtx from the original request context to respect cancellations
	var (
		hedgeCtx context.Context
		cancel   context.CancelFunc
	)
	if hasDeadline {
		// Use original deadline for the race (first to complete wins)
		remaining := time.Until(deadline)
		if remaining > 0 {
			hedgeCtx, cancel = context.WithTimeout(ctx, remaining)
		} else {
			// Deadline already expired, use context with cancel
			hedgeCtx, cancel = context.WithCancel(ctx)
		}
	} else {
		// No deadline in original context, create cancellable context from it
		hedgeCtx, cancel = context.WithCancel(ctx)
	}

	// defer cancel() ensures cleanup on all paths (timeout, cancellation, or normal return)
	// cancel() may also be called inside once.Do() when a request wins, but calling it
	// multiple times is safe and ensures the context is canceled as soon as any goroutine completes
	defer cancel()

	type result struct {
		resp *http.Response
		err  error
	}

	ht.lock.RLock()
	maxReq := ht.maxRequest
	delay := ht.delay
	rateDelay := ht.rateDelay
	ht.lock.RUnlock()

	resultCh := make(chan result, maxReq)
	var once sync.Once

	for i := range maxReq {
		if i > 0 {
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-hedgeCtx.Done():
					break
				}
			}

			// Rate limiting: add delay between requests based on maxPerSecond
			// to prevent overwhelming the server.
			if rateDelay > 0 {
				select {
				case <-time.After(rateDelay):
				case <-hedgeCtx.Done():
					break
				}
			}
		}

		go func() {
			hedgedReq := req.Clone(hedgeCtx)
			resp, err := ht.transport.RoundTrip(hedgedReq)

			won := false
			once.Do(func() {
				won = true
				resultCh <- result{resp: resp, err: err}

				// Cancel inside once.Do() to stop other goroutines immediately when a request wins
				// defer cancel() ensures cleanup even if no request completes successfully
				cancel()
			})

			if !won && resp != nil && resp.Body != nil {
				drainReadCloser(resp.Body)
			}
		}()
	}

	res := <-resultCh
	close(resultCh)
	return res.resp, res.err
}

// isReadOnlyMethod verifies if the HTTP method is read-only (safe for hedging)
func isReadOnlyMethod(method string) bool {
	switch method {
	case MethodGet, MethodHead, MethodOptions, MethodTrace:
		return true
	default:
		return false
	}
}
