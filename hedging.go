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

// Hedger is the interface for implementing a hedging strategy for HTTP requests.
// Implementations must also implement [http.RoundTripper] so they can be installed
// as the HTTP transport on a [Client].
//
// The [Hedger.SetTransport] and [Hedger.Transport] methods allow [Client.SetHedging] to wrap
// and unwrap the underlying transport when hedging is enabled or disabled.
//
// Use [NewHedging] to create the default implementation ([Hedging]).
type Hedger interface {
	http.RoundTripper

	// SetTransport sets the underlying HTTP transport that this hedging
	// implementation delegates individual requests to.
	SetTransport(http.RoundTripper)

	// Transport returns the underlying HTTP transport.
	Transport() http.RoundTripper
}

var _ Hedger = (*Hedging)(nil)

// NewHedging creates a new [Hedging] instance with default configuration.
// Defaults:
//   - 50ms delay between requests
//   - Maximum 3 hedged requests
//   - Maximum 3 hedged requests per second
//   - Only read-only methods are hedged
//
// Customize these values with the corresponding setter methods.
// For example:
//
//	hedging := resty.NewHedging().
//		SetDelay(100 * time.Millisecond).
//		SetMaxRequest(5).
//		SetMaxRequestPerSecond(10)
//
//	client := resty.New().
//		SetHedging(hedging)
//
//	defer client.Close()
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

// Hedging implements [Hedger] and [http.RoundTripper] to perform hedged HTTP requests.
// It sends multiple requests in parallel with a specified delay and returns the first successful
// response. Hedging is particularly useful for improving latency in scenarios where requests
// may occasionally fail or experience high latency.
//
// By default, only read-only HTTP methods (GET, HEAD, OPTIONS, TRACE) are hedged to avoid
// unintended side effects on the server. Non-read-only methods can be enabled via
// [Hedging.SetNonReadOnlyAllowed].
//
// NOTE:
//   - Hedging should be used with caution for non-read-only methods, as multiple requests
//     may be processed by the server.
//   - Ensure the server can safely handle concurrent requests; otherwise, hedging can
//     overwhelm the server.
//
// For more information on hedging and its use cases, see [The Tail at Scale].
//
// [The Tail at Scale]: https://research.google/pubs/the-tail-at-scale/
type Hedging struct {
	lock                 *sync.RWMutex
	underlying           http.RoundTripper
	delay                time.Duration
	maxRequest           int
	maxRequestPerSecond  float64
	rateDelay            time.Duration // delay between requests based on maxPerSecond
	isNonReadOnlyAllowed bool
}

// SetTransport sets the underlying HTTP transport that [Hedging] delegates
// individual requests to.
func (h *Hedging) SetTransport(t http.RoundTripper) {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.underlying = t
}

// Transport returns the underlying HTTP transport.
func (h *Hedging) Transport() http.RoundTripper {
	h.lock.RLock()
	defer h.lock.RUnlock()
	return h.underlying
}

// Delay method returns the delay between hedged requests.
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

// MaxRequest method returns the maximum number of concurrent hedged requests.
func (h *Hedging) MaxRequest() int {
	h.lock.RLock()
	defer h.lock.RUnlock()
	return h.maxRequest
}

// SetMaxRequest method sets the maximum number of concurrent hedged requests.
func (h *Hedging) SetMaxRequest(count int) *Hedging {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.maxRequest = count
	return h
}

// MaxRequestPerSecond method returns the maximum number of hedged requests allowed per second.
func (h *Hedging) MaxRequestPerSecond() float64 {
	h.lock.RLock()
	defer h.lock.RUnlock()
	return h.maxRequestPerSecond
}

// SetMaxRequestPerSecond method sets the maximum number of hedged requests allowed per second.
func (h *Hedging) SetMaxRequestPerSecond(count float64) *Hedging {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.maxRequestPerSecond = count
	h.calculateRateDelay()
	return h
}

// IsNonReadOnlyAllowed method reports whether hedging is enabled for non-read-only HTTP methods.
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

// calculateRateDelay calculates the inter-request delay from maxRequestPerSecond.
// If maxRequestPerSecond > 0, rateDelay is set to 1s / maxRequestPerSecond;
// otherwise rateDelay is 0 (no rate limiting).
//
// Must be called with the lock held.
func (h *Hedging) calculateRateDelay() {
	if h.maxRequestPerSecond > 0 {
		// Calculate rate delay: if maxPerSecond is 10, delay is 100ms (1s / 10)
		h.rateDelay = time.Duration(float64(time.Second) / h.maxRequestPerSecond)
	} else {
		h.rateDelay = 0 // no delay if maxPerSecond is 0 or negative
	}
}

// RoundTrip races up to [Hedging.MaxRequest] copies of req against each other and
// returns the result of whichever attempt finishes first.
//
// Each attempt gets its own context derived from the request context, so the
// losers can be cancelled the moment a winner is known without disturbing the
// winner. The winning attempt's context is released when its response body is
// closed — cancelling it any earlier would abort the caller's read of that body.
// Losing responses are drained so their connections can be reused.
func (ht *Hedging) RoundTrip(req *http.Request) (*http.Response, error) {
	ht.lock.RLock()
	underlying := ht.underlying
	maxReq := ht.maxRequest
	delay := ht.delay
	rateDelay := ht.rateDelay
	nonReadOnlyAllowed := ht.isNonReadOnlyAllowed
	ht.lock.RUnlock()

	if (!nonReadOnlyAllowed && !isReadOnlyMethod(req.Method)) || maxReq <= 1 {
		return underlying.RoundTrip(req)
	}

	reqCtx := req.Context()

	type result struct {
		resp *http.Response
		err  error
	}
	resultCh := make(chan result, 1)
	decidedCh := make(chan struct{})

	var (
		mu       sync.Mutex
		decided  bool
		inflight = make(map[int]context.CancelFunc, maxReq)
	)

	// decide records attempt i as the winner. It reports false when another
	// attempt already won. The winner's own cancel func is left untouched; every
	// other in-flight attempt is cancelled right away.
	decide := func(i int) bool {
		mu.Lock()
		if decided {
			mu.Unlock()
			return false
		}
		decided = true
		losers := make([]context.CancelFunc, 0, len(inflight))
		for idx, cancel := range inflight {
			if idx != i {
				losers = append(losers, cancel)
			}
		}
		clear(inflight)
		mu.Unlock()

		for _, cancel := range losers {
			cancel()
		}
		close(decidedCh)
		return true
	}

spawn:
	for i := range maxReq {
		if i > 0 {
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-decidedCh:
					break spawn
				case <-reqCtx.Done():
					break spawn
				}
			}

			// Rate limiting: add delay between requests based on maxPerSecond
			// to prevent overwhelming the server.
			if rateDelay > 0 {
				select {
				case <-time.After(rateDelay):
				case <-decidedCh:
					break spawn
				case <-reqCtx.Done():
					break spawn
				}
			}
		}

		attemptCtx, attemptCancel := context.WithCancel(reqCtx)

		mu.Lock()
		if decided {
			mu.Unlock()
			attemptCancel()
			break spawn
		}
		inflight[i] = attemptCancel
		mu.Unlock()

		go func(i int, attemptCancel context.CancelFunc) {
			resp, err := underlying.RoundTrip(req.Clone(attemptCtx))

			if !decide(i) {
				attemptCancel()
				if resp != nil && resp.Body != nil {
					drainReadCloser(resp.Body)
				}
				return
			}

			// Winner: the caller still has to read this body, so hand the cancel
			// func over to it instead of firing it here.
			if resp != nil && resp.Body != nil {
				resp.Body = &cancelReadCloser{r: resp.Body, cancel: attemptCancel}
			} else {
				attemptCancel()
			}
			resultCh <- result{resp: resp, err: err}
		}(i, attemptCancel)
	}

	res := <-resultCh
	return res.resp, res.err
}

// isReadOnlyMethod reports whether the HTTP method is read-only (safe for hedging).
func isReadOnlyMethod(method string) bool {
	switch method {
	case MethodGet, MethodHead, MethodOptions, MethodTrace, MethodQuery:
		return true
	default:
		return false
	}
}
