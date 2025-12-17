// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// Portions Copyright (c) MIT License cristalhq (https://github.com/cristalhq/hedgedhttp)
// 2025 Ahmet Demir (https://github.com/ahmet2mir)
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT
package resty

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	ErrHedgingRetryMutualExclusion = errors.New("resty: hedging and retry are mutually exclusive")
	ErrHedgingUnsafeMethod         = errors.New("resty: hedging is only supported for safe HTTP methods (GET, HEAD, OPTIONS, TRACE)")
)

type hedgingTransport struct {
	transport   http.RoundTripper
	delay       time.Duration
	upTo        int
	rateLimiter *rate.Limiter
}

func (ht *hedgingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !isSafeMethod(req.Method) {
		return ht.transport.RoundTrip(req)
	}

	if ht.upTo <= 1 {
		return ht.transport.RoundTrip(req)
	}

	ctx := req.Context()
	hedgeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		resp *http.Response
		err  error
	}

	resultCh := make(chan result, ht.upTo)
	var once sync.Once

	for i := 0; i < ht.upTo; i++ {
		if i > 0 {
			if ht.delay > 0 {
				select {
				case <-time.After(ht.delay):
				case <-hedgeCtx.Done():
					break
				}
			}

			if ht.rateLimiter != nil {
				if err := ht.rateLimiter.Wait(hedgeCtx); err != nil {
					break
				}
			}
		}

		go func() {
			hedgedReq := req.Clone(ctx)
			resp, err := ht.transport.RoundTrip(hedgedReq)

			won := false
			once.Do(func() {
				won = true
				resultCh <- result{resp: resp, err: err}
				cancel()
			})

			if !won && resp != nil && resp.Body != nil {
				closeq(resp.Body)
			}
		}()
	}

	res := <-resultCh
	return res.resp, res.err
}

// Verify if we do READ or WRITE
func isSafeMethod(method string) bool {
	switch method {
	case MethodGet, MethodHead, MethodOptions, MethodTrace:
		return true
	default:
		return false
	}
}
