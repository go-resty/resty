// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// 2025 Ahmet Demir (https://github.com/ahmet2mir)
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

// This hedging implementation draws inspiration from the reference provided here: https://github.com/cristalhq/hedgedhttp.

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

var (
	ErrHedgingDisabled = errors.New("resty: hedging not enabled, ignoring this option, please enable with EnableHedging() first")
)

const (
	hedgingDefaultEnabled          = true
	hedgingDefaultDelay            = 0
	hedgingDefaultUpTo             = 0
	hedgingDefaultMaxPerSecond     = 0
	hedgingDefaultAllowNonReadOnly = false
)

// hedgingConfig holds configuration for hedging requests
type hedgingConfig struct {
	enabled          bool
	delay            time.Duration
	upTo             int
	maxPerSecond     float64
	allowNonReadOnly bool
}

type hedgingTransport struct {
	transport        http.RoundTripper
	delay            time.Duration
	upTo             int
	rateDelay        time.Duration // delay between requests based on maxPerSecond
	allowNonReadOnly bool
}

func (ht *hedgingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !ht.allowNonReadOnly && !isReadOnlyMethod(req.Method) {
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

			// Rate limiting: add delay between requests based on maxPerSecond
			// to prevent overwhelming the server.
			if ht.rateDelay > 0 {
				select {
				case <-time.After(ht.rateDelay):
				case <-hedgeCtx.Done():
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
