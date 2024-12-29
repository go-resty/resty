// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"crypto/tls"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	defaultWaitTime    = time.Duration(100) * time.Millisecond
	defaultMaxWaitTime = time.Duration(2000) * time.Millisecond
)

type (
	// RetryConditionFunc type is for the retry condition function
	// input: non-nil Response OR request execution error
	RetryConditionFunc func(*Response, error) bool

	// RetryHookFunc is for side-effecting functions triggered on retry
	RetryHookFunc func(*Response, error)

	// RetryStrategyFunc type is for custom retry strategy implementation
	// By default Resty uses the capped exponential backoff with a jitter strategy
	RetryStrategyFunc func(*Response, error) (time.Duration, error)
)

var (
	regexErrTooManyRedirects = regexp.MustCompile(`stopped after \d+ redirects\z`)
	regexErrScheme           = regexp.MustCompile("unsupported protocol scheme")
	regexErrInvalidHeader    = regexp.MustCompile("invalid header")
)

func applyRetryDefaultConditions(res *Response, err error) bool {
	// no retry on TLS error
	if _, ok := err.(*tls.CertificateVerificationError); ok {
		return false
	}

	// validate url error, so we can decide to retry or not
	if u, ok := err.(*url.Error); ok {
		if regexErrTooManyRedirects.MatchString(u.Error()) {
			return false
		}
		if regexErrScheme.MatchString(u.Error()) {
			return false
		}
		if regexErrInvalidHeader.MatchString(u.Error()) {
			return false
		}
		return u.Temporary() // possible retry if it's true
	}

	if res == nil {
		return false
	}

	// certain HTTP status codes are temporary so that we can retry
	//	- 429 Too Many Requests
	//	- 500 or above (it's better to ignore 501 Not Implemented)
	//	- 0 No status code received
	if res.StatusCode() == http.StatusTooManyRequests ||
		(res.StatusCode() >= 500 && res.StatusCode() != http.StatusNotImplemented) ||
		res.StatusCode() == 0 {
		return true
	}

	return false
}

func newBackoffWithJitter(min, max time.Duration) *backoffWithJitter {
	if min <= 0 {
		min = defaultWaitTime
	}
	if max == 0 {
		max = defaultMaxWaitTime
	}

	return &backoffWithJitter{
		lock: new(sync.Mutex),
		rnd:  rand.New(rand.NewSource(time.Now().UnixNano())),
		min:  min,
		max:  max,
	}
}

type backoffWithJitter struct {
	lock *sync.Mutex
	rnd  *rand.Rand
	min  time.Duration
	max  time.Duration
}

func (b *backoffWithJitter) NextWaitDuration(c *Client, res *Response, err error, attempt int) (time.Duration, error) {
	if res != nil {
		if res.StatusCode() == http.StatusTooManyRequests || res.StatusCode() == http.StatusServiceUnavailable {
			if delay, ok := parseRetryAfterHeader(res.Header().Get(hdrRetryAfterKey)); ok {
				return delay, nil
			}
		}
	}

	const maxInt = 1<<31 - 1 // max int for arch 386
	if b.max < 0 {
		b.max = maxInt
	}

	var retryStrategyFunc RetryStrategyFunc
	if c != nil {
		retryStrategyFunc = c.RetryStrategy()
	}
	if res == nil || retryStrategyFunc == nil {
		return b.balanceMinMax(b.defaultStrategy(attempt)), nil
	}

	delay, rsErr := retryStrategyFunc(res, err)
	if rsErr != nil {
		return 0, rsErr
	}
	return b.balanceMinMax(delay), nil
}

// Return capped exponential backoff with jitter
// https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
func (b *backoffWithJitter) defaultStrategy(attempt int) time.Duration {
	temp := math.Min(float64(b.max), float64(b.min)*math.Exp2(float64(attempt)))
	ri := time.Duration(temp / 2)
	if ri <= 0 {
		ri = time.Nanosecond
	}
	return b.randDuration(ri)
}

func (b *backoffWithJitter) randDuration(center time.Duration) time.Duration {
	b.lock.Lock()
	defer b.lock.Unlock()

	var ri = int64(center)
	var jitter = b.rnd.Int63n(ri)
	return time.Duration(math.Abs(float64(ri + jitter)))
}

func (b *backoffWithJitter) balanceMinMax(delay time.Duration) time.Duration {
	if delay <= 0 || b.max < delay {
		return b.max
	}
	if delay < b.min {
		return b.min
	}
	return delay
}

var timeNow = time.Now

// parseRetryAfterHeader parses the Retry-After header and returns the
// delay duration according to the spec: https://httpwg.org/specs/rfc7231.html#header.retry-after
// The bool returned will be true if the header was successfully parsed.
// Otherwise, the header was either not present, or was not parseable according to the spec.
//
// Retry-After headers come in two flavors: Seconds or HTTP-Date
//
// Examples:
//   - Retry-After: Fri, 31 Dec 1999 23:59:59 GMT
//   - Retry-After: 120
func parseRetryAfterHeader(v string) (time.Duration, bool) {
	if isStringEmpty(v) {
		return 0, false
	}

	// Retry-After: 120
	if delay, err := strconv.ParseInt(v, 10, 64); err == nil {
		if delay < 0 { // a negative delay doesn't make sense
			return 0, false
		}
		return time.Second * time.Duration(delay), true
	}

	// Retry-After: Fri, 31 Dec 1999 23:59:59 GMT
	retryTime, err := time.Parse(time.RFC1123, v)
	if err != nil {
		return 0, false
	}
	if until := retryTime.Sub(timeNow()); until > 0 {
		return until, true
	}

	// date is in the past
	return 0, true
}
