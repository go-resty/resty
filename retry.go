// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"crypto/tls"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

const (
	defaultWaitTime    = time.Duration(100) * time.Millisecond
	defaultMaxWaitTime = time.Duration(2000) * time.Millisecond
)

type (
	// RetryConditionFunc is the function type used to decide whether a request
	// should be retried. It receives the response and any execution error from the
	// previous attempt. Either argument may be nil:
	//   - res is nil when no HTTP response was received (e.g. network error)
	//   - err is nil when the request completed without a transport error
	RetryConditionFunc func(*Response, error) bool

	// RetryHookFunc is a side-effecting function called after each failed attempt
	// and before the next retry. It can be used for logging, metrics, or mutating
	// request state. It receives the same response and error as [RetryConditionFunc].
	RetryHookFunc func(*Response, error)

	// RetryDelayStrategyFunc defines a custom retry delay strategy.
	// It receives the response/error from the previous attempt and returns the
	// wait duration before the next retry.
	// By default, Resty uses capped exponential backoff with jitter.
	RetryDelayStrategyFunc func(*Response, error) (time.Duration, error)
)

// RetryConstantDelayStrategy returns a [RetryDelayStrategyFunc] that always
// returns the specified delay duration.
func RetryConstantDelayStrategy(delay time.Duration) RetryDelayStrategyFunc {
	return func(*Response, error) (time.Duration, error) {
		return delay, nil
	}
}

var (
	regexErrTooManyRedirects = regexp.MustCompile(`stopped after \d+ redirects\z`)
	regexErrScheme           = regexp.MustCompile("unsupported protocol scheme")
	regexErrInvalidHeader    = regexp.MustCompile("invalid header")
)

// RetryConditionStatusTooManyRequests is a RetryConditionFunc that returns true
// if the response status code is 429 Too Many Requests.
//
//   - The 429 status code indicates that the user has sent too many requests in a given amount
//     of time ("rate limiting").
//   - Retrying after receiving a 429 status code can be effective, especially if the server includes
//     a Retry-After header indicating when to retry.
func RetryConditionStatusTooManyRequests(res *Response, _ error) bool {
	if res == nil {
		return false
	}
	return res.StatusCode() == http.StatusTooManyRequests
}

// RetryConditionStatus5XX is a [RetryConditionFunc] that returns true when the
// response status code is 500 or above, excluding 501 (Not Implemented).
//
//   - 5XX status codes are generally considered temporary server errors that may be resolved on retry.
//   - The rationale for excluding 501 Not Implemented is that it indicates the server does not support the
//     functionality required to fulfill the request.
func RetryConditionStatus5XX(res *Response, _ error) bool {
	if res == nil {
		return false
	}
	return res.StatusCode() >= 500 && res.StatusCode() != http.StatusNotImplemented
}

// RetryConditionStatusZero is a [RetryConditionFunc] that returns true if the
// response status code is 0.
//
//   - A status code of 0 typically indicates that no response was received from the server, which can occur
//     due to network errors, timeouts, or other issues that prevent the request from being completed.
//   - Retrying when a status code of 0 is encountered can be effective, as it may allow the request to succeed
//     on subsequent attempts if the underlying issue is transient.
func RetryConditionStatusZero(res *Response, _ error) bool {
	if res == nil {
		return false
	}
	return res.StatusCode() == 0
}

// isDoNotRetryError checks whether the given request error should trigger a retry.
//
// It returns true only for retryable URL/network errors and false for errors that
// should not be retried, such as TLS certificate errors, invalid scheme, invalid
// headers, and too many redirects. A nil error returns false.
func isDoNotRetryError(err error) bool {
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
		rnd: rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
		min: min,
		max: max,
	}
}

type backoffWithJitter struct {
	rnd *rand.Rand
	min time.Duration
	max time.Duration
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

	if res == nil || res.Request.RetryDelayStrategy == nil {
		return b.balanceMinMax(b.defaultDelayStrategy(attempt)), nil
	}

	// invoke custom retry delay strategy
	return res.Request.RetryDelayStrategy(res, err)
}

// defaultDelayStrategy returns capped exponential backoff with jitter.
// https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
func (b *backoffWithJitter) defaultDelayStrategy(attempt int) time.Duration {
	temp := math.Min(float64(b.max), float64(b.min)*math.Exp2(float64(attempt)))
	ri := time.Duration(temp / 2)
	if ri <= 0 {
		ri = time.Nanosecond
	}
	return b.randDuration(ri)
}

func (b *backoffWithJitter) randDuration(center time.Duration) time.Duration {
	var ri = int64(center)
	var jitter = b.rnd.Int64N(ri)
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

// parseRetryAfterHeader parses the Retry-After header and returns the delay
// duration according to the spec:
// https://httpwg.org/specs/rfc7231.html#header.retry-after
// The bool return value is true when the header was successfully parsed.
// Otherwise, the header was either not present or not parseable.
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
