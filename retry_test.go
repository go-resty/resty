// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Check to make sure the functions added to add conditionals work
func TestRetryConditionalGet(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()
	attemptCount := 1
	externalCounter := 0

	// This check should pass on first run, and let the response through
	check := RetryConditionFunc(func(*Response, error) bool {
		externalCounter++
		return attemptCount != externalCounter
	})

	client := dcnl()
	resp, err := client.R().
		AddRetryConditions(check).
		SetRetryCount(2).
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())
	assertEqual(t, externalCounter, attemptCount)

	logResponse(t, resp)
}

func TestRequestConditionalGet(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	externalCounter := 0
	// This check should pass on first run, and let the response through
	check := RetryConditionFunc(func(r *Response, _ error) bool {
		externalCounter++
		return false
	})

	// Clear the default client.
	c, lb := dcldb()

	resp, err := c.R().
		EnableDebug().
		AddRetryConditions(check).
		SetRetryCount(1).
		SetRetryWaitTime(50*time.Millisecond).
		SetRetryMaxWaitTime(1*time.Second).
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())
	assertEqual(t, 1, resp.Request.Attempt)
	assertEqual(t, 1, externalCounter)
	assertEqual(t, true, strings.Contains(lb.String(), "RETRY TRACE ID:"))

	logResponse(t, resp)
}

func TestClientRetryGetWithTimeout(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl().
		SetTimeout(50 * time.Millisecond).
		SetRetryCount(3)

	resp, err := c.R().Get(ts.URL + "/set-retrycount-test")
	assertEqual(t, "", resp.Status())
	assertEqual(t, "", resp.Proto())
	assertEqual(t, 0, resp.StatusCode())
	assertEqual(t, 0, len(resp.Cookies()))
	assertEqual(t, 0, len(resp.Header()))
	assertEqual(t, true, errors.Is(err, context.DeadlineExceeded))
}

func TestClientRetryWithMinAndMaxWaitTime(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := 10 * time.Millisecond
	retryMaxWaitTime := 100 * time.Millisecond

	c, lb := dcldb()

	c.SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		AddRetryConditions(
			func(r *Response, _ error) bool {
				retryIntervals[r.Request.Attempt-1] = parseTimeSleptFromResponse(r.String())
				return true
			},
		)
	res, _ := c.R().EnableDebug().Get(ts.URL + "/set-retrywaittime-test")

	retryIntervals[res.Request.Attempt-1] = parseTimeSleptFromResponse(res.String())

	// retryCount+1 == attempts were made
	assertEqual(t, retryCount+1, res.Request.Attempt)

	assertEqual(t, true, strings.Contains(lb.String(), "RETRY TRACE ID:"))

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	for i := 1; i < len(retryIntervals); i++ {
		slept := time.Duration(retryIntervals[i])
		// Ensure that client has slept some duration between
		// waitTime and maxWaitTime for consequent requests
		if slept < retryWaitTime-5*time.Millisecond {
			t.Logf("Client has slept %f seconds which is s < min (%f) before retry %d", slept.Seconds(), retryWaitTime.Seconds(), i)
		}
		if slept > retryMaxWaitTime+5*time.Millisecond {
			t.Logf("Client has slept %f seconds which is s > max (%f) before retry %d", slept.Seconds(), retryMaxWaitTime.Seconds(), i)
		}
	}
}

func TestClientRetryWaitMaxInfinite(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := time.Duration(10) * time.Millisecond
	retryMaxWaitTime := time.Duration(-1.0) // negative value

	c := dcnl().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		AddRetryConditions(
			func(r *Response, _ error) bool {
				retryIntervals[r.Request.Attempt-1] = parseTimeSleptFromResponse(r.String())
				return true
			},
		)
	res, _ := c.R().Get(ts.URL + "/set-retrywaittime-test")

	retryIntervals[res.Request.Attempt-1] = parseTimeSleptFromResponse(res.String())

	// retryCount+1 == attempts were made
	assertEqual(t, retryCount+1, res.Request.Attempt)

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	for i := 1; i < len(retryIntervals); i++ {
		slept := time.Duration(retryIntervals[i])
		// Ensure that client has slept some duration between
		// waitTime and maxWaitTime for consequent requests
		if slept < retryWaitTime-5*time.Millisecond {
			t.Logf("Client has slept %f seconds which is s < min (%f) before retry %d", slept.Seconds(), retryWaitTime.Seconds(), i)
		}
	}
}

func TestClientRetryWaitMaxMinimum(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	const retryMaxWaitTime = time.Nanosecond // minimal duration value

	c := dcnl().
		SetRetryCount(1).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		AddRetryConditions(func(*Response, error) bool { return true })
	_, err := c.R().Get(ts.URL + "/set-retrywaittime-test")
	assertError(t, err)
}

func TestClientRetryStrategyFuncError(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	attempt := 0
	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := 50 * time.Millisecond
	retryMaxWaitTime := 150 * time.Millisecond

	retryStrategyFunc := func(res *Response, err error) (time.Duration, error) {
		return 0, errors.New("quota exceeded")
	}

	c := dcnl().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		SetRetryStrategy(retryStrategyFunc).
		AddRetryConditions(
			func(r *Response, _ error) bool {
				retryIntervals[attempt] = parseTimeSleptFromResponse(r.String())
				attempt++
				return true
			},
		)

	_, err := c.R().Get(ts.URL + "/set-retrywaittime-test")

	// 1 attempts were made
	assertEqual(t, 1, attempt)

	// non-nil error was returned
	assertNotNil(t, err)
}

func TestClientRetryStrategyFunc(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	retryCount := 10
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times to constant delay
	retryWaitTime := 50 * time.Millisecond
	retryMaxWaitTime := 50 * time.Millisecond

	// custom strategy func with constant delay
	retryStrategyFunc := func(res *Response, err error) (time.Duration, error) {
		return 50 * time.Millisecond, nil
	}

	c := dcnl().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		SetRetryStrategy(retryStrategyFunc).
		AddRetryConditions(
			func(r *Response, _ error) bool {
				retryIntervals[r.Request.Attempt-1] = parseTimeSleptFromResponse(r.String())
				return true
			},
		)
	res, _ := c.R().Get(ts.URL + "/set-retrywaittime-test")

	retryIntervals[res.Request.Attempt-1] = parseTimeSleptFromResponse(res.String())

	// retryCount+1 == attempts were made
	assertEqual(t, retryCount+1, res.Request.Attempt)

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	for i := 1; i < len(retryIntervals); i++ {
		slept := time.Duration(retryIntervals[i])
		// Ensure that client has slept some duration between
		// waitTime and maxWaitTime for consequent requests
		if slept < retryWaitTime-5*time.Millisecond {
			t.Logf("Client has slept %f seconds which is s < min (%f) before retry %d", slept.Seconds(), retryWaitTime.Seconds(), i)
		}
		if retryMaxWaitTime+5*time.Millisecond < slept {
			t.Logf("Client has slept %f seconds which is max < s (%f) before retry %d", slept.Seconds(), retryMaxWaitTime.Seconds(), i)
		}
	}
}

func TestRequestRetryStrategyFunc(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	retryCount := 10
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times to constant delay
	retryWaitTime := 50 * time.Millisecond
	retryMaxWaitTime := 50 * time.Millisecond

	// custom strategy func with constant delay
	retryStrategyFunc := func(res *Response, err error) (time.Duration, error) {
		return 50 * time.Millisecond, nil
	}

	c := dcnl()

	res, _ := c.R().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		SetRetryStrategy(retryStrategyFunc).
		AddRetryConditions(
			func(r *Response, _ error) bool {
				retryIntervals[r.Request.Attempt-1] = parseTimeSleptFromResponse(r.String())
				return true
			},
		).
		Get(ts.URL + "/set-retrywaittime-test")

	retryIntervals[res.Request.Attempt-1] = parseTimeSleptFromResponse(res.String())

	// retryCount+1 == attempts were made
	assertEqual(t, retryCount+1, res.Request.Attempt)

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	for i := 1; i < len(retryIntervals); i++ {
		slept := time.Duration(retryIntervals[i])
		// Ensure that client has slept some duration between
		// waitTime and maxWaitTime for consequent requests
		if slept < retryWaitTime-5*time.Millisecond {
			t.Logf("Client has slept %f seconds which is s < min (%f) before retry %d", slept.Seconds(), retryWaitTime.Seconds(), i)
		}
		if retryMaxWaitTime+5*time.Millisecond < slept {
			t.Logf("Client has slept %f seconds which is max < s (%f) before retry %d", slept.Seconds(), retryMaxWaitTime.Seconds(), i)
		}
	}
}

func TestClientRetryStrategyWaitTooShort(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := 50 * time.Millisecond
	retryMaxWaitTime := 150 * time.Millisecond

	retryStrategyFunc := func(res *Response, err error) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	}

	c := dcnl().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		SetRetryStrategy(retryStrategyFunc).
		AddRetryConditions(
			func(r *Response, _ error) bool {
				retryIntervals[r.Request.Attempt-1] = parseTimeSleptFromResponse(r.String())
				return true
			},
		)
	res, _ := c.R().Get(ts.URL + "/set-retrywaittime-test")

	retryIntervals[res.Request.Attempt-1] = parseTimeSleptFromResponse(res.String())

	// retryCount+1 == attempts were made
	assertEqual(t, retryCount+1, res.Request.Attempt)

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	for i := 1; i < len(retryIntervals); i++ {
		slept := time.Duration(retryIntervals[i])
		// Ensure that client has slept some duration between
		// waitTime and maxWaitTime for consequent requests
		if slept < retryWaitTime-5*time.Millisecond {
			t.Logf("Client has slept %f seconds which is s < min (%f) before retry %d", slept.Seconds(), retryWaitTime.Seconds(), i)
		}
		if retryWaitTime+5*time.Millisecond < slept {
			t.Logf("Client has slept %f seconds which is min < s (%f) before retry %d", slept.Seconds(), retryWaitTime.Seconds(), i)
		}
	}
}

func TestClientRetryStrategyWaitTooLong(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := 10 * time.Millisecond
	retryMaxWaitTime := 50 * time.Millisecond

	retryStrategyFunc := func(res *Response, err error) (time.Duration, error) {
		return 1 * time.Second, nil
	}

	c := dcnl().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		SetRetryStrategy(retryStrategyFunc).
		AddRetryConditions(
			func(r *Response, _ error) bool {
				retryIntervals[r.Request.Attempt-1] = parseTimeSleptFromResponse(r.String())
				return true
			},
		)
	res, _ := c.R().Get(ts.URL + "/set-retrywaittime-test")

	retryIntervals[res.Request.Attempt-1] = parseTimeSleptFromResponse(res.String())

	// retryCount+1 == attempt attempts were made
	assertEqual(t, retryCount+1, res.Request.Attempt)

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	for i := 1; i < len(retryIntervals); i++ {
		slept := time.Duration(retryIntervals[i])
		// Ensure that client has slept some duration between
		// waitTime and maxWaitTime for consequent requests
		if slept < retryMaxWaitTime-5*time.Millisecond {
			t.Logf("Client has slept %f seconds which is s < max (%f) before retry %d", slept.Seconds(), retryMaxWaitTime.Seconds(), i)
		}
		if retryMaxWaitTime+5*time.Millisecond < slept {
			t.Logf("Client has slept %f seconds which is max < s (%f) before retry %d", slept.Seconds(), retryMaxWaitTime.Seconds(), i)
		}
	}
}

func TestClientRetryCancel(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := 100 * time.Millisecond
	retryMaxWaitTime := 200 * time.Millisecond

	c := dcnl().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		AddRetryConditions(
			func(r *Response, _ error) bool {
				retryIntervals[r.Request.Attempt-1] = parseTimeSleptFromResponse(r.String())
				return true
			},
		)

	timeout := 100 * time.Millisecond

	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	req := c.R().SetContext(ctx)
	_, _ = req.Get(ts.URL + "/set-retrywaittime-test")

	// 1 attempts were made
	assertEqual(t, 1, req.Attempt)

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	// Second attempt should be interrupted on context timeout
	if time.Duration(retryIntervals[1]) > timeout {
		t.Errorf("Client didn't awake on context cancel")
	}
	cancelFunc()
}

func TestClientRetryPost(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	usersmap := map[string]any{
		"user1": map[string]any{"FirstName": "firstname1", "LastName": "lastname1", "ZipCode": "10001"},
	}

	var users []map[string]any
	users = append(users, usersmap)

	c := dcnl()
	c.SetRetryCount(3)
	c.AddRetryConditions(RetryConditionFunc(func(r *Response, _ error) bool {
		return r.StatusCode() >= http.StatusInternalServerError
	}))

	resp, _ := c.R().
		SetBody(&users).
		Post(ts.URL + "/usersmap?status=500")

	if resp != nil {
		if resp.StatusCode() == http.StatusInternalServerError {
			t.Logf("Got response body: %s", resp.String())
			var usersResponse []map[string]any
			err := json.Unmarshal(resp.Bytes(), &usersResponse)
			assertError(t, err)

			if !reflect.DeepEqual(users, usersResponse) {
				t.Errorf("Expected request body to be echoed back as response body. Instead got: %s", resp.String())
			}

			return
		}
		t.Errorf("Got unexpected response code: %d with body: %s", resp.StatusCode(), resp.String())
	}
}

func TestClientRetryErrorRecover(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl().
		SetRetryCount(2).
		SetError(AuthError{}).
		AddRetryConditions(
			func(r *Response, _ error) bool {
				err, ok := r.Error().(*AuthError)
				retry := ok && r.StatusCode() == 429 && err.Message == "too many"
				return retry
			},
		)

	resp, err := c.R().
		SetHeader(hdrContentTypeKey, "application/json; charset=utf-8").
		SetJSONEscapeHTML(false).
		SetResult(AuthSuccess{}).
		Get(ts.URL + "/set-retry-error-recover")

	assertError(t, err)

	authSuccess := resp.Result().(*AuthSuccess)

	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "hello", authSuccess.Message)

	assertNil(t, resp.Error())
}

func TestClientRetryCountWithTimeout(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	attempt := 0

	c := dcnl().
		SetTimeout(50 * time.Millisecond).
		SetRetryCount(1).
		AddRetryConditions(
			func(r *Response, _ error) bool {
				attempt++
				return true
			},
		)

	resp, err := c.R().Get(ts.URL + "/set-retrycount-test")
	assertEqual(t, "", resp.Status())
	assertEqual(t, "", resp.Proto())
	assertEqual(t, 0, resp.StatusCode())
	assertEqual(t, 0, len(resp.Cookies()))
	assertEqual(t, 0, len(resp.Header()))
	assertEqual(t, 2, resp.Request.Attempt)
	assertEqual(t, true, errors.Is(err, context.DeadlineExceeded))
}

func TestClientRetryTooManyRequestsAndRecover(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl().
		SetTimeout(time.Second * 1).
		SetRetryCount(2)

	resp, err := c.R().
		SetHeader(hdrContentTypeKey, "application/json; charset=utf-8").
		SetJSONEscapeHTML(false).
		SetResult(AuthSuccess{}).
		SetTimeout(10 * time.Millisecond).
		Get(ts.URL + "/set-retry-error-recover")

	assertError(t, err)

	authSuccess := resp.Result().(*AuthSuccess)

	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "hello", authSuccess.Message)

	assertNil(t, resp.Error())
}

func TestClientRetryHookWithTimeout(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	hookCalledCount := 0

	retryHook := func(r *Response, _ error) {
		hookCalledCount++
	}

	retryCount := 3

	c := dcnl().
		SetRetryCount(retryCount).
		SetTimeout(50 * time.Millisecond).
		AddRetryHooks(retryHook)

	// Since reflect.DeepEqual can not compare two functions
	// just compare pointers of the two hooks
	originHookPointer := reflect.ValueOf(retryHook).Pointer()
	getterHookPointer := reflect.ValueOf(c.RetryHooks()[0]).Pointer()

	assertEqual(t, originHookPointer, getterHookPointer)

	resp, err := c.R().Get(ts.URL + "/set-retrycount-test")
	assertEqual(t, "", resp.Status())
	assertEqual(t, "", resp.Proto())
	assertEqual(t, 0, resp.StatusCode())
	assertEqual(t, 0, len(resp.Cookies()))
	assertEqual(t, 0, len(resp.Header()))

	assertEqual(t, retryCount+1, resp.Request.Attempt)
	assertEqual(t, 3, hookCalledCount)
	assertEqual(t, true, errors.Is(err, context.DeadlineExceeded))
}

var errSeekFailure = fmt.Errorf("failing seek test")

type failingSeeker struct {
	reader *bytes.Reader
}

func (f failingSeeker) Read(b []byte) (n int, err error) {
	return f.reader.Read(b)
}

func (f failingSeeker) Seek(offset int64, whence int) (int64, error) {
	if offset == 0 && whence == io.SeekStart {
		return 0, errSeekFailure
	}

	return f.reader.Seek(offset, whence)
}

func TestResetMultipartReaderSeekStartError(t *testing.T) {
	ts := createFileUploadServer(t)
	defer ts.Close()

	testSeeker := &failingSeeker{
		bytes.NewReader([]byte("test")),
	}

	c := dcnl().
		SetRetryCount(2).
		SetTimeout(200 * time.Millisecond)

	resp, err := c.R().
		SetFileReader("name", "filename", testSeeker).
		Put(ts.URL + "/set-reset-multipart-readers-test")

	assertEqual(t, 500, resp.StatusCode())
	assertEqual(t, err.Error(), errSeekFailure.Error())
}

func TestClientResetMultipartReaders(t *testing.T) {
	ts := createFileUploadServer(t)
	defer ts.Close()

	str := "test"
	buf := []byte(str)

	bufReader := bytes.NewReader(buf)
	bufCpy := make([]byte, len(buf))

	c := dcnl().
		SetRetryCount(2).
		SetTimeout(time.Second * 3).
		AddRetryHooks(
			func(response *Response, _ error) {
				read, err := bufReader.Read(bufCpy)

				assertNil(t, err)
				assertEqual(t, len(buf), read)
				assertEqual(t, str, string(bufCpy))
			},
		)

	resp, err := c.R().
		SetFileReader("name", "filename", bufReader).
		Put(ts.URL + "/set-reset-multipart-readers-test")

	assertEqual(t, 500, resp.StatusCode())
	assertNil(t, err)
}

func TestRequestResetMultipartReaders(t *testing.T) {
	ts := createFileUploadServer(t)
	defer ts.Close()

	str := "test"
	buf := []byte(str)

	bufReader := bytes.NewReader(buf)
	bufCpy := make([]byte, len(buf))

	c := dcnl().
		SetTimeout(time.Second * 3).
		AddRetryHooks(
			func(response *Response, _ error) {
				read, err := bufReader.Read(bufCpy)

				assertNil(t, err)
				assertEqual(t, len(buf), read)
				assertEqual(t, str, string(bufCpy))
			},
		)

	req := c.R().
		SetRetryCount(2).
		SetFileReader("name", "filename", bufReader)
	resp, err := req.Put(ts.URL + "/set-reset-multipart-readers-test")

	assertEqual(t, 500, resp.StatusCode())
	assertNil(t, err)
}

func TestParseRetryAfterHeader(t *testing.T) {
	testStaticTime(t)

	tests := []struct {
		name   string
		header string
		sleep  time.Duration
		ok     bool
	}{
		{"seconds", "2", time.Second * 2, true},
		{"date", "Fri, 31 Dec 1999 23:59:59 GMT", time.Second * 2, true},
		{"past-date", "Fri, 31 Dec 1999 23:59:00 GMT", 0, true},
		{"two-headers", "3", time.Second * 3, true},
		{"empty", "", 0, false},
		{"negative", "-2", 0, false},
		{"bad-date", "Fri, 32 Dec 1999 23:59:59 GMT", 0, false},
		{"bad-date-format", "badbadbad", 0, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sleep, ok := parseRetryAfterHeader(test.header)
			if ok != test.ok {
				t.Errorf("expected ok=%t, got ok=%t", test.ok, ok)
			}
			if sleep != test.sleep {
				t.Errorf("expected sleep=%v, got sleep=%v", test.sleep, sleep)
			}
		})
	}
}

func TestRequestRetryTooManyRequestsHeaderRetryAfter(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl()

	resp, err := c.R().
		SetRetryCount(2).
		SetHeader(hdrContentTypeKey, "application/json; charset=utf-8").
		SetResult(AuthSuccess{}).
		Get(ts.URL + "/retry-after-delay")

	assertError(t, err)

	authSuccess := resp.Result().(*AuthSuccess)

	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "hello", authSuccess.Message)

	assertNil(t, resp.Error())
}

func TestRetryDefaultConditions(t *testing.T) {
	t.Run("redirect error", func(t *testing.T) {
		ts := createRedirectServer(t)
		defer ts.Close()

		_, err := dcnl().R().
			SetRetryCount(2).
			Get(ts.URL + "/redirect-1")

		assertNotNil(t, err)
		assertEqual(t, true, (err.Error() == `Get "/redirect-11": stopped after 10 redirects`))
	})

	t.Run("invalid scheme error", func(t *testing.T) {
		ts := createGetServer(t)
		defer ts.Close()

		c := dcnl().SetBaseURL(strings.Replace(ts.URL, "http", "ftp", 1))

		_, err := c.R().
			SetRetryCount(2).
			Get("/")
		assertNotNil(t, err)
		assertEqual(t, true, strings.Contains(err.Error(), `unsupported protocol scheme "ftp"`))
	})

	t.Run("invalid header error", func(t *testing.T) {
		ts := createGetServer(t)
		defer ts.Close()

		_, err := dcnl().R().
			SetRetryCount(2).
			SetHeader("Header-Name", "bad header value \033").
			Get(ts.URL + "/")
		assertNotNil(t, err)
		assertEqual(t, true, strings.Contains(err.Error(), "net/http: invalid header field value"))

		_, err = dcnl().R().
			SetRetryCount(2).
			SetHeader("Header-Name\033", "bad header value").
			Get(ts.URL + "/")
		assertNotNil(t, err)
		assertEqual(t, true, strings.Contains(err.Error(), "net/http: invalid header field name"))
	})

	t.Run("nil values", func(t *testing.T) {
		result := applyRetryDefaultConditions(nil, nil)
		assertEqual(t, false, result)
	})
}

func TestRequestRetryPutIoReadSeekerForBuffer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		assertError(t, err)
		assertEqual(t, 12, len(b))
		assertEqual(t, "body content", string(b))
		w.WriteHeader(http.StatusInternalServerError)
	}))

	c := dcnl().
		AddRetryConditions(
			func(r *Response, err error) bool {
				return err != nil || r.StatusCode() > 499
			},
		).
		SetRetryCount(3).
		SetAllowNonIdempotentRetry(true)

	assertEqual(t, true, c.AllowNonIdempotentRetry())

	buf := bytes.NewBuffer([]byte("body content"))
	resp, err := c.R().
		SetBody(buf).
		SetAllowMethodGetPayload(false).
		Put(srv.URL)

	assertNil(t, err)
	assertEqual(t, 4, resp.Request.Attempt)
	assertEqual(t, http.StatusInternalServerError, resp.StatusCode())
	assertEqual(t, "", resp.String())
}

func TestRequestRetryPostIoReadSeeker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		assertError(t, err)
		assertEqual(t, 12, len(b))
		assertEqual(t, "body content", string(b))
		w.WriteHeader(http.StatusInternalServerError)
	}))

	c := dcnl().
		AddRetryConditions(
			func(r *Response, err error) bool {
				return err != nil || r.StatusCode() > 499
			},
		).
		SetRetryCount(3).
		SetAllowNonIdempotentRetry(false)

	assertEqual(t, false, c.AllowNonIdempotentRetry())

	resp, err := c.R().
		SetBody([]byte("body content")).
		SetAllowNonIdempotentRetry(true).
		Post(srv.URL)

	assertNil(t, err)
	assertEqual(t, 4, resp.Request.Attempt)
	assertEqual(t, http.StatusInternalServerError, resp.StatusCode())
	assertEqual(t, "", resp.String())
}

func TestRequestRetryHooks(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	hookFunc := func(msg string) RetryHookFunc {
		return func(res *Response, err error) {
			res.Request.log.Debugf(msg)
		}
	}

	c, lb := dcldb()
	c.AddRetryConditions(func(r *Response, err error) bool {
		return true
	}).
		AddRetryHooks(
			hookFunc("This is client hook1"),
			hookFunc("This is client hook2"),
		)

	_, _ = c.R().
		SetRetryCount(1).
		AddRetryHooks(hookFunc("This is request hook1")).
		SetRetryHooks(hookFunc("This is request overwrite hook1")).
		Get("/set-retrycount-test")

	debugLog := lb.String()
	assertEqual(t, false, strings.Contains(debugLog, "This is client hook1"))
	assertEqual(t, false, strings.Contains(debugLog, "This is client hook2"))
	assertEqual(t, false, strings.Contains(debugLog, "This is request hook1"))
	assertEqual(t, true, strings.Contains(debugLog, "This is request overwrite hook1"))
}

func TestRequestSetRetryConditions(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	condFunc := func(fn func() bool) RetryConditionFunc {
		return func(r *Response, err error) bool {
			return fn()
		}
	}

	c := dcnl().
		AddRetryConditions(
			condFunc(func() bool { return true }),
			condFunc(func() bool { return true }),
		)

	res, _ := c.R().
		SetRetryCount(2).
		SetRetryConditions(condFunc(func() bool { return false })). // disable retry with overwrite condition
		Get("/set-retrycount-test")

	assertEqual(t, 1, res.Request.Attempt)
}

func TestRequestRetryQueryParamsGH938(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	expectedQueryParams := "foo=baz&foo=bar&foo=bar"

	c := dcnl().
		SetBaseURL(ts.URL).
		SetRetryCount(5).
		SetRetryWaitTime(10 * time.Millisecond).
		SetRetryMaxWaitTime(20 * time.Millisecond).
		AddRetryConditions(
			func(r *Response, _ error) bool {
				assertEqual(t, expectedQueryParams, r.Request.RawRequest.URL.RawQuery)
				return true // always retry
			},
		)

	_, _ = c.R().
		SetQueryParamsFromValues(map[string][]string{
			"foo": {
				"baz",
				"bar",
				"bar",
			},
		}).
		Get("/set-retrycount-test")
}

func TestRetryCoverage(t *testing.T) {
	t.Run("apply retry default min and max value", func(t *testing.T) {
		backoff := newBackoffWithJitter(0, 0)
		assertEqual(t, defaultWaitTime, backoff.min)
		assertEqual(t, defaultMaxWaitTime, backoff.max)
	})

	t.Run("mock tls cert error", func(t *testing.T) {
		certError := tls.CertificateVerificationError{}
		result1 := applyRetryDefaultConditions(nil, &certError)
		assertEqual(t, false, result1)
	})
}

func parseTimeSleptFromResponse(v string) uint64 {
	timeSlept, _ := strconv.ParseUint(v, 10, 64)
	return timeSlept
}

func testStaticTime(t *testing.T) {
	timeNow = func() time.Time {
		now, err := time.Parse(time.RFC1123, "Fri, 31 Dec 1999 23:59:57 GMT")
		if err != nil {
			panic(err)
		}
		return now
	}
	t.Cleanup(func() {
		timeNow = time.Now
	})
}
