// Copyright (c) 2015-2021 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBackoffSuccess(t *testing.T) {
	attempts := 3
	externalCounter := 0
	retryErr := Backoff(func() (*Response, error) {
		externalCounter++
		if externalCounter < attempts {
			return nil, errors.New("not yet got the number we're after")
		}

		return nil, nil
	})

	assertError(t, retryErr)
	assertEqual(t, externalCounter, attempts)
}

func TestBackoffNoWaitForLastRetry(t *testing.T) {
	attempts := 1
	externalCounter := 0
	numRetries := 1

	canceledCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resp := &Response{
		Request: &Request{
			ctx: canceledCtx,
			client: &Client{
				RetryAfter: func(*Client, *Response) (time.Duration, error) {
					return 6, nil
				},
			},
		},
	}

	retryErr := Backoff(func() (*Response, error) {
		externalCounter++
		return resp, nil
	}, RetryConditions([]RetryConditionFunc{func(response *Response, err error) bool {
		if externalCounter == attempts + numRetries {
			// Backoff returns context canceled if goes to sleep after last retry.
			cancel()
		}
		return true
	}}), Retries(numRetries))

	assertNil(t, retryErr)
}

func TestBackoffTenAttemptsSuccess(t *testing.T) {
	attempts := 10
	externalCounter := 0
	retryErr := Backoff(func() (*Response, error) {
		externalCounter++
		if externalCounter < attempts {
			return nil, errors.New("not yet got the number we're after")
		}
		return nil, nil
	}, Retries(attempts), WaitTime(5), MaxWaitTime(500))

	assertError(t, retryErr)
	assertEqual(t, externalCounter, attempts)
}

// Check to make sure the conditional of the retry condition is being used
func TestConditionalBackoffCondition(t *testing.T) {
	attempts := 3
	counter := 0
	check := RetryConditionFunc(func(*Response, error) bool {
		return attempts != counter
	})
	retryErr := Backoff(func() (*Response, error) {
		counter++
		return nil, nil
	}, RetryConditions([]RetryConditionFunc{check}))

	assertError(t, retryErr)
	assertEqual(t, counter, attempts)
}

// Check to make sure that if the conditional is false we don't retry
func TestConditionalBackoffConditionNonExecution(t *testing.T) {
	attempts := 3
	counter := 0

	retryErr := Backoff(func() (*Response, error) {
		counter++
		return nil, nil
	}, RetryConditions([]RetryConditionFunc{filler}))

	assertError(t, retryErr)
	assertNotEqual(t, counter, attempts)
}

// Check to make sure that RetryHooks are executed
func TestOnRetryBackoff(t *testing.T) {
	attempts := 3
	counter := 0

	hook := func(r *Response, err error) {
		counter++
	}

	retryErr := Backoff(func() (*Response, error) {
		return nil, nil
	}, RetryHooks([]OnRetryFunc{hook}))

	assertError(t, retryErr)
	assertNotEqual(t, counter, attempts)
}

// Check to make sure the functions added to add conditionals work
func TestConditionalGet(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()
	attemptCount := 1
	externalCounter := 0

	// This check should pass on first run, and let the response through
	check := RetryConditionFunc(func(*Response, error) bool {
		externalCounter++
		return attemptCount != externalCounter
	})

	client := dc().AddRetryCondition(check).SetRetryCount(1)
	resp, err := client.R().
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertNotNil(t, resp.Body())
	assertEqual(t, "TestGet: text response", resp.String())
	assertEqual(t, externalCounter, attemptCount)

	logResponse(t, resp)
}

// Check to make sure the package Function works.
func TestConditionalGetDefaultClient(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()
	attemptCount := 1
	externalCounter := 0

	// This check should pass on first run, and let the response through
	check := RetryConditionFunc(func(*Response, error) bool {
		externalCounter++
		return attemptCount != externalCounter
	})

	// Clear the default client.
	client := dc()
	// Proceed to check.
	client.AddRetryCondition(check).SetRetryCount(1)
	resp, err := client.R().
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertNotNil(t, resp.Body())
	assertEqual(t, "TestGet: text response", resp.String())
	assertEqual(t, externalCounter, attemptCount)

	logResponse(t, resp)
}

func TestClientRetryGet(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc().
		SetTimeout(time.Second * 3).
		SetRetryCount(3)

	resp, err := c.R().Get(ts.URL + "/set-retrycount-test")
	assertEqual(t, "", resp.Status())
	assertEqual(t, "", resp.Proto())
	assertEqual(t, 0, resp.StatusCode())
	assertEqual(t, 0, len(resp.Cookies()))
	assertNotNil(t, resp.Body())
	assertEqual(t, 0, len(resp.Header()))

	assertEqual(t, true, strings.HasPrefix(err.Error(), "Get "+ts.URL+"/set-retrycount-test") ||
		strings.HasPrefix(err.Error(), "Get \""+ts.URL+"/set-retrycount-test\""))
}

func TestClientRetryWait(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	attempt := 0

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := time.Duration(3) * time.Second
	retryMaxWaitTime := time.Duration(9) * time.Second

	c := dc().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		AddRetryCondition(
			func(r *Response, _ error) bool {
				timeSlept, _ := strconv.ParseUint(string(r.Body()), 10, 64)
				retryIntervals[attempt] = timeSlept
				attempt++
				return true
			},
		)
	_, _ = c.R().Get(ts.URL + "/set-retrywaittime-test")

	// 6 attempts were made
	assertEqual(t, attempt, 6)

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	for i := 1; i < len(retryIntervals); i++ {
		slept := time.Duration(retryIntervals[i])
		// Ensure that client has slept some duration between
		// waitTime and maxWaitTime for consequent requests
		if slept < retryWaitTime || slept > retryMaxWaitTime {
			t.Errorf("Client has slept %f seconds before retry %d", slept.Seconds(), i)
		}
	}
}

func TestClientRetryWaitMaxInfinite(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	attempt := 0

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := time.Duration(3) * time.Second
	retryMaxWaitTime := time.Duration(-1.0) // negative value

	c := dc().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		AddRetryCondition(
			func(r *Response, _ error) bool {
				timeSlept, _ := strconv.ParseUint(string(r.Body()), 10, 64)
				retryIntervals[attempt] = timeSlept
				attempt++
				return true
			},
		)
	_, _ = c.R().Get(ts.URL + "/set-retrywaittime-test")

	// 6 attempts were made
	assertEqual(t, attempt, 6)

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	for i := 1; i < len(retryIntervals); i++ {
		slept := time.Duration(retryIntervals[i])
		// Ensure that client has slept some duration between
		// waitTime and maxWaitTime for consequent requests
		if slept < retryWaitTime {
			t.Errorf("Client has slept %f seconds before retry %d", slept.Seconds(), i)
		}
	}
}

func TestClientRetryWaitCallbackError(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	attempt := 0

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := 3 * time.Second
	retryMaxWaitTime := 9 * time.Second

	retryAfter := func(client *Client, resp *Response) (time.Duration, error) {
		return 0, errors.New("quota exceeded")
	}

	c := dc().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		SetRetryAfter(retryAfter).
		AddRetryCondition(
			func(r *Response, _ error) bool {
				timeSlept, _ := strconv.ParseUint(string(r.Body()), 10, 64)
				retryIntervals[attempt] = timeSlept
				attempt++
				return true
			},
		)

	_, err := c.R().Get(ts.URL + "/set-retrywaittime-test")

	// 1 attempts were made
	assertEqual(t, attempt, 1)

	// non-nil error was returned
	assertNotEqual(t, nil, err)
}

func TestClientRetryWaitCallback(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	attempt := 0

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := 3 * time.Second
	retryMaxWaitTime := 9 * time.Second

	retryAfter := func(client *Client, resp *Response) (time.Duration, error) {
		return 5 * time.Second, nil
	}

	c := dc().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		SetRetryAfter(retryAfter).
		AddRetryCondition(
			func(r *Response, _ error) bool {
				timeSlept, _ := strconv.ParseUint(string(r.Body()), 10, 64)
				retryIntervals[attempt] = timeSlept
				attempt++
				return true
			},
		)
	_, _ = c.R().Get(ts.URL + "/set-retrywaittime-test")

	// 6 attempts were made
	assertEqual(t, attempt, 6)

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	for i := 1; i < len(retryIntervals); i++ {
		slept := time.Duration(retryIntervals[i])
		// Ensure that client has slept some duration between
		// waitTime and maxWaitTime for consequent requests
		if slept < 5*time.Second-5*time.Millisecond || 5*time.Second+5*time.Millisecond < slept {
			t.Logf("Client has slept %f seconds before retry %d", slept.Seconds(), i)
		}
	}
}

func TestClientRetryWaitCallbackTooShort(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	attempt := 0

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := 3 * time.Second
	retryMaxWaitTime := 9 * time.Second

	retryAfter := func(client *Client, resp *Response) (time.Duration, error) {
		return 2 * time.Second, nil // too short duration
	}

	c := dc().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		SetRetryAfter(retryAfter).
		AddRetryCondition(
			func(r *Response, _ error) bool {
				timeSlept, _ := strconv.ParseUint(string(r.Body()), 10, 64)
				retryIntervals[attempt] = timeSlept
				attempt++
				return true
			},
		)
	_, _ = c.R().Get(ts.URL + "/set-retrywaittime-test")

	// 6 attempts were made
	assertEqual(t, attempt, 6)

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	for i := 1; i < len(retryIntervals); i++ {
		slept := time.Duration(retryIntervals[i])
		// Ensure that client has slept some duration between
		// waitTime and maxWaitTime for consequent requests
		if slept < retryWaitTime-5*time.Millisecond || retryWaitTime+5*time.Millisecond < slept {
			t.Logf("Client has slept %f seconds before retry %d", slept.Seconds(), i)
		}
	}
}

func TestClientRetryWaitCallbackTooLong(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	attempt := 0

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := 1 * time.Second
	retryMaxWaitTime := 3 * time.Second

	retryAfter := func(client *Client, resp *Response) (time.Duration, error) {
		return 4 * time.Second, nil // too long duration
	}

	c := dc().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		SetRetryAfter(retryAfter).
		AddRetryCondition(
			func(r *Response, _ error) bool {
				timeSlept, _ := strconv.ParseUint(string(r.Body()), 10, 64)
				retryIntervals[attempt] = timeSlept
				attempt++
				return true
			},
		)
	_, _ = c.R().Get(ts.URL + "/set-retrywaittime-test")

	// 6 attempts were made
	assertEqual(t, attempt, 6)

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	for i := 1; i < len(retryIntervals); i++ {
		slept := time.Duration(retryIntervals[i])
		// Ensure that client has slept some duration between
		// waitTime and maxWaitTime for consequent requests
		if slept < retryMaxWaitTime-5*time.Millisecond || retryMaxWaitTime+5*time.Millisecond < slept {
			t.Logf("Client has slept %f seconds before retry %d", slept.Seconds(), i)
		}
	}
}

func TestClientRetryWaitCallbackSwitchToDefault(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	attempt := 0

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := 1 * time.Second
	retryMaxWaitTime := 3 * time.Second

	retryAfter := func(client *Client, resp *Response) (time.Duration, error) {
		return 0, nil // use default algorithm to determine retry-after time
	}

	c := dc().
		EnableTrace().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		SetRetryAfter(retryAfter).
		AddRetryCondition(
			func(r *Response, _ error) bool {
				timeSlept, _ := strconv.ParseUint(string(r.Body()), 10, 64)
				retryIntervals[attempt] = timeSlept
				attempt++
				return true
			},
		)
	resp, _ := c.R().Get(ts.URL + "/set-retrywaittime-test")

	// 6 attempts were made
	assertEqual(t, attempt, 6)
	assertEqual(t, resp.Request.Attempt, 6)
	assertEqual(t, resp.Request.TraceInfo().RequestAttempt, 6)

	// Initial attempt has 0 time slept since last request
	assertEqual(t, retryIntervals[0], uint64(0))

	for i := 1; i < len(retryIntervals); i++ {
		slept := time.Duration(retryIntervals[i])
		expected := (1 << (uint(i - 1))) * time.Second
		if expected > retryMaxWaitTime {
			expected = retryMaxWaitTime
		}

		// Ensure that client has slept some duration between
		// waitTime and maxWaitTime for consequent requests
		if slept < expected/2-5*time.Millisecond || expected+5*time.Millisecond < slept {
			t.Errorf("Client has slept %f seconds before retry %d", slept.Seconds(), i)
		}
	}
}

func TestClientRetryCancel(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	attempt := 0

	retryCount := 5
	retryIntervals := make([]uint64, retryCount+1)

	// Set retry wait times that do not intersect with default ones
	retryWaitTime := time.Duration(10) * time.Second
	retryMaxWaitTime := time.Duration(20) * time.Second

	c := dc().
		SetRetryCount(retryCount).
		SetRetryWaitTime(retryWaitTime).
		SetRetryMaxWaitTime(retryMaxWaitTime).
		AddRetryCondition(
			func(r *Response, _ error) bool {
				timeSlept, _ := strconv.ParseUint(string(r.Body()), 10, 64)
				retryIntervals[attempt] = timeSlept
				attempt++
				return true
			},
		)

	timeout := 2 * time.Second

	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	_, _ = c.R().SetContext(ctx).Get(ts.URL + "/set-retrywaittime-test")

	// 1 attempts were made
	assertEqual(t, attempt, 1)

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

	usersmap := map[string]interface{}{
		"user1": map[string]interface{}{"FirstName": "firstname1", "LastName": "lastname1", "ZipCode": "10001"},
	}

	var users []map[string]interface{}
	users = append(users, usersmap)

	c := dc()
	c.SetRetryCount(3)
	c.AddRetryCondition(RetryConditionFunc(func(r *Response, _ error) bool {
		return r.StatusCode() >= http.StatusInternalServerError
	}))

	resp, _ := c.R().
		SetBody(&users).
		Post(ts.URL + "/usersmap?status=500")

	if resp != nil {
		if resp.StatusCode() == http.StatusInternalServerError {
			t.Logf("Got response body: %s", string(resp.body))
			var usersResponse []map[string]interface{}
			err := json.Unmarshal(resp.body, &usersResponse)
			assertError(t, err)

			if !reflect.DeepEqual(users, usersResponse) {
				t.Errorf("Expected request body to be echoed back as response body. Instead got: %s", string(resp.body))
			}

			return
		}
		t.Errorf("Got unexpected response code: %d with body: %s", resp.StatusCode(), string(resp.body))
	}
}

func TestClientRetryErrorRecover(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc().
		SetRetryCount(2).
		SetError(AuthError{}).
		AddRetryCondition(
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

func TestClientRetryCount(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	attempt := 0

	c := dc().
		SetTimeout(time.Second * 3).
		SetRetryCount(1).
		AddRetryCondition(
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
	assertNotNil(t, resp.Body())
	assertEqual(t, 0, len(resp.Header()))

	// 2 attempts were made
	assertEqual(t, attempt, 2)

	assertEqual(t, true, strings.HasPrefix(err.Error(), "Get "+ts.URL+"/set-retrycount-test") ||
		strings.HasPrefix(err.Error(), "Get \""+ts.URL+"/set-retrycount-test\""))
}

func TestClientErrorRetry(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc().
		SetTimeout(time.Second * 3).
		SetRetryCount(1).
		AddRetryAfterErrorCondition()

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

func TestClientRetryHook(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	attempt := 0

	c := dc().
		SetRetryCount(2).
		SetTimeout(time.Second * 3).
		AddRetryHook(
			func(r *Response, _ error) {
				attempt++
			},
		)

	resp, err := c.R().Get(ts.URL + "/set-retrycount-test")
	assertEqual(t, "", resp.Status())
	assertEqual(t, "", resp.Proto())
	assertEqual(t, 0, resp.StatusCode())
	assertEqual(t, 0, len(resp.Cookies()))
	assertNotNil(t, resp.Body())
	assertEqual(t, 0, len(resp.Header()))

	assertEqual(t, 3, attempt)

	assertEqual(t, true, strings.HasPrefix(err.Error(), "Get "+ts.URL+"/set-retrycount-test") ||
		strings.HasPrefix(err.Error(), "Get \""+ts.URL+"/set-retrycount-test\""))
}

func filler(*Response, error) bool {
	return false
}
