// Copyright (c) 2015-2016 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestBackoffSuccess(t *testing.T) {
	attempts := 3
	externalCounter := 0
	retryErr := Backoff(func() (*Response, error) {
		externalCounter++
		if externalCounter < attempts {
			return nil, errors.New("Not yet got the number we're after...")
		}

		return nil, nil
	})

	assertError(t, retryErr)
	assertEqual(t, externalCounter, attempts)
}

func TestBackoffTenAttemptsSuccess(t *testing.T) {
	attempts := 10
	externalCounter := 0
	retryErr := Backoff(func() (*Response, error) {
		externalCounter++
		if externalCounter < attempts {
			return nil, errors.New("Not yet got the number we're after...")
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
	check := RetryConditionFunc(func(*Response) (bool, error) {
		return attempts != counter, nil
	})
	retryErr := Backoff(func() (*Response, error) {
		counter++
		return nil, nil
	}, RetryConditions([]RetryConditionFunc{check}))

	assertError(t, retryErr)
	assertEqual(t, counter, attempts)
}

// Check to make sure that errors in the conditional cause a retry
func TestConditionalBackoffConditionError(t *testing.T) {
	attempts := 3
	counter := 0
	check := RetryConditionFunc(func(*Response) (bool, error) {
		if attempts != counter {
			return false, errors.New("Attempts not equal Counter")
		}
		return false, nil
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

// Check to make sure the functions added to add conditionals work
func TestConditionalGet(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()
	attemptCount := 1
	externalCounter := 0

	// This check should pass on first run, and let the response through
	check := RetryConditionFunc(func(*Response) (bool, error) {
		externalCounter++
		if attemptCount != externalCounter {
			return false, errors.New("Attempts not equal Counter")
		}
		return false, nil
	})

	client := dc().AddRetryCondition(check).SetRetryCount(1)
	resp, err := client.R().
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, true, resp.Body() != nil)
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
	check := RetryConditionFunc(func(*Response) (bool, error) {
		externalCounter++
		if attemptCount != externalCounter {
			return false, errors.New("Attempts not equal Counter")
		}
		return false, nil
	})

	// Clear the default client.
	_ = dc()
	// Proceed to check.
	client := AddRetryCondition(check).SetRetryCount(1)
	resp, err := client.R().
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, true, resp.Body() != nil)
	assertEqual(t, "TestGet: text response", resp.String())
	assertEqual(t, externalCounter, attemptCount)

	logResponse(t, resp)
}

func filler(*Response) (bool, error) {
	return false, nil
}
