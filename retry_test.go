// Copyright (c) 2015-2016 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"runtime"
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

func TestClientRetryGet(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetHTTPMode().
		SetTimeout(time.Duration(time.Second * 3)).
		SetRetryCount(3)

	_, err := c.R().Get(ts.URL + "/set-retrycount-test")

	assertError(t, err)
}

func GetFunctionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
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
	c.AddRetryCondition(RetryConditionFunc(func(r *Response) (bool, error) {
		if r.StatusCode() >= http.StatusInternalServerError {
			return false, errors.New("error")
		}
		return true, nil
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

func filler(*Response) (bool, error) {
	return false, nil
}
