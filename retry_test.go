package resty

import (
	"errors"
	"testing"
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
	check := func(*Response) (bool, error) {
		return attempts != counter, nil
	}
	retryErr := Backoff(func() (*Response, error) {
		counter++
		return nil, nil
	}, RetryConditions([]func(*Response) (bool, error){check}))

	assertError(t, retryErr)
	assertEqual(t, counter, attempts)
}

// Check to make sure that errors in the conditional cause a retry
func TestConditionalBackoffConditionError(t *testing.T) {
	attempts := 3
	counter := 0
	check := func(*Response) (bool, error) {
		if attempts != counter {
			return false, errors.New("Attempts not equal Counter")
		}
		return false, nil
	}

	retryErr := Backoff(func() (*Response, error) {
		counter++
		return nil, nil
	}, RetryConditions([]func(*Response) (bool, error){check}))

	assertError(t, retryErr)
	assertEqual(t, counter, attempts)
}

// Check to make sure that if the conditional is false we don't retry
func TestConditionalBackoffConditionNonExecution(t *testing.T) {
	attempts := 3
	counter := 0

	filler := func(*Response) (bool, error) {
		return false, nil
	}

	retryErr := Backoff(func() (*Response, error) {
		counter++
		return nil, nil
	}, RetryConditions([]func(*Response) (bool, error){filler}))

	assertError(t, retryErr)
	assertNotEqual(t, counter, attempts)
}
