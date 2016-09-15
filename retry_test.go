package resty

import (
	"errors"
	"testing"
)

func Test_Backoff_Success(t *testing.T) {
	attempts := 3
	externalCounter := 0
	retryErr := Backoff(func() error {
		externalCounter++
		if externalCounter < attempts {
			return errors.New("Not yet got the number we're after...")
		}
		return nil
	})

	assertError(t, retryErr)
	assertEqual(t, externalCounter, attempts)
}

func Test_BackoffTenAttempts_Success(t *testing.T) {
	attempts := 10
	externalCounter := 0
	retryErr := Backoff(func() error {
		externalCounter++
		if externalCounter < attempts {
			return errors.New("Not yet got the number we're after...")
		}
		return nil
	}, Retries(attempts), WaitTime(5), MaxWaitTime(500))

	assertError(t, retryErr)
	assertEqual(t, externalCounter, attempts)
}
