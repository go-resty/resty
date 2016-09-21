package resty

import (
	"math"
	"math/rand"
	"time"
)

type function func() error

// Option ...
type Option func(*Options)

// Options ...
type Options struct {
	maxRetries      int
	waitTime        int
	maxWaitTime     int
	retryConditions []func(*Response) (bool, error)
}

// Retries sets the max number of retries
func Retries(value int) Option {
	return func(o *Options) {
		o.maxRetries = value
	}
}

// WaitTime sets the default wait time to sleep between requests
func WaitTime(value int) Option {
	return func(o *Options) {
		o.waitTime = value
	}
}

// MaxWaitTime sets the max wait time to sleep between requests
func MaxWaitTime(value int) Option {
	return func(o *Options) {
		o.maxWaitTime = value
	}
}

// RetryConditions sets the conditions that will be checked for retry.
func RetryConditions(conditions []func(*Response) (bool, error)) Option {
	return func(o *Options) {
		o.retryConditions = conditions
	}
}

//Backoff retries with increasing timeout duration up until X amount of retries (Default is 3 attempts, Override with option Retries(n))
func Backoff(operation func() (*Response, error), options ...Option) error {
	// Defaults
	opts := Options{maxRetries: 3, waitTime: 100, maxWaitTime: 2000, retryConditions: []func(*Response) (bool, error){}}
	for _, o := range options {
		o(&opts)
	}

	var resp *Response
	var err error
	base := float64(opts.waitTime)        // Time to wait between each attempt
	capLevel := float64(opts.maxWaitTime) // Maximum amount of wait time for the retry
	for attempt := 0; attempt < opts.maxRetries; attempt++ {
		resp, err = operation()

		var needsRetry bool
		var conditionErr error
		for _, condition := range opts.retryConditions {
			needsRetry, conditionErr = condition(resp)
			if needsRetry || conditionErr != nil {
				break
			}
		}

		// If the operation returned no error, there was no condition satisfied and
		// there was no error caused by the conditional functions.
		if err == nil && needsRetry == false && conditionErr == nil {
			return nil
		}
		// Adding capped exponential backup with jitter
		// See the following article...
		// http://www.awsarchitectureblog.com/2015/03/backoff.html
		temp := math.Min(capLevel, base*math.Exp2(float64(attempt)))
		sleepTime := int(temp/2) + rand.Intn(int(temp/2))

		sleepDuration := time.Duration(sleepTime) * time.Millisecond
		time.Sleep(sleepDuration)
	}

	return err
}
