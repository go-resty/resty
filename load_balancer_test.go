// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestRoundRobin(t *testing.T) {

	t.Run("2 base urls", func(t *testing.T) {
		rr, err := NewRoundRobin("https://example1.com", "https://example2.com")
		assertNil(t, err)

		runCount := 5
		var result []string
		ctx := context.Background()
		for i := 0; i < runCount; i++ {
			baseURL, _ := rr.NextWithContext(ctx)
			result = append(result, baseURL)
		}

		expected := []string{
			"https://example1.com", "https://example2.com", "https://example1.com",
			"https://example2.com", "https://example1.com",
		}

		assertEqual(t, runCount, len(expected))
		assertEqual(t, runCount, len(result))
		assertEqual(t, expected, result)

		rr.Feedback(&RequestFeedback{})
		rr.Close()
	})

	t.Run("5 base urls", func(t *testing.T) {
		input := []string{"https://example1.com", "https://example2.com",
			"https://example3.com", "https://example4.com", "https://example5.com"}
		rr, err := NewRoundRobin(input...)
		assertNil(t, err)

		runCount := 30
		var result []string
		ctx := context.Background()
		for i := 0; i < runCount; i++ {
			baseURL, _ := rr.NextWithContext(ctx)
			result = append(result, baseURL)
		}

		var expected []string
		for i := 0; i < runCount/len(input); i++ {
			expected = append(expected, input...)
		}

		assertEqual(t, runCount, len(expected))
		assertEqual(t, runCount, len(result))
		assertEqual(t, expected, result)

		rr.Feedback(&RequestFeedback{})
		rr.Close()
	})

	t.Run("2 base urls with refresh", func(t *testing.T) {
		rr, err := NewRoundRobin("https://example1.com", "https://example2.com")
		assertNil(t, err)

		err = rr.Refresh("https://example3.com", "https://example4.com")
		assertNil(t, err)

		runCount := 5
		var result []string
		ctx := context.Background()
		for i := 0; i < runCount; i++ {
			baseURL, _ := rr.NextWithContext(ctx)
			result = append(result, baseURL)
		}

		expected := []string{
			"https://example3.com", "https://example4.com", "https://example3.com",
			"https://example4.com", "https://example3.com",
		}

		assertEqual(t, runCount, len(expected))
		assertEqual(t, runCount, len(result))
		assertEqual(t, expected, result)

		rr.Feedback(&RequestFeedback{})
		rr.Close()
	})

	t.Run("NextWithContext context cancellation", func(t *testing.T) {
		rr, _ := NewRoundRobin("https://example.com")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := rr.NextWithContext(ctx)
		assertErrorIs(t, context.Canceled, err)
	})

	t.Run("NextWithContext normal operation", func(t *testing.T) {
		rr, _ := NewRoundRobin("https://example1.com", "https://example2.com")
		ctx := context.Background()
		url1, err := rr.NextWithContext(ctx)
		assertNil(t, err)
		url2, err := rr.NextWithContext(ctx)
		assertNil(t, err)
		assertNotEqual(t, url1, url2)
	})
}

func TestRoundRobinNoBaseURLs(t *testing.T) {
	t.Run("new round robin no base urls", func(t *testing.T) {
		rr, err := NewRoundRobin()
		assertErrorIs(t, ErrNoBaseURLs, err)
		assertNil(t, rr)
	})

	t.Run("new round robin no base urls on next with context", func(t *testing.T) {
		rr, err := NewRoundRobin("https://example1.com")
		assertNil(t, err)
		assertNotNil(t, rr)

		rr.Refresh()
		ctx := context.Background()
		_, err = rr.NextWithContext(ctx)
		assertErrorIs(t, ErrNoBaseURLs, err)
	})
}

func TestWeightedRoundRobin(t *testing.T) {
	t.Run("3 hosts with weight {5,2,1}", func(t *testing.T) {
		hosts := []*Host{
			{BaseURL: "https://example1.com", Weight: 5},
			{BaseURL: "https://example2.com", Weight: 2},
			{BaseURL: "https://example3.com", Weight: 1},
		}

		wrr, err := NewWeightedRoundRobin(200*time.Millisecond, hosts...)
		assertNil(t, err)
		defer wrr.Close()

		runCount := 5
		var result []string
		ctx := context.Background()
		for i := 0; i < runCount; i++ {
			baseURL, err := wrr.NextWithContext(ctx)
			assertNil(t, err)
			result = append(result, baseURL)
		}

		expected := []string{
			"https://example1.com", "https://example2.com", "https://example1.com",
			"https://example1.com", "https://example3.com",
		}

		assertEqual(t, runCount, len(expected))
		assertEqual(t, runCount, len(result))
		assertEqual(t, expected, result)

		wrr.Feedback(nil)
	})

	t.Run("3 hosts with weight {2,1,10}", func(t *testing.T) {
		hosts := []*Host{
			{BaseURL: "https://example1.com", Weight: 2},
			{BaseURL: "https://example2.com", Weight: 1},
			{BaseURL: "https://example3.com", Weight: 10, MaxFailures: 3},
		}

		wrr, err := NewWeightedRoundRobin(200*time.Millisecond, hosts...)
		assertNil(t, err)
		defer wrr.Close()

		var stateChangeCalled int32
		wrr.SetOnStateChange(func(baseURL string, from, to HostState) {
			atomic.AddInt32(&stateChangeCalled, 1)
		})

		runCount := 10
		var result []string
		ctx := context.Background()
		for i := 0; i < runCount; i++ {
			baseURL, err := wrr.NextWithContext(ctx)
			assertNil(t, err)
			result = append(result, baseURL)
			if baseURL == "https://example3.com" && i%2 != 0 {
				wrr.Feedback(&RequestFeedback{BaseURL: baseURL, Success: false, Attempt: 1})
			} else {
				wrr.Feedback(&RequestFeedback{BaseURL: baseURL, Success: true, Attempt: 1})
			}
		}

		expected := []string{
			"https://example3.com", "https://example3.com", "https://example1.com",
			"https://example3.com", "https://example3.com", "https://example3.com",
			"https://example2.com", "https://example2.com", "https://example1.com",
			"https://example1.com",
		}

		assertEqual(t, int32(1), stateChangeCalled)
		assertEqual(t, runCount, len(expected))
		assertEqual(t, runCount, len(result))
		assertEqual(t, expected, result)
	})

	t.Run("2 hosts with weight {5,5} and refresh", func(t *testing.T) {
		wrr, err := NewWeightedRoundRobin(
			200*time.Millisecond,
			&Host{BaseURL: "https://example1.com", Weight: 5},
			&Host{BaseURL: "https://example2.com", Weight: 5},
		)
		assertNil(t, err)
		defer wrr.Close()

		err = wrr.Refresh(
			&Host{BaseURL: "https://example3.com", Weight: 5},
			&Host{BaseURL: "https://example4.com", Weight: 5},
		)
		assertNil(t, err)

		runCount := 5
		var result []string
		ctx := context.Background()
		for i := 0; i < runCount; i++ {
			baseURL, err := wrr.NextWithContext(ctx)
			assertNil(t, err)
			result = append(result, baseURL)
		}

		expected := []string{
			"https://example3.com", "https://example4.com", "https://example3.com",
			"https://example4.com", "https://example3.com",
		}

		assertEqual(t, runCount, len(expected))
		assertEqual(t, runCount, len(result))
		assertEqual(t, expected, result)
	})

	t.Run("no active hosts error", func(t *testing.T) {
		wrr, err := NewWeightedRoundRobin(200 * time.Millisecond)
		assertNil(t, err)
		defer wrr.Close()

		_, err = wrr.NextWithContext(context.Background())
		assertErrorIs(t, ErrNoActiveHost, err)
	})

	t.Run("NextWithContext context cancellation", func(t *testing.T) {
		wrr, _ := NewWeightedRoundRobin(0, &Host{BaseURL: "https://example.com", Weight: 1})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := wrr.NextWithContext(ctx)
		assertErrorIs(t, context.Canceled, err)
	})

	t.Run("NextWithContext normal operation", func(t *testing.T) {
		hosts := []*Host{
			{BaseURL: "https://example1.com", Weight: 1},
			{BaseURL: "https://example2.com", Weight: 1},
		}
		wrr, _ := NewWeightedRoundRobin(0, hosts...)
		ctx := context.Background()
		url1, err := wrr.NextWithContext(ctx)
		assertNil(t, err)
		url2, err := wrr.NextWithContext(ctx)
		assertNil(t, err)
		assertNotEqual(t, url1, url2)
	})
}

func TestSRVWeightedRoundRobin(t *testing.T) {
	t.Run("3 records with weight {50,30,20}", func(t *testing.T) {
		srv, err := NewSRVWeightedRoundRobin("_sample-server", "", "example.com", "")
		assertNotNil(t, err)
		assertNotNil(t, srv)
		var dnsErr *net.DNSError
		assertTrue(t, errors.As(err, &dnsErr), "expected net.DNSError type")

		// mock net.LookupSRV call
		srv.lookupSRV = func() ([]*net.SRV, error) {
			return []*net.SRV{
				{Target: "service1.example.com.", Port: 443, Priority: 10, Weight: 50},
				{Target: "service2.example.com.", Port: 443, Priority: 20, Weight: 30},
				{Target: "service3.example.com.", Port: 443, Priority: 20, Weight: 20},
			}, nil
		}
		err = srv.Refresh()
		assertNil(t, err)

		srv.SetRecoveryDuration(200 * time.Millisecond)

		runCount := 5
		var result []string
		ctx := context.Background()
		for i := 0; i < runCount; i++ {
			baseURL, err := srv.NextWithContext(ctx)
			assertNil(t, err)
			result = append(result, baseURL)
		}

		expected := []string{
			"https://service1.example.com:443", "https://service2.example.com:443",
			"https://service3.example.com:443", "https://service1.example.com:443",
			"https://service1.example.com:443",
		}

		assertEqual(t, runCount, len(expected))
		assertEqual(t, runCount, len(result))
		assertEqual(t, expected, result)
	})

	t.Run("2 records with weight {50,50}", func(t *testing.T) {
		srv, err := NewSRVWeightedRoundRobin("_sample-server", "", "example.com", "")
		assertNotNil(t, err)
		assertNotNil(t, srv)
		var dnsErr *net.DNSError
		assertTrue(t, errors.As(err, &dnsErr), "expected net.DNSError type")

		// mock net.LookupSRV call
		srv.lookupSRV = func() ([]*net.SRV, error) {
			return []*net.SRV{
				{Target: "service1.example.com.", Port: 443, Priority: 10, Weight: 50},
				{Target: "service2.example.com.", Port: 443, Priority: 20, Weight: 50},
			}, nil
		}
		err = srv.Refresh()
		assertNil(t, err)

		srv.SetRecoveryDuration(200 * time.Millisecond)

		runCount := 5
		var result []string
		ctx := context.Background()
		for i := 0; i < runCount; i++ {
			baseURL, err := srv.NextWithContext(ctx)
			assertNil(t, err)
			result = append(result, baseURL)
		}

		expected := []string{
			"https://service1.example.com:443", "https://service2.example.com:443",
			"https://service1.example.com:443", "https://service2.example.com:443",
			"https://service1.example.com:443",
		}

		assertEqual(t, runCount, len(expected))
		assertEqual(t, runCount, len(result))
		assertEqual(t, expected, result)
	})

	t.Run("3 records with weight {60,20,20}", func(t *testing.T) {
		srv, err := NewSRVWeightedRoundRobin("_sample-server", "", "example.com", "")
		assertNotNil(t, err)
		assertNotNil(t, srv)
		var dnsErr *net.DNSError
		assertTrue(t, errors.As(err, &dnsErr), "expected net.DNSError type")

		// mock net.LookupSRV call
		srv.lookupSRV = func() ([]*net.SRV, error) {
			return []*net.SRV{
				{Target: "service1.example.com.", Port: 443, Priority: 10, Weight: 60},
				{Target: "service2.example.com.", Port: 443, Priority: 20, Weight: 20},
				{Target: "service3.example.com.", Port: 443, Priority: 20, Weight: 20},
			}, nil
		}
		err = srv.Refresh()
		assertNil(t, err)

		var stateChangeCalled int32
		srv.SetOnStateChange(func(baseURL string, from, to HostState) {
			atomic.AddInt32(&stateChangeCalled, 1)
		})

		srv.SetRecoveryDuration(200 * time.Millisecond)

		runCount := 20
		var result []string
		ctx := context.Background()
		for i := 0; i < runCount; i++ {
			baseURL, err := srv.NextWithContext(ctx)
			assertNil(t, err)
			result = append(result, baseURL)

			if baseURL == "https://service1.example.com:443" {
				srv.Feedback(&RequestFeedback{BaseURL: baseURL, Success: false, Attempt: 1})
			} else {
				srv.Feedback(&RequestFeedback{BaseURL: baseURL, Success: true, Attempt: 1})
			}
		}

		expected := []string{
			"https://service1.example.com:443", "https://service2.example.com:443", "https://service1.example.com:443",
			"https://service3.example.com:443", "https://service1.example.com:443", "https://service1.example.com:443",
			"https://service2.example.com:443", "https://service1.example.com:443", "https://service3.example.com:443",
			"https://service3.example.com:443", "https://service3.example.com:443", "https://service2.example.com:443",
			"https://service3.example.com:443", "https://service2.example.com:443", "https://service3.example.com:443",
			"https://service2.example.com:443", "https://service3.example.com:443", "https://service2.example.com:443",
			"https://service3.example.com:443", "https://service2.example.com:443",
		}

		assertEqual(t, runCount, len(expected))
		assertEqual(t, runCount, len(result))
		assertEqual(t, expected, result)
	})

	t.Run("srv record with refresh duration 100ms", func(t *testing.T) {
		srv, err := NewSRVWeightedRoundRobin("_sample-server", "", "example.com", "")
		assertNotNil(t, err)
		assertNotNil(t, srv)
		var dnsErr *net.DNSError
		assertTrue(t, errors.As(err, &dnsErr), "expected net.DNSError type")

		// mock net.LookupSRV call
		srv.lookupSRV = func() ([]*net.SRV, error) {
			return []*net.SRV{
				{Target: "service1.example.com.", Port: 443, Priority: 10, Weight: 50},
				{Target: "service2.example.com.", Port: 443, Priority: 20, Weight: 50},
			}, nil
		}
		err = srv.Refresh()
		assertNil(t, err)

		srv.SetRecoveryDuration(200 * time.Millisecond)

		go func() {
			for i := 0; i < 10; i++ {
				baseURL, _ := srv.NextWithContext(context.Background())
				assertNotNil(t, baseURL)
				time.Sleep(15 * time.Millisecond)
			}
		}()

		srv.SetRefreshDuration(150 * time.Millisecond)
		time.Sleep(320 * time.Millisecond)
		srv.Close()
	})

	t.Run("srv record with error on default lookupSRV", func(t *testing.T) {
		srv, err := NewSRVWeightedRoundRobin("_sample-server", "", "example.com", "")
		assertNotNil(t, err)
		assertNotNil(t, srv)
		var dnsErr *net.DNSError
		assertTrue(t, errors.As(err, &dnsErr), "expected net.DNSError type")

		// default error flow
		err = srv.Refresh()
		assertNotNil(t, err)
		assertTrue(t, errors.As(err, &dnsErr), "expected net.DNSError type")

		// replace with mock error flow
		errMockTest := errors.New("network error")
		srv.lookupSRV = func() ([]*net.SRV, error) { return nil, errMockTest }
		err = srv.Refresh()
		assertNotNil(t, err)
		assertErrorIs(t, errMockTest, err, "expected network error type")

	})

}

func TestLoadBalancerRequest(t *testing.T) {
	ts1 := createGetServer(t)
	defer ts1.Close()

	ts2 := createGetServer(t)
	defer ts2.Close()

	rr, err := NewRoundRobin(ts1.URL, ts2.URL)
	assertNil(t, err)

	c := dcnl()
	defer c.Close()

	c.SetLoadBalancer(rr)

	ts1URL, ts2URL := 0, 0
	for i := 0; i < 20; i++ {
		resp, err := c.R().Get("/")
		assertNil(t, err)
		switch resp.Request.baseURL {
		case ts1.URL:
			ts1URL++
		case ts2.URL:
			ts2URL++
		}
	}
	assertEqual(t, ts1URL, ts2URL)
}

func TestLoadBalancerRequestFlowError(t *testing.T) {

	t.Run("obtain next url error", func(t *testing.T) {
		wrr, err := NewWeightedRoundRobin(0)
		assertNil(t, err)

		c := dcnl()
		defer c.Close()

		c.SetLoadBalancer(wrr)

		resp, err := c.R().Get("/")
		assertErrorIs(t, ErrNoActiveHost, err)
		assertNil(t, resp)
	})

	t.Run("round-robin invalid url input", func(t *testing.T) {
		rr, err := NewRoundRobin("://example.com")
		assertType(t, url.Error{}, err)
		assertNotNil(t, rr)

		wrr, err := NewWeightedRoundRobin(0, &Host{BaseURL: "://example.com"})
		assertType(t, url.Error{}, err)
		assertNotNil(t, wrr)
	})

	t.Run("weighted round-robin invalid url input", func(t *testing.T) {
		wrr, err := NewWeightedRoundRobin(0, &Host{BaseURL: "://example.com"})
		assertType(t, url.Error{}, err)
		assertNotNil(t, wrr)
	})
}

func Test_extractBaseURL(t *testing.T) {
	for _, tt := range []struct {
		name        string
		inputURL    string
		expectedURL string
		expectedErr error
	}{
		{
			name:        "simple relative path",
			inputURL:    "https://resty.dev/welcome",
			expectedURL: "https://resty.dev",
		},
		{
			name:        "longer relative path with file extension",
			inputURL:    "https://resty.dev/welcome/path/to/remove.html",
			expectedURL: "https://resty.dev",
		},
		{
			name:        "longer relative path with file extension and query params",
			inputURL:    "https://resty.dev/welcome/path/to/remove.html?a=1&b=2",
			expectedURL: "https://resty.dev",
		},
		{
			name:        "invalid url input",
			inputURL:    "://resty.dev/welcome",
			expectedURL: "",
			expectedErr: &url.Error{Op: "parse", URL: "://resty.dev/welcome", Err: errors.New("missing protocol scheme")},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			outputURL, err := extractBaseURL(tt.inputURL)
			if tt.expectedErr != nil {
				assertEqual(t, tt.expectedErr, err)
			}
			assertEqual(t, tt.expectedURL, outputURL)
		})
	}
}

func TestLoadBalancerRequestFailures(t *testing.T) {
	ts1 := createGetServer(t)
	ts1.Close()

	ts2 := createGetServer(t)
	defer ts2.Close()

	rr, err := NewWeightedRoundRobin(200*time.Millisecond,
		&Host{BaseURL: ts1.URL, Weight: 50, MaxFailures: 3}, &Host{BaseURL: ts2.URL, Weight: 50})
	assertNil(t, err)

	c := dcnl()
	defer c.Close()

	c.SetLoadBalancer(rr)

	ts1URL, ts2URL := 0, 0
	for i := 0; i < 10; i++ {
		resp, _ := c.R().Get("/")
		switch resp.Request.baseURL {
		case ts1.URL:
			ts1URL++
		case ts2.URL:
			assertError(t, err)
			ts2URL++
		}
	}
	assertEqual(t, 3, ts1URL)
	assertEqual(t, 7, ts2URL)
}

type mockTimeoutErr struct{}

func (e *mockTimeoutErr) Error() string { return "i/o timeout" }
func (e *mockTimeoutErr) Timeout() bool { return true }

func TestLoadBalancerCoverage(t *testing.T) {
	t.Run("mock net op timeout error", func(t *testing.T) {
		wrr, err := NewWeightedRoundRobin(0)
		assertNil(t, err)

		c := dcnl()
		defer c.Close()

		c.SetLoadBalancer(wrr)

		req := c.R()

		netOpErr := &net.OpError{Op: "mock", Net: "mock", Err: &mockTimeoutErr{}}
		req.sendLoadBalancerFeedback(&Response{}, netOpErr)

		req.sendLoadBalancerFeedback(&Response{RawResponse: &http.Response{
			StatusCode: http.StatusInternalServerError,
		}}, nil)
	})
}

// Ticker.Stop does not close its channel, so the recovery goroutines needed a
// separate shutdown signal.
func TestLoadBalancerCloseStopsTickerGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()

	for range 20 {
		wrr, err := NewWeightedRoundRobin(10*time.Millisecond,
			&Host{BaseURL: "https://example1.com", Weight: 1},
			&Host{BaseURL: "https://example2.com", Weight: 1},
		)
		assertNil(t, err)
		assertNil(t, wrr.Close())
		assertNil(t, wrr.Close()) // Close is idempotent
	}

	// give the goroutines a moment to observe the closed done channel
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	assertTrue(t, runtime.NumGoroutine() <= before+2,
		"recovery goroutines did not exit after Close")
}

// Feedback must report the active -> inactive transition once, not on every
// report that arrives while the host is already out of the pool.
func TestWeightedRoundRobinStateChangeFiresOnce(t *testing.T) {
	wrr, err := NewWeightedRoundRobin(time.Hour,
		&Host{BaseURL: "https://example1.com", Weight: 1, MaxFailures: 2},
	)
	assertNil(t, err)
	defer func() { assertNil(t, wrr.Close()) }()

	var changes int32
	wrr.SetOnStateChange(func(_ string, from, to HostState) {
		atomic.AddInt32(&changes, 1)
		assertEqual(t, HostStateActive, from)
		assertEqual(t, HostStateInActive, to)
	})

	for range 5 {
		wrr.Feedback(&RequestFeedback{BaseURL: "https://example1.com", Success: false, Attempt: 1})
	}
	assertEqual(t, int32(1), atomic.LoadInt32(&changes))
}

// Refresh must not hand the balancer's bookkeeping back to the caller, nor read
// the caller's later edits.
func TestWeightedRoundRobinRefreshCopiesHosts(t *testing.T) {
	h := &Host{BaseURL: "https://example.com/some/path", Weight: 1}
	wrr, err := NewWeightedRoundRobin(time.Hour, h)
	assertNil(t, err)
	defer func() { assertNil(t, wrr.Close()) }()

	// the caller's value is untouched
	assertEqual(t, "https://example.com/some/path", h.BaseURL)

	// and mutating it afterwards does not reach the balancer
	h.BaseURL = "https://elsewhere.example"
	got, err := wrr.NextWithContext(context.Background())
	assertNil(t, err)
	assertEqual(t, "https://example.com", got)
}

// A zero SRV weight never raises currentWeight, which left WRR always returning
// the first host.
func TestWeightedRoundRobinZeroWeightRotates(t *testing.T) {
	wrr, err := NewWeightedRoundRobin(time.Hour,
		&Host{BaseURL: "https://example1.com"},
		&Host{BaseURL: "https://example2.com"},
	)
	assertNil(t, err)
	defer func() { assertNil(t, wrr.Close()) }()

	seen := make(map[string]int)
	for range 4 {
		got, err := wrr.NextWithContext(context.Background())
		assertNil(t, err)
		seen[got]++
	}
	assertEqual(t, 2, len(seen))
}

// The recovery ticker puts inactive hosts back into rotation, resets their
// failure counters and reports the transition once the lock has been released,
// so a hook is free to call back into the balancer.
func TestWeightedRoundRobinHostRecovery(t *testing.T) {
	const host1, host2 = "https://example1.com", "https://example2.com"

	wrr, err := NewWeightedRoundRobin(50*time.Millisecond,
		&Host{BaseURL: host1, Weight: 10, MaxFailures: 1},
		&Host{BaseURL: host2, Weight: 10, MaxFailures: 1},
	)
	assertNil(t, err)
	defer func() { assertNil(t, wrr.Close()) }()

	recovered := make(chan string, 4)
	wrr.SetOnStateChange(func(baseURL string, from, to HostState) {
		if from == HostStateInActive && to == HostStateActive {
			// calling back in has to be safe: the hook runs without the lock held
			_, _ = wrr.NextWithContext(context.Background())
			recovered <- baseURL
		}
	})

	wrr.Feedback(&RequestFeedback{BaseURL: host1, Success: false})

	// only the healthy host is handed out while the other one is out of the pool
	for range 3 {
		baseURL, err := wrr.NextWithContext(context.Background())
		assertNil(t, err)
		assertEqual(t, host2, baseURL)
	}

	select {
	case baseURL := <-recovered:
		assertEqual(t, host1, baseURL)
	case <-time.After(5 * time.Second):
		t.Fatal("the inactive host was never returned to the pool")
	}

	wrr.lock.RLock()
	defer wrr.lock.RUnlock()
	for _, h := range wrr.hosts {
		assertEqual(t, HostStateActive, h.state, "expected every host to be active again")
		assertEqual(t, 0, h.failedRequests, "expected the failure count to be reset")
	}
}

// Recovery must still work when no state change hook is registered.
func TestWeightedRoundRobinHostRecoveryWithoutHook(t *testing.T) {
	const host1 = "https://example1.com"

	wrr, err := NewWeightedRoundRobin(50*time.Millisecond,
		&Host{BaseURL: host1, Weight: 10, MaxFailures: 1},
	)
	assertNil(t, err)
	defer func() { assertNil(t, wrr.Close()) }()

	wrr.Feedback(&RequestFeedback{BaseURL: host1, Success: false})
	_, err = wrr.NextWithContext(context.Background())
	assertErrorIs(t, ErrNoActiveHost, err)

	deadline := time.Now().Add(5 * time.Second)
	for {
		baseURL, err := wrr.NextWithContext(context.Background())
		if err == nil {
			assertEqual(t, host1, baseURL)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the inactive host was never returned to the pool")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The SRV refresh goroutine keeps running across a failed lookup, logs it rather
// than dropping it, and stops when Close is called.
func TestSRVWeightedRoundRobinTickerRefresh(t *testing.T) {
	srv, err := NewSRVWeightedRoundRobin("_sample-server", "", "example.com", "")
	assertNotNil(t, err) // example.com has no such SRV record, so no ticker was started
	assertNotNil(t, srv)

	var logBuf bytes.Buffer
	srv.log = &logger{l: log.New(&logBuf, "", 0)}

	var lookups atomic.Int32
	errLookup := errors.New("srv lookup failed")
	srv.lookupSRV = func() ([]*net.SRV, error) {
		if lookups.Add(1) == 1 {
			return nil, errLookup // the first refresh fails
		}
		return []*net.SRV{
			{Target: "service1.example.com.", Port: 443, Priority: 10, Weight: 50},
		}, nil
	}

	srv.SetRefreshDuration(20 * time.Millisecond)
	go srv.ticker()

	deadline := time.Now().Add(5 * time.Second)
	for lookups.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the SRV refresh ticker did not run")
		}
		time.Sleep(5 * time.Millisecond)
	}

	assertTrue(t, strings.Contains(logBuf.String(), errLookup.Error()),
		"expected the failed refresh to be logged, got: "+logBuf.String())

	baseURL, err := srv.NextWithContext(context.Background())
	assertNil(t, err)
	assertEqual(t, "https://service1.example.com:443", baseURL)

	assertNil(t, srv.Close())
	assertNil(t, srv.Close()) // Close is documented to be idempotent

	// the goroutine is gone, so no further lookups happen
	settled := lookups.Load()
	time.Sleep(100 * time.Millisecond)
	assertEqual(t, settled, lookups.Load(), "expected the refresh goroutine to have stopped")
}

// The successful construction path starts the SRV refresh goroutine, which Close
// then has to shut down.
func TestSRVWeightedRoundRobinResolvedAtConstruction(t *testing.T) {
	srv, err := newSRVWeightedRoundRobin("_sample-server", "tcp", "example.com", "https",
		func() ([]*net.SRV, error) {
			return []*net.SRV{
				{Target: "service1.example.com.", Port: 8443, Priority: 10, Weight: 50},
			}, nil
		})
	assertNil(t, err)
	assertNotNil(t, srv)

	baseURL, err := srv.NextWithContext(context.Background())
	assertNil(t, err)
	assertEqual(t, "https://service1.example.com:8443", baseURL)

	assertNil(t, srv.Close())
}

type feedbackRecorder struct {
	LoadBalancer
	reports []RequestFeedback
}

func (r *feedbackRecorder) Feedback(f *RequestFeedback) {
	r.reports = append(r.reports, *f)
	r.LoadBalancer.Feedback(f)
}

type feedbackRoundTripper func(*http.Request) (*http.Response, error)

func (f feedbackRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLoadBalancerTimeoutIsFailure(t *testing.T) {
	rr, err := NewRoundRobin("http://bad.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	client := dcnl().SetLoadBalancer(lb).SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	}))
	defer client.Close()
	_, err = client.R().Get("/")
	if err == nil {
		t.Fatal("expected a transport timeout")
	}
	if len(lb.reports) != 1 || lb.reports[0].Success {
		t.Fatalf("timeout feedback = %+v, want one failed attempt", lb.reports)
	}
}

func TestLoadBalancerTimeoutFeedbackBeforeRetry(t *testing.T) {
	rr, err := NewRoundRobin("http://bad.invalid", "http://good.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	calls := 0
	client := dcnl().SetLoadBalancer(lb).SetRetryCount(1).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(time.Millisecond).
		SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
			}
			if len(lb.reports) != 1 || lb.reports[0].Success {
				t.Errorf("feedback before retry = %+v, want first attempt recorded as failed", lb.reports)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
		}))
	defer client.Close()
	res, err := client.R().Get("/")
	assertNil(t, err)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if len(lb.reports) != 2 {
		t.Fatalf("feedback = %+v, want one report per attempt", lb.reports)
	}
	if lb.reports[0].BaseURL != "http://bad.invalid" || lb.reports[0].Success || lb.reports[0].Attempt != 1 {
		t.Errorf("first attempt feedback = %+v", lb.reports[0])
	}
	if lb.reports[1].BaseURL != "http://good.invalid" || !lb.reports[1].Success || lb.reports[1].Attempt != 2 {
		t.Errorf("second attempt feedback = %+v", lb.reports[1])
	}
}

func TestLoadBalancerTimeoutWeightedFailover(t *testing.T) {
	bad := &Host{BaseURL: "http://bad.invalid", Weight: 100, MaxFailures: 1}
	good := &Host{BaseURL: "http://good.invalid", Weight: 1, MaxFailures: 1}
	wrr, err := NewWeightedRoundRobin(time.Hour, bad, good)
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: wrr}
	var hosts []string
	client := dcnl().SetLoadBalancer(lb).SetRetryCount(2).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(time.Millisecond).
		SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
			hosts = append(hosts, r.URL.Host)
			if r.URL.Host == "bad.invalid" {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
			}
			return feedbackResponse(r, http.StatusOK), nil
		}))
	defer client.Close()
	res, err := client.R().Get("/")
	assertNil(t, err)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if strings.Join(hosts, ",") != "bad.invalid,good.invalid" {
		t.Errorf("attempted hosts = %v, want immediate failover", hosts)
	}
	wrr.lock.RLock()
	states := make(map[string]HostState)
	for _, host := range wrr.hosts {
		states[host.BaseURL] = host.state
	}
	wrr.lock.RUnlock()
	if states[bad.BaseURL] != HostStateInActive || states[good.BaseURL] != HostStateActive {
		t.Errorf("host states: %v", states)
	}
	if len(lb.reports) != 2 {
		t.Errorf("feedback = %+v, want exactly two reports", lb.reports)
	}
}

func TestLoadBalancerTimeoutFinalAttemptReportedOnce(t *testing.T) {
	rr, err := NewRoundRobin("http://bad.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	client := dcnl().SetLoadBalancer(lb).SetRetryCount(2).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(time.Millisecond).
		SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
			return nil, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
		}))
	defer client.Close()
	_, err = client.R().Get("/")
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if len(lb.reports) != 3 {
		t.Fatalf("feedback = %+v, want exactly three attempts", lb.reports)
	}
	for i, report := range lb.reports {
		if report.Attempt != i+1 || report.Success {
			t.Errorf("attempt %d feedback = %+v", i+1, report)
		}
	}
}

func TestLoadBalancerFeedbackStatusCodes(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusNotImplemented, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			rr, err := NewRoundRobin("http://backend.invalid")
			assertNil(t, err)
			lb := &feedbackRecorder{LoadBalancer: rr}
			client := dcnl().SetLoadBalancer(lb).SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
				return feedbackResponse(r, status), nil
			}))
			defer client.Close()
			res, err := client.R().Get("/")
			assertNil(t, err)
			if res != nil && res.Body != nil {
				defer res.Body.Close()
			}
			wantSuccess := status < 500 || status == http.StatusNotImplemented
			if len(lb.reports) != 1 || lb.reports[0].Success != wantSuccess || lb.reports[0].Attempt != 1 {
				t.Errorf("status %d feedback = %+v, want success=%v", status, lb.reports, wantSuccess)
			}
		})
	}
}

func TestLoadBalancerFeedbackConnectionRefused(t *testing.T) {
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	client := dcnl().SetLoadBalancer(lb).SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	}))
	defer client.Close()
	_, err = client.R().Get("/")
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("got %v, want connection refused", err)
	}
	if len(lb.reports) != 1 || lb.reports[0].Success {
		t.Errorf("connection-refused feedback = %+v", lb.reports)
	}
}

func TestLoadBalancerFeedbackCallerCancellation(t *testing.T) {
	for _, when := range []string{"before_request", "during_transport", "deadline_cause"} {
		t.Run(when, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			cause := context.Canceled
			if when == "deadline_cause" {
				cause = context.DeadlineExceeded
			}
			if when == "before_request" {
				cancel(cause)
			}
			rr, err := NewRoundRobin("http://backend.invalid")
			assertNil(t, err)
			lb := &feedbackRecorder{LoadBalancer: rr}
			calls := 0
			client := dcnl().SetLoadBalancer(lb).SetRetryCount(2).
				SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
					calls++
					cancel(cause)
					return nil, cause
				}))
			defer client.Close()
			_, err = client.R().SetContext(ctx).Get("/")
			if !errors.Is(err, context.Canceled) {
				t.Errorf("got %v, want caller cancellation", err)
			}
			wantCalls := 1
			if when == "before_request" {
				wantCalls = 0
			}
			if calls != wantCalls || len(lb.reports) != 0 {
				t.Errorf("calls=%d feedback=%+v, want %d calls and no backend report", calls, lb.reports, wantCalls)
			}
		})
	}
}

func TestLoadBalancerFeedbackInvalidRequest(t *testing.T) {
	for _, tc := range []struct{ method, url string }{{MethodGet, "%"}, {"bad method", "/"}} {
		t.Run(tc.method+tc.url, func(t *testing.T) {
			rr, err := NewRoundRobin("http://backend.invalid")
			assertNil(t, err)
			lb := &feedbackRecorder{LoadBalancer: rr}
			client := dcnl().SetLoadBalancer(lb).SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
				t.Error("invalid request reached the transport")
				return nil, errors.New("unexpected transport call")
			}))
			defer client.Close()
			_, err = client.R().Execute(tc.method, tc.url)
			if err == nil || len(lb.reports) != 0 {
				t.Errorf("invalid request: error=%v feedback=%+v", err, lb.reports)
			}
		})
	}
}

func TestLoadBalancerFeedbackBeforeCanceledRetryWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	calls := 0
	client := dcnl().SetLoadBalancer(lb).SetRetryCount(1).
		SetRetryWaitTime(time.Hour).SetRetryMaxWaitTime(time.Hour).
		AddRetryConditions(func(res *Response, _ error) bool { return res.StatusCode() == http.StatusServiceUnavailable }).
		AddRetryHooks(func(*Response, error) {
			if len(lb.reports) != 1 || lb.reports[0].Success {
				t.Errorf("feedback before retry hook = %+v, want the failed HTTP attempt", lb.reports)
			}
			cancel()
		}).
		SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			return feedbackResponse(r, http.StatusServiceUnavailable), nil
		}))
	defer client.Close()
	res, err := client.R().SetContext(ctx).Get("/")
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if !errors.Is(err, context.Canceled) || calls != 1 || len(lb.reports) != 1 {
		t.Errorf("error=%v calls=%d feedback=%+v, want cancellation after one reported attempt", err, calls, lb.reports)
	}
}

func TestLoadBalancerFeedbackCompletedResponseAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	client := dcnl().SetLoadBalancer(lb).SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
		cancel()
		return feedbackResponse(r, http.StatusOK), nil
	}))
	defer client.Close()
	res, err := client.R().SetContext(ctx).Get("/")
	assertNil(t, err)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if len(lb.reports) != 1 || !lb.reports[0].Success {
		t.Errorf("completed-response feedback = %+v, want the successful response retained", lb.reports)
	}
}

func feedbackResponse(r *http.Request, status int) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader("ok")), Request: r}
}

func TestLoadBalancerFeedbackParentDeadline(t *testing.T) {
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	calls := 0
	client := dcnl().SetLoadBalancer(lb).SetRetryCount(2).
		SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			<-r.Context().Done()
			return nil, r.Context().Err()
		}))
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = client.R().SetContext(ctx).Get("/")
	if !errors.Is(err, context.DeadlineExceeded) || calls > 1 || len(lb.reports) != 0 {
		t.Errorf("parent deadline: error=%v calls=%d feedback=%+v", err, calls, lb.reports)
	}
}

func TestLoadBalancerFeedbackNonIdempotent(t *testing.T) {
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	calls := 0
	client := dcnl().SetLoadBalancer(lb).SetRetryCount(2).
		SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, &net.OpError{Op: "write", Net: "tcp", Err: os.ErrDeadlineExceeded}
		}))
	defer client.Close()
	_, err = client.R().Post("/")
	if err == nil || calls != 1 || len(lb.reports) != 1 || lb.reports[0].Success {
		t.Errorf("non-idempotent request: error=%v calls=%d feedback=%+v", err, calls, lb.reports)
	}
}

func TestLoadBalancerFeedbackResponseErrorAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	middlewareErr := errors.New("response processing failed")
	client := dcnl().SetLoadBalancer(lb).
		AddResponseMiddleware(func(*Client, *Response) error {
			cancel()
			return middlewareErr
		}).
		SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
			return feedbackResponse(r, http.StatusServiceUnavailable), nil
		}))
	defer client.Close()
	res, err := client.R().SetContext(ctx).Get("/")
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err == nil || len(lb.reports) != 1 || lb.reports[0].Success {
		t.Errorf("observed HTTP failure: error=%v feedback=%+v", err, lb.reports)
	}
}

func TestLoadBalancerFeedbackPreparationError(t *testing.T) {
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	prepareErr := errors.New("request preparation failed")
	client := dcnl().SetLoadBalancer(lb).
		SetRequestMiddlewares(MiddlewareRequestCreate, func(*Client, *Request) error { return prepareErr }).
		SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
			t.Error("request preparation error reached the transport")
			return nil, errors.New("unexpected transport call")
		}))
	defer client.Close()
	_, err = client.R().Get("/")
	if !errors.Is(err, prepareErr) || len(lb.reports) != 0 {
		t.Errorf("preparation error=%v feedback=%+v", err, lb.reports)
	}
}
