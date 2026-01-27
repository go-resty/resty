// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestRoundRobin(t *testing.T) {

	t.Run("2 base urls", func(t *testing.T) {
		rr, err := NewRoundRobin("https://example1.com", "https://example2.com")
		assertNil(t, err)

		runCount := 5
		var result []string
		for i := 0; i < runCount; i++ {
			baseURL, _ := rr.Next()
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
		for i := 0; i < runCount; i++ {
			baseURL, _ := rr.Next()
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
		for i := 0; i < runCount; i++ {
			baseURL, _ := rr.Next()
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
		for i := 0; i < runCount; i++ {
			baseURL, err := wrr.Next()
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
		for i := 0; i < runCount; i++ {
			baseURL, err := wrr.Next()
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
		for i := 0; i < runCount; i++ {
			baseURL, err := wrr.Next()
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

		_, err = wrr.Next()
		assertErrorIs(t, ErrNoActiveHost, err)
	})
}

func TestSRVWeightedRoundRobin(t *testing.T) {
	t.Run("3 records with weight {50,30,20}", func(t *testing.T) {
		srv, err := NewSRVWeightedRoundRobin("_sample-server", "", "example.com", "")
		assertNotNil(t, err)
		assertNotNil(t, srv)
		var dnsErr *net.DNSError
		assertEqual(t, true, errors.As(err, &dnsErr))

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
		for i := 0; i < runCount; i++ {
			baseURL, err := srv.Next()
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
		assertEqual(t, true, errors.As(err, &dnsErr))

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
		for i := 0; i < runCount; i++ {
			baseURL, err := srv.Next()
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
		assertEqual(t, true, errors.As(err, &dnsErr))

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
		for i := 0; i < runCount; i++ {
			baseURL, err := srv.Next()
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
		assertEqual(t, true, errors.As(err, &dnsErr))

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
				baseURL, _ := srv.Next()
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
		assertEqual(t, true, errors.As(err, &dnsErr))

		// default error flow
		err = srv.Refresh()
		assertNotNil(t, err)
		assertEqual(t, true, errors.As(err, &dnsErr))

		// replace with mock error flow
		errMockTest := errors.New("network error")
		srv.lookupSRV = func() ([]*net.SRV, error) { return nil, errMockTest }
		err = srv.Refresh()
		assertNotNil(t, err)
		assertErrorIs(t, errMockTest, err)

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
		assertEqual(t, ErrNoActiveHost, err)
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
