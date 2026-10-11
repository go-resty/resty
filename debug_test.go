// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type headerInjectingTransport struct {
	base    http.RoundTripper
	headers map[string]string
	clone   bool
}

func (t *headerInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	targetReq := req
	if t.clone {
		targetReq = req.Clone(req.Context())
	}
	for k, v := range t.headers {
		targetReq.Header.Set(k, v)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(targetReq)
}

func TestDebugLogRoundTripperInjectedHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	c, lb := dcldb()
	defer releaseBuffer(lb)

	transport := &headerInjectingTransport{
		base: http.DefaultTransport,
		headers: map[string]string{
			"traceparent":              "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			"X-Custom-Injected-Header": "injected-value",
		},
		clone: true,
	}
	c.SetTransport(transport)

	var callbackReqHeader http.Header
	c.OnDebugLog(func(dl *DebugLog) {
		callbackReqHeader = dl.Request.Header.Clone()
	})

	resp, err := c.R().
		SetHeader("X-Initial-Header", "initial-value").
		Get(ts.URL + "/test-endpoint")

	assertNil(t, err)
	assertNotNil(t, resp)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	assertNotNil(t, callbackReqHeader)
	assertEqual(t, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", callbackReqHeader.Get("traceparent"))
	assertEqual(t, "injected-value", callbackReqHeader.Get("X-Custom-Injected-Header"))
	assertEqual(t, "initial-value", callbackReqHeader.Get("X-Initial-Header"))

	logOutput := lb.String()
	assertTrue(t, strings.Contains(logOutput, "Traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
		"debug log output should contain injected traceparent header")
	assertTrue(t, strings.Contains(logOutput, "X-Custom-Injected-Header: injected-value"),
		"debug log output should contain injected X-Custom-Injected-Header")
	assertTrue(t, strings.Contains(logOutput, "X-Initial-Header: initial-value"),
		"debug log output should contain initial header")
}

func TestDebugLogRoundTripperInjectedHeadersJSONFormatter(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	c, lb := dcldb()
	defer releaseBuffer(lb)

	c.SetDebugLogFormatter(DebugLogJSONFormatter)
	transport := &headerInjectingTransport{
		base: http.DefaultTransport,
		headers: map[string]string{
			"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		},
		clone: true,
	}
	c.SetTransport(transport)

	resp, err := c.R().Get(ts.URL + "/json-test")
	assertNil(t, err)
	assertNotNil(t, resp)

	logOutput := lb.String()
	jsonIdx := strings.Index(logOutput, "{")
	assertTrue(t, jsonIdx >= 0, "log output should contain JSON opening brace")

	var parsedLog DebugLog
	err = json.Unmarshal([]byte(strings.TrimSpace(logOutput[jsonIdx:])), &parsedLog)
	assertNil(t, err, "JSON debug log should unmarshal cleanly")
	assertNotNil(t, parsedLog.Request)
	assertEqual(t, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", parsedLog.Request.Header.Get("traceparent"))
}

func TestDebugLogRoundTripperInjectedHeadersSanitization(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	c, lb := dcldb()
	defer releaseBuffer(lb)

	transport := &headerInjectingTransport{
		base: http.DefaultTransport,
		headers: map[string]string{
			"Authorization": "Bearer injected-secret-token",
		},
		clone: true,
	}
	c.SetTransport(transport)

	var loggedAuthHeader string
	c.OnDebugLog(func(dl *DebugLog) {
		loggedAuthHeader = dl.Request.Header.Get("Authorization")
	})

	resp, err := c.R().Get(ts.URL + "/auth-test")
	assertNil(t, err)
	assertNotNil(t, resp)

	assertEqual(t, "*****REDACTED*****", loggedAuthHeader)
	logOutput := lb.String()
	assertFalse(t, strings.Contains(logOutput, "injected-secret-token"),
		"debug log output should not contain secret authorization token")
	assertTrue(t, strings.Contains(logOutput, "*****REDACTED*****"),
		"debug log output should contain redacted authorization header")
}

func TestDebugLoggerExecutedRequestFallback(t *testing.T) {
	var lb strings.Builder
	c := New().SetLogger(&logger{l: log.New(&lb, "", 0)})
	defer c.Close()

	req := c.R()
	req.IsDebug = true
	req.initValuesMap()

	httpReq, err := http.NewRequest(http.MethodGet, "http://example.com/fallback-test", nil)
	assertNil(t, err)
	httpReq.Header.Set("traceparent", "00-test-trace-id-01")

	httpRes := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     make(http.Header),
		Request:    httpReq,
	}

	res := &Response{
		Request:     req,
		RawResponse: httpRes,
	}
	res.setReceivedAt()

	debugLogger(c, res)

	output := lb.String()
	assertTrue(t, strings.Contains(output, "Traceparent: 00-test-trace-id-01"),
		"debug log should capture executed request headers even without prior prepared request log")
	assertTrue(t, strings.Contains(output, "example.com"),
		"debug log should capture host from executed request")
}

func TestDebugLoggerNilSafeguards(t *testing.T) {
	c := New()
	defer c.Close()

	// Should not panic on nil response
	debugLogger(c, nil)

	// Should not panic on nil request
	debugLogger(c, &Response{})

	// Should not panic on nil RawResponse
	req := c.R()
	req.IsDebug = true
	res := &Response{Request: req}
	debugLogger(c, res)
}
