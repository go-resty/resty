// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
)

func TestCurlGenerateUnexecutedRequest(t *testing.T) {
	req := dcnldr().
		SetBody(map[string]string{
			"name": "Resty",
		}).
		SetCookies(
			[]*http.Cookie{
				{Name: "count", Value: "1"},
			},
		).
		SetMethod(MethodPost)

	assertEqual(t, "", req.CurlCmd())

	curlCmdUnexecuted := req.EnableGenerateCurlCmd().CurlCmd()
	req.DisableGenerateCurlCmd()

	if !strings.Contains(curlCmdUnexecuted, "Cookie: count=1") ||
		!strings.Contains(curlCmdUnexecuted, "curl -X POST") ||
		!strings.Contains(curlCmdUnexecuted, `-d '{"name":"Resty"}'`) {
		t.Fatal("Incomplete curl:", curlCmdUnexecuted)
	} else {
		t.Log("curlCmdUnexecuted: \n", curlCmdUnexecuted)
	}

}

func TestCurlGenerateExecutedRequest(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	data := map[string]string{
		"name": "Resty",
	}
	c := dcnl().EnableDebug()
	req := c.R().
		SetBody(data).
		SetCookies(
			[]*http.Cookie{
				{Name: "count", Value: "1"},
			},
		)

	url := ts.URL + "/curl-cmd-post"
	resp, err := req.
		EnableGenerateCurlCmd().
		Post(url)
	if err != nil {
		t.Fatal(err)
	}
	curlCmdExecuted := resp.Request.CurlCmd()

	c.DisableGenerateCurlCmd()
	req.DisableGenerateCurlCmd()
	if !strings.Contains(curlCmdExecuted, "Cookie: count=1") ||
		!strings.Contains(curlCmdExecuted, "curl -X POST") ||
		!strings.Contains(curlCmdExecuted, `-d '{"name":"Resty"}'`) ||
		!strings.Contains(curlCmdExecuted, url) {
		t.Fatal("Incomplete curl:", curlCmdExecuted)
	} else {
		t.Log("curlCmdExecuted: \n", curlCmdExecuted)
	}
}

func TestCurlCmdDebugMode(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c, logBuf := dcldb()
	c.EnableGenerateCurlCmd().
		SetDebugLogCurlCmd(true)

	// Build request
	req := c.R().
		SetBody(map[string]string{
			"name": "Resty",
		}).
		SetCookies(
			[]*http.Cookie{
				{Name: "count", Value: "1"},
			},
		).
		SetDebugLogCurlCmd(true)

	// Execute request: set debug mode
	url := ts.URL + "/curl-cmd-post"
	_, err := req.SetDebug(true).Post(url)
	if err != nil {
		t.Fatal(err)
	}

	c.DisableGenerateCurlCmd()
	req.DisableGenerateCurlCmd()

	// test logContent curl cmd
	logContent := logBuf.String()
	if !strings.Contains(logContent, "Cookie: count=1") ||
		!strings.Contains(logContent, `-d '{"name":"Resty"}'`) {
		t.Fatal("Incomplete debug curl info:", logContent)
	}
}

func TestCurl_buildCurlCmd(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		url      string
		headers  map[string]string
		body     string
		cookies  []*http.Cookie
		expected string
	}{
		{
			name:     "With Headers",
			method:   "GET",
			url:      "http://example.com",
			headers:  map[string]string{"Content-Type": "application/json", "Authorization": "Bearer token"},
			expected: "curl -X GET -H 'Authorization: Bearer token' -H 'Content-Type: application/json' http://example.com",
		},
		{
			name:     "With Body",
			method:   "POST",
			url:      "http://example.com",
			headers:  map[string]string{"Content-Type": "application/json"},
			body:     `{"key":"value"}`,
			expected: "curl -X POST -H 'Content-Type: application/json' -d '{\"key\":\"value\"}' http://example.com",
		},
		{
			name:     "With Empty Body",
			method:   "POST",
			url:      "http://example.com",
			headers:  map[string]string{"Content-Type": "application/json"},
			expected: "curl -X POST -H 'Content-Type: application/json' http://example.com",
		},
		{
			name:     "With Query Params",
			method:   "GET",
			url:      "http://example.com?param1=value1&param2=value2",
			expected: "curl -X GET 'http://example.com?param1=value1&param2=value2'",
		},
		{
			name:     "With Special Characters in URL",
			method:   "GET",
			url:      "http://example.com/path with spaces",
			expected: "curl -X GET http://example.com/path%20with%20spaces",
		},
		{
			name:     "With Cookies",
			method:   "GET",
			url:      "http://example.com",
			cookies:  []*http.Cookie{{Name: "session_id", Value: "abc123"}},
			expected: "curl -X GET -H 'Cookie: session_id=abc123' http://example.com",
		},
		{
			name:     "Without Cookies",
			method:   "GET",
			url:      "http://example.com",
			expected: "curl -X GET http://example.com",
		},
		{
			name:     "With Multiple Cookies",
			method:   "GET",
			url:      "http://example.com",
			cookies:  []*http.Cookie{{Name: "session_id", Value: "abc123"}, {Name: "user_id", Value: "user456"}},
			expected: "curl -X GET -H 'Cookie: session_id=abc123&user_id=user456' http://example.com",
		},
		{
			name:     "With Empty Cookie Jar",
			method:   "GET",
			url:      "http://example.com",
			expected: "curl -X GET http://example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := dcnl()
			req := c.R().SetMethod(tt.method).SetURL(tt.url)

			if !isStringEmpty(tt.body) {
				req.SetBody(bytes.NewBufferString(tt.body))
			}

			for k, v := range tt.headers {
				req.SetHeader(k, v)
			}

			err := createRawRequest(c, req)
			assertNil(t, err)

			if len(tt.cookies) > 0 {
				cookieJar, _ := cookiejar.New(nil)
				cookieJar.SetCookies(req.RawRequest.URL, tt.cookies)
				c.SetCookieJar(cookieJar)
			}

			curlCmd := buildCurlCmd(req)
			assertEqual(t, tt.expected, curlCmd)
		})
	}
}

func TestCurlRequestGetBodyError(t *testing.T) {
	c := dcnl().
		EnableDebug().
		SetRequestMiddlewares(
			PrepareRequestMiddleware,
			func(_ *Client, r *Request) error {
				r.RawRequest.GetBody = func() (io.ReadCloser, error) {
					return nil, errors.New("test case error")
				}
				return nil
			},
		)

	req := c.R().
		SetBody(map[string]string{
			"name": "Resty",
		}).
		SetCookies(
			[]*http.Cookie{
				{Name: "count", Value: "1"},
			},
		).
		SetMethod(MethodPost)

	assertEqual(t, "", req.CurlCmd())

	curlCmdUnexecuted := req.EnableGenerateCurlCmd().CurlCmd()
	req.DisableGenerateCurlCmd()

	if !strings.Contains(curlCmdUnexecuted, "Cookie: count=1") ||
		!strings.Contains(curlCmdUnexecuted, "curl -X POST") ||
		!strings.Contains(curlCmdUnexecuted, `-d ''`) {
		t.Fatal("Incomplete curl:", curlCmdUnexecuted)
	} else {
		t.Log("curlCmdUnexecuted: \n", curlCmdUnexecuted)
	}
}

func TestCurlRequestMiddlewaresError(t *testing.T) {
	errMsg := "middleware error"
	c := dcnl().EnableDebug().
		SetRequestMiddlewares(
			func(c *Client, r *Request) error {
				return errors.New(errMsg)
			},
			PrepareRequestMiddleware,
		)

	curlCmdUnexecuted := c.R().EnableGenerateCurlCmd().CurlCmd()
	assertEqual(t, "", curlCmdUnexecuted)
}

func TestCurlMiscTestCoverage(t *testing.T) {
	cookieStr := dumpCurlCookies([]*http.Cookie{
		{Name: "count", Value: "1"},
	})
	assertEqual(t, "Cookie: count=1", cookieStr)
}
