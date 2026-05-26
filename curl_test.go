// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"errors"
	"fmt"
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

	curlCmdUnexecuted := req.SetCurlCmdGenerate(true).CurlCmd()
	req.SetCurlCmdGenerate(false)

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
	c := dcnl().SetDebug(true)
	req := c.R().
		SetBody(data).
		SetCookies(
			[]*http.Cookie{
				{Name: "count", Value: "1"},
			},
		)

	url := ts.URL + "/curl-cmd-post"
	resp, err := req.
		SetCurlCmdGenerate(true).
		Post(url)
	if err != nil {
		t.Fatal(err)
	}
	curlCmdExecuted := resp.Request.CurlCmd()

	c.SetCurlCmdGenerate(false)
	req.SetCurlCmdGenerate(false)
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
	c.SetCurlCmdGenerate(true).
		SetCurlCmdDebugLog(true)

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
		SetCurlCmdDebugLog(true)

	// Execute request: set debug mode
	url := ts.URL + "/curl-cmd-post"
	_, err := req.SetDebug(true).Post(url)
	if err != nil {
		t.Fatal(err)
	}

	c.SetCurlCmdGenerate(false)
	req.SetCurlCmdGenerate(false)

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
			expected: "curl -X GET -H 'Authorization: *****REDACTED*****' -H 'Content-Type: application/json' http://example.com",
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
			expected: "curl -X GET -H 'Cookie: session_id=abc123; user_id=user456' http://example.com",
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
		SetDebug(true).
		SetRequestMiddlewares(
			MiddlewareRequestCreate,
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

	curlCmdUnexecuted := req.SetCurlCmdGenerate(true).CurlCmd()
	req.SetCurlCmdGenerate(false)

	if !strings.Contains(curlCmdUnexecuted, "Cookie: count=1") ||
		!strings.Contains(curlCmdUnexecuted, "curl -X POST") ||
		!strings.Contains(curlCmdUnexecuted, `-d '' http`) {
		t.Fatal("Incomplete curl:", curlCmdUnexecuted)
	} else {
		t.Log("curlCmdUnexecuted: \n", curlCmdUnexecuted)
	}
}

func TestCurlRequestMiddlewaresError(t *testing.T) {
	errMsg := "middleware error"
	c := dcnl().SetDebug(true).
		SetRequestMiddlewares(
			func(c *Client, r *Request) error {
				return errors.New(errMsg)
			},
			MiddlewareRequestCreate,
		)

	curlCmdUnexecuted := c.R().SetCurlCmdGenerate(true).CurlCmd()
	assertEqual(t, "", curlCmdUnexecuted)
}

func TestCurlMultipleCookies(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "id", Value: "123"},
		{Name: "token", Value: "abc"},
		{Name: "pref", Value: "lang=en"},
	}

	curl := dumpCurlCookies(cookies)

	// Should be semicolon-delimited per RFC 6265
	expected := "Cookie: id=123; token=abc; pref=lang%3Den"
	assertEqual(t, expected, curl)
}

func TestCurlMiscTestCoverage(t *testing.T) {
	cookieStr := dumpCurlCookies([]*http.Cookie{
		{Name: "count", Value: "1"},
	})
	assertEqual(t, "Cookie: count=1", cookieStr)

	// cmdQuote with empty string
	assertEqual(t, "''", cmdQuote(""), "Empty string should be quoted as ''")
}

func TestCurlMultipartFormData(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		method      string
		url         string
		hasBody     bool
		shouldMatch string
	}{
		{
			name:        "Multipart form-data basic",
			contentType: "multipart/form-data",
			method:      "POST",
			url:         "http://example.com/upload",
			hasBody:     true,
			shouldMatch: "-F '<fields omitted, see original request>'",
		},
		{
			name:        "Multipart form-data with boundary",
			contentType: "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
			method:      "POST",
			url:         "http://example.com/upload",
			hasBody:     true,
			shouldMatch: "-F '<fields omitted, see original request>'",
		},
		{
			name:        "Multipart form-data with charset",
			contentType: "multipart/form-data; charset=utf-8",
			method:      "POST",
			url:         "http://example.com/upload",
			hasBody:     true,
			shouldMatch: "-F '<fields omitted, see original request>'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := dcnl()
			req := c.R().
				SetMethod(tt.method).
				SetURL(tt.url).
				SetHeader(hdrContentTypeKey, tt.contentType)

			if tt.hasBody {
				req.SetBody(bytes.NewBufferString("multipart body data"))
			}

			err := createRawRequest(c, req)
			if err != nil {
				t.Fatalf("Failed to create raw request: %v", err)
			}

			curlCmd := buildCurlCmd(req)

			// Verify multipart placeholder is included
			assertTrue(t, strings.Contains(curlCmd, tt.shouldMatch), fmt.Sprintf("Expected curl command to contain '%s', but got: %s", tt.shouldMatch, curlCmd))

			// Verify -F flag is used (not -d)
			assertTrue(t, strings.Contains(curlCmd, "-F"), fmt.Sprintf("Expected curl command to contain '-F' flag, but got: %s", curlCmd))

			// Verify method is included
			assertTrue(t, strings.Contains(curlCmd, "curl -X "+tt.method), fmt.Sprintf("Expected curl command to contain 'curl -X %s'", tt.method))

			// Verify URL is included and separated from the -F placeholder by a space
			assertTrue(t, strings.Contains(curlCmd, " "+tt.url), fmt.Sprintf("Expected curl command to contain URL '%s' preceded by a space, got: %s", tt.url, curlCmd))

			// Verify -d flag is NOT used for multipart
			assertFalse(t, strings.Contains(curlCmd, "-d '"), "Multipart request should use -F flag, not -d flag")
		})
	}
}

func TestCurlMultipartWithCookies(t *testing.T) {
	c := dcnl()
	cookies := []*http.Cookie{
		{Name: "session", Value: "abc123"},
		{Name: "user_id", Value: "user456"},
	}

	req := c.R().
		SetMethod("POST").
		SetURL("http://example.com/upload").
		SetHeader("Content-Type", "multipart/form-data")

	req.SetBody(bytes.NewBufferString("file content"))

	err := createRawRequest(c, req)
	assertError(t, err, "failed to create raw request")

	// Set cookies in the client's cookie jar
	cookieJar, _ := cookiejar.New(nil)
	cookieJar.SetCookies(req.RawRequest.URL, cookies)
	c.SetCookieJar(cookieJar)

	curlCmd := buildCurlCmd(req)

	// Verify multipart placeholder
	assertTrue(t, strings.Contains(curlCmd, "-F '<fields omitted, see original request>'"), "expected multipart placeholder in curl command")

	// Verify method
	assertTrue(t, strings.Contains(curlCmd, "curl -X POST"), "expected POST method to be included in curl command")

	// Verify URL
	assertTrue(t, strings.Contains(curlCmd, "http://example.com/upload"), "expected URL to be included in curl command")

	// Verify cookies are included
	assertTrue(t, strings.Contains(curlCmd, "-H 'Cookie:"), "expected cookies to be included in curl command")
}
