// Copyright (c) 2015-2024 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"testing"
)

func TestIsJSONType(t *testing.T) {
	for _, test := range []struct {
		input  string
		expect bool
	}{
		{"application/json", true},
		{"application/xml+json", true},
		{"application/vnd.foo+json", true},

		{"application/json; charset=utf-8", true},
		{"application/vnd.foo+json; charset=utf-8", true},

		{"text/json", true},
		{"text/vnd.foo+json", true},

		{"application/foo-json", true},
		{"application/foo.json", true},
		{"application/vnd.foo-json", true},
		{"application/vnd.foo.json", true},
		{"application/x-amz-json-1.1", true},

		{"text/foo-json", true},
		{"text/foo.json", true},
		{"text/vnd.foo-json", true},
		{"text/vnd.foo.json", true},
	} {
		result := IsJSONType(test.input)

		if result != test.expect {
			t.Errorf("failed on %q: want %v, got %v", test.input, test.expect, result)
		}
	}
}

func TestIsXMLType(t *testing.T) {
	for _, test := range []struct {
		input  string
		expect bool
	}{
		{"application/xml", true},
		{"application/vnd.foo+xml", true},

		{"application/xml; charset=utf-8", true},
		{"application/vnd.foo+xml; charset=utf-8", true},

		{"text/xml", true},
		{"text/vnd.foo+xml", true},

		{"application/foo-xml", true},
		{"application/foo.xml", true},
		{"application/vnd.foo-xml", true},
		{"application/vnd.foo.xml", true},

		{"text/foo-xml", true},
		{"text/foo.xml", true},
		{"text/vnd.foo-xml", true},
		{"text/vnd.foo.xml", true},
	} {
		result := IsXMLType(test.input)

		if result != test.expect {
			t.Errorf("failed on %q: want %v, got %v", test.input, test.expect, result)
		}
	}
}

func TestWriteMultipartFormFileReaderEmpty(t *testing.T) {
	w := multipart.NewWriter(bytes.NewBuffer(nil))
	defer func() { _ = w.Close() }()
	if err := writeMultipartFormFile(w, "foo", "bar", bytes.NewReader(nil)); err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
}

func TestWriteMultipartFormFileReaderError(t *testing.T) {
	err := writeMultipartFormFile(nil, "", "", &brokenReadCloser{})
	assertNotNil(t, err)
	assertEqual(t, "read error", err.Error())
}

func TestRestyErrorFuncs(t *testing.T) {
	ne1 := errors.New("new error 1")
	nie1 := errors.New("inner error 1")

	e := wrapErrors(ne1, nie1)
	assertEqual(t, "new error 1", e.Error())
	assertEqual(t, "inner error 1", errors.Unwrap(e).Error())

	e = wrapErrors(ne1, nil)
	assertEqual(t, "new error 1", e.Error())

	e = wrapErrors(nil, nie1)
	assertEqual(t, "inner error 1", e.Error())
}

func TestBuildCurlCommand(t *testing.T) {
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
			// Setup request
			var (
				req *http.Request
				err error
			)

			if tt.body != "" {
				req, err = http.NewRequest(tt.method, tt.url, bytes.NewBufferString(tt.body))
			} else {
				req, err = http.NewRequest(tt.method, tt.url, nil)
			}

			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			// Setup cookie jar
			cookieJar, _ := cookiejar.New(nil)
			if len(tt.cookies) > 0 {
				cookieJar.SetCookies(req.URL, tt.cookies)
			}

			// Generate curl command
			curl := buildCurlRequest(req, cookieJar)

			// Assert
			assertEqual(t, tt.expected, curl)
		})
	}
}
