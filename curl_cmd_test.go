package resty

import (
	"bytes"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
)

// 1. Generate curl for unexecuted request(dry-run)
func TestGenerateUnexecutedCurl(t *testing.T) {
	req := dclr().
		SetBody(map[string]string{
			"name": "Alex",
		}).
		SetCookies(
			[]*http.Cookie{
				{Name: "count", Value: "1"},
			},
		)

	curlCmdUnexecuted := req.EnableGenerateCurlOnDebug().GenerateCurlCommand()
	req.DisableGenerateCurlOnDebug()

	if !strings.Contains(curlCmdUnexecuted, "Cookie: count=1") ||
		!strings.Contains(curlCmdUnexecuted, "curl -X GET") ||
		!strings.Contains(curlCmdUnexecuted, `-d '{"name":"Alex"}'`) {
		t.Fatal("Incomplete curl:", curlCmdUnexecuted)
	} else {
		t.Log("curlCmdUnexecuted: \n", curlCmdUnexecuted)
	}

}

// 2. Generate curl for executed request
func TestGenerateExecutedCurl(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	data := map[string]string{
		"name": "Alex",
	}
	c := dcl()
	req := c.R().
		SetBody(data).
		SetCookies(
			[]*http.Cookie{
				{Name: "count", Value: "1"},
			},
		)

	url := ts.URL + "/curl-cmd-post"
	resp, err := req.
		EnableGenerateCurlOnDebug().
		Post(url)
	if err != nil {
		t.Fatal(err)
	}
	curlCmdExecuted := resp.Request.GenerateCurlCommand()

	c.DisableGenerateCurlOnDebug()
	req.DisableGenerateCurlOnDebug()
	if !strings.Contains(curlCmdExecuted, "Cookie: count=1") ||
		!strings.Contains(curlCmdExecuted, "curl -X POST") ||
		!strings.Contains(curlCmdExecuted, `-d '{"name":"Alex"}'`) ||
		!strings.Contains(curlCmdExecuted, url) {
		t.Fatal("Incomplete curl:", curlCmdExecuted)
	} else {
		t.Log("curlCmdExecuted: \n", curlCmdExecuted)
	}
}

// 3. Generate curl in debug mode
func TestDebugModeCurl(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	// 1. Capture stderr
	getOutput, restore := captureStderr()
	defer restore()

	// 2. Build request
	c := New()
	req := c.EnableGenerateCurlOnDebug().R().
		SetBody(map[string]string{
			"name": "Alex",
		}).
		SetCookies(
			[]*http.Cookie{
				{Name: "count", Value: "1"},
			},
		)

	// 3. Execute request: set debug mode
	url := ts.URL + "/curl-cmd-post"
	_, err := req.SetDebug(true).Post(url)
	if err != nil {
		t.Fatal(err)
	}

	c.DisableGenerateCurlOnDebug()
	req.DisableGenerateCurlOnDebug()

	// 4. test output curl
	output := getOutput()
	if !strings.Contains(output, "Cookie: count=1") ||
		!strings.Contains(output, `-d '{"name":"Alex"}'`) {
		t.Fatal("Incomplete debug curl info:", output)
	} else {
		t.Log("Normal debug curl info: \n", output)
	}
}

func captureStderr() (getOutput func() string, restore func()) {
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	os.Stderr = w
	getOutput = func() string {
		w.Close()
		buf := make([]byte, 2048)
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		return string(buf[:n])
	}
	restore = func() {
		os.Stderr = old
		w.Close()
	}
	return getOutput, restore
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
