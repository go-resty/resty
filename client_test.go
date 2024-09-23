// Copyright (c) 2015-2024 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClientBasicAuth(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dc()
	c.SetBasicAuth("myuser", "basicauth").
		SetBaseURL(ts.URL).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		Post("/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))
	logResponse(t, resp)
}

func TestClientAuthToken(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dc()
	c.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF").
		SetBaseURL(ts.URL + "/")

	resp, err := c.R().Get("/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestClientAuthScheme(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dc()
	// Ensure default Bearer
	c.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF").
		SetBaseURL(ts.URL + "/")

	resp, err := c.R().Get("/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	// Ensure setting the scheme works as well
	c.SetAuthScheme("Bearer")
	assertEqual(t, "Bearer", c.AuthScheme())

	resp2, err2 := c.R().Get("/profile")
	assertError(t, err2)
	assertEqual(t, http.StatusOK, resp2.StatusCode())

}

func TestClientDigestAuth(t *testing.T) {
	conf := defaultDigestServerConf()
	ts := createDigestServer(t, conf)
	defer ts.Close()

	c := dc().
		SetBaseURL(ts.URL+"/").
		SetDigestAuth(conf.username, conf.password)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		Get(conf.uri)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))
	logResponse(t, resp)
}

func TestClientDigestSession(t *testing.T) {
	conf := defaultDigestServerConf()
	conf.algo = "MD5-sess"
	conf.qop = "auth, auth-int"
	ts := createDigestServer(t, conf)
	defer ts.Close()

	c := dc().
		SetBaseURL(ts.URL+"/").
		SetDigestAuth(conf.username, conf.password)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		Get(conf.uri)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))
	logResponse(t, resp)
}

func TestClientDigestErrors(t *testing.T) {
	type test struct {
		mutateConf func(*digestServerConfig)
		expect     error
	}
	tests := []test{
		{mutateConf: func(c *digestServerConfig) { c.algo = "BAD_ALGO" }, expect: ErrDigestAlgNotSupported},
		{mutateConf: func(c *digestServerConfig) { c.qop = "bad-qop" }, expect: ErrDigestQopNotSupported},
		{mutateConf: func(c *digestServerConfig) { c.qop = "" }, expect: ErrDigestNoQop},
		{mutateConf: func(c *digestServerConfig) { c.charset = "utf-16" }, expect: ErrDigestCharset},
		{mutateConf: func(c *digestServerConfig) { c.uri = "/bad" }, expect: ErrDigestBadChallenge},
		{mutateConf: func(c *digestServerConfig) { c.uri = "/unknown_param" }, expect: ErrDigestBadChallenge},
		{mutateConf: func(c *digestServerConfig) { c.uri = "/missing_value" }, expect: ErrDigestBadChallenge},
		{mutateConf: func(c *digestServerConfig) { c.uri = "/unclosed_quote" }, expect: ErrDigestBadChallenge},
		{mutateConf: func(c *digestServerConfig) { c.uri = "/no_challenge" }, expect: ErrDigestBadChallenge},
		{mutateConf: func(c *digestServerConfig) { c.uri = "/status_500" }, expect: nil},
	}

	for _, tc := range tests {
		conf := defaultDigestServerConf()
		tc.mutateConf(conf)
		ts := createDigestServer(t, conf)

		c := dc().
			SetBaseURL(ts.URL+"/").
			SetDigestAuth(conf.username, conf.password)

		_, err := c.R().Get(conf.uri)
		assertErrorIs(t, tc.expect, err)
		ts.Close()
	}
}

func TestOnAfterMiddleware(t *testing.T) {
	ts := createGenServer(t)
	defer ts.Close()

	c := dc()
	c.OnAfterResponse(func(c *Client, res *Response) error {
		t.Logf("Request sent at: %v", res.Request.Time)
		t.Logf("Response Received at: %v", res.ReceivedAt())

		return nil
	})

	resp, err := c.R().
		SetBody("OnAfterResponse: This is plain text body to server").
		Put(ts.URL + "/plaintext")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestPut: plain text response", resp.String())
}

func TestClientRedirectPolicy(t *testing.T) {
	ts := createRedirectServer(t)
	defer ts.Close()

	c := dc().SetRedirectPolicy(FlexibleRedirectPolicy(20))
	_, err := c.R().Get(ts.URL + "/redirect-1")

	assertEqual(t, true, (err.Error() == "Get /redirect-21: stopped after 20 redirects" ||
		err.Error() == "Get \"/redirect-21\": stopped after 20 redirects"))

	c.SetRedirectPolicy(NoRedirectPolicy())
	_, err = c.R().Get(ts.URL + "/redirect-1")
	assertEqual(t, true, (err.Error() == "Get /redirect-2: auto redirect is disabled" ||
		err.Error() == "Get \"/redirect-2\": auto redirect is disabled"))
}

func TestClientTimeout(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc().SetTimeout(time.Second * 3)
	_, err := c.R().Get(ts.URL + "/set-timeout-test")

	assertEqual(t, true, strings.Contains(strings.ToLower(err.Error()), "timeout"))
}

func TestClientTimeoutWithinThreshold(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc().SetTimeout(time.Second * 3)
	resp, err := c.R().Get(ts.URL + "/set-timeout-test-with-sequence")

	assertError(t, err)

	seq1, _ := strconv.ParseInt(resp.String(), 10, 32)

	resp, err = c.R().Get(ts.URL + "/set-timeout-test-with-sequence")
	assertError(t, err)

	seq2, _ := strconv.ParseInt(resp.String(), 10, 32)

	assertEqual(t, seq1+1, seq2)
}

func TestClientTimeoutInternalError(t *testing.T) {
	c := dc().SetTimeout(time.Second * 1)
	_, _ = c.R().Get("http://localhost:9000/set-timeout-test")
}

func TestClientProxy(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetTimeout(1 * time.Second)
	c.SetProxy("http://sampleproxy:8888")

	resp, err := c.R().Get(ts.URL)
	assertNotNil(t, resp)
	assertNotNil(t, err)

	// error
	c.SetProxy("//not.a.user@%66%6f%6f.com:8888")

	resp, err = c.R().
		Get(ts.URL)
	assertNotNil(t, err)
	assertNotNil(t, resp)
}

func TestClientSetCertificates(t *testing.T) {
	client := dc()
	client.SetCertificates(tls.Certificate{})

	transport, err := client.Transport()

	assertNil(t, err)
	assertEqual(t, 1, len(transport.TLSClientConfig.Certificates))
}

func TestClientSetRootCertificate(t *testing.T) {
	client := dc()
	client.SetRootCertificate(filepath.Join(getTestDataPath(), "sample-root.pem"))

	transport, err := client.Transport()

	assertNil(t, err)
	assertNotNil(t, transport.TLSClientConfig.RootCAs)
}

func TestClientSetRootCertificateNotExists(t *testing.T) {
	client := dc()
	client.SetRootCertificate(filepath.Join(getTestDataPath(), "not-exists-sample-root.pem"))

	transport, err := client.Transport()

	assertNil(t, err)
	assertNil(t, transport.TLSClientConfig)
}

func TestClientSetRootCertificateFromString(t *testing.T) {
	client := dc()
	rootPemData, err := os.ReadFile(filepath.Join(getTestDataPath(), "sample-root.pem"))
	assertNil(t, err)

	client.SetRootCertificateFromString(string(rootPemData))

	transport, err := client.Transport()

	assertNil(t, err)
	assertNotNil(t, transport.TLSClientConfig.RootCAs)
}

func TestClientSetRootCertificateFromStringErrorTls(t *testing.T) {
	client := NewWithClient(&http.Client{})
	client.outputLogTo(io.Discard)

	rootPemData, err := os.ReadFile(filepath.Join(getTestDataPath(), "sample-root.pem"))
	assertNil(t, err)
	rt := &CustomRoundTripper{}
	client.SetTransport(rt)
	transport, err := client.Transport()

	client.SetRootCertificateFromString(string(rootPemData))

	assertNotNil(t, rt)
	assertNotNil(t, err)
	assertNil(t, transport)
}

func TestClientSetClientRootCertificate(t *testing.T) {
	client := dc()
	client.SetClientRootCertificate(filepath.Join(getTestDataPath(), "sample-root.pem"))

	transport, err := client.Transport()

	assertNil(t, err)
	assertNotNil(t, transport.TLSClientConfig.ClientCAs)
}

func TestClientSetClientRootCertificateNotExists(t *testing.T) {
	client := dc()
	client.SetClientRootCertificate(filepath.Join(getTestDataPath(), "not-exists-sample-root.pem"))

	transport, err := client.Transport()

	assertNil(t, err)
	assertNil(t, transport.TLSClientConfig)
}

func TestClientSetClientRootCertificateFromString(t *testing.T) {
	client := dc()
	rootPemData, err := os.ReadFile(filepath.Join(getTestDataPath(), "sample-root.pem"))
	assertNil(t, err)

	client.SetClientRootCertificateFromString(string(rootPemData))

	transport, err := client.Transport()

	assertNil(t, err)
	assertNotNil(t, transport.TLSClientConfig.ClientCAs)
}

func TestClientSetClientRootCertificateFromStringErrorTls(t *testing.T) {
	client := NewWithClient(&http.Client{})
	client.outputLogTo(io.Discard)

	rootPemData, err := os.ReadFile(filepath.Join(getTestDataPath(), "sample-root.pem"))
	assertNil(t, err)
	rt := &CustomRoundTripper{}
	client.SetTransport(rt)
	transport, err := client.Transport()

	client.SetClientRootCertificateFromString(string(rootPemData))

	assertNotNil(t, rt)
	assertNotNil(t, err)
	assertNil(t, transport)
}

func TestClientOnBeforeRequestModification(t *testing.T) {
	tc := dc()
	tc.OnBeforeRequest(func(c *Client, r *Request) error {
		r.SetAuthToken("This is test auth token")
		return nil
	})

	ts := createGetServer(t)
	defer ts.Close()

	resp, err := tc.R().Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertNotNil(t, resp.BodyBytes())
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
}

func TestClientSetHeaderVerbatim(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dc().
		SetHeaderVerbatim("header-lowercase", "value_lowercase").
		SetHeader("header-lowercase", "value_standard")

	//lint:ignore SA1008 valid one, so ignore this!
	unConventionHdrValue := strings.Join(c.Header()["header-lowercase"], "")
	assertEqual(t, "value_lowercase", unConventionHdrValue)
	assertEqual(t, "value_standard", c.Header().Get("Header-Lowercase"))
}

func TestClientSetTransport(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()
	client := dc()

	transport := &http.Transport{
		// something like Proxying to httptest.Server, etc...
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(ts.URL)
		},
	}
	client.SetTransport(transport)
	transportInUse, err := client.Transport()

	assertNil(t, err)
	assertEqual(t, true, transport == transportInUse)
}

func TestClientSetScheme(t *testing.T) {
	client := dc()

	client.SetScheme("http")

	assertEqual(t, true, client.scheme == "http")
}

func TestClientSetCookieJar(t *testing.T) {
	client := dc()
	backupJar := client.httpClient.Jar

	client.SetCookieJar(nil)
	assertNil(t, client.httpClient.Jar)

	client.SetCookieJar(backupJar)
	assertEqual(t, true, client.httpClient.Jar == backupJar)
}

// This test methods exist for test coverage purpose
// to validate the getter and setter
func TestClientSettingsCoverage(t *testing.T) {
	c := dc()

	assertNotNil(t, c.CookieJar())
	assertNotNil(t, c.ContentTypeEncoders())
	assertNotNil(t, c.ContentTypeDecoders())
	assertEqual(t, false, c.IsDebug())
	assertEqual(t, math.MaxInt32, c.DebugBodyLimit())
	assertNotNil(t, c.Logger())
	assertEqual(t, false, c.IsContentLength())
	assertEqual(t, 0, c.RetryCount())
	assertEqual(t, time.Millisecond*100, c.RetryWaitTime())
	assertEqual(t, time.Second*2, c.RetryMaxWaitTime())
	assertEqual(t, false, c.IsTrace())

	authToken := "sample auth token value"
	c.SetAuthToken(authToken)
	assertEqual(t, authToken, c.AuthToken())

	type brokenRedirectPolicy struct{}
	c.SetRedirectPolicy(&brokenRedirectPolicy{})

	c.SetCloseConnection(true)

	// [Start] Custom Transport scenario
	ct := dc()
	ct.SetTransport(&CustomRoundTripper{})
	_, err := ct.Transport()
	assertNotNil(t, err)
	assertEqual(t, ErrNotHttpTransportType, err)

	ct.SetProxy("http://localhost:8080")
	ct.RemoveProxy()

	ct.SetCertificates(tls.Certificate{})
	ct.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	ct.outputLogTo(io.Discard)
	// [End] Custom Transport scenario
}

func TestContentLengthWhenBodyIsNil(t *testing.T) {
	client := dc()

	client.SetPreRequestHook(func(c *Client, r *http.Request) error {
		assertEqual(t, "0", r.Header.Get(hdrContentLengthKey))
		return nil
	})

	client.R().SetContentLength(true).SetBody(nil).Get("http://localhost")
}

func TestClientPreRequestHook(t *testing.T) {
	client := dc()
	client.SetPreRequestHook(func(c *Client, r *http.Request) error {
		c.log.Debugf("I'm in Pre-Request Hook")
		return nil
	})

	client.SetPreRequestHook(func(c *Client, r *http.Request) error {
		c.log.Debugf("I'm Overwriting existing Pre-Request Hook")

		// Reading Request `N` no of times
		for i := 0; i < 5; i++ {
			b, _ := r.GetBody()
			rb, _ := io.ReadAll(b)
			c.log.Debugf("%s %v", string(rb), len(rb))
			assertEqual(t, true, len(rb) >= 45)
		}
		return nil
	})

	ts := createPostServer(t)
	defer ts.Close()

	// Regular bodybuf use case
	resp, _ := client.R().
		SetBody(map[string]any{"username": "testuser", "password": "testpass"}).
		Post(ts.URL + "/login")
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, `{ "id": "success", "message": "login successful" }`, resp.String())

	// io.Reader body use case
	resp, _ = client.R().
		SetHeader(hdrContentTypeKey, jsonContentType).
		SetBody(bytes.NewReader([]byte(`{"username":"testuser", "password":"testpass"}`))).
		Post(ts.URL + "/login")
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, `{ "id": "success", "message": "login successful" }`, resp.String())
}

func TestClientAllowsGetMethodPayload(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetAllowGetMethodPayload(true)
	c.SetPreRequestHook(func(*Client, *http.Request) error { return nil }) // for coverage

	payload := "test-payload"
	resp, err := c.R().SetBody(payload).Get(ts.URL + "/get-method-payload-test")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, payload, resp.String())
}

func TestClientAllowsGetMethodPayloadIoReader(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetAllowGetMethodPayload(true)

	payload := "test-payload"
	body := bytes.NewReader([]byte(payload))
	resp, err := c.R().SetBody(body).Get(ts.URL + "/get-method-payload-test")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, payload, resp.String())
}

func TestClientAllowsGetMethodPayloadDisabled(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetAllowGetMethodPayload(false)

	payload := bytes.NewReader([]byte("test-payload"))
	resp, err := c.R().SetBody(payload).Get(ts.URL + "/get-method-payload-test")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "", resp.String())
}

func TestClientRoundTripper(t *testing.T) {
	c := NewWithClient(&http.Client{})
	c.outputLogTo(io.Discard)

	rt := &CustomRoundTripper{}
	c.SetTransport(rt)

	ct, err := c.Transport()
	assertNotNil(t, err)
	assertNil(t, ct)
	assertEqual(t, ErrNotHttpTransportType, err)
}

func TestClientNewRequest(t *testing.T) {
	c := New()
	request := c.NewRequest()
	assertNotNil(t, request)
}

func TestDebugBodySizeLimit(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc().
		SetDebug(true).
		SetDebugBodyLimit(30)

	var lgr bytes.Buffer
	c.outputLogTo(&lgr) // internal method

	testcases := []struct{ url, want string }{
		// Text, does not exceed limit.
		{ts.URL, "TestGet: text response"},
		// Empty response.
		{ts.URL + "/no-content", "***** NO CONTENT *****"},
		// JSON, does not exceed limit.
		{ts.URL + "/json", "{\n   \"TestGet\": \"JSON response\"\n}"},
		// Invalid JSON, does not exceed limit.
		{ts.URL + "/json-invalid", "TestGet: Invalid JSON"},
		// Text, exceeds limit.
		{ts.URL + "/long-text", "RESPONSE TOO LARGE"},
		// JSON, exceeds limit.
		{ts.URL + "/long-json", "RESPONSE TOO LARGE"},
	}

	for _, tc := range testcases {
		_, err := c.R().Get(tc.url)
		assertError(t, err)
		debugLog := lgr.String()
		if !strings.Contains(debugLog, tc.want) {
			t.Errorf("Expected logs to contain [%v], got [\n%v]", tc.want, debugLog)
		}
		lgr.Reset()
	}
}

// CustomRoundTripper just for test
type CustomRoundTripper struct {
}

// RoundTrip just for test
func (rt *CustomRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{}, nil
}

func TestAutoGzip(t *testing.T) {
	ts := createGenServer(t)
	defer ts.Close()

	c := New()
	testcases := []struct{ url, want string }{
		{ts.URL + "/gzip-test", "This is Gzip response testing"},
		{ts.URL + "/gzip-test-gziped-empty-body", ""},
		{ts.URL + "/gzip-test-no-gziped-body", ""},
	}
	for _, tc := range testcases {
		resp, err := c.R().
			// SetHeader("Accept-Encoding", "gzip"). // TODO put back when implementing compression handling
			Get(tc.url)

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, "200 OK", resp.Status())
		assertNotNil(t, resp.BodyBytes())
		assertEqual(t, tc.want, resp.String())

		logResponse(t, resp)
	}
}

func TestLogCallbacks(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := New().SetDebug(true)

	var lgr bytes.Buffer
	c.outputLogTo(&lgr)

	c.OnRequestLog(func(r *RequestLog) error {
		// masking authorization header
		r.Header.Set("Authorization", "Bearer *******************************")
		return nil
	})
	c.OnResponseLog(func(r *ResponseLog) error {
		r.Header.Add("X-Debug-Response-Log", "Modified :)")
		r.Body += "\nModified the response body content"
		return nil
	})

	c.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF")

	resp, err := c.R().
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF-Request").
		Get(ts.URL + "/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	// Validating debug log updates
	logInfo := lgr.String()
	assertEqual(t, true, strings.Contains(logInfo, "Bearer *******************************"))
	assertEqual(t, true, strings.Contains(logInfo, "X-Debug-Response-Log"))
	assertEqual(t, true, strings.Contains(logInfo, "Modified the response body content"))

	// Error scenario
	c.OnRequestLog(func(r *RequestLog) error { return errors.New("request test error") })
	resp, err = c.R().
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF-Request").
		Get(ts.URL + "/profile")
	assertEqual(t, errors.New("request test error"), err)
	assertNil(t, resp)
	assertNotNil(t, err)

	c.OnRequestLog(nil)
	c.OnResponseLog(func(r *ResponseLog) error { return errors.New("response test error") })
	resp, err = c.R().
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF-Request").
		Get(ts.URL + "/profile")
	assertEqual(t, errors.New("response test error"), err)
	assertNotNil(t, resp)
}

func TestDebugLogSimultaneously(t *testing.T) {
	ts := createGetServer(t)

	c := New().
		SetDebug(true).
		SetBaseURL(ts.URL).
		outputLogTo(io.Discard)

	t.Cleanup(ts.Close)
	for i := 0; i < 50; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			resp, err := c.R().
				SetBody([]int{1, 2, 3}).
				SetHeader(hdrContentTypeKey, "application/json; charset=utf-8").
				Post("/")

			assertError(t, err)
			assertEqual(t, http.StatusOK, resp.StatusCode())
		})
	}
}

func TestCustomTransportSettings(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	customTransportSettings := &TransportSettings{
		DialerTimeout:          30 * time.Second,
		DialerKeepAlive:        15 * time.Second,
		IdleConnTimeout:        120 * time.Second,
		TLSHandshakeTimeout:    20 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		MaxIdleConns:           50,
		MaxIdleConnsPerHost:    3,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 1 << 10,
		WriteBufferSize:        2 << 10,
		ReadBufferSize:         2 << 10,
	}
	client := NewWithTransportSettings(customTransportSettings)
	client.SetBaseURL(ts.URL)

	resp, err := client.R().Get("/")
	assertNil(t, err)
	assertEqual(t, resp.String(), "TestGet: text response")
}

func TestDefaultDialerTransportSettings(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	t.Run("transport-default", func(t *testing.T) {
		client := NewWithTransportSettings(nil)
		client.SetBaseURL(ts.URL)

		resp, err := client.R().Get("/")
		assertNil(t, err)
		assertEqual(t, resp.String(), "TestGet: text response")
	})

	t.Run("dialer-transport-default", func(t *testing.T) {
		client := NewWithDialerAndTransportSettings(nil, nil)
		client.SetBaseURL(ts.URL)

		resp, err := client.R().Get("/")
		assertNil(t, err)
		assertEqual(t, resp.String(), "TestGet: text response")
	})
}

func TestNewWithDialer(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 15 * time.Second,
	}
	client := NewWithDialer(dialer)
	client.SetBaseURL(ts.URL)

	resp, err := client.R().Get("/")
	assertNil(t, err)
	assertEqual(t, resp.String(), "TestGet: text response")
}

func TestNewWithLocalAddr(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	localAddress, _ := net.ResolveTCPAddr("tcp", "127.0.0.1")
	client := NewWithLocalAddr(localAddress)
	client.SetBaseURL(ts.URL)

	resp, err := client.R().Get("/")
	assertNil(t, err)
	assertEqual(t, resp.String(), "TestGet: text response")
}

func TestClientOnResponseError(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*Client)
		isError     bool
		hasResponse bool
		panics      bool
	}{
		{
			name: "successful_request",
		},
		{
			name: "http_status_error",
			setup: func(client *Client) {
				client.SetAuthToken("BAD")
			},
		},
		{
			name: "before_request_error",
			setup: func(client *Client) {
				client.OnBeforeRequest(func(client *Client, request *Request) error {
					return fmt.Errorf("before request")
				})
			},
			isError: true,
		},
		{
			name: "before_request_error_retry",
			setup: func(client *Client) {
				client.SetRetryCount(3).OnBeforeRequest(func(client *Client, request *Request) error {
					return fmt.Errorf("before request")
				})
			},
			isError: true,
		},
		{
			name: "after_response_error",
			setup: func(client *Client) {
				client.OnAfterResponse(func(client *Client, response *Response) error {
					return fmt.Errorf("after response")
				})
			},
			isError:     true,
			hasResponse: true,
		},
		{
			name: "after_response_error_retry",
			setup: func(client *Client) {
				client.SetRetryCount(3).OnAfterResponse(func(client *Client, response *Response) error {
					return fmt.Errorf("after response")
				})
			},
			isError:     true,
			hasResponse: true,
		},
		{
			name: "panic with error",
			setup: func(client *Client) {
				client.OnBeforeRequest(func(client *Client, request *Request) error {
					panic(fmt.Errorf("before request"))
				})
			},
			isError:     false,
			hasResponse: false,
			panics:      true,
		},
		{
			name: "panic with string",
			setup: func(client *Client) {
				client.OnBeforeRequest(func(client *Client, request *Request) error {
					panic("before request")
				})
			},
			isError:     false,
			hasResponse: false,
			panics:      true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ts := createAuthServer(t)
			defer ts.Close()

			var assertErrorHook = func(r *Request, err error) {
				assertNotNil(t, r)
				v, ok := err.(*ResponseError)
				assertEqual(t, test.hasResponse, ok)
				if ok {
					assertNotNil(t, v.Response)
					assertNotNil(t, v.Err)
				}
			}
			var hook1, hook2, hook3, hook4, hook5, hook6 int
			defer func() {
				if rec := recover(); rec != nil {
					assertEqual(t, true, test.panics)
					assertEqual(t, 0, hook1)
					assertEqual(t, 0, hook3)
					assertEqual(t, 1, hook5)
					assertEqual(t, 1, hook6)
				}
			}()
			c := New().outputLogTo(io.Discard).
				SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
				SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF").
				SetRetryCount(0).
				SetRetryMaxWaitTime(time.Microsecond).
				AddRetryCondition(func(response *Response, err error) bool {
					if err != nil {
						return true
					}
					return response.IsError()
				}).
				OnError(func(r *Request, err error) {
					assertErrorHook(r, err)
					hook1++
				}).
				OnError(func(r *Request, err error) {
					assertErrorHook(r, err)
					hook2++
				}).
				OnPanic(func(r *Request, err error) {
					assertErrorHook(r, err)
					hook5++
				}).
				OnPanic(func(r *Request, err error) {
					assertErrorHook(r, err)
					hook6++
				}).
				OnSuccess(func(c *Client, resp *Response) {
					assertNotNil(t, c)
					assertNotNil(t, resp)
					hook3++
				}).
				OnSuccess(func(c *Client, resp *Response) {
					assertNotNil(t, c)
					assertNotNil(t, resp)
					hook4++
				})
			if test.setup != nil {
				test.setup(c)
			}
			_, err := c.R().Get(ts.URL + "/profile")
			if test.isError {
				assertNotNil(t, err)
				assertEqual(t, 1, hook1)
				assertEqual(t, 1, hook2)
				assertEqual(t, 0, hook3)
				assertEqual(t, 0, hook5)
			} else {
				assertError(t, err)
				assertEqual(t, 0, hook1)
				assertEqual(t, 1, hook3)
				assertEqual(t, 1, hook4)
				assertEqual(t, 0, hook5)
			}
		})
	}
}

func TestResponseError(t *testing.T) {
	err := errors.New("error message")
	re := &ResponseError{
		Response: &Response{},
		Err:      err,
	}
	assertNotNil(t, re.Unwrap())
	assertEqual(t, err.Error(), re.Error())
}

func TestHostURLForGH318AndGH407(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	targetURL, _ := url.Parse(ts.URL)
	t.Log("ts.URL:", ts.URL)
	t.Log("targetURL.Host:", targetURL.Host)
	// Sample output
	// ts.URL: http://127.0.0.1:55967
	// targetURL.Host: 127.0.0.1:55967

	// Unable use the local http test server for this
	// use case testing
	//
	// using `targetURL.Host` value or test case yield to ERROR
	// "parse "127.0.0.1:55967": first path segment in URL cannot contain colon"

	// test the functionality with httpbin.org locally
	// will figure out later

	c := dc()
	// c.SetScheme("http")
	// c.SetHostURL(targetURL.Host + "/")

	// t.Log("with leading `/`")
	// resp, err := c.R().Post("/login")
	// assertNil(t, err)
	// assertNotNil(t, resp)

	// t.Log("\nwithout leading `/`")
	// resp, err = c.R().Post("login")
	// assertNil(t, err)
	// assertNotNil(t, resp)

	t.Log("with leading `/` on request & with trailing `/` on host url")
	c.SetBaseURL(ts.URL + "/")
	resp, err := c.R().
		SetBody(map[string]any{"username": "testuser", "password": "testpass"}).
		Post("/login")
	assertNil(t, err)
	assertNotNil(t, resp)
}

func TestPostRedirectWithBody(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	targetURL, _ := url.Parse(ts.URL)
	t.Log("ts.URL:", ts.URL)
	t.Log("targetURL.Host:", targetURL.Host)

	c := dc()
	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.R().
				SetBody([]byte(strconv.Itoa(newRnd().Int()))).
				Post(targetURL.String() + "/redirect-with-body")
			assertError(t, err)
			assertNotNil(t, resp)
		}()
	}
	wg.Wait()
}

func TestUnixSocket(t *testing.T) {
	unixSocketAddr := createUnixSocketEchoServer(t)
	defer os.Remove(unixSocketAddr)

	// Create a Go's http.Transport so we can set it in resty.
	transport := http.Transport{
		Dial: func(_, _ string) (net.Conn, error) {
			return net.Dial("unix", unixSocketAddr)
		},
	}

	// Create a Resty Client
	client := New()

	// Set the previous transport that we created, set the scheme of the communication to the
	// socket and set the unixSocket as the HostURL.
	client.SetTransport(&transport).SetScheme("http").SetBaseURL(unixSocketAddr)

	// No need to write the host's URL on the request, just the path.
	res, err := client.R().Get("http://localhost/")
	assertNil(t, err)
	assertEqual(t, "Hi resty client from a server running on Unix domain socket!", res.String())

	res, err = client.R().Get("http://localhost/hello")
	assertNil(t, err)
	assertEqual(t, "Hello resty client from a server running on endpoint /hello!", res.String())
}

func TestClientClone(t *testing.T) {
	parent := New()

	// set a non-interface field
	parent.SetBaseURL("http://localhost")

	// set an interface field
	parent.SetBasicAuth("parent", "")

	clone := parent.Clone()
	// update value of non-interface type - change will only happen on clone
	clone.SetBaseURL("https://local.host")
	// update value of interface type - change will also happen on parent
	clone.UserInfo().Username = "clone"

	// assert non-interface type
	assertEqual(t, "http://localhost", parent.BaseURL())
	assertEqual(t, "https://local.host", clone.BaseURL())

	// assert interface type
	assertEqual(t, "clone", parent.UserInfo().Username)
	assertEqual(t, "clone", clone.UserInfo().Username)
}

func TestResponseBodyLimit(t *testing.T) {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		io.CopyN(w, rand.Reader, 100*800)
	})
	defer ts.Close()

	t.Run("Client body limit", func(t *testing.T) {
		c := dc().SetResponseBodyLimit(1024)
		assertEqual(t, int64(1024), c.ResponseBodyLimit())
		resp, err := c.R().Get(ts.URL + "/")
		assertNotNil(t, err)
		assertErrorIs(t, ErrReadExceedsThresholdLimit, err)
		assertEqual(t, int64(1408), resp.Size())
	})

	t.Run("request body limit", func(t *testing.T) {
		c := dc()

		resp, err := c.R().SetResponseBodyLimit(1024).Get(ts.URL + "/")
		assertNotNil(t, err)
		assertErrorIs(t, ErrReadExceedsThresholdLimit, err)
		assertEqual(t, int64(1408), resp.Size())
	})

	t.Run("body less than limit", func(t *testing.T) {
		c := dc()

		res, err := c.R().SetResponseBodyLimit(800*100 + 10).Get(ts.URL + "/")
		assertNil(t, err)
		assertEqual(t, 800*100, len(res.BodyBytes()))
		assertEqual(t, int64(800*100), res.Size())
	})

	t.Run("no body limit", func(t *testing.T) {
		c := dc()

		res, err := c.R().Get(ts.URL + "/")
		assertNil(t, err)
		assertEqual(t, 800*100, len(res.BodyBytes()))
		assertEqual(t, int64(800*100), res.Size())
	})

	t.Run("read error", func(t *testing.T) {
		tse := createTestServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(hdrContentEncodingKey, "gzip")
			var buf [1024]byte
			w.Write(buf[:])
		})
		defer tse.Close()

		c := dc()

		_, err := c.R().SetResponseBodyLimit(10240).Get(tse.URL + "/")
		assertErrorIs(t, gzip.ErrHeader, err)
	})
}
