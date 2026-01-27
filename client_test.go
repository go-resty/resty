// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"compress/gzip"
	"compress/lzw"
	"context"
	cryprand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
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

	c := dcnl()
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

	c := dcnl()
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

	c := dcnl()
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

func TestClientResponseMiddleware(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	c := dcnl()
	c.AddResponseMiddleware(func(c *Client, res *Response) error {
		t.Logf("Request sent at: %v", res.Request.Time)
		t.Logf("Response Received at: %v", res.ReceivedAt())

		return nil
	})

	resp, err := c.R().
		SetBody("ResponseMiddleware: This is plain text body to server").
		Put(ts.URL + "/plaintext")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestPut: plain text response", resp.String())
}

func TestClientRedirectPolicy(t *testing.T) {
	ts := createRedirectServer(t)
	defer ts.Close()

	c := dcnl().SetRedirectPolicy(FlexibleRedirectPolicy(20), DomainCheckRedirectPolicy("127.0.0.1"))
	res, err := c.R().
		SetHeader("Name1", "Value1").
		SetHeader("Name2", "Value2").
		SetHeader("Name3", "Value3").
		Get(ts.URL + "/redirect-1")

	assertEqual(t, true, err.Error() == "Get \"/redirect-21\": resty: stopped after 20 redirects")

	redirects := res.RedirectHistory()
	assertEqual(t, 20, len(redirects))

	finalReq := redirects[0]
	assertEqual(t, 307, finalReq.StatusCode)
	assertEqual(t, ts.URL+"/redirect-20", finalReq.URL)

	c.SetRedirectPolicy(NoRedirectPolicy())
	res, err = c.R().Get(ts.URL + "/redirect-1")
	assertNil(t, err)
	assertEqual(t, http.StatusTemporaryRedirect, res.StatusCode())
	assertEqual(t, `<a href="/redirect-2">Temporary Redirect</a>.`, res.String())
}

func TestClientTimeout(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl().SetTimeout(200 * time.Millisecond)
	_, err := c.R().Get(ts.URL + "/set-timeout-test")
	assertEqual(t, true, errors.Is(err, context.DeadlineExceeded))
}

func TestClientTimeoutWithinThreshold(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl().SetTimeout(200 * time.Millisecond)

	resp, err := c.R().Get(ts.URL + "/set-timeout-test-with-sequence")
	assertError(t, err)

	seq1, _ := strconv.ParseInt(resp.String(), 10, 32)

	resp, err = c.R().Get(ts.URL + "/set-timeout-test-with-sequence")
	assertError(t, err)

	seq2, _ := strconv.ParseInt(resp.String(), 10, 32)

	assertEqual(t, seq1+1, seq2)
}

func TestClientTimeoutInternalError(t *testing.T) {
	c := dcnl().SetTimeout(time.Second * 1)
	_, _ = c.R().Get("http://localhost:9000/set-timeout-test")
}

func TestClientProxy(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl()
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
	certFile := filepath.Join(getTestDataPath(), "cert.pem")
	keyFile := filepath.Join(getTestDataPath(), "key.pem")

	t.Run("client cert from file", func(t *testing.T) {
		c := dcnl()
		c.SetCertificateFromFile(certFile, keyFile)
		assertEqual(t, 1, len(c.TLSClientConfig().Certificates))
	})

	t.Run("error-client cert from file", func(t *testing.T) {
		c := dcnl()
		c.SetCertificateFromFile(certFile+"no", keyFile+"no")
		assertEqual(t, 0, len(c.TLSClientConfig().Certificates))
	})

	t.Run("client cert from string", func(t *testing.T) {
		certPemData, _ := os.ReadFile(certFile)
		keyPemData, _ := os.ReadFile(keyFile)
		c := dcnl()
		c.SetCertificateFromString(string(certPemData), string(keyPemData))
		assertEqual(t, 1, len(c.TLSClientConfig().Certificates))
	})

	t.Run("error-client cert from string", func(t *testing.T) {
		c := dcnl()
		c.SetCertificateFromString(string("empty"), string("empty"))
		assertEqual(t, 0, len(c.TLSClientConfig().Certificates))
	})
}

func TestClientSetRootCertificate(t *testing.T) {
	t.Run("root cert", func(t *testing.T) {
		client := dcnl()
		client.SetRootCertificates(filepath.Join(getTestDataPath(), "sample-root.pem"))

		transport, err := client.HTTPTransport()

		assertNil(t, err)
		assertNotNil(t, transport.TLSClientConfig.RootCAs)
	})

	t.Run("root cert not exists", func(t *testing.T) {
		client := dcnl()
		client.SetRootCertificates(filepath.Join(getTestDataPath(), "not-exists-sample-root.pem"))

		transport, err := client.HTTPTransport()

		assertNil(t, err)
		assertNil(t, transport.TLSClientConfig)
	})

	t.Run("root cert from string", func(t *testing.T) {
		client := dcnl()
		rootPemData, err := os.ReadFile(filepath.Join(getTestDataPath(), "sample-root.pem"))
		assertNil(t, err)

		client.SetRootCertificateFromString(string(rootPemData))

		transport, err := client.HTTPTransport()

		assertNil(t, err)
		assertNotNil(t, transport.TLSClientConfig.RootCAs)
	})
}

type CustomRoundTripper1 struct{}

// RoundTrip just for test
func (rt *CustomRoundTripper1) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{}, nil
}

func TestClientCACertificateFromStringErrorTls(t *testing.T) {
	t.Run("root cert string", func(t *testing.T) {
		client := NewWithClient(&http.Client{})
		client.outputLogTo(io.Discard)

		rootPemData, err := os.ReadFile(filepath.Join(getTestDataPath(), "sample-root.pem"))
		assertNil(t, err)
		rt := &CustomRoundTripper1{}
		client.SetTransport(rt)
		transport, err := client.HTTPTransport()

		client.SetRootCertificateFromString(string(rootPemData))

		assertNotNil(t, rt)
		assertNotNil(t, err)
		assertNil(t, transport)
	})

	t.Run("client cert string", func(t *testing.T) {
		client := NewWithClient(&http.Client{})
		client.outputLogTo(io.Discard)

		rootPemData, err := os.ReadFile(filepath.Join(getTestDataPath(), "sample-root.pem"))
		assertNil(t, err)
		rt := &CustomRoundTripper1{}
		client.SetTransport(rt)
		transport, err := client.HTTPTransport()

		client.SetClientRootCertificateFromString(string(rootPemData))

		assertNotNil(t, rt)
		assertNotNil(t, err)
		assertNil(t, transport)
	})
}

// CustomRoundTripper2 just for test
type CustomRoundTripper2 struct {
	http.RoundTripper
	TLSClientConfiger
	tlsConfig *tls.Config
	returnErr bool
}

// RoundTrip just for test
func (rt *CustomRoundTripper2) RoundTrip(_ *http.Request) (*http.Response, error) {
	if rt.returnErr {
		return nil, errors.New("test req mock error")
	}
	return &http.Response{}, nil
}

func (rt *CustomRoundTripper2) TLSClientConfig() *tls.Config {
	return rt.tlsConfig
}
func (rt *CustomRoundTripper2) SetTLSClientConfig(tlsConfig *tls.Config) error {
	if rt.returnErr {
		return errors.New("test mock error")
	}
	rt.tlsConfig = tlsConfig
	return nil
}

func TestClientTLSConfigerInterface(t *testing.T) {

	t.Run("assert transport and custom roundtripper", func(t *testing.T) {
		c := dcnl()

		assertNotNil(t, c.Transport())
		assertEqual(t, "http.Transport", inferType(c.Transport()).String())

		ct := &CustomRoundTripper2{}
		c.SetTransport(ct)
		assertNotNil(t, c.Transport())
		assertEqual(t, "resty.CustomRoundTripper2", inferType(c.Transport()).String())
	})

	t.Run("get and set tls config", func(t *testing.T) {
		c := dcnl()

		ct := &CustomRoundTripper2{}
		c.SetTransport(ct)

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		c.SetTLSClientConfig(tlsConfig)
		assertEqual(t, tlsConfig, c.TLSClientConfig())
	})

	t.Run("get tls config error", func(t *testing.T) {
		c := dcnl()

		ct := &CustomRoundTripper1{}
		c.SetTransport(ct)
		assertNil(t, c.TLSClientConfig())
	})

	t.Run("set tls config error", func(t *testing.T) {
		c := dcnl()

		ct := &CustomRoundTripper2{returnErr: true}
		c.SetTransport(ct)

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		c.SetTLSClientConfig(tlsConfig)
		assertNil(t, c.TLSClientConfig())
	})
}

func TestClientSetClientRootCertificate(t *testing.T) {
	client := dcnl()
	client.SetClientRootCertificates(filepath.Join(getTestDataPath(), "sample-root.pem"))

	transport, err := client.HTTPTransport()

	assertNil(t, err)
	assertNotNil(t, transport.TLSClientConfig.ClientCAs)
}

func TestClientSetClientRootCertificateNotExists(t *testing.T) {
	client := dcnl()
	client.SetClientRootCertificates(filepath.Join(getTestDataPath(), "not-exists-sample-root.pem"))

	transport, err := client.HTTPTransport()

	assertNil(t, err)
	assertNil(t, transport.TLSClientConfig)
}

func TestClientSetClientRootCertificateWatcher(t *testing.T) {
	t.Run("Cert exists", func(t *testing.T) {
		client := dcnl()
		client.SetClientRootCertificatesWatcher(
			&CertWatcherOptions{PoolInterval: time.Second * 1},
			filepath.Join(getTestDataPath(), "sample-root.pem"),
		)

		transport, err := client.HTTPTransport()

		assertNil(t, err)
		assertNotNil(t, transport.TLSClientConfig.ClientCAs)
	})

	t.Run("Cert does not exist", func(t *testing.T) {
		client := dcnl()
		client.SetClientRootCertificatesWatcher(nil, filepath.Join(getTestDataPath(), "not-exists-sample-root.pem"))

		transport, err := client.HTTPTransport()

		assertNil(t, err)
		assertNil(t, transport.TLSClientConfig)
	})
}

func TestClientSetClientRootCertificateFromString(t *testing.T) {
	client := dcnl()
	rootPemData, err := os.ReadFile(filepath.Join(getTestDataPath(), "sample-root.pem"))
	assertNil(t, err)

	client.SetClientRootCertificateFromString(string(rootPemData))

	transport, err := client.HTTPTransport()

	assertNil(t, err)
	assertNotNil(t, transport.TLSClientConfig.ClientCAs)
}

func TestClientRequestMiddlewareModification(t *testing.T) {
	tc := dcnl()
	tc.AddRequestMiddleware(func(c *Client, r *Request) error {
		r.SetAuthToken("This is test auth token")
		return nil
	})

	ts := createGetServer(t)
	defer ts.Close()

	resp, err := tc.R().Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
}

func TestClientSetHeaderVerbatim(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl().
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
	client := dcnl()

	transport := &http.Transport{
		// something like Proxying to httptest.Server, etc...
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(ts.URL)
		},
	}
	client.SetTransport(transport)
	transportInUse, err := client.HTTPTransport()

	assertNil(t, err)
	assertEqual(t, true, transport == transportInUse)
}

func TestClientSetScheme(t *testing.T) {
	client := dcnl()

	client.SetScheme("http")

	assertEqual(t, true, client.scheme == "http")
}

func TestClientSetCookieJar(t *testing.T) {
	client := dcnl()
	backupJar := client.httpClient.Jar

	client.SetCookieJar(nil)
	assertNil(t, client.httpClient.Jar)

	client.SetCookieJar(backupJar)
	assertEqual(t, true, client.httpClient.Jar == backupJar)
}

// This test methods exist for test coverage purpose
// to validate the getter and setter
func TestClientSettingsCoverage(t *testing.T) {
	c := dcnl()

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
	assertEqual(t, 0, len(c.RetryConditions()))

	authToken := "sample auth token value"
	c.SetAuthToken(authToken)
	assertEqual(t, authToken, c.AuthToken())

	customAuthHeader := "X-Custom-Authorization"
	c.SetHeaderAuthorizationKey(customAuthHeader)
	assertEqual(t, customAuthHeader, c.HeaderAuthorizationKey())

	c.SetCloseConnection(true)

	c.DisableDebug()

	assertEqual(t, true, c.IsRetryDefaultConditions())
	c.DisableRetryDefaultConditions()
	assertEqual(t, false, c.IsRetryDefaultConditions())
	c.EnableRetryDefaultConditions()
	assertEqual(t, true, c.IsRetryDefaultConditions())

	nr := nopReader{}
	n, err1 := nr.Read(nil)
	assertEqual(t, 0, n)
	assertEqual(t, io.EOF, err1)
	b, err1 := nr.ReadByte()
	assertEqual(t, byte(0), b)
	assertEqual(t, io.EOF, err1)

	// [Start] Custom Transport scenario
	ct := dcnl()
	ct.SetTransport(&CustomRoundTripper1{})
	_, err := ct.HTTPTransport()
	assertNotNil(t, err)
	assertEqual(t, ErrNotHttpTransportType, err)

	ct.SetProxy("http://localhost:8080")
	ct.RemoveProxy()

	ct.SetCertificates(tls.Certificate{})
	ct.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	ct.SetRootCertificateFromString("root cert")

	ct.outputLogTo(io.Discard)
	// [End] Custom Transport scenario

	// Response - for now stay here
	resp := &Response{Request: &Request{}}
	s := resp.fmtBodyString(0)
	assertEqual(t, "***** NO CONTENT *****", s)
}

func TestContentLengthWhenBodyIsNil(t *testing.T) {
	client := dcnl()

	fnPreRequestMiddleware1 := func(c *Client, r *Request) error {
		assertEqual(t, "0", r.Header.Get(hdrContentLengthKey))
		return nil
	}
	client.SetRequestMiddlewares(
		PrepareRequestMiddleware,
		fnPreRequestMiddleware1,
	)

	client.R().SetContentLength(true).SetBody(nil).Get("http://localhost")
}

func TestClientPreRequestMiddlewares(t *testing.T) {
	client := dcnl()

	fnPreRequestMiddleware1 := func(c *Client, r *Request) error {
		c.Logger().Debugf("I'm in Pre-Request Hook")
		return nil
	}

	fnPreRequestMiddleware2 := func(c *Client, r *Request) error {
		c.Logger().Debugf("I'm Overwriting existing Pre-Request Hook")

		// Reading Request `N` no of times
		for i := 0; i < 5; i++ {
			b, _ := r.RawRequest.GetBody()
			rb, _ := io.ReadAll(b)
			c.Logger().Debugf("%s %v", string(rb), len(rb))
			assertEqual(t, true, len(rb) >= 45)
		}
		return nil
	}

	client.SetRequestMiddlewares(
		PrepareRequestMiddleware,
		fnPreRequestMiddleware1,
		fnPreRequestMiddleware2,
	)

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

func TestClientPreRequestMiddlewareError(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl()
	fnPreRequestMiddleware1 := func(c *Client, r *Request) error {
		return errors.New("error from PreRequestMiddleware")
	}
	c.SetRequestMiddlewares(
		PrepareRequestMiddleware,
		fnPreRequestMiddleware1,
	)

	resp, err := c.R().Get(ts.URL)
	assertNotNil(t, err)
	assertEqual(t, "error from PreRequestMiddleware", err.Error())
	assertNil(t, resp)
}

func TestClientAllowMethodGetPayload(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	t.Run("method GET allow string payload at client level", func(t *testing.T) {
		c := dcnl()
		c.SetAllowMethodGetPayload(true)
		assertEqual(t, true, c.AllowMethodGetPayload())

		payload := "test-payload"
		resp, err := c.R().SetBody(payload).Get(ts.URL + "/get-method-payload-test")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, payload, resp.String())
	})

	t.Run("method GET allow io.Reader payload at client level", func(t *testing.T) {
		c := dcnl()
		c.SetAllowMethodGetPayload(true)
		assertEqual(t, true, c.AllowMethodGetPayload())

		payload := "test-payload"
		body := bytes.NewReader([]byte(payload))
		resp, err := c.R().SetBody(body).Get(ts.URL + "/get-method-payload-test")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, payload, resp.String())
	})

	t.Run("method GET disallow payload at client level", func(t *testing.T) {
		c := dcnl()
		c.SetAllowMethodGetPayload(false)
		assertEqual(t, false, c.AllowMethodGetPayload())

		payload := bytes.NewReader([]byte("test-payload"))
		resp, err := c.R().SetBody(payload).Get(ts.URL + "/get-method-payload-test")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, "", resp.String())
	})
}

func TestClientAllowMethodDeletePayload(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	t.Run("method DELETE allow string payload at client level", func(t *testing.T) {
		c := dcnl().SetBaseURL(ts.URL)

		c.SetAllowMethodDeletePayload(true)
		assertEqual(t, true, c.AllowMethodDeletePayload())

		payload := "test-payload"
		resp, err := c.R().SetBody(payload).Delete("/delete")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, payload, resp.String())
	})

	t.Run("method DELETE allow io.Reader payload at client level", func(t *testing.T) {
		c := dcnl().SetBaseURL(ts.URL)

		c.SetAllowMethodDeletePayload(true)
		assertEqual(t, true, c.AllowMethodDeletePayload())

		payload := "test-payload"
		body := bytes.NewReader([]byte(payload))
		resp, err := c.R().SetBody(body).Delete("/delete")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, payload, resp.String())
	})

	t.Run("method DELETE disallow payload at client level", func(t *testing.T) {
		c := dcnl().SetBaseURL(ts.URL)

		c.SetAllowMethodDeletePayload(false)
		assertEqual(t, false, c.AllowMethodDeletePayload())

		payload := bytes.NewReader([]byte("test-payload"))
		resp, err := c.R().SetBody(payload).Delete("/delete")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, "", resp.String())
	})
}

func TestClientRoundTripper(t *testing.T) {
	c := NewWithClient(&http.Client{})
	c.outputLogTo(io.Discard)

	rt := &CustomRoundTripper2{}
	c.SetTransport(rt)

	ct, err := c.HTTPTransport()
	assertNotNil(t, err)
	assertNil(t, ct)
	assertEqual(t, ErrNotHttpTransportType, err)
}

func TestClientNewRequest(t *testing.T) {
	c := New()
	request := c.NewRequest()
	assertNotNil(t, request)
}

func TestClientDebugBodySizeLimit(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c, lb := dcldb()
	c.SetDebugBodyLimit(30)

	testcases := []struct{ url, want string }{
		// Text, does not exceed limit.
		{url: ts.URL, want: "TestGet: text response"},
		// Empty response.
		{url: ts.URL + "/no-content", want: "***** NO CONTENT *****"},
		// JSON, does not exceed limit.
		{url: ts.URL + "/json", want: "{\n   \"TestGet\": \"JSON response\"\n}"},
		// Invalid JSON, does not exceed limit.
		{url: ts.URL + "/json-invalid", want: "DebugLog: Response.fmtBodyString: invalid character 'T' looking for beginning of value"},
		// Text, exceeds limit.
		{url: ts.URL + "/long-text", want: "RESPONSE TOO LARGE"},
		// JSON, exceeds limit.
		{url: ts.URL + "/long-json", want: "RESPONSE TOO LARGE"},
	}
	for _, tc := range testcases {
		_, err := c.R().Get(tc.url)
		if tc.want != "" {
			assertError(t, err)
			debugLog := lb.String()
			if !strings.Contains(debugLog, tc.want) {
				t.Errorf("Expected logs to contain [%v], got [\n%v]", tc.want, debugLog)
			}
			lb.Reset()
		}
	}
}

func TestGzipCompress(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	c := dcnl()
	testcases := []struct{ url, want string }{
		{ts.URL + "/gzip-test", "This is Gzip response testing"},
		{ts.URL + "/gzip-test-gziped-empty-body", ""},
		{ts.URL + "/gzip-test-no-gziped-body", ""},
	}
	for _, tc := range testcases {
		resp, err := c.R().Get(tc.url)

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, "200 OK", resp.Status())
		assertEqual(t, tc.want, resp.String())

		logResponse(t, resp)
	}
}

func TestDeflateCompress(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	c := dcnl()
	testcases := []struct{ url, want string }{
		{ts.URL + "/deflate-test", "This is Deflate response testing"},
		{ts.URL + "/deflate-test-empty-body", ""},
		{ts.URL + "/deflate-test-no-body", ""},
	}
	for _, tc := range testcases {
		resp, err := c.R().Get(tc.url)

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, "200 OK", resp.Status())
		assertEqual(t, tc.want, resp.String())

		logResponse(t, resp)
	}
}

type lzwReader struct {
	s io.ReadCloser
	r io.ReadCloser
}

func (l *lzwReader) Read(p []byte) (n int, err error) {
	return l.r.Read(p)
}

func (l *lzwReader) Close() error {
	closeq(l.r)
	closeq(l.s)
	return nil
}

func TestLzwCompress(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	c := dcnl()

	// Not found scenario
	_, err := c.R().Get(ts.URL + "/lzw-test")
	assertNotNil(t, err)
	assertEqual(t, ErrContentDecompresserNotFound, err)

	// Register LZW content decoder
	c.AddContentDecompresser("compress", func(r io.ReadCloser) (io.ReadCloser, error) {
		l := &lzwReader{
			s: r,
			r: lzw.NewReader(r, lzw.LSB, 8),
		}
		return l, nil
	})
	c.SetContentDecompresserKeys([]string{"compress"})

	testcases := []struct{ url, want string }{
		{ts.URL + "/lzw-test", "This is LZW response testing"},
		{ts.URL + "/lzw-test-empty-body", ""},
		{ts.URL + "/lzw-test-no-body", ""},
	}
	for _, tc := range testcases {
		resp, err := c.R().Get(tc.url)

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, "200 OK", resp.Status())
		assertEqual(t, tc.want, resp.String())

		logResponse(t, resp)
	}
}

func TestClientLogCallbacks(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c, lb := dcldb()

	c.OnDebugLog(func(dl *DebugLog) {
		// request
		// masking authorization header
		dl.Request.Header.Set("Authorization", "Bearer *******************************")

		// response
		dl.Response.Header.Add("X-Debug-Response-Log", "Modified :)")
		dl.Response.Body += "\nModified the response body content"
	})

	c.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF")

	resp, err := c.R().
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF-Request").
		Get(ts.URL + "/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	// Validating debug log updates
	logInfo := lb.String()
	assertEqual(t, true, strings.Contains(logInfo, "Bearer *******************************"))
	assertEqual(t, true, strings.Contains(logInfo, "X-Debug-Response-Log"))
	assertEqual(t, true, strings.Contains(logInfo, "Modified the response body content"))

	// overwrite scenario
	c.OnDebugLog(func(dl *DebugLog) {
		// overwrite debug log
	})
	resp, err = c.R().
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF-Request").
		Get(ts.URL + "/profile")
	assertNil(t, err)
	assertNotNil(t, resp)
	assertEqual(t, int64(66), resp.Size())
	assertEqual(t, true, strings.Contains(lb.String(), "Overwriting an existing on-debug-log callback from=resty.dev/v3.TestClientLogCallbacks.func1 to=resty.dev/v3.TestClientLogCallbacks.func2"))
}

func TestDebugLogSimultaneously(t *testing.T) {
	ts := createGetServer(t)

	c := dcnl().
		SetDebug(true).
		SetBaseURL(ts.URL)

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
	assertEqual(t, "TestGet: text response", resp.String())
}

func TestDefaultDialerTransportSettings(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	t.Run("transport-default", func(t *testing.T) {
		client := NewWithTransportSettings(nil)
		client.SetBaseURL(ts.URL)

		resp, err := client.R().Get("/")
		assertNil(t, err)
		assertEqual(t, "TestGet: text response", resp.String())
	})

	t.Run("dialer-transport-default", func(t *testing.T) {
		client := NewWithDialerAndTransportSettings(nil, nil)
		client.SetBaseURL(ts.URL)

		resp, err := client.R().Get("/")
		assertNil(t, err)
		assertEqual(t, "TestGet: text response", resp.String())
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
	assertEqual(t, "TestGet: text response", resp.String())
}

func TestNewWithLocalAddr(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	localAddress, _ := net.ResolveTCPAddr("tcp", "127.0.0.1")
	client := NewWithLocalAddr(localAddress)
	client.SetBaseURL(ts.URL)

	resp, err := client.R().Get("/")
	assertNil(t, err)
	assertEqual(t, "TestGet: text response", resp.String())
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
				client.AddRequestMiddleware(func(client *Client, request *Request) error {
					return fmt.Errorf("before request")
				})
			},
			isError: true,
		},
		{
			name: "before_request_error_retry",
			setup: func(client *Client) {
				client.SetRetryCount(3).AddRequestMiddleware(func(client *Client, request *Request) error {
					return fmt.Errorf("before request")
				})
			},
			isError: true,
		},
		{
			name: "after_response_error",
			setup: func(client *Client) {
				client.AddResponseMiddleware(func(client *Client, response *Response) error {
					return fmt.Errorf("after response")
				})
			},
			isError:     true,
			hasResponse: true,
		},
		{
			name: "after_response_error_retry",
			setup: func(client *Client) {
				client.SetRetryCount(3).AddResponseMiddleware(func(client *Client, response *Response) error {
					return fmt.Errorf("after response")
				})
			},
			isError:     true,
			hasResponse: true,
		},
		{
			name: "panic with error",
			setup: func(client *Client) {
				client.AddRequestMiddleware(func(client *Client, request *Request) error {
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
				client.AddRequestMiddleware(func(client *Client, request *Request) error {
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
			var errorHook1, errorHook2, successHook1, successHook2, panicHook1, panicHook2 int
			defer func() {
				if rec := recover(); rec != nil {
					assertEqual(t, true, test.panics)
					assertEqual(t, 0, errorHook1)
					assertEqual(t, 0, successHook1)
					assertEqual(t, 1, panicHook1)
					assertEqual(t, 1, panicHook2)
				}
			}()
			c := dcnl().
				SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
				SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF").
				SetRetryCount(0).
				SetRetryMaxWaitTime(time.Microsecond).
				AddRetryConditions(func(response *Response, err error) bool {
					if err != nil {
						return true
					}
					return response.IsError()
				}).
				OnError(func(r *Request, err error) {
					assertErrorHook(r, err)
					errorHook1++
				}).
				OnError(func(r *Request, err error) {
					assertErrorHook(r, err)
					errorHook2++
				}).
				OnPanic(func(r *Request, err error) {
					assertErrorHook(r, err)
					panicHook1++
				}).
				OnPanic(func(r *Request, err error) {
					assertErrorHook(r, err)
					panicHook2++
				}).
				OnSuccess(func(c *Client, resp *Response) {
					assertNotNil(t, c)
					assertNotNil(t, resp)
					successHook1++
				}).
				OnSuccess(func(c *Client, resp *Response) {
					assertNotNil(t, c)
					assertNotNil(t, resp)
					successHook2++
				})
			if test.setup != nil {
				test.setup(c)
			}
			_, err := c.R().Get(ts.URL + "/profile")
			if test.isError {
				assertNotNil(t, err)
				assertEqual(t, 1, errorHook1)
				assertEqual(t, 1, errorHook2)
				assertEqual(t, 0, successHook1)
				assertEqual(t, 0, panicHook1)
			} else {
				assertError(t, err)
				assertEqual(t, 0, errorHook1)
				assertEqual(t, 1, successHook1)
				assertEqual(t, 1, successHook2)
				assertEqual(t, 0, panicHook1)
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

	c := dcnl()
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

	mu := sync.Mutex{}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	c := dcnl().SetBaseURL(ts.URL)

	totalRequests := 4000
	wg := sync.WaitGroup{}
	wg.Add(totalRequests)
	for i := 0; i < totalRequests; i++ {
		if i%50 == 0 {
			time.Sleep(20 * time.Millisecond) // to prevent test server socket exhaustion
		}
		go func() {
			defer wg.Done()
			mu.Lock()
			randNumber := rnd.Int()
			mu.Unlock()
			resp, err := c.R().
				SetBody([]byte(strconv.Itoa(randNumber))).
				Post("/redirect-with-body")
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
	parent.SetBasicAuth("parent", "")
	parent.SetProxy("http://localhost:8080")

	parent.SetCookie(&http.Cookie{
		Name:  "go-resty-1",
		Value: "This is cookie 1 value",
	})
	parent.SetCookies([]*http.Cookie{
		{
			Name:  "go-resty-2",
			Value: "This is cookie 2 value",
		},
		{
			Name:  "go-resty-3",
			Value: "This is cookie 3 value",
		},
	})

	clone := parent.Clone(context.Background())
	// update value of non-interface type - change will only happen on clone
	clone.SetBaseURL("https://local.host")

	clone.SetBasicAuth("clone", "clone")

	// assert non-interface type
	assertEqual(t, "http://localhost", parent.BaseURL())
	assertEqual(t, "https://local.host", clone.BaseURL())
	assertEqual(t, "parent", parent.credentials.Username)
	assertEqual(t, "clone", clone.credentials.Username)

	// assert interface/pointer type
	assertEqual(t, parent.Client(), clone.Client())
}

func TestResponseBodyLimit(t *testing.T) {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		io.CopyN(w, cryprand.Reader, 100*800)
	})
	defer ts.Close()

	t.Run("client body limit", func(t *testing.T) {
		c := dcnl().SetResponseBodyLimit(1024)
		assertEqual(t, int64(1024), c.ResponseBodyLimit())
		resp, err := c.R().Get(ts.URL + "/")
		assertNotNil(t, err)
		assertErrorIs(t, ErrReadExceedsThresholdLimit, err)
		assertEqual(t, int64(1408), resp.Size())
	})

	t.Run("request body limit", func(t *testing.T) {
		c := dcnl()

		resp, err := c.R().SetResponseBodyLimit(1024).Get(ts.URL + "/")
		assertNotNil(t, err)
		assertErrorIs(t, ErrReadExceedsThresholdLimit, err)
		assertEqual(t, int64(1408), resp.Size())
	})

	t.Run("body less than limit", func(t *testing.T) {
		c := dcnl()

		res, err := c.R().SetResponseBodyLimit(800*100 + 10).Get(ts.URL + "/")
		assertNil(t, err)
		assertEqual(t, 800*100, len(res.Bytes()))
		assertEqual(t, int64(800*100), res.Size())
	})

	t.Run("no body limit", func(t *testing.T) {
		c := dcnl()

		res, err := c.R().Get(ts.URL + "/")
		assertNil(t, err)
		assertEqual(t, 800*100, len(res.Bytes()))
		assertEqual(t, int64(800*100), res.Size())
	})

	t.Run("read error", func(t *testing.T) {
		tse := createTestServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(hdrContentEncodingKey, "gzip")
			var buf [1024]byte
			w.Write(buf[:])
		})
		defer tse.Close()

		c := dcnl()

		_, err := c.R().SetResponseBodyLimit(10240).Get(tse.URL + "/")
		assertErrorIs(t, gzip.ErrHeader, err)
	})
}

func TestClient_executeReadAllError(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	ioReadAll = func(_ io.Reader) ([]byte, error) {
		return nil, errors.New("test case error")
	}
	t.Cleanup(func() {
		ioReadAll = io.ReadAll
	})

	c := dcnld()

	resp, err := c.R().
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Get(ts.URL + "/json")

	assertNotNil(t, err)
	assertEqual(t, "test case error", err.Error())
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "", resp.String())
}

func TestClientDebugf(t *testing.T) {
	t.Run("Debug mode enabled", func(t *testing.T) {
		var b bytes.Buffer
		c := New().SetLogger(&logger{l: log.New(&b, "", 0)}).SetDebug(true)
		c.debugf("hello")
		assertEqual(t, "DEBUG RESTY hello\n", b.String())
	})

	t.Run("Debug mode disabled", func(t *testing.T) {
		var b bytes.Buffer
		c := New().SetLogger(&logger{l: log.New(&b, "", 0)})
		c.debugf("hello")
		assertEqual(t, "", b.String())
	})
}

var _ CircuitBreakerPolicy = CircuitBreaker5xxPolicy

func TestClientCircuitBreaker(t *testing.T) {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)

		switch r.URL.Path {
		case "/200":
			w.WriteHeader(http.StatusOK)
			return
		case "/500":
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})
	defer ts.Close()

	failThreshold := uint32(2)
	successThreshold := uint32(1)
	timeout := 100 * time.Millisecond

	cb := NewCircuitBreaker().
		SetTimeout(timeout).
		SetFailureThreshold(failThreshold).
		SetSuccessThreshold(successThreshold).
		SetPolicies(CircuitBreaker5xxPolicy)

	c := dcnl().SetCircuitBreaker(cb)

	for i := uint32(0); i < failThreshold; i++ {
		_, err := c.R().Get(ts.URL + "/500")
		assertNil(t, err)
	}
	resp, err := c.R().Get(ts.URL + "/500")
	assertErrorIs(t, ErrCircuitBreakerOpen, err)
	assertNil(t, resp)
	assertEqual(t, circuitBreakerStateOpen, c.circuitBreaker.getState())

	time.Sleep(timeout + 50*time.Millisecond)
	assertEqual(t, circuitBreakerStateHalfOpen, c.circuitBreaker.getState())

	_, err = c.R().Get(ts.URL + "/500")
	assertError(t, err)
	assertEqual(t, circuitBreakerStateOpen, c.circuitBreaker.getState())

	time.Sleep(timeout + 50*time.Millisecond)
	assertEqual(t, circuitBreakerStateHalfOpen, c.circuitBreaker.getState())

	for i := uint32(0); i < successThreshold; i++ {
		_, err := c.R().Get(ts.URL + "/200")
		assertNil(t, err)
	}
	assertEqual(t, circuitBreakerStateClosed, c.circuitBreaker.getState())

	resp, err = c.R().Get(ts.URL + "/200")
	assertNil(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	_, err = c.R().Get(ts.URL + "/500")
	assertError(t, err)
	assertEqual(t, uint32(1), c.circuitBreaker.failureCount.Load())

	time.Sleep(timeout)

	_, err = c.R().Get(ts.URL + "/500")
	assertError(t, err)
	assertEqual(t, uint32(1), c.circuitBreaker.failureCount.Load())
}
