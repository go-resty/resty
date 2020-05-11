// Copyright (c) 2015-2020 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClientBasicAuth(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dc()
	c.SetBasicAuth("myuser", "basicauth").
		SetHostURL(ts.URL).
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
		SetHostURL(ts.URL + "/")

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
		SetHostURL(ts.URL + "/")

	resp, err := c.R().Get("/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	// Ensure setting the scheme works as well
	c.SetAuthScheme("Bearer")

	resp2, err2 := c.R().Get("/profile")
	assertError(t, err2)
	assertEqual(t, http.StatusOK, resp2.StatusCode())

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

	assertEqual(t, true, ("Get /redirect-21: stopped after 20 redirects" == err.Error() ||
		"Get \"/redirect-21\": stopped after 20 redirects" == err.Error()))

	c.SetRedirectPolicy(NoRedirectPolicy())
	_, err = c.R().Get(ts.URL + "/redirect-1")
	assertEqual(t, true, ("Get /redirect-2: auto redirect is disabled" == err.Error() ||
		"Get \"/redirect-2\": auto redirect is disabled" == err.Error()))
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

	// Error
	c.SetProxy("//not.a.user@%66%6f%6f.com:8888")

	resp, err = c.R().
		Get(ts.URL)
	assertNotNil(t, err)
	assertNotNil(t, resp)
}

func TestClientSetCertificates(t *testing.T) {
	client := dc()
	client.SetCertificates(tls.Certificate{})

	transport, err := client.transport()

	assertNil(t, err)
	assertEqual(t, 1, len(transport.TLSClientConfig.Certificates))
}

func TestClientSetRootCertificate(t *testing.T) {
	client := dc()
	client.SetRootCertificate(filepath.Join(getTestDataPath(), "sample-root.pem"))

	transport, err := client.transport()

	assertNil(t, err)
	assertNotNil(t, transport.TLSClientConfig.RootCAs)
}

func TestClientSetRootCertificateNotExists(t *testing.T) {
	client := dc()
	client.SetRootCertificate(filepath.Join(getTestDataPath(), "not-exists-sample-root.pem"))

	transport, err := client.transport()

	assertNil(t, err)
	assertNil(t, transport.TLSClientConfig)
}

func TestClientSetRootCertificateFromString(t *testing.T) {
	client := dc()
	rootPemData, err := ioutil.ReadFile(filepath.Join(getTestDataPath(), "sample-root.pem"))
	assertNil(t, err)

	client.SetRootCertificateFromString(string(rootPemData))

	transport, err := client.transport()

	assertNil(t, err)
	assertNotNil(t, transport.TLSClientConfig.RootCAs)
}

func TestClientSetRootCertificateFromStringErrorTls(t *testing.T) {
	client := NewWithClient(&http.Client{})
	client.outputLogTo(ioutil.Discard)

	rootPemData, err := ioutil.ReadFile(filepath.Join(getTestDataPath(), "sample-root.pem"))
	assertNil(t, err)
	rt := &CustomRoundTripper{}
	client.SetTransport(rt)
	transport, err := client.transport()

	client.SetRootCertificateFromString(string(rootPemData))

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
	assertNotNil(t, resp.Body())
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
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
	transportInUse, err := client.transport()

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

func TestClientOptions(t *testing.T) {
	client := dc()
	client.SetContentLength(true)
	assertEqual(t, client.setContentLength, true)

	client.SetHostURL("http://httpbin.org")
	assertEqual(t, "http://httpbin.org", client.HostURL)

	client.SetHeader(hdrContentTypeKey, "application/json; charset=utf-8")
	client.SetHeaders(map[string]string{
		hdrUserAgentKey: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) go-resty v0.1",
		"X-Request-Id":  strconv.FormatInt(time.Now().UnixNano(), 10),
	})
	assertEqual(t, "application/json; charset=utf-8", client.Header.Get(hdrContentTypeKey))

	client.SetCookie(&http.Cookie{
		Name:  "default-cookie",
		Value: "This is cookie default-cookie value",
	})
	assertEqual(t, "default-cookie", client.Cookies[0].Name)

	cookies := []*http.Cookie{
		{
			Name:  "default-cookie-1",
			Value: "This is default-cookie 1 value",
		}, {
			Name:  "default-cookie-2",
			Value: "This is default-cookie 2 value",
		},
	}
	client.SetCookies(cookies)
	assertEqual(t, "default-cookie-1", client.Cookies[1].Name)
	assertEqual(t, "default-cookie-2", client.Cookies[2].Name)

	client.SetQueryParam("test_param_1", "Param_1")
	client.SetQueryParams(map[string]string{"test_param_2": "Param_2", "test_param_3": "Param_3"})
	assertEqual(t, "Param_3", client.QueryParam.Get("test_param_3"))

	rTime := strconv.FormatInt(time.Now().UnixNano(), 10)
	client.SetFormData(map[string]string{"r_time": rTime})
	assertEqual(t, rTime, client.FormData.Get("r_time"))

	client.SetBasicAuth("myuser", "mypass")
	assertEqual(t, "myuser", client.UserInfo.Username)

	client.SetAuthToken("AC75BD37F019E08FBC594900518B4F7E")
	assertEqual(t, "AC75BD37F019E08FBC594900518B4F7E", client.Token)

	client.SetDisableWarn(true)
	assertEqual(t, client.DisableWarn, true)

	client.SetRetryCount(3)
	assertEqual(t, 3, client.RetryCount)

	rwt := time.Duration(1000) * time.Millisecond
	client.SetRetryWaitTime(rwt)
	assertEqual(t, rwt, client.RetryWaitTime)

	mrwt := time.Duration(2) * time.Second
	client.SetRetryMaxWaitTime(mrwt)
	assertEqual(t, mrwt, client.RetryMaxWaitTime)

	err := &AuthError{}
	client.SetError(err)
	if reflect.TypeOf(err) == client.Error {
		t.Error("SetError failed")
	}

	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	transport, transportErr := client.transport()

	assertNil(t, transportErr)
	assertEqual(t, true, transport.TLSClientConfig.InsecureSkipVerify)

	client.OnBeforeRequest(func(c *Client, r *Request) error {
		c.log.Debugf("I'm in Request middleware")
		return nil // if it success
	})
	client.OnAfterResponse(func(c *Client, r *Response) error {
		c.log.Debugf("I'm in Response middleware")
		return nil // if it success
	})

	client.SetTimeout(5 * time.Second)
	client.SetRedirectPolicy(FlexibleRedirectPolicy(10), func(req *http.Request, via []*http.Request) error {
		return errors.New("sample test redirect")
	})
	client.SetContentLength(true)

	client.SetDebug(true)
	assertEqual(t, client.Debug, true)

	var sl int64 = 1000000
	client.SetDebugBodyLimit(sl)
	assertEqual(t, client.debugBodySizeLimit, sl)

	client.SetAllowGetMethodPayload(true)
	assertEqual(t, client.AllowGetMethodPayload, true)

	client.SetScheme("http")
	assertEqual(t, client.scheme, "http")

	client.SetCloseConnection(true)
	assertEqual(t, client.closeConnection, true)
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
			rb, _ := ioutil.ReadAll(b)
			c.log.Debugf("%s %v", string(rb), len(rb))
			assertEqual(t, true, len(rb) >= 45)
		}
		return nil
	})

	ts := createPostServer(t)
	defer ts.Close()

	// Regular bodybuf use case
	resp, _ := client.R().
		SetBody(map[string]interface{}{"username": "testuser", "password": "testpass"}).
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

func TestClientRoundTripper(t *testing.T) {
	c := NewWithClient(&http.Client{})
	c.outputLogTo(ioutil.Discard)

	rt := &CustomRoundTripper{}
	c.SetTransport(rt)

	ct, err := c.transport()
	assertNotNil(t, err)
	assertNil(t, ct)
	assertEqual(t, "current transport is not an *http.Transport instance", err.Error())

	c.SetTLSClientConfig(&tls.Config{})
	c.SetProxy("http://localhost:9090")
	c.RemoveProxy()
	c.SetCertificates(tls.Certificate{})
	c.SetRootCertificate(filepath.Join(getTestDataPath(), "sample-root.pem"))
}

func TestClientNewRequest(t *testing.T) {
	c := New()
	request := c.NewRequest()
	assertNotNil(t, request)
}

func TestDebugBodySizeLimit(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	var lgr bytes.Buffer
	c := dc()
	c.SetDebug(true)
	c.SetDebugBodyLimit(30)
	c.outputLogTo(&lgr)

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
			SetHeader("Accept-Encoding", "gzip").
			Get(tc.url)

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, "200 OK", resp.Status())
		assertNotNil(t, resp.Body())
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
		// masking authorzation header
		r.Header.Set("Authorization", "Bearer *******************************")
		return nil
	})
	c.OnResponseLog(func(r *ResponseLog) error {
		r.Header.Add("X-Debug-Resposne-Log", "Modified :)")
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
	assertEqual(t, true, strings.Contains(logInfo, "X-Debug-Resposne-Log"))
	assertEqual(t, true, strings.Contains(logInfo, "Modified the response body content"))

	// Error scenario
	c.OnRequestLog(func(r *RequestLog) error { return errors.New("request test error") })
	resp, err = c.R().
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF-Request").
		Get(ts.URL + "/profile")
	assertEqual(t, errors.New("request test error"), err)
	assertNil(t, resp)

	c.OnRequestLog(nil)
	c.OnResponseLog(func(r *ResponseLog) error { return errors.New("response test error") })
	resp, err = c.R().
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF-Request").
		Get(ts.URL + "/profile")
	assertEqual(t, errors.New("response test error"), err)
	assertNotNil(t, resp)
}

func TestNewWithLocalAddr(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	localAddress, _ := net.ResolveTCPAddr("tcp", "127.0.0.1")
	client := NewWithLocalAddr(localAddress)
	client.SetHostURL(ts.URL)

	resp, err := client.R().Get("/")
	assertNil(t, err)
	assertEqual(t, resp.String(), "TestGet: text response")
}
