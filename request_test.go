// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type AuthSuccess struct {
	ID, Message string
}

type AuthError struct {
	ID, Message string
}

func TestGet(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcnl().R().
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "HTTP/1.1", resp.Proto())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
}

func TestGetGH524(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcnl().R().
		SetPathParams((map[string]string{
			"userId":       "sample@sample.com",
			"subAccountId": "100002",
			"path":         "groups/developers",
		})).
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		SetDebug(true).
		Get(ts.URL + "/v1/users/{userId}/{subAccountId}/{path}/details")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, resp.Request.Header.Get("Content-Type"), "") //  unable to reproduce reported issue
}

func TestRequestNegativeRetryCount(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcnl().SetRetryCount(-1).R().Get(ts.URL + "/")

	assertNil(t, err)
	assertNotNil(t, resp)
	assertEqual(t, "TestGet: text response", resp.String())
}

func TestGetCustomUserAgent(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcnlr().
		SetHeader(hdrUserAgentKey, "Test Custom User agent").
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "HTTP/1.1", resp.Proto())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
}

func TestGetClientParamRequestParam(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetQueryParam("client_param", "true").
		SetQueryParams(map[string]string{"req_1": "jeeva", "req_3": "jeeva3"}).
		SetDebug(true)
	c.outputLogTo(io.Discard)

	resp, err := c.R().
		SetQueryParams(map[string]string{"req_1": "req 1 value", "req_2": "req 2 value"}).
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		SetHeader(hdrUserAgentKey, "Test Custom User agent").
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "HTTP/1.1", resp.Proto())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
}

func TestGetRelativePath(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetBaseURL(ts.URL)

	resp, err := c.R().Get("mypage2")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestGet: text response from mypage2", resp.String())

	logResponse(t, resp)
}

func TestGet400Error(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcnlr().Get(ts.URL + "/mypage")

	assertError(t, err)
	assertEqual(t, http.StatusBadRequest, resp.StatusCode())
	assertEqual(t, "", resp.String())

	logResponse(t, resp)
}

func TestPostJSONStringSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetHeader(hdrContentTypeKey, "application/json; charset=utf-8").
		SetHeaders(map[string]string{hdrUserAgentKey: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) go-resty v0.1", hdrAcceptKey: "application/json; charset=utf-8"})

	resp, err := c.R().
		SetBody(`{"username":"testuser", "password":"testpass"}`).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	logResponse(t, resp)

	// PostJSONStringError
	resp, err = c.R().
		SetBody(`{"username":"testuser" "password":"testpass"}`).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusBadRequest, resp.StatusCode())

	logResponse(t, resp)
}

func TestPostJSONBytesSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetHeader(hdrContentTypeKey, "application/json; charset=utf-8").
		SetHeaders(map[string]string{hdrUserAgentKey: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) go-resty v0.7", hdrAcceptKey: "application/json; charset=utf-8"})

	resp, err := c.R().
		SetBody([]byte(`{"username":"testuser", "password":"testpass"}`)).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	logResponse(t, resp)
}

func TestPostJSONBytesIoReader(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetHeader(hdrContentTypeKey, "application/json; charset=utf-8")

	bodyBytes := []byte(`{"username":"testuser", "password":"testpass"}`)

	resp, err := c.R().
		SetBody(bytes.NewReader(bodyBytes)).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	logResponse(t, resp)
}

func TestPostJSONStructSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	user := &credentials{Username: "testuser", Password: "testpass"}
	assertEqual(t, "Username: **********, Password: **********", user.String())

	c := dcnl().SetJSONEscapeHTML(false)
	r := c.R().
		SetHeader(hdrContentTypeKey, "application/json; charset=utf-8").
		SetBody(user).
		SetResult(&AuthSuccess{})

	rr := r.WithContext(context.Background())
	resp, err := rr.Post(ts.URL + "/login")

	_ = rr.Clone(context.Background())

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int64(50), resp.Size())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	logResponse(t, resp)
}

func TestPostJSONRPCStructSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	user := &credentials{Username: "testuser", Password: "testpass"}
	assertEqual(t, "Username: **********, Password: **********", user.String())

	c := dcnl().SetJSONEscapeHTML(false)
	r := c.R().
		SetHeader(hdrContentTypeKey, "application/json-rpc").
		SetBody(user).
		SetResult(&AuthSuccess{}).
		SetQueryParam("ct", "rpc")

	rr := r.WithContext(context.Background())
	resp, err := rr.Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int64(50), resp.Size())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	logResponse(t, resp)
}

func TestPostJSONStructInvalidLogin(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetDebug(false)

	resp, err := c.R().
		SetHeader(hdrContentTypeKey, "application/json; charset=utf-8").
		SetBody(credentials{Username: "testuser", Password: "testpass1"}).
		SetError(AuthError{}).
		SetJSONEscapeHTML(false).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusUnauthorized, resp.StatusCode())

	authError := resp.Error().(*AuthError)
	assertEqual(t, "unauthorized", authError.ID)
	assertEqual(t, "Invalid credentials", authError.Message)
	t.Logf("Result Error: %q", resp.Error().(*AuthError))

	logResponse(t, resp)
}

func TestPostJSONErrorRFC7807(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl()
	resp, err := c.R().
		SetHeader(hdrContentTypeKey, "application/json; charset=utf-8").
		SetBody(credentials{Username: "testuser", Password: "testpass1"}).
		SetError(AuthError{}).
		Post(ts.URL + "/login?ct=problem")

	assertError(t, err)
	assertEqual(t, http.StatusUnauthorized, resp.StatusCode())

	authError := resp.Error().(*AuthError)
	assertEqual(t, "unauthorized", authError.ID)
	assertEqual(t, "Invalid credentials", authError.Message)
	t.Logf("Result Error: %q", resp.Error().(*AuthError))

	logResponse(t, resp)
}

func TestPostJSONMapSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetDebug(false)

	resp, err := c.R().
		SetBody(map[string]any{"username": "testuser", "password": "testpass"}).
		SetResult(AuthSuccess{}).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	logResponse(t, resp)
}

func TestPostJSONMapInvalidResponseJson(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	resp, err := dcnldr().
		SetBody(map[string]any{"username": "testuser", "password": "invalidjson"}).
		SetResult(&AuthSuccess{}).
		Post(ts.URL + "/login")

	assertEqual(t, "invalid character '}' looking for beginning of object key string", err.Error())
	assertEqual(t, http.StatusOK, resp.StatusCode())

	authSuccess := resp.Result().(*AuthSuccess)
	assertEqual(t, "", authSuccess.ID)
	assertEqual(t, "", authSuccess.Message)

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	logResponse(t, resp)
}

type brokenMarshalJSON struct{}

func (b brokenMarshalJSON) MarshalJSON() ([]byte, error) {
	return nil, errors.New("b0rk3d")
}

func TestPostJSONMarshalError(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	b := brokenMarshalJSON{}
	exp := "b0rk3d"

	_, err := dcnldr().
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(b).
		Post(ts.URL + "/login")
	if err == nil {
		t.Fatalf("expected error but got %v", err)
	}

	if !strings.Contains(err.Error(), exp) {
		t.Errorf("expected error string %q to contain %q", err, exp)
	}
}

func TestForceContentTypeForGH276andGH240(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	retried := 0
	c := dcnl()
	c.SetDebug(false)

	resp, err := c.R().
		SetBody(map[string]any{"username": "testuser", "password": "testpass"}).
		SetResult(AuthSuccess{}).
		SetForceResponseContentType("application/json").
		Post(ts.URL + "/login-json-html")

	assertNil(t, err) // JSON response comes with incorrect content-type, we correct it with ForceContentType
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, 0, retried)
	assertEqual(t, int64(50), resp.Size())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	logResponse(t, resp)
}

func TestPostXMLStringSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetDebug(false)

	resp, err := c.R().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(`<?xml version="1.0" encoding="UTF-8"?><User><Username>testuser</Username><Password>testpass</Password></User>`).
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int64(116), resp.Size())

	logResponse(t, resp)
}

type brokenMarshalXML struct{}

func (b brokenMarshalXML) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return errors.New("b0rk3d")
}

func TestPostXMLMarshalError(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	b := brokenMarshalXML{}
	exp := "b0rk3d"

	_, err := dcnldr().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(b).
		Post(ts.URL + "/login")
	if err == nil {
		t.Fatalf("expected error but got %v", err)
	}

	if !strings.Contains(err.Error(), exp) {
		t.Errorf("expected error string %q to contain %q", err, exp)
	}
}

func TestPostXMLStringError(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	resp, err := dcnldr().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(`<?xml version="1.0" encoding="UTF-8"?><User><Username>testuser</Username>testpass</Password></User>`).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusBadRequest, resp.StatusCode())
	assertEqual(t, `<?xml version="1.0" encoding="UTF-8"?><AuthError><Id>bad_request</Id><Message>Unable to read user info</Message></AuthError>`, resp.String())

	logResponse(t, resp)
}

func TestPostXMLBytesSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetDebug(false)

	resp, err := c.R().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody([]byte(`<?xml version="1.0" encoding="UTF-8"?><User><Username>testuser</Username><Password>testpass</Password></User>`)).
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		SetContentLength(true).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	logResponse(t, resp)
}

func TestPostXMLStructSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	resp, err := dcnldr().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(credentials{Username: "testuser", Password: "testpass"}).
		SetContentLength(true).
		SetResult(&AuthSuccess{}).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	logResponse(t, resp)
}

func TestPostXMLStructInvalidLogin(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetError(&AuthError{})

	resp, err := c.R().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(credentials{Username: "testuser", Password: "testpass1"}).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusUnauthorized, resp.StatusCode())
	assertEqual(t, resp.Header().Get("Www-Authenticate"), "Protected Realm")

	t.Logf("Result Error: %q", resp.Error().(*AuthError))

	logResponse(t, resp)
}

func TestPostXMLStructInvalidResponseXml(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	resp, err := dcnldr().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(credentials{Username: "testuser", Password: "invalidxml"}).
		SetResult(&AuthSuccess{}).
		Post(ts.URL + "/login")

	assertEqual(t, "XML syntax error on line 1: element <Message> closed by </AuthSuccess>", err.Error())
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	logResponse(t, resp)
}

func TestPostXMLMapNotSupported(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	_, err := dcnldr().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(map[string]any{"Username": "testuser", "Password": "testpass"}).
		Post(ts.URL + "/login")

	assertErrorIs(t, ErrUnsupportedRequestBodyKind, err)
}

func TestRequestBasicAuth(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetBaseURL(ts.URL).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	resp, err := c.R().
		SetBasicAuth("myuser", "basicauth").
		SetResult(&AuthSuccess{}).
		Post("/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))
	logResponse(t, resp)
}

func TestRequestBasicAuthWithBody(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetBaseURL(ts.URL).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	resp, err := c.R().
		SetBasicAuth("myuser", "basicauth").
		SetBody([]string{strings.Repeat("hello", 25)}).
		SetResult(&AuthSuccess{}).
		Post("/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))
	logResponse(t, resp)
}

func TestRequestInsecureBasicAuth(t *testing.T) {
	ts := createAuthServerTLSOptional(t, false)
	defer ts.Close()

	var logBuf bytes.Buffer
	logger := createLogger()
	logger.l.SetOutput(&logBuf)

	c := dcnl()
	c.SetBaseURL(ts.URL)

	resp, err := c.R().
		SetBasicAuth("myuser", "basicauth").
		SetResult(&AuthSuccess{}).
		SetLogger(logger).
		Post("/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, true, strings.Contains(logBuf.String(),
		"WARN RESTY Using sensitive credentials in HTTP mode is not secure. Use HTTPS"))

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))
	logResponse(t, resp)
	t.Logf("captured request-level logs: %s", logBuf.String())
}

func TestRequestBasicAuthFail(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetError(AuthError{})

	resp, err := c.R().
		SetBasicAuth("myuser", "basicauth1").
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusUnauthorized, resp.StatusCode())

	t.Logf("Result Error: %q", resp.Error().(*AuthError))
	logResponse(t, resp)
}

func TestRequestAuthToken(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF")

	resp, err := c.R().
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF-Request").
		Get(ts.URL + "/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestRequestAuthScheme(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetAuthScheme("OAuth").
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF")

	t.Run("override auth scheme", func(t *testing.T) {
		resp, err := c.R().
			SetAuthScheme("Bearer").
			SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF-Request").
			Get(ts.URL + "/profile")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
	})

	t.Run("empty auth scheme at client level GH954", func(t *testing.T) {
		tokenValue := "004DDB79-6801-4587-B976-F093E6AC44FF"

		// set client level
		c.SetAuthScheme("").
			SetAuthToken(tokenValue)

		resp, err := c.R().
			Get(ts.URL + "/profile")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, tokenValue, resp.Request.Header.Get(hdrAuthorizationKey))
	})

	t.Run("empty auth scheme at request level GH954", func(t *testing.T) {
		tokenValue := "004DDB79-6801-4587-B976-F093E6AC44FF"

		// set client level
		c := dcnl().
			SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
			SetAuthToken(tokenValue)

		resp, err := c.R().
			SetAuthScheme("").
			Get(ts.URL + "/profile")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, tokenValue, resp.Request.Header.Get(hdrAuthorizationKey))
	})

	t.Run("only client level auth token GH959", func(t *testing.T) {
		tokenValue := "004DDB79-6801-4587-B976-F093E6AC44FF"

		c := dcnl().
			SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
			SetAuthToken(tokenValue)

		resp, err := c.R().
			Get(ts.URL + "/profile")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, "Bearer "+tokenValue, resp.Request.Header.Get(hdrAuthorizationKey))
	})
}

func TestFormData(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetFormData(map[string]string{"zip_code": "00000", "city": "Los Angeles"}).
		SetContentLength(true).
		SetDebug(true)
	c.outputLogTo(io.Discard)

	resp, err := c.R().
		SetFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M", "zip_code": "00001"}).
		SetBasicAuth("myuser", "mypass").
		Post(ts.URL + "/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "Success", resp.String())
}

func TestMultiValueFormData(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	v := url.Values{
		"search_criteria": []string{"book", "glass", "pencil"},
	}

	c := dcnl()
	c.SetContentLength(true).SetDebug(true)
	c.outputLogTo(io.Discard)

	resp, err := c.R().
		SetQueryParamsFromValues(v).
		Post(ts.URL + "/search")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "Success", resp.String())
}

func TestFormDataDisableWarn(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetFormData(map[string]string{"zip_code": "00000", "city": "Los Angeles"}).
		SetContentLength(true).
		SetDisableWarn(true)
	c.outputLogTo(io.Discard)

	resp, err := c.R().
		SetDebug(true).
		SetFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M", "zip_code": "00001"}).
		SetBasicAuth("myuser", "mypass").
		Post(ts.URL + "/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "Success", resp.String())
}

func TestGetWithCookie(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetBaseURL(ts.URL)
	c.SetCookie(&http.Cookie{
		Name:  "go-resty-1",
		Value: "This is cookie 1 value",
	})

	r := c.R().
		SetCookie(&http.Cookie{
			Name:  "go-resty-2",
			Value: "This is cookie 2 value",
		}).
		SetCookies([]*http.Cookie{
			{
				Name:  "go-resty-1",
				Value: "This is cookie 1 value additional append",
			},
		})
	resp, err := r.Get("mypage2")

	_ = r.Clone(context.Background())

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestGet: text response from mypage2", resp.String())

	logResponse(t, resp)
}

func TestGetWithCookies(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetBaseURL(ts.URL).SetDebug(true)

	tu, _ := url.Parse(ts.URL)
	c.Client().Jar.SetCookies(tu, []*http.Cookie{
		{
			Name:  "jar-go-resty-1",
			Value: "From Jar - This is cookie 1 value",
		},
		{
			Name:  "jar-go-resty-2",
			Value: "From Jar - This is cookie 2 value",
		},
	})

	resp, err := c.R().SetHeader(hdrCookieKey, "").Get("mypage2")
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	// Client cookies
	c.SetCookies([]*http.Cookie{
		{
			Name:  "go-resty-1",
			Value: "This is cookie 1 value",
		},
		{
			Name:  "go-resty-2",
			Value: "This is cookie 2 value",
		},
	})

	r := c.R().
		SetCookie(&http.Cookie{
			Name:  "req-go-resty-1",
			Value: "This is request cookie 1 value additional append",
		})
	resp, err = r.Get("mypage2")

	_ = r.Clone(context.Background())

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestGet: text response from mypage2", resp.String())

	logResponse(t, resp)
}

func TestPutPlainString(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	resp, err := dcnl().R().
		SetBody("This is plain text body to server").
		Put(ts.URL + "/plaintext")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestPut: plain text response", resp.String())
}

func TestPutJSONString(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	client := dcnl()

	client.AddRequestMiddleware(func(c *Client, r *Request) error {
		c.SetContentLength(true)
		r.SetHeader("X-Custom-Request-Middleware", "Request middleware")
		return nil
	})
	client.AddRequestMiddleware(func(c *Client, r *Request) error {
		r.SetHeader("X-ContentLength", "Request middleware ContentLength set")
		return nil
	})

	client.SetDebug(true)
	client.outputLogTo(io.Discard)

	resp, err := client.R().
		SetHeaders(map[string]string{hdrContentTypeKey: "application/json; charset=utf-8", hdrAcceptKey: "application/json; charset=utf-8"}).
		SetBody(`{"content":"json content sending to server"}`).
		Put(ts.URL + "/json")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, `{"response":"json response"}`, resp.String())
}

func TestPutXMLString(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	resp, err := dcnl().R().
		SetHeaders(map[string]string{hdrContentTypeKey: "application/xml", hdrAcceptKey: "application/xml"}).
		SetBody(`<?xml version="1.0" encoding="UTF-8"?><Request>XML Content sending to server</Request>`).
		Put(ts.URL + "/xml")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, `<?xml version="1.0" encoding="UTF-8"?><Response>XML response</Response>`, resp.String())
}

func TestRequestMiddleware(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetContentLength(true)

	c.AddRequestMiddleware(func(c *Client, r *Request) error {
		r.SetHeader("X-Custom-Request-Middleware", "Request middleware")
		return nil
	})
	c.AddRequestMiddleware(func(c *Client, r *Request) error {
		r.SetHeader("X-ContentLength", "Request middleware ContentLength set")
		return nil
	})

	resp, err := c.R().
		SetBody("RequestMiddleware: This is plain text body to server").
		Put(ts.URL + "/plaintext")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestPut: plain text response", resp.String())
}

func TestHTTPAutoRedirectUpTo10(t *testing.T) {
	ts := createRedirectServer(t)
	defer ts.Close()

	res, err := dcnl().R().Get(ts.URL + "/redirect-1")
	redirects := res.RedirectHistory()
	assertEqual(t, 10, len(redirects))

	finalReq := redirects[0]
	assertEqual(t, 307, finalReq.StatusCode)
	assertEqual(t, ts.URL+"/redirect-10", finalReq.URL)

	assertEqual(t, true, (err.Error() == "Get /redirect-11: stopped after 10 redirects" ||
		err.Error() == "Get \"/redirect-11\": stopped after 10 redirects"))
}

func TestHostCheckRedirectPolicy(t *testing.T) {
	ts := createRedirectServer(t)
	defer ts.Close()

	c := dcnl().
		SetRedirectPolicy(DomainCheckRedirectPolicy("127.0.0.1"))

	_, err := c.R().Get(ts.URL + "/redirect-host-check-1")

	assertNotNil(t, err)
	assertEqual(t, true, strings.Contains(err.Error(), "redirect is not allowed as per DomainCheckRedirectPolicy"))
}

func TestHttpMethods(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	t.Run("head method", func(t *testing.T) {
		resp, err := dcnldr().Head(ts.URL + "/")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
	})

	t.Run("options method", func(t *testing.T) {
		resp, err := dcnldr().Options(ts.URL + "/options")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, resp.Header().Get("Access-Control-Expose-Headers"), "x-go-resty-id")
	})

	t.Run("patch method", func(t *testing.T) {
		resp, err := dcnldr().Patch(ts.URL + "/patch")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())

		assertEqual(t, "", resp.String())
	})

	t.Run("trace method", func(t *testing.T) {
		resp, err := dcnldr().Trace(ts.URL + "/trace")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())

		assertEqual(t, "", resp.String())
	})
}

func TestSendMethod(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	t.Run("send-get-implicit", func(t *testing.T) {
		req := dcnldr()
		req.URL = ts.URL + "/gzip-test"

		resp, err := req.Send()

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())

		assertEqual(t, "This is Gzip response testing", resp.String())
	})

	t.Run("send-get", func(t *testing.T) {
		req := dcnldr()
		req.SetMethod(MethodGet)
		req.URL = ts.URL + "/gzip-test"

		resp, err := req.Send()

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())

		assertEqual(t, "This is Gzip response testing", resp.String())
	})

	t.Run("send-options", func(t *testing.T) {
		req := dcnldr()
		req.SetMethod(MethodOptions)
		req.URL = ts.URL + "/options"

		resp, err := req.Send()

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())

		assertEqual(t, "", resp.String())
		assertEqual(t, "x-go-resty-id", resp.Header().Get("Access-Control-Expose-Headers"))
	})

	t.Run("send-patch", func(t *testing.T) {
		req := dcnldr()
		req.SetMethod(MethodPatch)
		req.URL = ts.URL + "/patch"

		resp, err := req.Send()

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())

		assertEqual(t, "", resp.String())
	})

	t.Run("send-put", func(t *testing.T) {
		req := dcnldr()
		req.SetMethod(MethodPut)
		req.URL = ts.URL + "/plaintext"

		resp, err := req.Send()

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())

		assertEqual(t, "TestPut: plain text response", resp.String())
	})
}

func TestRawFileUploadByBody(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	fileBytes, err := os.ReadFile(filepath.Join(getTestDataPath(), "test-img.png"))
	assertNil(t, err)

	resp, err := dcnldr().
		SetBody(fileBytes).
		SetContentLength(true).
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF").
		Put(ts.URL + "/raw-upload")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "image/png", resp.Request.Header.Get(hdrContentTypeKey))
}

func TestProxySetting(t *testing.T) {
	c := dcnl()

	transport, err := c.HTTPTransport()

	assertNil(t, err)

	assertEqual(t, false, c.IsProxySet())
	assertNotNil(t, transport.Proxy)

	c.SetProxy("http://sampleproxy:8888")
	assertEqual(t, true, c.IsProxySet())
	assertNotNil(t, transport.Proxy)

	c.SetProxy("//not.a.user@%66%6f%6f.com:8888")
	assertEqual(t, true, c.IsProxySet())
	assertNotNil(t, transport.Proxy)

	c.SetProxy("http://sampleproxy:8888")
	assertEqual(t, true, c.IsProxySet())
	c.RemoveProxy()
	assertNil(t, c.ProxyURL())
	assertNil(t, transport.Proxy)
}

func TestGetClient(t *testing.T) {
	client := New()
	custom := New()
	customClient := custom.Client()

	assertNotNil(t, customClient)
	assertNotEqual(t, client, http.DefaultClient)
	assertNotEqual(t, customClient, http.DefaultClient)
	assertNotEqual(t, client, customClient)
}

func TestIncorrectURL(t *testing.T) {
	c := dcnl()
	_, err := c.R().Get("//not.a.user@%66%6f%6f.com/just/a/path/also")
	assertEqual(t, true, (strings.Contains(err.Error(), "parse //not.a.user@%66%6f%6f.com/just/a/path/also") ||
		strings.Contains(err.Error(), "parse \"//not.a.user@%66%6f%6f.com/just/a/path/also\"")))

	c.SetBaseURL("//not.a.user@%66%6f%6f.com")
	_, err1 := c.R().Get("/just/a/path/also")
	assertEqual(t, true, (strings.Contains(err1.Error(), "parse //not.a.user@%66%6f%6f.com/just/a/path/also") ||
		strings.Contains(err1.Error(), "parse \"//not.a.user@%66%6f%6f.com/just/a/path/also\"")))
}

func TestDetectContentTypeForPointer(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	user := &credentials{Username: "testuser", Password: "testpass"}

	resp, err := dcnldr().
		SetBody(user).
		SetResult(AuthSuccess{}).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	logResponse(t, resp)
}

type ExampleUser struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	ZipCode   string `json:"zip_code"`
}

func TestDetectContentTypeForPointerWithSlice(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	users := &[]ExampleUser{
		{FirstName: "firstname1", LastName: "lastname1", ZipCode: "10001"},
		{FirstName: "firstname2", LastName: "lastname3", ZipCode: "10002"},
		{FirstName: "firstname3", LastName: "lastname3", ZipCode: "10003"},
	}

	resp, err := dcnldr().
		SetBody(users).
		Post(ts.URL + "/users")

	assertError(t, err)
	assertEqual(t, http.StatusAccepted, resp.StatusCode())

	t.Logf("Result Success: %q", resp)

	logResponse(t, resp)
}

func TestDetectContentTypeForPointerWithSliceMap(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	usersmap := map[string]any{
		"user1": ExampleUser{FirstName: "firstname1", LastName: "lastname1", ZipCode: "10001"},
		"user2": &ExampleUser{FirstName: "firstname2", LastName: "lastname3", ZipCode: "10002"},
		"user3": ExampleUser{FirstName: "firstname3", LastName: "lastname3", ZipCode: "10003"},
	}

	var users []map[string]any
	users = append(users, usersmap)

	resp, err := dcnldr().
		SetBody(&users).
		Post(ts.URL + "/usersmap")

	assertError(t, err)
	assertEqual(t, http.StatusAccepted, resp.StatusCode())

	t.Logf("Result Success: %q", resp)

	logResponse(t, resp)
}

func TestDetectContentTypeForSlice(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	users := []ExampleUser{
		{FirstName: "firstname1", LastName: "lastname1", ZipCode: "10001"},
		{FirstName: "firstname2", LastName: "lastname3", ZipCode: "10002"},
		{FirstName: "firstname3", LastName: "lastname3", ZipCode: "10003"},
	}

	resp, err := dcnldr().
		SetBody(users).
		Post(ts.URL + "/users")

	assertError(t, err)
	assertEqual(t, http.StatusAccepted, resp.StatusCode())

	t.Logf("Result Success: %q", resp)

	logResponse(t, resp)
}

func TestMultiParamsQueryString(t *testing.T) {
	ts1 := createGetServer(t)
	defer ts1.Close()

	client := dcnl()
	req1 := client.R()

	client.SetQueryParam("status", "open")

	_, _ = req1.SetQueryParam("status", "pending").
		Get(ts1.URL)

	assertEqual(t, true, strings.Contains(req1.URL, "status=pending"))
	// pending overrides open
	assertEqual(t, false, strings.Contains(req1.URL, "status=open"))

	_, _ = req1.SetQueryParam("status", "approved").
		Get(ts1.URL)

	assertEqual(t, true, strings.Contains(req1.URL, "status=approved"))
	// approved overrides pending
	assertEqual(t, false, strings.Contains(req1.URL, "status=pending"))

	ts2 := createGetServer(t)
	defer ts2.Close()

	req2 := client.R()

	v := url.Values{
		"status": []string{"pending", "approved", "reject"},
	}

	_, _ = req2.SetQueryParamsFromValues(v).Get(ts2.URL)

	assertEqual(t, true, strings.Contains(req2.URL, "status=pending"))
	assertEqual(t, true, strings.Contains(req2.URL, "status=approved"))
	assertEqual(t, true, strings.Contains(req2.URL, "status=reject"))

	// because it's removed by key
	assertEqual(t, false, strings.Contains(req2.URL, "status=open"))
}

func TestSetQueryStringTypical(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcnldr().
		SetQueryString("productId=232&template=fresh-sample&cat=resty&source=google&kw=buy a lot more").
		Get(ts.URL)

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())

	resp, err = dcnldr().
		SetQueryString("&%%amp;").
		Get(ts.URL)

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())
}

func TestSetHeaderVerbatim(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	r := dcnldr().
		SetHeaderVerbatim("header-lowercase", "value_lowercase").
		SetHeader("header-lowercase", "value_standard")

	//lint:ignore SA1008 valid one ignore this!
	assertEqual(t, "value_lowercase", strings.Join(r.Header["header-lowercase"], ""))
	assertEqual(t, "value_standard", r.Header.Get("Header-Lowercase"))
}

func TestSetHeaderMultipleValue(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	r := dcnldr().
		SetHeaderMultiValues(map[string][]string{
			"Content":       {"text/*", "text/html", "*"},
			"Authorization": {"Bearer xyz"},
		})
	assertEqual(t, "text/*, text/html, *", r.Header.Get("content"))
	assertEqual(t, "Bearer xyz", r.Header.Get("authorization"))
}

func TestOutputFileWithBaseDirAndRelativePath(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/dir-sample")

	baseOutputDir := filepath.Join(getTestDataPath(), "dir-sample")
	client := dcnl().
		SetRedirectPolicy(FlexibleRedirectPolicy(10)).
		SetOutputDirectory(baseOutputDir).
		SetDebug(true)

	outputFilePath := "go-resty/test-img-success.png"
	resp, err := client.R().
		SetOutputFileName(outputFilePath).
		Get(ts.URL + "/my-image.png")

	assertError(t, err)
	assertEqual(t, true, resp.Size() != 0)
	assertEqual(t, true, resp.Duration() > 0)

	f, err1 := os.Open(filepath.Join(baseOutputDir, outputFilePath))
	defer closeq(f)
	assertError(t, err1)
}

func TestOutputFileWithBaseDirError(t *testing.T) {
	c := dcnl().SetRedirectPolicy(FlexibleRedirectPolicy(10)).
		SetOutputDirectory(filepath.Join(getTestDataPath(), `go-resty\0`))

	_ = c
}

func TestOutputPathDirNotExists(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()
	defer cleanupFiles(filepath.Join(".testdata", "not-exists-dir"))

	client := dcnl().
		SetRedirectPolicy(FlexibleRedirectPolicy(10)).
		SetOutputDirectory(filepath.Join(getTestDataPath(), "not-exists-dir"))

	resp, err := client.R().
		SetOutputFileName("test-img-success.png").
		Get(ts.URL + "/my-image.png")

	assertError(t, err)
	assertEqual(t, true, resp.Size() != 0)
	assertEqual(t, true, resp.Duration() > 0)
}

func TestOutputFileAbsPath(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()
	defer cleanupFiles(filepath.Join(".testdata", "go-resty"))

	outputFile := filepath.Join(getTestDataPath(), "go-resty", "test-img-success-2.png")

	res, err := dcnlr().
		SetOutputFileName(outputFile).
		Get(ts.URL + "/my-image.png")

	assertError(t, err)
	assertEqual(t, int64(2579468), res.Size())

	_, err = os.Stat(outputFile)
	assertNil(t, err)
}

func TestRequestSaveResponse(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()
	defer cleanupFiles(filepath.Join(".testdata", "go-resty"))

	c := dcnl().
		SetSaveResponse(true).
		SetOutputDirectory(filepath.Join(getTestDataPath(), "go-resty"))

	assertEqual(t, true, c.IsSaveResponse())

	t.Run("content-disposition save response request", func(t *testing.T) {
		outputFile := filepath.Join(getTestDataPath(), "go-resty", "test-img-success-2.png")
		c.SetSaveResponse(false)
		assertEqual(t, false, c.IsSaveResponse())

		res, err := c.R().
			SetSaveResponse(true).
			Get(ts.URL + "/my-image.png?content-disposition=true&filename=test-img-success-2.png")

		assertError(t, err)
		assertEqual(t, int64(2579468), res.Size())

		_, err = os.Stat(outputFile)
		assertNil(t, err)
	})

	t.Run("use filename from path", func(t *testing.T) {
		outputFile := filepath.Join(getTestDataPath(), "go-resty", "my-image.png")
		c.SetSaveResponse(false)
		assertEqual(t, false, c.IsSaveResponse())

		res, err := c.R().
			SetSaveResponse(true).
			Get(ts.URL + "/my-image.png")

		assertError(t, err)
		assertEqual(t, int64(2579468), res.Size())

		_, err = os.Stat(outputFile)
		assertNil(t, err)
	})

	t.Run("empty path", func(t *testing.T) {
		_, err := c.R().
			SetSaveResponse(true).
			Get(ts.URL)
		assertError(t, err)
	})

}

func TestContextInternal(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	r := dcnl().R().
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10))

	resp, err := r.Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestRequestDoNotParseResponse(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	t.Run("do not parse response 1", func(t *testing.T) {
		client := dcnl().SetDoNotParseResponse(true)
		resp, err := client.R().
			SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
			Get(ts.URL + "/")

		assertError(t, err)

		b, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		assertError(t, err)
		assertEqual(t, "TestGet: text response", string(b))
	})

	t.Run("manual reset raw response - do not parse response 2", func(t *testing.T) {
		resp, err := dcnl().R().
			SetDoNotParseResponse(true).
			Get(ts.URL + "/")

		assertError(t, err)

		resp.RawResponse = nil
		assertEqual(t, 0, resp.StatusCode())
		assertEqual(t, "", resp.String())
	})
}

func TestRequestDoNotParseResponseDebugLog(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	t.Run("do not parse response debug log client level", func(t *testing.T) {
		c := dcnl().
			SetDoNotParseResponse(true).
			SetDebug(true)

		var lgr bytes.Buffer
		c.outputLogTo(&lgr)

		_, err := c.R().
			SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
			Get(ts.URL + "/")

		assertError(t, err)
		assertEqual(t, true, strings.Contains(lgr.String(), "***** DO NOT PARSE RESPONSE - Enabled *****"))
	})

	t.Run("do not parse response debug log request level", func(t *testing.T) {
		c := dcnl()

		var lgr bytes.Buffer
		c.outputLogTo(&lgr)

		_, err := c.R().
			SetDebug(true).
			SetDoNotParseResponse(true).
			SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
			Get(ts.URL + "/")

		assertError(t, err)
		assertEqual(t, true, strings.Contains(lgr.String(), "***** DO NOT PARSE RESPONSE - Enabled *****"))
	})
}

type noCtTest struct {
	Response string `json:"response"`
}

func TestRequestExpectContentTypeTest(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	c := dcnl()
	resp, err := c.R().
		SetResult(noCtTest{}).
		SetExpectResponseContentType("application/json").
		Get(ts.URL + "/json-no-set")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertNotNil(t, resp.Result())
	assertEqual(t, "json response no content type set", resp.Result().(*noCtTest).Response)

	assertEqual(t, "", firstNonEmpty("", ""))
}

func TestGetPathParamAndPathParams(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl().
		SetBaseURL(ts.URL).
		SetPathParam("userId", "sample@sample.com")

	assertEqual(t, "sample@sample.com", c.PathParams()["userId"])

	resp, err := c.R().SetPathParam("subAccountId", "100002").
		Get("/v1/users/{userId}/{subAccountId}/details")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, true, strings.Contains(resp.String(), "TestGetPathParams: text response"))
	assertEqual(t, true, strings.Contains(resp.String(), "/v1/users/sample@sample.com/100002/details"))

	logResponse(t, resp)
}

func TestReportMethodSupportsPayload(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	c := dcnl()
	resp, err := c.R().
		SetBody("body").
		Execute("REPORT", ts.URL+"/report")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestRequestQueryStringOrder(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := New().R().
		SetQueryString("productId=232&template=fresh-sample&cat=resty&source=google&kw=buy a lot more").
		Get(ts.URL + "/?UniqueId=ead1d0ed-XXX-XXX-XXX-abb7612b3146&Translate=false&tempauth=eyJ0eXAiOiJKV1QiLC...HZEhwVnJ1d0NSUGVLaUpSaVNLRG5scz0&ApiVersion=2.0")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
}

func TestRequestOverridesClientAuthorizationHeader(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dcnl()
	c.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetHeader("Authorization", "some token").
		SetBaseURL(ts.URL + "/")

	resp, err := c.R().
		SetHeader("Authorization", "Bearer 004DDB79-6801-4587-B976-F093E6AC44FF").
		Get("/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestRequestFileUploadAsReader(t *testing.T) {
	ts := createFileUploadServer(t)
	defer ts.Close()

	file, _ := os.Open(filepath.Join(getTestDataPath(), "test-img.png"))
	defer file.Close()

	resp, err := dcnldr().
		SetBody(file).
		SetContentType("image/png").
		Post(ts.URL + "/upload")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, true, strings.Contains(resp.String(), "File Uploaded successfully"))

	file, _ = os.Open(filepath.Join(getTestDataPath(), "test-img.png"))
	defer file.Close()

	resp, err = dcnldr().
		SetBody(file).
		SetContentType("image/png").
		SetContentLength(true).
		Post(ts.URL + "/upload")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, true, strings.Contains(resp.String(), "File Uploaded successfully"))
}

func TestHostHeaderOverride(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcnl().R().
		SetHeader("Host", "myhostname").
		Get(ts.URL + "/host-header")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "myhostname", resp.String())

	logResponse(t, resp)
}

type HTTPErrorResponse struct {
	Error string `json:"error,omitempty"`
}

func TestNotFoundWithError(t *testing.T) {
	var httpError HTTPErrorResponse
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcnl().R().
		SetHeader(hdrContentTypeKey, "application/json").
		SetError(&httpError).
		Get(ts.URL + "/not-found-with-error")

	assertError(t, err)
	assertEqual(t, http.StatusNotFound, resp.StatusCode())
	assertEqual(t, "404 Not Found", resp.Status())
	assertNotNil(t, httpError)
	assertEqual(t, "Not found", httpError.Error)

	logResponse(t, resp)
}

func TestNotFoundWithoutError(t *testing.T) {
	var httpError HTTPErrorResponse

	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl().outputLogTo(os.Stdout)
	resp, err := c.R().
		SetError(&httpError).
		SetHeader(hdrContentTypeKey, "application/json").
		Get(ts.URL + "/not-found-no-error")

	assertError(t, err)
	assertEqual(t, http.StatusNotFound, resp.StatusCode())
	assertEqual(t, "404 Not Found", resp.Status())
	assertNotNil(t, httpError)
	assertEqual(t, "", httpError.Error)

	logResponse(t, resp)
}

func TestPathParamURLInput(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl().
		SetBaseURL(ts.URL).
		SetPathParams(map[string]string{
			"userId": "sample@sample.com",
			"path":   "users/developers",
		})

	resp, err := c.R().
		SetDebug(true).
		SetPathParams(map[string]string{
			"subAccountId": "100002",
			"website":      "https://example.com",
		}).Get("/v1/users/{userId}/{subAccountId}/{path}/{website}")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, true, strings.Contains(resp.String(), "TestPathParamURLInput: text response"))
	assertEqual(t, true, strings.Contains(resp.String(), "/v1/users/sample@sample.com/100002/users%2Fdevelopers/https:%2F%2Fexample.com"))

	logResponse(t, resp)
}

func TestRawPathParamURLInput(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl().
		SetBaseURL(ts.URL).
		SetRawPathParams(map[string]string{
			"userId": "sample@sample.com",
			"path":   "users/developers",
		})

	assertEqual(t, "sample@sample.com", c.PathParams()["userId"])
	assertEqual(t, "users/developers", c.PathParams()["path"])

	resp, err := c.R().EnableDebug().
		SetRawPathParams(map[string]string{
			"subAccountId": "100002",
			"website":      "https://example.com",
		}).Get("/v1/users/{userId}/{subAccountId}/{path}/{website}")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, true, strings.Contains(resp.String(), "TestPathParamURLInput: text response"))
	assertEqual(t, true, strings.Contains(resp.String(), "/v1/users/sample@sample.com/100002/users/developers/https://example.com"))

	logResponse(t, resp)
}

// This test case is kind of pass always
func TestTraceInfo(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	serverAddr := ts.URL[strings.LastIndex(ts.URL, "/")+1:]

	client := dcnl()

	t.Run("enable trace on client", func(t *testing.T) {
		client.SetBaseURL(ts.URL).EnableTrace()
		for _, u := range []string{"/", "/json", "/long-text", "/long-json"} {
			resp, err := client.R().Get(u)
			assertNil(t, err)
			assertNotNil(t, resp)

			tr := resp.Request.TraceInfo()
			assertEqual(t, true, tr.DNSLookup >= 0)
			assertEqual(t, true, tr.ConnTime >= 0)
			assertEqual(t, true, tr.TLSHandshake >= 0)
			assertEqual(t, true, tr.ServerTime >= 0)
			assertEqual(t, true, tr.ResponseTime >= 0)
			assertEqual(t, true, tr.TotalTime >= 0)
			assertEqual(t, true, tr.TotalTime < time.Hour)
			assertEqual(t, true, tr.TotalTime == resp.Duration())
			assertEqual(t, tr.RemoteAddr, serverAddr)

			assertNotNil(t, tr.Clone())
		}

		client.DisableTrace()
	})

	t.Run("enable trace on request", func(t *testing.T) {
		for _, u := range []string{"/", "/json", "/long-text", "/long-json"} {
			resp, err := client.R().EnableTrace().Get(u)
			assertNil(t, err)
			assertNotNil(t, resp)

			tr := resp.Request.TraceInfo()
			assertEqual(t, true, tr.DNSLookup >= 0)
			assertEqual(t, true, tr.ConnTime >= 0)
			assertEqual(t, true, tr.TLSHandshake >= 0)
			assertEqual(t, true, tr.ServerTime >= 0)
			assertEqual(t, true, tr.ResponseTime >= 0)
			assertEqual(t, true, tr.TotalTime >= 0)
			assertEqual(t, true, tr.TotalTime == resp.Duration())
			assertEqual(t, tr.RemoteAddr, serverAddr)
		}

	})

	t.Run("enable trace and debug on request", func(t *testing.T) {
		c, logBuf := dcldb()
		c.SetBaseURL(ts.URL)

		requestURLs := []string{"/", "/json", "/long-text", "/long-json"}
		for _, u := range requestURLs {
			resp, err := c.R().EnableTrace().EnableDebug().Get(u)
			assertNil(t, err)
			assertNotNil(t, resp)

			jsonStr := resp.Request.TraceInfo().JSON()
			assertEqual(t, true, strings.Contains(jsonStr, serverAddr))
		}

		logContent := logBuf.String()
		regexTraceInfoHeader := regexp.MustCompile("TRACE INFO:")
		matches := regexTraceInfoHeader.FindAllStringIndex(logContent, -1)
		assertEqual(t, len(requestURLs), len(matches))
	})

	t.Run("enable trace and debug on request json formatter", func(t *testing.T) {
		c, logBuf := dcldb()
		c.SetBaseURL(ts.URL)
		c.SetDebugLogFormatter(DebugLogJSONFormatter)

		requestURLs := []string{"/", "/json", "/long-text", "/long-json"}
		for _, u := range requestURLs {
			resp, err := c.R().EnableTrace().EnableDebug().Get(u)
			assertNil(t, err)
			assertNotNil(t, resp)
		}

		logContent := logBuf.String()
		regexTraceInfoHeader := regexp.MustCompile(`"trace_info":{"`)
		matches := regexTraceInfoHeader.FindAllStringIndex(logContent, -1)
		assertEqual(t, len(requestURLs), len(matches))
	})

	// for sake of hook funcs
	_, _ = client.R().SetTrace(true).Get("https://httpbin.org/get")
}

func TestTraceInfoWithoutEnableTrace(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	client := dcnl()
	client.SetBaseURL(ts.URL)
	for _, u := range []string{"/", "/json", "/long-text", "/long-json"} {
		resp, err := client.R().Get(u)
		assertNil(t, err)
		assertNotNil(t, resp)

		tr := resp.Request.TraceInfo()
		assertEqual(t, true, tr.DNSLookup == 0)
		assertEqual(t, true, tr.ConnTime == 0)
		assertEqual(t, true, tr.TLSHandshake == 0)
		assertEqual(t, true, tr.ServerTime == 0)
		assertEqual(t, true, tr.ResponseTime == 0)
		assertEqual(t, true, tr.TotalTime == 0)
	}
}

func TestTraceInfoOnTimeout(t *testing.T) {
	client := NewWithTransportSettings(&TransportSettings{
		DialerTimeout: 100 * time.Millisecond,
	}).
		SetBaseURL("http://resty-nowhere.local").
		EnableTrace()

	resp, err := client.R().Get("/")
	assertNotNil(t, err)
	assertNotNil(t, resp)

	tr := resp.Request.TraceInfo()
	assertEqual(t, true, tr.DNSLookup >= 0)
	assertEqual(t, true, tr.ConnTime == 0)
	assertEqual(t, true, tr.TLSHandshake == 0)
	assertEqual(t, true, tr.TCPConnTime == 0)
	assertEqual(t, true, tr.ServerTime == 0)
	assertEqual(t, true, tr.ResponseTime == 0)
	assertEqual(t, true, tr.TotalTime > 0)
	assertEqual(t, true, tr.TotalTime == resp.Duration())
}

func TestDebugLoggerRequestBodyTooLarge(t *testing.T) {
	formTs := createFormPostServer(t)
	defer formTs.Close()

	debugBodySizeLimit := 512

	t.Run("post form with more than 512 bytes data", func(t *testing.T) {
		output := bytes.NewBufferString("")
		resp, err := New().SetDebug(true).outputLogTo(output).SetDebugBodyLimit(debugBodySizeLimit).R().
			SetFormData(map[string]string{
				"first_name": "Alex",
				"last_name":  strings.Repeat("C", int(debugBodySizeLimit)),
				"zip_code":   "00001",
			}).
			SetBasicAuth("myuser", "mypass").
			Post(formTs.URL + "/profile")
		assertNil(t, err)
		assertNotNil(t, resp)
		assertEqual(t, true, strings.Contains(output.String(), "REQUEST TOO LARGE"))
	})

	t.Run("post form with no more than 512 bytes data", func(t *testing.T) {
		output := bytes.NewBufferString("")
		resp, err := New().outputLogTo(output).SetDebugBodyLimit(debugBodySizeLimit).R().
			SetDebug(true).
			SetFormData(map[string]string{
				"first_name": "Alex",
				"last_name":  "C",
				"zip_code":   "00001",
			}).
			SetBasicAuth("myuser", "mypass").
			Post(formTs.URL + "/profile")
		assertNil(t, err)
		assertNotNil(t, resp)
		assertEqual(t, true, strings.Contains(output.String(), "Alex"))
	})

	t.Run("post string with more than 512 bytes data", func(t *testing.T) {
		output := bytes.NewBufferString("")
		resp, err := New().SetDebug(true).outputLogTo(output).SetDebugBodyLimit(debugBodySizeLimit).R().
			SetBody(`{
			"first_name": "Alex",
			"last_name": "`+strings.Repeat("C", int(debugBodySizeLimit))+`C",
			"zip_code": "00001"}`).
			SetBasicAuth("myuser", "mypass").
			Post(formTs.URL + "/profile")
		assertNil(t, err)
		assertNotNil(t, resp)
		assertEqual(t, true, strings.Contains(output.String(), "REQUEST TOO LARGE"))
	})

	t.Run("post string slice with more than 512 bytes data", func(t *testing.T) {
		output := bytes.NewBufferString("")
		resp, err := New().outputLogTo(output).SetDebugBodyLimit(debugBodySizeLimit).R().
			SetDebug(true).
			SetBody([]string{strings.Repeat("hello", debugBodySizeLimit)}).
			SetBasicAuth("myuser", "mypass").
			Post(formTs.URL + "/profile")
		assertNil(t, err)
		assertNotNil(t, resp)
		assertEqual(t, true, strings.Contains(output.String(), "REQUEST TOO LARGE"))
	})

}

func TestPostMapTemporaryRedirect(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl()
	resp, err := c.R().SetBody(map[string]string{"username": "testuser", "password": "testpass"}).
		Post(ts.URL + "/redirect")

	assertNil(t, err)
	assertNotNil(t, resp)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestPostWith204Responset(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl()
	resp, err := c.R().SetBody(map[string]string{"username": "testuser", "password": "testpass"}).
		Post(ts.URL + "/204-response")

	assertNil(t, err)
	assertNotNil(t, resp)
	assertEqual(t, http.StatusNoContent, resp.StatusCode())
}

type brokenReadCloser struct{}

func (b brokenReadCloser) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func (b brokenReadCloser) Close() error {
	return nil
}

func TestPostBodyError(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dcnl()
	resp, err := c.R().SetBody(brokenReadCloser{}).Post(ts.URL + "/redirect")
	assertNotNil(t, err)
	assertEqual(t, "read error", errors.Unwrap(err).Error())
	assertNotNil(t, resp)
}

func TestSetResultMustNotPanicOnNil(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("must not panic")
		}
	}()
	dcnl().R().SetResult(nil)
}

func TestRequestClone(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl()
	parent := c.R()

	// set an non-interface value
	parent.URL = ts.URL
	parent.SetPathParam("name", "parent")
	parent.SetRawPathParam("name", "parent")
	// set http header
	parent.SetHeader("X-Header", "parent")
	// set an interface value
	parent.SetBasicAuth("parent", "")
	parent.bodyBuf = acquireBuffer()
	parent.bodyBuf.WriteString("parent")
	parent.RawRequest = &http.Request{}

	clone := parent.Clone(context.Background())

	// assume parent request is used
	_, _ = parent.Get(ts.URL)

	// update value of non-interface type - change will only happen on clone
	clone.URL = "http://localhost.clone"
	clone.PathParams["name"] = "clone"
	// update value of http header - change will only happen on clone
	clone.SetHeader("X-Header", "clone")
	// update value of interface type - change will only happen on clone
	clone.credentials.Username = "clone"
	clone.bodyBuf.Reset()
	clone.bodyBuf.WriteString("clone")

	// assert non-interface type
	assertEqual(t, "http://localhost.clone", clone.URL)
	assertEqual(t, ts.URL, parent.URL)
	assertEqual(t, "clone", clone.PathParams["name"])
	assertEqual(t, "parent", parent.PathParams["name"])
	// assert http header
	assertEqual(t, "parent", parent.Header.Get("X-Header"))
	assertEqual(t, "clone", clone.Header.Get("X-Header"))
	// assert interface type
	assertEqual(t, "parent", parent.credentials.Username)
	assertEqual(t, "clone", clone.credentials.Username)
	assertEqual(t, "", parent.bodyBuf.String())
	assertEqual(t, "clone", clone.bodyBuf.String())

	// parent request should have raw request while clone should not
	assertNil(t, clone.RawRequest)
	assertNotNil(t, parent.RawRequest)
	assertNotEqual(t, parent.RawRequest, clone.RawRequest)
}

func TestResponseBodyUnlimitedReads(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	user := &credentials{Username: "testuser", Password: "testpass"}

	c := dcnl().
		SetJSONEscapeHTML(false).
		SetResponseBodyUnlimitedReads(true)

	assertEqual(t, true, c.ResponseBodyUnlimitedReads())

	resp, err := c.R().
		SetHeader(hdrContentTypeKey, "application/json; charset=utf-8").
		SetBody(user).
		SetResult(&AuthSuccess{}).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int64(50), resp.Size())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	for i := 1; i <= 5; i++ {
		b, err := io.ReadAll(resp.Body)
		assertNil(t, err)
		assertEqual(t, `{ "id": "success", "message": "login successful" }`, string(b))
	}

	logResponse(t, resp)
}

func TestRequestAllowPayload(t *testing.T) {
	c := dcnl()

	t.Run("default method is GET", func(t *testing.T) {
		r := c.R()
		result1 := r.isPayloadSupported()
		assertEqual(t, false, result1)

		r.SetAllowMethodGetPayload(true)
		result2 := r.isPayloadSupported()
		assertEqual(t, true, result2)
	})

	t.Run("method GET", func(t *testing.T) {
		r := c.R().
			SetMethod(MethodGet)

		result1 := r.isPayloadSupported()
		assertEqual(t, false, result1)

		r.SetAllowMethodGetPayload(true)
		result2 := r.isPayloadSupported()
		assertEqual(t, true, result2)
	})

	t.Run("method POST", func(t *testing.T) {
		r := c.R().
			SetMethod(MethodPost)
		result1 := r.isPayloadSupported()
		assertEqual(t, true, result1)
	})

	t.Run("method PUT", func(t *testing.T) {
		r := c.R().
			SetMethod(MethodPut)
		result1 := r.isPayloadSupported()
		assertEqual(t, true, result1)
	})

	t.Run("method PATCH", func(t *testing.T) {
		r := c.R().
			SetMethod(MethodPatch)
		result1 := r.isPayloadSupported()
		assertEqual(t, true, result1)
	})

	t.Run("method DELETE", func(t *testing.T) {
		r := c.R().
			SetMethod(MethodDelete)

		result1 := r.isPayloadSupported()
		assertEqual(t, false, result1)

		r.SetAllowMethodDeletePayload(true)
		result2 := r.isPayloadSupported()
		assertEqual(t, true, result2)
	})

	t.Run("method HEAD", func(t *testing.T) {
		r := c.R().
			SetMethod(MethodHead)
		result1 := r.isPayloadSupported()
		assertEqual(t, false, result1)
	})

	t.Run("method OPTIONS", func(t *testing.T) {
		r := c.R().
			SetMethod(MethodOptions)
		result1 := r.isPayloadSupported()
		assertEqual(t, false, result1)
	})

	t.Run("method TRACE", func(t *testing.T) {
		r := c.R().
			SetMethod(MethodTrace)
		result1 := r.isPayloadSupported()
		assertEqual(t, false, result1)
	})

}

func TestRequestNoRetryOnNonIdempotentMethod(t *testing.T) {
	ts := createFileUploadServer(t)
	defer ts.Close()

	str := "test"
	buf := []byte(str)

	bufReader := bytes.NewReader(buf)
	bufCpy := make([]byte, len(buf))

	c := dcnl().
		SetTimeout(time.Second * 3).
		AddRetryHooks(
			func(response *Response, _ error) {
				read, err := bufReader.Read(bufCpy)

				assertNil(t, err)
				assertEqual(t, len(buf), read)
				assertEqual(t, str, string(bufCpy))
			},
		)

	req := c.R().
		SetRetryCount(3).
		SetFileReader("name", "filename", bufReader)
	resp, err := req.Post(ts.URL + "/set-reset-multipart-readers-test")

	assertNil(t, err)
	assertEqual(t, 1, resp.Request.Attempt)
	assertEqual(t, 500, resp.StatusCode())
}

func TestRequestContextTimeout(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	t.Run("use client set timeout", func(t *testing.T) {
		c := dcnl().SetTimeout(200 * time.Millisecond)
		assertEqual(t, true, c.Timeout() > 0)

		req := c.R()
		assertEqual(t, true, req.Timeout > 0)

		_, err := req.Get(ts.URL + "/set-timeout-test")

		assertEqual(t, true, errors.Is(err, context.DeadlineExceeded))
	})

	t.Run("use request set timeout", func(t *testing.T) {
		c := dcnl()
		assertEqual(t, true, c.Timeout() == 0)

		_, err := c.R().
			SetTimeout(200 * time.Millisecond).
			Get(ts.URL + "/set-timeout-test")

		assertEqual(t, true, errors.Is(err, context.DeadlineExceeded))
	})

	t.Run("use external context for timeout", func(t *testing.T) {
		ctx, ctxCancelFunc := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer ctxCancelFunc()

		c := dcnl()
		_, err := c.R().
			SetContext(ctx).
			Get(ts.URL + "/set-timeout-test")

		assertEqual(t, true, errors.Is(err, context.DeadlineExceeded))
	})

}

func TestRequestPanicContext(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	c := dcnl()

	//lint:ignore SA1012 test case nil check
	_ = c.R().WithContext(nil)
}

func TestRequestSetResultAndSetOutputFile(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	outputFile := filepath.Join(getTestDataPath(), "login-success.txt")
	defer cleanupFiles(outputFile)

	c := dcnl().SetBaseURL(ts.URL)

	res, err := c.R().
		SetHeader(hdrContentTypeKey, "application/json; charset=utf-8").
		SetBody(&credentials{Username: "testuser", Password: "testpass"}).
		SetResponseBodyUnlimitedReads(true).
		SetResult(&AuthSuccess{}).
		SetOutputFileName(outputFile).
		Post("/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, res.StatusCode())
	assertEqual(t, int64(50), res.Size())

	loginResult := res.Result().(*AuthSuccess)
	assertEqual(t, "success", loginResult.ID)
	assertEqual(t, "login successful", loginResult.Message)

	fileContent, _ := os.ReadFile(outputFile)
	assertEqual(t, `{ "id": "success", "message": "login successful" }`, string(fileContent))
}

func TestRequestBodyContentLength(t *testing.T) {
	ts := createGenericServer(t)
	defer ts.Close()

	c := dcnl().SetBaseURL(ts.URL)

	c.SetRequestMiddlewares(
		PrepareRequestMiddleware,
		func(c *Client, r *Request) error {
			_, found := r.Header[hdrContentLengthKey]
			assertEqual(t, true, found)
			return nil
		},
	)

	buf := bytes.NewBuffer([]byte(`{"content":"json content sending to server"}`))
	res, err := c.R().
		SetHeader(hdrContentTypeKey, "application/json").
		SetContentLength(true).
		SetBody(buf).
		Put("/json")

	assertError(t, err)
	assertEqual(t, http.StatusOK, res.StatusCode())
	assertEqual(t, `{"response":"json response"}`, res.String())
	assertEqual(t, int64(44), res.Request.RawRequest.ContentLength)
}

func TestRequestFuncs(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl().
		SetQueryParam("client_param", "true").
		SetQueryParams(map[string]string{"req_1": "value1", "req_3": "value3"}).
		SetDebug(true)

	addRequestQueryParams := func(page, size int) func(r *Request) *Request {
		return func(r *Request) *Request {
			return r.SetQueryParam("page", strconv.Itoa(page)).
				SetQueryParam("size", strconv.Itoa(size)).
				SetQueryParam("request_no", strconv.Itoa(int(time.Now().Unix())))
		}
	}

	addRequestHeaders := func(r *Request) *Request {
		return r.SetHeader(hdrAcceptKey, "application/json").
			SetHeader(hdrUserAgentKey, "my-client/v1.0")
	}

	resp, err := c.R().
		Funcs(addRequestQueryParams(1, 100), addRequestHeaders).
		SetHeader(hdrUserAgentKey, "Test Custom User agent").
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "HTTP/1.1", resp.Proto())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())
}

func TestHTTPWarnGH970(t *testing.T) {
	lookupText := "Using sensitive credentials in HTTP mode is not secure. Use HTTPS"

	t.Run("SSL used", func(t *testing.T) {
		ts := createAuthServerTLSOptional(t, true)
		defer ts.Close()

		c, lb := dcldb()
		c.SetBaseURL(ts.URL).
			SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

		res, err := c.R().
			SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF").
			Get("/profile")

		assertNil(t, err)
		assertEqual(t, true, strings.Contains(res.String(), "profile fetch successful"))
		assertEqual(t, false, strings.Contains(lb.String(), lookupText))
	})

	t.Run("non-SSL used", func(t *testing.T) {
		ts := createAuthServerTLSOptional(t, false)
		defer ts.Close()

		c, lb := dcldb()
		c.SetBaseURL(ts.URL)

		res, err := c.R().
			SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF").
			Get("/profile")

		assertNil(t, err)
		assertEqual(t, true, strings.Contains(res.String(), "profile fetch successful"))
		assertEqual(t, true, strings.Contains(lb.String(), lookupText))
	})
}

// This test methods exist for test coverage purpose
// to validate the getter and setter
func TestRequestSettingsCoverage(t *testing.T) {
	c := dcnl()

	r1 := c.R()
	assertEqual(t, false, r1.CloseConnection)
	r1.SetCloseConnection(true)
	assertEqual(t, true, r1.CloseConnection)

	r2 := c.R()
	assertEqual(t, false, r2.IsTrace)
	r2.EnableTrace()
	assertEqual(t, true, r2.IsTrace)
	r2.DisableTrace()
	assertEqual(t, false, r2.IsTrace)

	r3 := c.R()
	assertEqual(t, false, r3.ResponseBodyUnlimitedReads)
	r3.SetResponseBodyUnlimitedReads(true)
	assertEqual(t, true, r3.ResponseBodyUnlimitedReads)
	r3.SetResponseBodyUnlimitedReads(false)
	assertEqual(t, false, r3.ResponseBodyUnlimitedReads)

	r4 := c.R()
	assertEqual(t, false, r4.Debug)
	r4.EnableDebug()
	assertEqual(t, true, r4.Debug)
	r4.DisableDebug()
	assertEqual(t, false, r4.Debug)

	r5 := c.R()
	assertEqual(t, true, r5.IsRetryDefaultConditions)
	r5.DisableRetryDefaultConditions()
	assertEqual(t, false, r5.IsRetryDefaultConditions)
	r5.EnableRetryDefaultConditions()
	assertEqual(t, true, r5.IsRetryDefaultConditions)

	r6 := c.R()
	customAuthHeader := "X-Custom-Authorization"
	r6.SetHeaderAuthorizationKey(customAuthHeader)
	assertEqual(t, customAuthHeader, r6.HeaderAuthorizationKey)

	invalidJsonBytes := []byte(`{\" \": "value here"}`)
	result := jsonIndent(invalidJsonBytes)
	assertEqual(t, string(invalidJsonBytes), string(result))

	res := &Response{}
	assertNil(t, res.RedirectHistory())

	defer func() {
		if rec := recover(); rec != nil {
			if err, ok := rec.(error); ok {
				assertEqual(t, true, strings.Contains(err.Error(), "resty: Request.Clone nil context"))
			}
		}
	}()
	rc := c.R()
	//lint:ignore SA1012 test case nil check
	rc2 := rc.Clone(nil)
	assertEqual(t, nil, rc2.ctx)
}

func TestRequestDataRace(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	usersmap := map[string]any{
		"user1": ExampleUser{FirstName: "firstname1", LastName: "lastname1", ZipCode: "10001"},
		"user2": &ExampleUser{FirstName: "firstname2", LastName: "lastname3", ZipCode: "10002"},
		"user3": ExampleUser{FirstName: "firstname3", LastName: "lastname3", ZipCode: "10003"},
	}

	var users []map[string]any
	users = append(users, usersmap)

	c := dcnl().SetBaseURL(ts.URL)

	totalRequests := 4000
	wg := sync.WaitGroup{}
	wg.Add(totalRequests)
	for i := 0; i < totalRequests; i++ {
		if i%100 == 0 {
			time.Sleep(20 * time.Millisecond) // to prevent test server socket exhaustion
		}
		go func() {
			defer wg.Done()
			res, err := c.R().SetContext(context.Background()).SetBody(users).Post("/usersmap")
			assertError(t, err)
			assertEqual(t, http.StatusAccepted, res.StatusCode())
		}()
	}
	wg.Wait()
}
