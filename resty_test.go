// Copyright (c) 2015-2016 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
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

	resp, err := R().
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, true, resp.Body() != nil)
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
}

func TestGetCustomUserAgent(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcr().
		SetHeader(hdrUserAgentKey, "Test Custom User agent").
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
}

func TestGetClientParamRequestParam(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetQueryParam("client_param", "true").
		SetQueryParams(map[string]string{"req_1": "jeeva", "req_3": "jeeva3"}).
		SetDebug(true).
		SetLogger(ioutil.Discard)

	resp, err := c.R().
		SetQueryParams(map[string]string{"req_1": "req 1 value", "req_2": "req 2 value"}).
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		SetHeader(hdrUserAgentKey, "Test Custom User agent").
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
}

func TestGetRelativePath(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetHostURL(ts.URL)

	resp, err := c.R().Get("mypage2")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestGet: text response from mypage2", resp.String())

	logResponse(t, resp)
}

func TestGet400Error(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcr().Get(ts.URL + "/mypage")

	assertError(t, err)
	assertEqual(t, http.StatusBadRequest, resp.StatusCode())
	assertEqual(t, "", resp.String())

	logResponse(t, resp)
}

func TestPostJSONStringSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dc()
	c.SetHeader(hdrContentTypeKey, jsonContentType).
		SetHeaders(map[string]string{hdrUserAgentKey: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) go-resty v0.1", hdrAcceptKey: jsonContentType})

	resp, err := c.R().
		SetBody(`{"username":"testuser", "password":"testpass"}`).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	logResponse(t, resp)
}

func TestPostJSONStringError(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dc()
	c.SetHeader(hdrContentTypeKey, jsonContentType).
		SetHeaders(map[string]string{hdrUserAgentKey: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) go-resty v0.1", hdrAcceptKey: jsonContentType})

	resp, err := c.R().
		SetBody(`{"username":"testuser" "password":"testpass"}`).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusBadRequest, resp.StatusCode())

	logResponse(t, resp)
}

func TestPostJSONBytesSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dc()
	c.SetHeader(hdrContentTypeKey, jsonContentType).
		SetHeaders(map[string]string{hdrUserAgentKey: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) go-resty v0.7", hdrAcceptKey: jsonContentType})

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

	c := dc()
	c.SetHeader(hdrContentTypeKey, jsonContentType)

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

	user := &User{Username: "testuser", Password: "testpass"}

	c := dc()
	resp, err := c.R().
		SetHeader(hdrContentTypeKey, jsonContentType).
		SetBody(user).
		SetResult(&AuthSuccess{}).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	logResponse(t, resp)
}

func TestPostJSONStructInvalidLogin(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dc()
	c.SetDebug(false)

	resp, err := c.R().
		SetHeader(hdrContentTypeKey, jsonContentType).
		SetBody(User{Username: "testuser", Password: "testpass1"}).
		SetError(AuthError{}).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusUnauthorized, resp.StatusCode())
	assertEqual(t, resp.Header().Get("Www-Authenticate"), "Protected Realm")

	t.Logf("Result Error: %q", resp.Error().(*AuthError))

	logResponse(t, resp)
}

func TestPostJSONMapSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dc()
	c.SetDebug(false)

	resp, err := c.R().
		SetBody(map[string]interface{}{"username": "testuser", "password": "testpass"}).
		SetResult(AuthSuccess{}).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	logResponse(t, resp)
}

func TestPostJSONMapInvaildResponseJson(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	resp, err := dclr().
		SetBody(map[string]interface{}{"username": "testuser", "password": "invalidjson"}).
		SetResult(&AuthSuccess{}).
		Post(ts.URL + "/login")

	assertEqual(t, "invalid character '}' looking for beginning of object key string", err.Error())
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	logResponse(t, resp)
}

func TestPostXMLStringSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	c := dc()
	c.SetDebug(false)

	resp, err := c.R().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(`<?xml version="1.0" encoding="UTF-8"?><User><Username>testuser</Username><Password>testpass</Password></User>`).
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	logResponse(t, resp)
}

func TestPostXMLStringError(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	resp, err := dclr().
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

	c := dc()
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

	resp, err := dclr().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(User{Username: "testuser", Password: "testpass"}).
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

	c := dc()
	c.SetError(&AuthError{})

	resp, err := c.R().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(User{Username: "testuser", Password: "testpass1"}).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusUnauthorized, resp.StatusCode())
	assertEqual(t, resp.Header().Get("Www-Authenticate"), "Protected Realm")

	t.Logf("Result Error: %q", resp.Error().(*AuthError))

	logResponse(t, resp)
}

func TestPostXMLStructInvaildResponseXml(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	resp, err := dclr().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(User{Username: "testuser", Password: "invalidxml"}).
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

	_, err := dclr().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(map[string]interface{}{"Username": "testuser", "Password": "testpass"}).
		Post(ts.URL + "/login")

	assertEqual(t, "Unsupported 'Body' type/value", err.Error())
}

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

func TestRequestBasicAuth(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dc()
	c.SetHostURL(ts.URL).
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

func TestRequestBasicAuthFail(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dc()
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

func TestRequestAuthToken(t *testing.T) {
	ts := createAuthServer(t)
	defer ts.Close()

	c := dc()
	c.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF")

	resp, err := c.R().
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF-Request").
		Get(ts.URL + "/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestFormData(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	c := dc()
	c.SetFormData(map[string]string{"zip_code": "00000", "city": "Los Angeles"}).
		SetContentLength(true).
		SetDebug(true).
		SetLogger(ioutil.Discard)

	resp, err := c.R().
		SetFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M", "zip_code": "00001"}).
		SetBasicAuth("myuser", "mypass").
		Post(ts.URL + "/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "Success", resp.String())
}

func TestFormDataDisableWarn(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	c := dc()
	c.SetFormData(map[string]string{"zip_code": "00000", "city": "Los Angeles"}).
		SetContentLength(true).
		SetDebug(true).
		SetLogger(ioutil.Discard).
		SetDisableWarn(true)

	resp, err := c.R().
		SetFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M", "zip_code": "00001"}).
		SetBasicAuth("myuser", "mypass").
		Post(ts.URL + "/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "Success", resp.String())
}

func TestMultiPartUploadFile(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	basePath := getTestDataPath()

	c := dc()
	c.SetFormData(map[string]string{"zip_code": "00001", "city": "Los Angeles"})

	resp, err := c.R().
		SetFile("profile_img", basePath+"/test-img.png").
		SetContentLength(true).
		Post(ts.URL + "/upload")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestMultiPartUploadFileError(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	basePath := getTestDataPath()

	c := dc()
	c.SetFormData(map[string]string{"zip_code": "00001", "city": "Los Angeles"})

	resp, err := c.R().
		SetFile("profile_img", basePath+"/test-img-not-exists.png").
		Post(ts.URL + "/upload")

	if err == nil {
		t.Errorf("Expected [%v], got [%v]", nil, err)
	}
	if resp != nil {
		t.Errorf("Expected [%v], got [%v]", nil, resp)
	}
}

func TestMultiPartUploadFiles(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	basePath := getTestDataPath()

	resp, err := dclr().
		SetFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M"}).
		SetFiles(map[string]string{"profile_img": basePath + "/test-img.png", "notes": basePath + "/text-file.txt"}).
		Post(ts.URL + "/upload")

	responseStr := resp.String()

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, true, strings.Contains(responseStr, "test-img.png"))
	assertEqual(t, true, strings.Contains(responseStr, "text-file.txt"))
}

func TestMultiPartIoReaderFiles(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	basePath := getTestDataPath()
	profileImgBytes, _ := ioutil.ReadFile(basePath + "/test-img.png")
	notesBytes, _ := ioutil.ReadFile(basePath + "/text-file.txt")

	// Just info values
	file := File{
		Name:      "test_file_name.jpg",
		ParamName: "test_param",
		Reader:    bytes.NewBuffer([]byte("test bytes")),
	}
	t.Logf("File Info: %v", file.String())

	resp, err := dclr().
		SetFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M"}).
		SetFileReader("profile_img", "test-img.png", bytes.NewReader(profileImgBytes)).
		SetFileReader("notes", "text-file.txt", bytes.NewReader(notesBytes)).
		Post(ts.URL + "/upload")

	responseStr := resp.String()

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, true, strings.Contains(responseStr, "test-img.png"))
	assertEqual(t, true, strings.Contains(responseStr, "text-file.txt"))
}

func TestMultiPartUploadFileNotOnGetOrDelete(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	basePath := getTestDataPath()

	_, err := dclr().
		SetFile("profile_img", basePath+"/test-img.png").
		Get(ts.URL + "/upload")

	assertEqual(t, "Multipart content is not allowed in HTTP verb [GET]", err.Error())

	_, err = dclr().
		SetFile("profile_img", basePath+"/test-img.png").
		Delete(ts.URL + "/upload")

	assertEqual(t, "Multipart content is not allowed in HTTP verb [DELETE]", err.Error())
}

func TestGetWithCookie(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetHostURL(ts.URL)
	c.SetCookie(&http.Cookie{
		Name:     "go-resty-1",
		Value:    "This is cookie 1 value",
		Path:     "/",
		Domain:   "localhost",
		MaxAge:   36000,
		HttpOnly: true,
		Secure:   false,
	})

	resp, err := c.R().Get("mypage2")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestGet: text response from mypage2", resp.String())

	logResponse(t, resp)
}

func TestGetWithCookies(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	var cookies []*http.Cookie

	cookies = append(cookies, &http.Cookie{
		Name:     "go-resty-1",
		Value:    "This is cookie 1 value",
		Path:     "/",
		Domain:   "sample.com",
		MaxAge:   36000,
		HttpOnly: true,
		Secure:   false,
	})

	cookies = append(cookies, &http.Cookie{
		Name:     "go-resty-2",
		Value:    "This is cookie 2 value",
		Path:     "/",
		Domain:   "sample.com",
		MaxAge:   36000,
		HttpOnly: true,
		Secure:   false,
	})

	c := dc()
	c.SetHostURL(ts.URL).
		SetCookies(cookies)

	resp, err := c.R().Get("mypage2")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestGet: text response from mypage2", resp.String())

	logResponse(t, resp)
}

func TestPutPlainString(t *testing.T) {
	ts := createGenServer(t)
	defer ts.Close()

	resp, err := R().
		SetBody("This is plain text body to server").
		Put(ts.URL + "/plaintext")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestPut: plain text response", resp.String())
}

func TestPutJSONString(t *testing.T) {
	ts := createGenServer(t)
	defer ts.Close()

	DefaultClient.OnBeforeRequest(func(c *Client, r *Request) error {
		r.SetHeader("X-Custom-Request-Middleware", "OnBeforeRequest middleware")
		return nil
	})
	DefaultClient.OnBeforeRequest(func(c *Client, r *Request) error {
		c.SetContentLength(true)
		r.SetHeader("X-ContentLength", "OnBeforeRequest ContentLength set")
		return nil
	})

	DefaultClient.SetDebug(true).SetLogger(ioutil.Discard)

	resp, err := R().
		SetHeaders(map[string]string{hdrContentTypeKey: jsonContentType, hdrAcceptKey: jsonContentType}).
		SetBody(`{"content":"json content sending to server"}`).
		Put(ts.URL + "/json")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, `{"response":"json response"}`, resp.String())
}

func TestPutXMLString(t *testing.T) {
	ts := createGenServer(t)
	defer ts.Close()

	resp, err := R().
		SetHeaders(map[string]string{hdrContentTypeKey: "application/xml", hdrAcceptKey: "application/xml"}).
		SetBody(`<?xml version="1.0" encoding="UTF-8"?><Request>XML Content sending to server</Request>`).
		Put(ts.URL + "/xml")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, `<?xml version="1.0" encoding="UTF-8"?><Response>XML response</Response>`, resp.String())
}

func TestOnBeforeMiddleware(t *testing.T) {
	ts := createGenServer(t)
	defer ts.Close()

	c := dc()
	c.OnBeforeRequest(func(c *Client, r *Request) error {
		r.SetHeader("X-Custom-Request-Middleware", "OnBeforeRequest middleware")
		return nil
	})
	c.OnBeforeRequest(func(c *Client, r *Request) error {
		c.SetContentLength(true)
		r.SetHeader("X-ContentLength", "OnBeforeRequest ContentLength set")
		return nil
	})

	resp, err := c.R().
		SetBody("OnBeforeRequest: This is plain text body to server").
		Put(ts.URL + "/plaintext")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestPut: plain text response", resp.String())
}

func TestOnAfterMiddleware(t *testing.T) {
	ts := createGenServer(t)
	defer ts.Close()

	c := dc()
	c.OnAfterResponse(func(c *Client, res *Response) error {
		t.Logf("Request sent at: %v", res.Request.Time)
		t.Logf("Response Recevied at: %v", res.ReceivedAt())

		return nil
	})

	resp, err := c.R().
		SetBody("OnAfterResponse: This is plain text body to server").
		Put(ts.URL + "/plaintext")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "TestPut: plain text response", resp.String())
}

func TestNoAutoRedirect(t *testing.T) {
	ts := createRedirectServer(t)
	defer ts.Close()

	_, err := R().Get(ts.URL + "/redirect-1")

	assertEqual(t, "Get /redirect-2: Auto redirect is disabled", err.Error())
}

func TestHTTPAutoRedirectUpto10(t *testing.T) {
	ts := createRedirectServer(t)
	defer ts.Close()

	c := dc()
	c.SetHTTPMode()
	_, err := c.R().Get(ts.URL + "/redirect-1")

	assertEqual(t, "Get /redirect-11: Stopped after 10 redirects", err.Error())
}

func TestHostCheckRedirectPolicy(t *testing.T) {
	ts := createRedirectServer(t)
	defer ts.Close()

	c := dc().
		SetRedirectPolicy(DomainCheckRedirectPolicy("127.0.0.1"))

	_, err := c.R().Get(ts.URL + "/redirect-host-check-1")

	assertEqual(t, true, err != nil)
	assertEqual(t, true, strings.Contains(err.Error(), "Redirect is not allowed as per DomainCheckRedirectPolicy"))
}

func TestClientRedirectPolicy(t *testing.T) {
	ts := createRedirectServer(t)
	defer ts.Close()

	c := dc()
	c.SetHTTPMode().
		SetRedirectPolicy(FlexibleRedirectPolicy(20))

	_, err := c.R().Get(ts.URL + "/redirect-1")

	assertEqual(t, "Get /redirect-21: Stopped after 20 redirects", err.Error())
}

func TestClientTimeout(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetHTTPMode().
		SetTimeout(time.Duration(time.Second * 3))

	_, err := c.R().Get(ts.URL + "/set-timeout-test")

	assertEqual(t, true, strings.Contains(err.Error(), "i/o timeout"))
}

func TestClientRetry(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetHTTPMode().
		SetTimeout(time.Duration(time.Second * 3)).
		SetRetryCount(3)

	_, err := c.R().Get(ts.URL + "/set-retrycount-test")

	assertError(t, err)
}

func TestClientTimeoutInternalError(t *testing.T) {
	c := dc()
	c.SetHTTPMode()
	c.SetTimeout(time.Duration(time.Second * 1))

	c.R().Get("http://localhost:9000/set-timeout-test")
}

func TestHeadMethod(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dclr().Head(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestOptionsMethod(t *testing.T) {
	ts := createGenServer(t)
	defer ts.Close()

	resp, err := dclr().Options(ts.URL + "/options")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, resp.Header().Get("Access-Control-Expose-Headers"), "x-go-resty-id")
}

func TestPatchMethod(t *testing.T) {
	ts := createGenServer(t)
	defer ts.Close()

	resp, err := dclr().Patch(ts.URL + "/patch")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	resp.body = nil
	assertEqual(t, "", resp.String())
}

func TestRawFileUploadByBody(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	file, _ := os.Open(getTestDataPath() + "/test-img.png")
	fileBytes, _ := ioutil.ReadAll(file)

	resp, err := dclr().
		SetBody(fileBytes).
		SetContentLength(true).
		SetAuthToken("004DDB79-6801-4587-B976-F093E6AC44FF").
		Put(ts.URL + "/raw-upload")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "image/png", resp.Request.Header.Get(hdrContentTypeKey))
}

func TestProxySetting(t *testing.T) {
	c := dc()

	assertEqual(t, true, c.proxyURL == nil)
	assertEqual(t, true, (c.transport.Proxy == nil))

	c.SetProxy("http://sampleproxy:8888")
	assertEqual(t, true, c.proxyURL != nil)
	assertEqual(t, true, (c.transport.Proxy == nil))

	c.SetProxy("//not.a.user@%66%6f%6f.com:8888")
	assertEqual(t, true, (c.proxyURL == nil))
	assertEqual(t, true, (c.transport.Proxy == nil))

	SetProxy("http://sampleproxy:8888")
	RemoveProxy()
	assertEqual(t, true, (DefaultClient.proxyURL == nil))
	assertEqual(t, true, (DefaultClient.transport.Proxy == nil))
}

func TestClientProxy(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetTimeout(1 * time.Second)
	c.SetProxy("http://sampleproxy:8888")

	resp, err := c.R().Get(ts.URL)
	assertEqual(t, true, resp != nil)
	assertEqual(t, true, err != nil)
}

func TestPerRequestProxy(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetTimeout(1 * time.Second)

	resp, err := c.R().
		SetProxy("http://sampleproxy:8888").
		Get(ts.URL)
	assertEqual(t, true, resp != nil)
	assertEqual(t, true, err != nil)
}

func TestClientProxyOverride(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetTimeout(1 * time.Second)
	c.SetProxy("http://sampleproxy:8888")

	resp, err := c.R().
		SetProxy("http://requestproxy:8888").
		Get(ts.URL)
	assertEqual(t, true, resp != nil)
	assertEqual(t, true, err != nil)
}

func TestClientProxyOverrideError(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetTimeout(1 * time.Second)

	resp, err := c.R().
		SetProxy("//not.a.user@%66%6f%6f.com:8888").
		Get(ts.URL)
	assertEqual(t, false, resp == nil)
	assertEqual(t, true, err == nil)
}

func TestIncorrectURL(t *testing.T) {
	_, err := R().Get("//not.a.user@%66%6f%6f.com/just/a/path/also")
	assertEqual(t, true, strings.Contains(err.Error(), "parse //not.a.user@%66%6f%6f.com/just/a/path/also"))

	c := dc()
	c.SetHostURL("//not.a.user@%66%6f%6f.com")
	_, err1 := c.R().Get("/just/a/path/also")
	assertEqual(t, true, strings.Contains(err1.Error(), "parse //not.a.user@%66%6f%6f.com/just/a/path/also"))
}

func TestDetectContentTypeForPointer(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	user := &User{Username: "testuser", Password: "testpass"}

	resp, err := dclr().
		SetBody(user).
		SetResult(AuthSuccess{}).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	t.Logf("Result Success: %q", resp.Result().(*AuthSuccess))

	logResponse(t, resp)
}

type ExampleUser struct {
	FirstName string `json:"frist_name"`
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

	resp, err := dclr().
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

	usersmap := map[string]interface{}{
		"user1": ExampleUser{FirstName: "firstname1", LastName: "lastname1", ZipCode: "10001"},
		"user2": &ExampleUser{FirstName: "firstname2", LastName: "lastname3", ZipCode: "10002"},
		"user3": ExampleUser{FirstName: "firstname3", LastName: "lastname3", ZipCode: "10003"},
	}

	var users []map[string]interface{}
	users = append(users, usersmap)

	resp, err := dclr().
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

	resp, err := dclr().
		SetBody(users).
		Post(ts.URL + "/users")

	assertError(t, err)
	assertEqual(t, http.StatusAccepted, resp.StatusCode())

	t.Logf("Result Success: %q", resp)

	logResponse(t, resp)
}

func TestMuliParamQueryString(t *testing.T) {
	ts1 := createGetServer(t)
	defer ts1.Close()

	client := dc()
	req1 := client.R()

	client.SetQueryParam("status", "open")

	req1.SetQueryParam("status", "pending").
		SetQueryParam("status", "approved").
		Get(ts1.URL)

	assertEqual(t, true, strings.Contains(req1.URL, "status=pending"))
	assertEqual(t, true, strings.Contains(req1.URL, "status=approved"))

	// because it's removed by key
	assertEqual(t, false, strings.Contains(req1.URL, "status=open"))

	ts2 := createGetServer(t)
	defer ts2.Close()

	req2 := client.R()

	v := url.Values{
		"status": []string{"pending", "approved", "reject"},
	}

	req2.SetMultiValueQueryParams(v).Get(ts2.URL)

	assertEqual(t, true, strings.Contains(req2.URL, "status=pending"))
	assertEqual(t, true, strings.Contains(req2.URL, "status=approved"))
	assertEqual(t, true, strings.Contains(req2.URL, "status=reject"))

	// because it's removed by key
	assertEqual(t, false, strings.Contains(req2.URL, "status=open"))
}

func TestSetQueryStringTypical(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dclr().
		SetQueryString("productId=232&template=fresh-sample&cat=resty&source=google&kw=buy a lot more").
		Get(ts.URL)

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())
}

func TestSetQueryStringTypicalError(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dclr().
		SetQueryString("&%%amp;").
		Get(ts.URL)

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())
}

func TestSetCertificates(t *testing.T) {
	DefaultClient = dc()
	SetCertificates(tls.Certificate{})

	assertEqual(t, 1, len(DefaultClient.transport.TLSClientConfig.Certificates))
}

func TestSetRootCertificate(t *testing.T) {
	DefaultClient = dc()
	SetRootCertificate(getTestDataPath() + "/sample-root.pem")

	assertEqual(t, true, DefaultClient.transport.TLSClientConfig.RootCAs != nil)
}

func TestSetRootCertificateNotExists(t *testing.T) {
	DefaultClient = dc()
	SetRootCertificate(getTestDataPath() + "/not-exists-sample-root.pem")

	assertEqual(t, true, DefaultClient.transport.TLSClientConfig == nil)
}

func TestOutputFileWithBaseDirAndRelativePath(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	DefaultClient = dc()
	SetRedirectPolicy(FlexibleRedirectPolicy(10))
	SetOutputDirectory(getTestDataPath() + "/dir-sample")
	SetDebug(true)

	resp, err := R().
		SetOutput("go-resty/test-img-success.png").
		Get(ts.URL + "/my-image.png")

	assertError(t, err)
	assertEqual(t, true, resp.Size() != 0)
}

func TestOutputFileWithBaseDirError(t *testing.T) {
	c := dc().SetRedirectPolicy(FlexibleRedirectPolicy(10)).
		SetOutputDirectory(getTestDataPath() + `/go-resty\0`)

	_ = c
}

func TestOutputPathDirNotExists(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	DefaultClient = dc()
	SetRedirectPolicy(FlexibleRedirectPolicy(10))
	SetOutputDirectory(getTestDataPath() + "/not-exists-dir")

	resp, err := R().
		SetOutput("test-img-success.png").
		Get(ts.URL + "/my-image.png")

	assertError(t, err)
	assertEqual(t, true, resp.Size() != 0)
}

func TestOutputFileAbsPath(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	_, err := dcr().
		SetOutput(getTestDataPath() + "/go-resty/test-img-success-2.png").
		Get(ts.URL + "/my-image.png")

	assertError(t, err)
}

func TestSetTransport(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()
	DefaultClient = dc()

	transport := &http.Transport{
		// somthing like Proxying to httptest.Server, etc...
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(ts.URL)
		},
	}
	SetTransport(transport)

	assertEqual(t, true, DefaultClient.transport != nil)
}

func TestSetScheme(t *testing.T) {
	DefaultClient = dc()

	SetScheme("http")

	assertEqual(t, true, DefaultClient.scheme == "http")
}

func TestClientOptions(t *testing.T) {
	SetHTTPMode().SetContentLength(true)
	assertEqual(t, Mode(), "http")
	assertEqual(t, DefaultClient.setContentLength, true)

	SetRESTMode()
	assertEqual(t, Mode(), "rest")

	SetHostURL("http://httpbin.org")
	assertEqual(t, "http://httpbin.org", DefaultClient.HostURL)

	SetHeader(hdrContentTypeKey, jsonContentType)
	SetHeaders(map[string]string{
		hdrUserAgentKey: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) go-resty v0.1",
		"X-Request-Id":  strconv.FormatInt(time.Now().UnixNano(), 10),
	})
	assertEqual(t, jsonContentType, DefaultClient.Header.Get(hdrContentTypeKey))

	SetCookie(&http.Cookie{
		Name:     "default-cookie",
		Value:    "This is cookie default-cookie value",
		Path:     "/",
		Domain:   "localhost",
		MaxAge:   36000,
		HttpOnly: true,
		Secure:   false,
	})
	assertEqual(t, "default-cookie", DefaultClient.Cookies[0].Name)

	var cookies []*http.Cookie
	cookies = append(cookies, &http.Cookie{
		Name:  "default-cookie-1",
		Value: "This is default-cookie 1 value",
		Path:  "/",
	})
	cookies = append(cookies, &http.Cookie{
		Name:  "default-cookie-2",
		Value: "This is default-cookie 2 value",
		Path:  "/",
	})
	SetCookies(cookies)
	assertEqual(t, "default-cookie-1", DefaultClient.Cookies[1].Name)
	assertEqual(t, "default-cookie-2", DefaultClient.Cookies[2].Name)

	SetQueryParam("test_param_1", "Param_1")
	SetQueryParams(map[string]string{"test_param_2": "Param_2", "test_param_3": "Param_3"})
	assertEqual(t, "Param_3", DefaultClient.QueryParam.Get("test_param_3"))

	rTime := strconv.FormatInt(time.Now().UnixNano(), 10)
	SetFormData(map[string]string{"r_time": rTime})
	assertEqual(t, rTime, DefaultClient.FormData.Get("r_time"))

	SetBasicAuth("myuser", "mypass")
	assertEqual(t, "myuser", DefaultClient.UserInfo.Username)

	SetAuthToken("AC75BD37F019E08FBC594900518B4F7E")
	assertEqual(t, "AC75BD37F019E08FBC594900518B4F7E", DefaultClient.Token)

	SetDisableWarn(true)
	assertEqual(t, DefaultClient.DisableWarn, true)

	SetRetryCount(3)
	assertEqual(t, 3, DefaultClient.RetryCount)

	err := &AuthError{}
	SetError(err)
	if reflect.TypeOf(err) == DefaultClient.Error {
		t.Error("SetError failed")
	}

	SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	assertEqual(t, true, DefaultClient.transport.TLSClientConfig.InsecureSkipVerify)

	OnBeforeRequest(func(c *Client, r *Request) error {
		c.Log.Println("I'm in Request middleware")
		return nil // if it success
	})
	OnAfterResponse(func(c *Client, r *Response) error {
		c.Log.Println("I'm in Response middleware")
		return nil // if it success
	})

	SetTimeout(time.Duration(5 * time.Second))
	SetRedirectPolicy(FlexibleRedirectPolicy(10), func(req *http.Request, via []*http.Request) error {
		return errors.New("sample test redirect")
	})
	SetContentLength(true)

	SetDebug(true)
	assertEqual(t, DefaultClient.Debug, true)

	SetScheme("http")
	assertEqual(t, DefaultClient.scheme, "http")

	SetCloseConnection(true)
	assertEqual(t, DefaultClient.closeConnection, true)

	SetLogger(ioutil.Discard)
}

func getTestDataPath() string {
	pwd, _ := os.Getwd()
	return pwd + "/test-data"
}

// Used for retry testing...
var attempt int

func createGetServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)

		if r.Method == GET {
			if r.URL.Path == "/" {
				w.Write([]byte("TestGet: text response"))
			} else if r.URL.Path == "/mypage" {
				w.WriteHeader(http.StatusBadRequest)
			} else if r.URL.Path == "/mypage2" {
				w.Write([]byte("TestGet: text response from mypage2"))
			} else if r.URL.Path == "/set-retrycount-test" {
				attempt++
				if attempt != 3 {
					time.Sleep(time.Second * 6)
				}
				w.Write([]byte("TestClientRetry page"))
			} else if r.URL.Path == "/set-timeout-test" {
				time.Sleep(time.Second * 6)
				w.Write([]byte("TestClientTimeout page"))

			} else if r.URL.Path == "/my-image.png" {
				fileBytes, _ := ioutil.ReadFile(getTestDataPath() + "/test-img.png")
				w.Header().Set("Content-Type", "image/png")
				w.Header().Set("Content-Length", strconv.Itoa(len(fileBytes)))
				w.Write(fileBytes)
			}
		}
	})

	return ts
}

func handleLoginEndpoint(t *testing.T, w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/login" {
		user := &User{}

		// JSON
		if IsJSONType(r.Header.Get(hdrContentTypeKey)) {
			jd := json.NewDecoder(r.Body)
			err := jd.Decode(user)
			w.Header().Set(hdrContentTypeKey, jsonContentType)
			if err != nil {
				t.Logf("Error: %#v", err)
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{ "id": "bad_request", "message": "Unable to read user info" }`))
				return
			}

			if user.Username == "testuser" && user.Password == "testpass" {
				w.Write([]byte(`{ "id": "success", "message": "login successful" }`))
			} else if user.Username == "testuser" && user.Password == "invalidjson" {
				w.Write([]byte(`{ "id": "success", "message": "login successful", }`))
			} else {
				w.Header().Set("Www-Authenticate", "Protected Realm")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{ "id": "unauthorized", "message": "Invalid credentials" }`))
			}

			return
		}

		// XML
		if IsXMLType(r.Header.Get(hdrContentTypeKey)) {
			xd := xml.NewDecoder(r.Body)
			err := xd.Decode(user)

			w.Header().Set(hdrContentTypeKey, "application/xml")
			if err != nil {
				t.Logf("Error: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
				w.Write([]byte(`<AuthError><Id>bad_request</Id><Message>Unable to read user info</Message></AuthError>`))
				return
			}

			if user.Username == "testuser" && user.Password == "testpass" {
				w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
				w.Write([]byte(`<AuthSuccess><Id>success</Id><Message>login successful</Message></AuthSuccess>`))
			} else if user.Username == "testuser" && user.Password == "invalidxml" {
				w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
				w.Write([]byte(`<AuthSuccess><Id>success</Id><Message>login successful</AuthSuccess>`))
			} else {
				w.Header().Set("Www-Authenticate", "Protected Realm")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
				w.Write([]byte(`<AuthError><Id>unauthorized</Id><Message>Invalid credentials</Message></AuthError>`))
			}

			return
		}
	}
}

func handleUsersEndpoint(t *testing.T, w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/users" {
		// JSON
		if IsJSONType(r.Header.Get(hdrContentTypeKey)) {
			var users []ExampleUser
			jd := json.NewDecoder(r.Body)
			err := jd.Decode(&users)
			w.Header().Set(hdrContentTypeKey, jsonContentType)
			if err != nil {
				t.Logf("Error: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{ "id": "bad_request", "message": "Unable to read user info" }`))
				return
			}

			// logic check, since we are excepting to reach 3 records
			if len(users) != 3 {
				t.Log("Error: Excepted count of 3 records")
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{ "id": "bad_request", "message": "Expected record count doesn't match" }`))
				return
			}

			eu := users[2]
			if eu.FirstName == "firstname3" && eu.ZipCode == "10003" {
				w.WriteHeader(http.StatusAccepted)
				w.Write([]byte(`{ "message": "Accepted" }`))
			}

			return
		}
	}
}

func createPostServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)
		t.Logf("Content-Type: %v", r.Header.Get(hdrContentTypeKey))

		if r.Method == POST {
			handleLoginEndpoint(t, w, r)

			handleUsersEndpoint(t, w, r)

			if r.URL.Path == "/usersmap" {
				// JSON
				if IsJSONType(r.Header.Get(hdrContentTypeKey)) {
					var users []map[string]interface{}
					jd := json.NewDecoder(r.Body)
					err := jd.Decode(&users)
					w.Header().Set(hdrContentTypeKey, jsonContentType)
					if err != nil {
						t.Logf("Error: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						w.Write([]byte(`{ "id": "bad_request", "message": "Unable to read user info" }`))
						return
					}

					// logic check, since we are excepting to reach 1 map records
					if len(users) != 1 {
						t.Log("Error: Excepted count of 1 map records")
						w.WriteHeader(http.StatusBadRequest)
						w.Write([]byte(`{ "id": "bad_request", "message": "Expected record count doesn't match" }`))
						return
					}

					w.WriteHeader(http.StatusAccepted)
					w.Write([]byte(`{ "message": "Accepted" }`))

					return
				}
			}
		}
	})

	return ts
}

func createFormPostServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)
		t.Logf("Content-Type: %v", r.Header.Get(hdrContentTypeKey))

		if r.Method == POST {
			r.ParseMultipartForm(10e6)

			if r.URL.Path == "/profile" {
				t.Logf("FirstName: %v", r.FormValue("first_name"))
				t.Logf("LastName: %v", r.FormValue("last_name"))
				t.Logf("City: %v", r.FormValue("city"))
				t.Logf("Zip Code: %v", r.FormValue("zip_code"))

				w.Write([]byte("Success"))
				return
			} else if r.URL.Path == "/upload" {
				t.Logf("FirstName: %v", r.FormValue("first_name"))
				t.Logf("LastName: %v", r.FormValue("last_name"))

				targetPath := getTestDataPath() + "/upload"
				os.MkdirAll(targetPath, 0700)

				for _, fhdrs := range r.MultipartForm.File {
					for _, hdr := range fhdrs {
						t.Logf("Name: %v", hdr.Filename)
						t.Logf("Header: %v", hdr.Header)
						dotPos := strings.LastIndex(hdr.Filename, ".")

						fname := fmt.Sprintf("%s-%v%s", hdr.Filename[:dotPos], time.Now().Unix(), hdr.Filename[dotPos:])
						t.Logf("Write name: %v", fname)

						infile, _ := hdr.Open()
						f, err := os.OpenFile(targetPath+"/"+fname, os.O_WRONLY|os.O_CREATE, 0666)
						if err != nil {
							t.Logf("Error: %v", err)
							return
						}
						defer f.Close()
						io.Copy(f, infile)

						w.Write([]byte(fmt.Sprintf("File: %v, uploaded as: %v\n", hdr.Filename, fname)))
					}
				}

				return
			}
		}
	})

	return ts
}

func createAuthServer(t *testing.T) *httptest.Server {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)
		t.Logf("Content-Type: %v", r.Header.Get(hdrContentTypeKey))

		if r.Method == GET {
			if r.URL.Path == "/profile" {
				// 004DDB79-6801-4587-B976-F093E6AC44FF
				auth := r.Header.Get("Authorization")
				t.Logf("Bearer Auth: %v", auth)

				w.Header().Set(hdrContentTypeKey, jsonContentType)

				if !strings.HasPrefix(auth, "Bearer ") {
					w.Header().Set("Www-Authenticate", "Protected Realm")
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{ "id": "unauthorized", "message": "Invalid credentials" }`))

					return
				}

				if auth[7:] == "004DDB79-6801-4587-B976-F093E6AC44FF" || auth[7:] == "004DDB79-6801-4587-B976-F093E6AC44FF-Request" {
					w.Write([]byte(`{ "id": "success", "message": "login successful" }`))
				}
			}

			return
		}

		if r.Method == POST {
			if r.URL.Path == "/login" {
				auth := r.Header.Get("Authorization")
				t.Logf("Basic Auth: %v", auth)

				w.Header().Set(hdrContentTypeKey, jsonContentType)

				password, err := base64.StdEncoding.DecodeString(auth[6:])
				if err != nil || string(password) != "myuser:basicauth" {
					w.Header().Set("Www-Authenticate", "Protected Realm")
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{ "id": "unauthorized", "message": "Invalid credentials" }`))

					return
				}

				w.Write([]byte(`{ "id": "success", "message": "login successful" }`))
			}

			return
		}
	}))

	return ts
}

func createGenServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)

		if r.Method == PUT {
			if r.URL.Path == "/plaintext" {
				w.Write([]byte("TestPut: plain text response"))
			} else if r.URL.Path == "/json" {
				w.Header().Set(hdrContentTypeKey, jsonContentType)
				w.Write([]byte(`{"response":"json response"}`))
			} else if r.URL.Path == "/xml" {
				w.Header().Set(hdrContentTypeKey, "application/xml")
				w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Response>XML response</Response>`))
			}
		}

		if r.Method == OPTIONS && r.URL.Path == "/options" {
			w.Header().Set("Access-Control-Allow-Origin", "localhost")
			w.Header().Set("Access-Control-Allow-Methods", "PUT, PATCH")
			w.Header().Set("Access-Control-Expose-Headers", "x-go-resty-id")
			w.WriteHeader(http.StatusOK)
		}

		if r.Method == PATCH && r.URL.Path == "/patch" {
			w.WriteHeader(http.StatusOK)
		}
	})

	return ts
}

func createRedirectServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)

		if r.Method == GET {
			if strings.HasPrefix(r.URL.Path, "/redirect-host-check-") {
				cntStr := strings.SplitAfter(r.URL.Path, "-")[3]
				cnt, _ := strconv.Atoi(cntStr)

				if cnt != 7 { // Testing hard stop via logical
					if cnt >= 5 {
						http.Redirect(w, r, "http://httpbin.org/get", http.StatusTemporaryRedirect)
					} else {
						http.Redirect(w, r, fmt.Sprintf("/redirect-host-check-%d", (cnt+1)), http.StatusTemporaryRedirect)
					}
				}
			} else if strings.HasPrefix(r.URL.Path, "/redirect-") {
				cntStr := strings.SplitAfter(r.URL.Path, "-")[1]
				cnt, _ := strconv.Atoi(cntStr)

				http.Redirect(w, r, fmt.Sprintf("/redirect-%d", (cnt+1)), http.StatusTemporaryRedirect)
			}
		}
	})

	return ts
}

func createTestServer(fn func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(fn))
}

func dc() *Client {
	DefaultClient = New()
	return DefaultClient
}

func dcr() *Request {
	return dc().R()
}

func dclr() *Request {
	c := dc()
	c.SetDebug(true)
	c.SetLogger(ioutil.Discard)

	return c.R()
}

func assertError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Error occurred [%v]", err)
	}
}

func assertEqual(t *testing.T, e, g interface{}) (r bool) {
	r = compare(e, g)
	if !r {
		t.Errorf("Expected [%v], got [%v]", e, g)
	}

	return
}

func assertNotEqual(t *testing.T, e, g interface{}) (r bool) {
	if compare(e, g) {
		t.Errorf("Expected [%v], got [%v]", e, g)
	} else {
		r = true
	}

	return
}

func compare(e, g interface{}) (r bool) {
	ev := reflect.ValueOf(e)
	gv := reflect.ValueOf(g)

	if ev.Kind() != gv.Kind() {
		return
	}

	switch ev.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		r = (ev.Int() == gv.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		r = (ev.Uint() == gv.Uint())
	case reflect.Float32, reflect.Float64:
		r = (ev.Float() == gv.Float())
	case reflect.String:
		r = (ev.String() == gv.String())
	case reflect.Bool:
		r = (ev.Bool() == gv.Bool())
	}

	return
}

func logResponse(t *testing.T, resp *Response) {
	t.Logf("Response Status: %v", resp.Status())
	t.Logf("Response Time: %v", resp.Time())
	t.Logf("Response Headers: %v", resp.Header())
	t.Logf("Response Cookies: %v", resp.Cookies())
	t.Logf("Response Body: %v", resp)
}
