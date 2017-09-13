// Copyright (c) 2015-2017 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
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
	assertNotNil(t, resp.Body())
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

func TestPostJSONMapInvalidResponseJson(t *testing.T) {
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

func TestPostXMLStructInvalidResponseXml(t *testing.T) {
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

func TestMultiValueFormData(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	v := url.Values{
		"search_criteria": []string{"book", "glass", "pencil"},
	}

	c := dc()
	c.SetContentLength(true).
		SetDebug(true).
		SetLogger(ioutil.Discard)

	resp, err := c.R().
		SetMultiValueFormData(v).
		Post(ts.URL + "/search")

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
	defer cleaupFiles("test-data/upload")

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
	defer cleaupFiles("test-data/upload")

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
	defer cleaupFiles("test-data/upload")

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
	defer cleaupFiles("test-data/upload")

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
	defer cleaupFiles("test-data/upload")

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

func TestNoAutoRedirect(t *testing.T) {
	ts := createRedirectServer(t)
	defer ts.Close()

	_, err := R().Get(ts.URL + "/redirect-1")

	assertEqual(t, "Get /redirect-2: Auto redirect is disabled", err.Error())
}

func TestHTTPAutoRedirectUpTo10(t *testing.T) {
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

	assertNotNil(t, err)
	assertEqual(t, true, strings.Contains(err.Error(), "Redirect is not allowed as per DomainCheckRedirectPolicy"))
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

	transport, err := c.getTransport()

	assertNil(t, err)

	assertEqual(t, false, c.IsProxySet())
	assertNil(t, transport.Proxy)

	c.SetProxy("http://sampleproxy:8888")
	assertEqual(t, true, c.IsProxySet())
	assertNotNil(t, transport.Proxy)

	c.SetProxy("//not.a.user@%66%6f%6f.com:8888")
	assertEqual(t, false, c.IsProxySet())
	assertNil(t, transport.Proxy)

	SetProxy("http://sampleproxy:8888")
	assertEqual(t, true, IsProxySet())
	RemoveProxy()
	assertNil(t, DefaultClient.proxyURL)
	assertNil(t, transport.Proxy)
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

func TestMultiParamsQueryString(t *testing.T) {
	ts1 := createGetServer(t)
	defer ts1.Close()

	client := dc()
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

	_, _ = req2.SetMultiValueQueryParams(v).Get(ts2.URL)

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

	resp, err = dclr().
		SetQueryString("&%%amp;").
		Get(ts.URL)

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())
}

func TestOutputFileWithBaseDirAndRelativePath(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()
	defer cleaupFiles("test-data/dir-sample")

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
	defer cleaupFiles("test-data/not-exists-dir")

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
	defer cleaupFiles("test-data/go-resty")

	_, err := dcr().
		SetOutput(getTestDataPath() + "/go-resty/test-img-success-2.png").
		Get(ts.URL + "/my-image.png")

	assertError(t, err)
}

func TestContextInternal(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	r := R().
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10))

	if r.isContextCancelledIfAvailable() {
		t.Error("isContextCancelledIfAvailable != false for vanilla R()")
	}
	r.addContextIfAvailable()

	resp, err := r.Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestSRV(t *testing.T) {
	c := dc().
		SetRedirectPolicy(FlexibleRedirectPolicy(20)).
		SetScheme("http")

	r := c.R().
		SetSRV(&SRVRecord{"xmpp-server", "google.com"})

	assertEqual(t, "xmpp-server", r.SRV.Service)
	assertEqual(t, "google.com", r.SRV.Domain)

	resp, err := r.Get("/")
	assertError(t, err)
	assertNotNil(t, resp)
	if resp != nil {
		assertEqual(t, http.StatusOK, resp.StatusCode())
	}
}

func TestSRVInvalidService(t *testing.T) {
	_, err := R().
		SetSRV(&SRVRecord{"nonexistantservice", "sampledomain"}).
		Get("/")

	assertNotNil(t, err)
	assertEqual(t, true, strings.Contains(err.Error(), "no such host"))
}

func TestDeprecatedCodeCovergae(t *testing.T) {
	var user1 User
	err := Unmarshal("application/json",
		[]byte(`{"username":"testuser", "password":"testpass"}`), &user1)
	assertError(t, err)
	assertEqual(t, "testuser", user1.Username)
	assertEqual(t, "testpass", user1.Password)

	var user2 User
	err = Unmarshal("application/xml",
		[]byte(`<?xml version="1.0" encoding="UTF-8"?><User><Username>testuser</Username><Password>testpass</Password></User>`),
		&user2)
	assertError(t, err)
	assertEqual(t, "testuser", user1.Username)
	assertEqual(t, "testpass", user1.Password)
}

func TestRequestDoNotParseResponse(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dc().R().
		SetDoNotParseResponse(true).
		SetQueryParam("request_no", strconv.FormatInt(time.Now().Unix(), 10)).
		Get(ts.URL + "/")

	assertError(t, err)

	buf := acquireBuffer()
	defer releaseBuffer(buf)
	_, _ = io.Copy(buf, resp.RawBody())

	assertEqual(t, "TestGet: text response", buf.String())
	_ = resp.RawBody().Close()

	// Manually setting RawResponse as nil
	resp, err = dc().R().
		SetDoNotParseResponse(true).
		Get(ts.URL + "/")

	assertError(t, err)

	resp.RawResponse = nil
	assertNil(t, resp.RawBody())

	// just set test part
	SetDoNotParseResponse(true)
	assertEqual(t, true, DefaultClient.notParseResponse)
	SetDoNotParseResponse(false)
}

type noCtTest struct {
	Response string `json:"response"`
}

func TestRequestExpectContentTypeTest(t *testing.T) {
	ts := createGenServer(t)
	defer ts.Close()

	c := dc()
	resp, err := c.R().
		SetResult(noCtTest{}).
		ExpectContentType("application/json").
		Get(ts.URL + "/json-no-set")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertNotNil(t, resp.Result())
	assertEqual(t, "json response no content type set", resp.Result().(*noCtTest).Response)

	assertEqual(t, "", firstNonEmpty("", ""))
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Testing Unexported methods
//___________________________________

func getTestDataPath() string {
	pwd, _ := os.Getwd()
	return pwd + "/test-data"
}

func createGetServer(t *testing.T) *httptest.Server {
	var attempt int32
	var sequence int32
	var lastRequest time.Time
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)

		if r.Method == MethodGet {
			if r.URL.Path == "/" {
				_, _ = w.Write([]byte("TestGet: text response"))
			} else if r.URL.Path == "/mypage" {
				w.WriteHeader(http.StatusBadRequest)
			} else if r.URL.Path == "/mypage2" {
				_, _ = w.Write([]byte("TestGet: text response from mypage2"))
			} else if r.URL.Path == "/set-retrycount-test" {
				attp := atomic.AddInt32(&attempt, 1)
				if attp <= 3 {
					time.Sleep(time.Second * 6)
				}
				_, _ = w.Write([]byte("TestClientRetry page"))
			} else if r.URL.Path == "/set-retrywaittime-test" {
				// Returns time.Duration since last request here
				// or 0 for the very first request
				if atomic.LoadInt32(&attempt) == 0 {
					lastRequest = time.Now()
					_, _ = fmt.Fprint(w, "0")
				} else {
					now := time.Now()
					sinceLastRequest := now.Sub(lastRequest)
					lastRequest = now
					_, _ = fmt.Fprintf(w, "%d", uint64(sinceLastRequest))
				}
				atomic.AddInt32(&attempt, 1)
			} else if r.URL.Path == "/set-timeout-test-with-sequence" {
				seq := atomic.AddInt32(&sequence, 1)
				time.Sleep(time.Second * 2)
				_, _ = fmt.Fprintf(w, "%d", seq)
			} else if r.URL.Path == "/set-timeout-test" {
				time.Sleep(time.Second * 6)
				_, _ = w.Write([]byte("TestClientTimeout page"))

			} else if r.URL.Path == "/my-image.png" {
				fileBytes, _ := ioutil.ReadFile(getTestDataPath() + "/test-img.png")
				w.Header().Set("Content-Type", "image/png")
				w.Header().Set("Content-Length", strconv.Itoa(len(fileBytes)))
				_, _ = w.Write(fileBytes)
			} else if r.URL.Path == "/get-method-payload-test" {
				body, err := ioutil.ReadAll(r.Body)
				if err != nil {
					t.Errorf("Error: could not read get body: %s", err.Error())
				}
				_, _ = w.Write(body)
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
				_, _ = w.Write([]byte(`{ "id": "bad_request", "message": "Unable to read user info" }`))
				return
			}

			if user.Username == "testuser" && user.Password == "testpass" {
				_, _ = w.Write([]byte(`{ "id": "success", "message": "login successful" }`))
			} else if user.Username == "testuser" && user.Password == "invalidjson" {
				_, _ = w.Write([]byte(`{ "id": "success", "message": "login successful", }`))
			} else {
				w.Header().Set("Www-Authenticate", "Protected Realm")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{ "id": "unauthorized", "message": "Invalid credentials" }`))
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
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
				_, _ = w.Write([]byte(`<AuthError><Id>bad_request</Id><Message>Unable to read user info</Message></AuthError>`))
				return
			}

			if user.Username == "testuser" && user.Password == "testpass" {
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
				_, _ = w.Write([]byte(`<AuthSuccess><Id>success</Id><Message>login successful</Message></AuthSuccess>`))
			} else if user.Username == "testuser" && user.Password == "invalidxml" {
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
				_, _ = w.Write([]byte(`<AuthSuccess><Id>success</Id><Message>login successful</AuthSuccess>`))
			} else {
				w.Header().Set("Www-Authenticate", "Protected Realm")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
				_, _ = w.Write([]byte(`<AuthError><Id>unauthorized</Id><Message>Invalid credentials</Message></AuthError>`))
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
				_, _ = w.Write([]byte(`{ "id": "bad_request", "message": "Unable to read user info" }`))
				return
			}

			// logic check, since we are excepting to reach 3 records
			if len(users) != 3 {
				t.Log("Error: Excepted count of 3 records")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{ "id": "bad_request", "message": "Expected record count doesn't match" }`))
				return
			}

			eu := users[2]
			if eu.FirstName == "firstname3" && eu.ZipCode == "10003" {
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{ "message": "Accepted" }`))
			}

			return
		}
	}
}

func createPostServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)
		t.Logf("RawQuery: %v", r.URL.RawQuery)
		t.Logf("Content-Type: %v", r.Header.Get(hdrContentTypeKey))

		if r.Method == MethodPost {
			handleLoginEndpoint(t, w, r)

			handleUsersEndpoint(t, w, r)

			if r.URL.Path == "/usersmap" {
				// JSON
				if IsJSONType(r.Header.Get(hdrContentTypeKey)) {
					if r.URL.Query().Get("status") == "500" {
						body, err := ioutil.ReadAll(r.Body)
						if err != nil {
							t.Errorf("Error: could not read post body: %s", err.Error())
						}
						t.Logf("Got query param: status=500 so we're returning the post body as response and a 500 status code. body: %s", string(body))
						w.Header().Set(hdrContentTypeKey, jsonContentType)
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = w.Write(body)
						return
					}

					var users []map[string]interface{}
					jd := json.NewDecoder(r.Body)
					err := jd.Decode(&users)
					w.Header().Set(hdrContentTypeKey, jsonContentType)
					if err != nil {
						t.Logf("Error: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{ "id": "bad_request", "message": "Unable to read user info" }`))
						return
					}

					// logic check, since we are excepting to reach 1 map records
					if len(users) != 1 {
						t.Log("Error: Excepted count of 1 map records")
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{ "id": "bad_request", "message": "Expected record count doesn't match" }`))
						return
					}

					w.WriteHeader(http.StatusAccepted)
					_, _ = w.Write([]byte(`{ "message": "Accepted" }`))

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

		if r.Method == MethodPost {
			_ = r.ParseMultipartForm(10e6)

			if r.URL.Path == "/profile" {
				t.Logf("FirstName: %v", r.FormValue("first_name"))
				t.Logf("LastName: %v", r.FormValue("last_name"))
				t.Logf("City: %v", r.FormValue("city"))
				t.Logf("Zip Code: %v", r.FormValue("zip_code"))

				_, _ = w.Write([]byte("Success"))
				return
			} else if r.URL.Path == "/search" {
				formEncodedData := r.Form.Encode()
				t.Logf("Recevied Form Encoded values: %v", formEncodedData)

				assertEqual(t, true, strings.Contains(formEncodedData, "search_criteria=pencil"))
				assertEqual(t, true, strings.Contains(formEncodedData, "search_criteria=glass"))

				_, _ = w.Write([]byte("Success"))
				return
			} else if r.URL.Path == "/upload" {
				t.Logf("FirstName: %v", r.FormValue("first_name"))
				t.Logf("LastName: %v", r.FormValue("last_name"))

				targetPath := getTestDataPath() + "/upload"
				_ = os.MkdirAll(targetPath, 0700)

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
						defer func() {
							_ = f.Close()
						}()
						_, _ = io.Copy(f, infile)

						_, _ = w.Write([]byte(fmt.Sprintf("File: %v, uploaded as: %v\n", hdr.Filename, fname)))
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

		if r.Method == MethodGet {
			if r.URL.Path == "/profile" {
				// 004DDB79-6801-4587-B976-F093E6AC44FF
				auth := r.Header.Get("Authorization")
				t.Logf("Bearer Auth: %v", auth)

				w.Header().Set(hdrContentTypeKey, jsonContentType)

				if !strings.HasPrefix(auth, "Bearer ") {
					w.Header().Set("Www-Authenticate", "Protected Realm")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{ "id": "unauthorized", "message": "Invalid credentials" }`))

					return
				}

				if auth[7:] == "004DDB79-6801-4587-B976-F093E6AC44FF" || auth[7:] == "004DDB79-6801-4587-B976-F093E6AC44FF-Request" {
					_, _ = w.Write([]byte(`{ "id": "success", "message": "login successful" }`))
				}
			}

			return
		}

		if r.Method == MethodPost {
			if r.URL.Path == "/login" {
				auth := r.Header.Get("Authorization")
				t.Logf("Basic Auth: %v", auth)

				w.Header().Set(hdrContentTypeKey, jsonContentType)

				password, err := base64.StdEncoding.DecodeString(auth[6:])
				if err != nil || string(password) != "myuser:basicauth" {
					w.Header().Set("Www-Authenticate", "Protected Realm")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{ "id": "unauthorized", "message": "Invalid credentials" }`))

					return
				}

				_, _ = w.Write([]byte(`{ "id": "success", "message": "login successful" }`))
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

		if r.Method == MethodGet {
			if r.URL.Path == "/json-no-set" {
				// Set empty header value for testing, since Go server sets to
				// text/plain; charset=utf-8
				w.Header().Set(hdrContentTypeKey, "")
				_, _ = w.Write([]byte(`{"response":"json response no content type set"}`))
			}
			return
		}

		if r.Method == MethodPut {
			if r.URL.Path == "/plaintext" {
				_, _ = w.Write([]byte("TestPut: plain text response"))
			} else if r.URL.Path == "/json" {
				w.Header().Set(hdrContentTypeKey, jsonContentType)
				_, _ = w.Write([]byte(`{"response":"json response"}`))
			} else if r.URL.Path == "/xml" {
				w.Header().Set(hdrContentTypeKey, "application/xml")
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Response>XML response</Response>`))
			}
			return
		}

		if r.Method == MethodOptions && r.URL.Path == "/options" {
			w.Header().Set("Access-Control-Allow-Origin", "localhost")
			w.Header().Set("Access-Control-Allow-Methods", "PUT, PATCH")
			w.Header().Set("Access-Control-Expose-Headers", "x-go-resty-id")
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == MethodPatch && r.URL.Path == "/patch" {
			w.WriteHeader(http.StatusOK)
			return
		}
	})

	return ts
}

func createRedirectServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)

		if r.Method == MethodGet {
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

func assertNil(t *testing.T, v interface{}) {
	if !isNil(v) {
		t.Errorf("[%v] was expected to be nil", v)
	}
}

func assertNotNil(t *testing.T, v interface{}) {
	if isNil(v) {
		t.Errorf("[%v] was expected to be non-nil", v)
	}
}

func assertError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Error occurred [%v]", err)
	}
}

func assertEqual(t *testing.T, e, g interface{}) (r bool) {
	if !equal(e, g) {
		t.Errorf("Expected [%v], got [%v]", e, g)
	}

	return
}

func assertNotEqual(t *testing.T, e, g interface{}) (r bool) {
	if equal(e, g) {
		t.Errorf("Expected [%v], got [%v]", e, g)
	} else {
		r = true
	}

	return
}

func equal(expected, got interface{}) bool {
	return reflect.DeepEqual(expected, got)
}

func isNil(v interface{}) bool {
	if v == nil {
		return true
	}

	rv := reflect.ValueOf(v)
	kind := rv.Kind()
	if kind >= reflect.Chan && kind <= reflect.Slice && rv.IsNil() {
		return true
	}

	return false
}

func logResponse(t *testing.T, resp *Response) {
	t.Logf("Response Status: %v", resp.Status())
	t.Logf("Response Time: %v", resp.Time())
	t.Logf("Response Headers: %v", resp.Header())
	t.Logf("Response Cookies: %v", resp.Cookies())
	t.Logf("Response Body: %v", resp)
}

func cleaupFiles(files ...string) {
	pwd, _ := os.Getwd()

	for _, f := range files {
		_ = os.RemoveAll(filepath.Join(pwd, f))
	}
}
