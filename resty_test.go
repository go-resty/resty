// Copyright (c) 2015 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type AuthSuccess struct {
	Id, Message string
}

type AuthError struct {
	Id, Message string
}

func TestGet(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcr().Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
}

func TestGetCustomUserAgent(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcr().
		SetHeader(hdrUserAgentKey, "Test Custom User agent").
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
		SetQueryParam("req_1", "jeeva").
		SetQueryParam("req_3", "jeeva3").
		SetDebug(true).
		SetLogger(ioutil.Discard)

	resp, err := c.R().
		SetQueryParams(map[string]string{"req_1": "req 1 value", "req_2": "req 2 value"}).
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
	c.SetHostUrl(ts.URL)

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

	resp, err := dclr().
		SetHeader(hdrContentTypeKey, jsonContentType).
		SetBody(`{"username":"testuser", "password":"testpass"}`).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	logResponse(t, resp)
}

func TestPostJSONStringError(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	resp, err := dclr().
		SetHeader(hdrContentTypeKey, jsonContentType).
		SetBody(`{"username":"testuser" "password":"testpass"}`).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusBadRequest, resp.StatusCode())

	logResponse(t, resp)
}

func TestPostJSONBytesSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	resp, err := dclr().
		SetHeader(hdrContentTypeKey, jsonContentType).
		SetBody([]byte(`{"username":"testuser", "password":"testpass"}`)).
		Post(ts.URL + "/login")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())

	logResponse(t, resp)
}

func TestPostJSONStructSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	resp, err := dclr().
		SetHeader(hdrContentTypeKey, jsonContentType).
		SetBody(User{Username: "testuser", Password: "testpass"}).
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

	resp, err := dclr().
		SetHeader(hdrContentTypeKey, jsonContentType).
		SetBody(User{Username: "testuser", Password: "testpass1"}).
		SetError(&AuthError{}).
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

	resp, err := dclr().
		SetBody(map[string]interface{}{"username": "testuser", "password": "testpass"}).
		SetResult(&AuthSuccess{}).
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

	resp, err := dclr().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(`<?xml version="1.0" encoding="UTF-8"?><User><Username>testuser</Username><Password>testpass</Password></User>`).
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

	resp, err := dclr().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody([]byte(`<?xml version="1.0" encoding="UTF-8"?><User><Username>testuser</Username><Password>testpass</Password></User>`)).
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

	resp, err := dclr().
		SetHeader(hdrContentTypeKey, "application/xml").
		SetBody(User{Username: "testuser", Password: "testpass1"}).
		SetError(&AuthError{}).
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
		SetHostUrl(ts.URL).
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
	c.SetHostUrl(ts.URL).
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
	c.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	resp, err := c.R().
		SetBasicAuth("myuser", "basicauth1").
		SetError(&AuthError{}).
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
		SetHostUrl(ts.URL + "/")

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
		SetDebug(true).
		SetLogger(ioutil.Discard)

	resp, err := c.R().
		SetFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M", "zip_code": "00001"}).
		Post(ts.URL + "/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "Success", resp.String())
}

func TestMultiPartUploadFile(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	pwd, _ := os.Getwd()
	basePath := pwd + "/test-data"

	resp, err := dclr().
		SetFile("profile_img", basePath+"/test-img.png").
		Post(ts.URL + "/upload")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	fmt.Println(resp)
}

func TestMultiPartUploadFiles(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	pwd, _ := os.Getwd()
	basePath := pwd + "/test-data"

	resp, err := dclr().
		SetFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M"}).
		SetFiles(map[string]string{"profile_img": basePath + "/test-img.png", "notes": basePath + "/text-file.txt"}).
		Post(ts.URL + "/upload")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	fmt.Println(resp)
}

func TestClientOptions(t *testing.T) {
	c := dc()

	c.SetHTTPMode().
		SetContentLength(true)

	assertEqual(t, c.Mode(), "http")
	assertEqual(t, c.setContentLength, true)
}

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
			}
		}
	})

	return ts
}

func createPostServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)
		t.Logf("Content-Type: %v", r.Header.Get(hdrContentTypeKey))

		if r.Method == POST {
			if r.URL.Path == "/login" {
				user := &User{}

				// JSON
				if IsJsonType(r.Header.Get(hdrContentTypeKey)) {
					jd := json.NewDecoder(r.Body)
					err := jd.Decode(user)
					w.Header().Set(hdrContentTypeKey, jsonContentType)
					if err != nil {
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
				if IsXmlType(r.Header.Get(hdrContentTypeKey)) {
					xd := xml.NewDecoder(r.Body)
					err := xd.Decode(user)

					w.Header().Set(hdrContentTypeKey, "application/xml")
					if err != nil {
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

				pwd, _ := os.Getwd()
				targetPath := pwd + "/test-data/upload"
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
