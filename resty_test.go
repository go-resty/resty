// Copyright (c) 2015 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultGet(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcr().Get(ts.URL + "/")

	if err != nil {
		t.Errorf("TestDefaultGet - Error occurred [%v]: ", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected 200, got %v", resp.StatusCode())
	}
	if resp.Status() != "200 OK" {
		t.Errorf("Expected 200, got %v", resp.Status())
	}
	if resp.String() != "TestDefaultGet: text response" {
		t.Errorf("Expected [TestDefaultGet: text response], got [%v]", resp.String())
	}
	logResponse(t, "TestDefaultGet", resp)
}

func TestDefaultGet400Error(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcr().Get(ts.URL + "/mypage")

	if err != nil {
		t.Errorf("TestDefaultGet - Error occurred [%v]: ", err)
	}
	if resp.StatusCode() != 400 {
		t.Errorf("Expected 200, got %v", resp.StatusCode())
	}
	if resp.String() != "" {
		t.Errorf("Expected [], got [%v]", resp.String())
	}
	logResponse(t, "TestDefaultGet400Error", resp)
}

func TestDefaultPostStringSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	resp, err := dcr().
		SetHeader(hdrContentTypeKey, jsonContentType).
		SetBody(`{"username":"testuser", "password":"testpass"}`).
		Post(ts.URL + "/login")

	if err != nil {
		t.Errorf("TestDefaultPostStringSuccess - Error occurred [%v]: ", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected 200, got %v", resp.StatusCode())
	}
	if resp.Status() != "200 OK" {
		t.Errorf("Expected 200, got %v", resp.Status())
	}
	logResponse(t, "TestDefaultPostStringSuccess", resp)
}

func TestDefaultPostBytesSuccess(t *testing.T) {
	ts := createPostServer(t)
	defer ts.Close()

	resp, err := dcr().
		SetHeader(hdrContentTypeKey, jsonContentType).
		SetBody([]byte(`{"username":"testuser", "password":"testpass"}`)).
		Post(ts.URL + "/login")

	if err != nil {
		t.Errorf("TestDefaultPostStringSuccess - Error occurred [%v]: ", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected 200, got %v", resp.StatusCode())
	}
	if resp.Status() != "200 OK" {
		t.Errorf("Expected 200, got %v", resp.Status())
	}
	logResponse(t, "TestDefaultPostBytesSuccess", resp)
}

func createGetServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)
		if r.Method == GET {
			if r.URL.Path == "/" {
				w.Write([]byte("TestDefaultGet: text response"))
			} else if r.URL.Path == "/mypage" {
				w.WriteHeader(http.StatusBadRequest)
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
					decoder := json.NewDecoder(r.Body)
					err := decoder.Decode(user)
					w.Header().Set(hdrContentTypeKey, jsonContentType)
					if err != nil {
						w.WriteHeader(http.StatusBadRequest)
						w.Write([]byte(`{
							"id":      "bad_request",
							"message": "Unable to read user info",
						}`))
					}

					if user.Username == "testuser" && user.Password == "testpass" {
						w.Write([]byte(`{
							"id":      "success",
							"message": "login successful",
						}`))
					}
				}

				// XML
				if IsXmlType(r.Header.Get(hdrContentTypeKey)) {

				}

			}
		}
	})

	return ts
}

func createTestServer(fn func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(fn))
}

func dc() *Client {
	return DefaultClient
}

func dcr() *Request {
	return dc().R()
}

func logResponse(t *testing.T, mn string, resp *Response) {
	t.Logf("\n\nMethod: %v", mn)
	t.Logf("\nResponse Status: %v", resp.Status())
	t.Logf("\nResponse Time: %v", resp.Time())
	t.Logf("\nResponse Headers: %v", resp.Header())
	t.Logf("\nResponse Cookies: %v", resp.Cookies())
	t.Logf("\nResponse Body: %v", resp)
}
