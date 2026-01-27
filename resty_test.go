// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/lzw"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
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

var (
	hdrLocationKey = http.CanonicalHeaderKey("Location")
)

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Testing Unexported methods
//___________________________________

func getTestDataPath() string {
	pwd, _ := os.Getwd()
	return filepath.Join(pwd, ".testdata")
}

func createGetServer(t *testing.T) *httptest.Server {
	var attempt int32
	var sequence int32
	var lastRequest time.Time
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)

		if r.Method == MethodGet {
			switch r.URL.Path {
			case "/":
				_, _ = w.Write([]byte("TestGet: text response"))
			case "/no-content":
				_, _ = w.Write([]byte(""))
			case "/json":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"TestGet": "JSON response"}`))
			case "/json-invalid":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("TestGet: Invalid JSON"))
			case "/long-text":
				_, _ = w.Write([]byte("TestGet: text response with size > 30"))
			case "/long-json":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"TestGet": "JSON response with size > 30"}`))
			case "/mypage":
				w.WriteHeader(http.StatusBadRequest)
			case "/mypage2":
				_, _ = w.Write([]byte("TestGet: text response from mypage2"))
			case "/set-retrycount-test":
				attp := atomic.AddInt32(&attempt, 1)
				if attp <= 4 {
					time.Sleep(time.Millisecond * 150)
				}
				_, _ = w.Write([]byte("TestClientRetry page"))
			case "/set-retrywaittime-test":
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

			case "/set-retry-error-recover":
				w.Header().Set(hdrContentTypeKey, "application/json; charset=utf-8")
				if atomic.LoadInt32(&attempt) == 0 {
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{ "message": "too many" }`))
				} else {
					_, _ = w.Write([]byte(`{ "message": "hello" }`))
				}
				atomic.AddInt32(&attempt, 1)
			case "/set-timeout-test-with-sequence":
				seq := atomic.AddInt32(&sequence, 1)
				time.Sleep(100 * time.Millisecond)
				_, _ = fmt.Fprintf(w, "%d", seq)
			case "/set-timeout-test":
				time.Sleep(400 * time.Millisecond)
				_, _ = w.Write([]byte("TestClientTimeout page"))
			case "/my-image.png":
				fileBytes, _ := os.ReadFile(filepath.Join(getTestDataPath(), "test-img.png"))
				w.Header().Set("Content-Type", "image/png")
				w.Header().Set("Content-Length", strconv.Itoa(len(fileBytes)))
				if r.URL.Query().Get("content-disposition") == "true" {
					filename := r.URL.Query().Get("filename")
					w.Header().Set(hdrContentDisposition, "inline; filename=\""+filename+"\"")
				}
				_, _ = w.Write(fileBytes)
			case "/get-method-payload-test":
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("Error: could not read get body: %s", err.Error())
				}
				_, _ = w.Write(body)
			case "/host-header":
				_, _ = w.Write([]byte(r.Host))
			case "/not-found-with-error":
				w.Header().Set(hdrContentTypeKey, "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error": "Not found"}`))
			case "/not-found-no-error":
				w.Header().Set(hdrContentTypeKey, "application/json")
				w.WriteHeader(http.StatusNotFound)
			case "/retry-after-delay":
				w.Header().Set(hdrContentTypeKey, "application/json; charset=utf-8")
				if atomic.LoadInt32(&attempt) == 0 {
					w.Header().Set(hdrRetryAfterKey, "1")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{ "message": "too many" }`))
				} else {
					_, _ = w.Write([]byte(`{ "message": "hello" }`))
				}
				atomic.AddInt32(&attempt, 1)
			case "/unescape-query-params":
				initOne := r.URL.Query().Get("initone")
				fromClient := r.URL.Query().Get("fromclient")
				registry := r.URL.Query().Get("registry")
				assertEqual(t, "cáfe", initOne)
				assertEqual(t, "hey unescape", fromClient)
				assertEqual(t, "nacos://test:6801", registry)
				_, _ = w.Write([]byte(`query params looks good`))
			}

			switch {
			case strings.HasPrefix(r.URL.Path, "/v1/users/sample@sample.com/100002"):
				if strings.HasSuffix(r.URL.Path, "details") {
					_, _ = w.Write([]byte("TestGetPathParams: text response: " + r.URL.String()))
				} else {
					_, _ = w.Write([]byte("TestPathParamURLInput: text response: " + r.URL.String()))
				}
			}

		}
	})

	return ts
}

func handleLoginEndpoint(t *testing.T, w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/login" {
		user := &credentials{}

		// JSON
		if isJSONContentType(r.Header.Get(hdrContentTypeKey)) {
			jd := json.NewDecoder(r.Body)
			err := jd.Decode(user)
			if r.URL.Query().Get("ct") == "problem" {
				w.Header().Set(hdrContentTypeKey, "application/problem+json; charset=utf-8")
			} else if r.URL.Query().Get("ct") == "rpc" {
				w.Header().Set(hdrContentTypeKey, "application/json-rpc")
			} else {
				w.Header().Set(hdrContentTypeKey, "application/json")
			}

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
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{ "id": "unauthorized", "message": "Invalid credentials" }`))
			}

			return
		}

		// XML
		if isXMLContentType(r.Header.Get(hdrContentTypeKey)) {
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
		if isJSONContentType(r.Header.Get(hdrContentTypeKey)) {
			var users []ExampleUser
			jd := json.NewDecoder(r.Body)
			err := jd.Decode(&users)
			w.Header().Set(hdrContentTypeKey, "application/json")
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
		if r.Method == MethodPost {
			handleLoginEndpoint(t, w, r)

			handleUsersEndpoint(t, w, r)
			switch r.URL.Path {
			case "/login-json-html":
				w.Header().Set(hdrContentTypeKey, "text/html")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{ "id": "success", "message": "login successful" }`))
				return
			case "/usersmap":
				// JSON
				if isJSONContentType(r.Header.Get(hdrContentTypeKey)) {
					if r.URL.Query().Get("status") == "500" {
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Errorf("Error: could not read post body: %s", err.Error())
						}
						t.Logf("Got query param: status=500 so we're returning the post body as response and a 500 status code. body: %s", string(body))
						w.Header().Set(hdrContentTypeKey, "application/json; charset=utf-8")
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = w.Write(body)
						return
					}

					var users []map[string]any
					jd := json.NewDecoder(r.Body)
					err := jd.Decode(&users)
					w.Header().Set(hdrContentTypeKey, "application/json; charset=utf-8")
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
			case "/redirect":
				w.Header().Set(hdrLocationKey, "/login")
				w.WriteHeader(http.StatusTemporaryRedirect)
			case "/redirect-with-body":
				body, _ := io.ReadAll(r.Body)
				query := url.Values{}
				query.Add("body", string(body))
				w.Header().Set(hdrLocationKey, "/redirected-with-body?"+query.Encode())
				w.WriteHeader(http.StatusTemporaryRedirect)
			case "/redirected-with-body":
				body, _ := io.ReadAll(r.Body)
				assertEqual(t, r.URL.Query().Get("body"), string(body))
				w.WriteHeader(http.StatusOK)
			case "/curl-cmd-post":
				cookie := http.Cookie{
					Name:    "testserver",
					Domain:  "localhost",
					Path:    "/",
					Expires: time.Now().AddDate(0, 0, 1),
					Value:   "yes",
				}
				http.SetCookie(w, &cookie)
				w.WriteHeader(http.StatusOK)
			case "/204-response":
				w.WriteHeader(http.StatusNoContent)
			}
		}
	})

	return ts
}

func createFormPostServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == MethodPost {
			_ = r.ParseMultipartForm(10e6)

			if r.URL.Path == "/profile" {
				if r.MultipartForm == nil {
					values := r.Form
					t.Log(values)
				} else {
					values := r.MultipartForm.Value
					t.Log(values)
				}

				_, _ = w.Write([]byte("Success"))
				return
			} else if r.URL.Path == "/search" {
				formEncodedData := r.Form.Encode()
				t.Logf("Received Form Encoded values: %v", formEncodedData)

				assertEqual(t, true, strings.Contains(formEncodedData, "search_criteria=pencil"))
				assertEqual(t, true, strings.Contains(formEncodedData, "search_criteria=glass"))

				_, _ = w.Write([]byte("Success"))
				return
			} else if r.URL.Path == "/upload" {
				t.Logf("FirstName: %v", r.FormValue("first_name"))
				t.Logf("LastName: %v", r.FormValue("last_name"))

				targetPath := filepath.Join(getTestDataPath(), "upload")
				_ = os.MkdirAll(targetPath, 0700)

				values := r.MultipartForm.Value
				t.Logf("%v", values)

				for _, fhdrs := range r.MultipartForm.File {
					for _, hdr := range fhdrs {
						t.Logf("Name: %v", hdr.Filename)
						t.Logf("Header: %v", hdr.Header)
						dotPos := strings.LastIndex(hdr.Filename, ".")

						fname := fmt.Sprintf("%s-%v%s", hdr.Filename[:dotPos], time.Now().Unix(), hdr.Filename[dotPos:])
						t.Logf("Write name: %v", fname)

						infile, _ := hdr.Open()
						f, err := os.OpenFile(filepath.Join(targetPath, fname), os.O_WRONLY|os.O_CREATE, 0666)
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

		if r.Method == MethodPut {

			if r.URL.Path == "/raw-upload" {
				body, _ := io.ReadAll(r.Body)
				bl, _ := strconv.Atoi(r.Header.Get("Content-Length"))
				assertEqual(t, len(body), bl)
				w.WriteHeader(http.StatusOK)
			}

		}
	})

	return ts
}

func createFormPatchServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)
		t.Logf("Content-Type: %v", r.Header.Get(hdrContentTypeKey))

		if r.Method == MethodPatch {
			_ = r.ParseMultipartForm(10e6)

			if r.URL.Path == "/upload" {
				t.Logf("FirstName: %v", r.FormValue("first_name"))
				t.Logf("LastName: %v", r.FormValue("last_name"))

				targetPath := filepath.Join(getTestDataPath(), "upload")
				_ = os.MkdirAll(targetPath, 0700)

				for _, fhdrs := range r.MultipartForm.File {
					for _, hdr := range fhdrs {
						t.Logf("Name: %v", hdr.Filename)
						t.Logf("Header: %v", hdr.Header)
						dotPos := strings.LastIndex(hdr.Filename, ".")

						fname := fmt.Sprintf("%s-%v%s", hdr.Filename[:dotPos], time.Now().Unix(), hdr.Filename[dotPos:])
						t.Logf("Write name: %v", fname)

						infile, _ := hdr.Open()
						f, err := os.OpenFile(filepath.Join(targetPath, fname), os.O_WRONLY|os.O_CREATE, 0666)
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

func createFileUploadServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)
		t.Logf("Content-Type: %v", r.Header.Get(hdrContentTypeKey))

		if r.Method != MethodPost && r.Method != MethodPut {
			t.Log("createFileUploadServer:: Not a POST or PUT request")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, http.StatusText(http.StatusBadRequest))
			return
		}

		targetPath := filepath.Join(getTestDataPath(), "upload-large")
		_ = os.MkdirAll(targetPath, 0700)
		defer cleanupFiles(targetPath)

		switch r.URL.Path {
		case "/upload":
			f, err := os.OpenFile(filepath.Join(targetPath, "large-file.png"),
				os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				t.Logf("Error: %v", err)
				return
			}
			defer func() {
				_ = f.Close()
			}()
			size, _ := io.Copy(f, r.Body)

			fmt.Fprintf(w, "File Uploaded successfully, file size: %v", size)
		case "/set-reset-multipart-readers-test":
			w.Header().Set(hdrContentTypeKey, "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(w, `{ "message": "error" }`)
		}
	})

	return ts
}

func createAuthServer(t *testing.T) *httptest.Server {
	return createAuthServerTLSOptional(t, true)
}

func createAuthServerTLSOptional(t *testing.T, useTLS bool) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf(`createAuthServerTLSOptional: Method: %v, Path: %v, Content-Type: %v`,
			r.Method, r.URL.Path, r.Header.Get(hdrContentTypeKey))

		if r.Method == MethodGet {
			if r.URL.Path == "/profile" {
				// 004DDB79-6801-4587-B976-F093E6AC44FF
				auth := r.Header.Get("Authorization")
				t.Logf("Bearer Auth: %v", auth)

				w.Header().Set(hdrContentTypeKey, "application/json; charset=utf-8")

				if strings.HasPrefix(auth, "Basic ") {
					w.Header().Set("Www-Authenticate", "Protected Realm")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{ "id": "unauthorized", "message": "Invalid credentials" }`))

					return
				}

				if strings.Contains(auth, "004DDB79-6801-4587-B976-F093E6AC44FF") {
					_, _ = w.Write([]byte(`{ "username": "auth_test", "message": "profile fetch successful" }`))
				}
			}

			return
		}

		if r.Method == MethodPost {
			if r.URL.Path == "/login" {
				auth := r.Header.Get("Authorization")
				t.Logf("Basic Auth: %v", auth)

				_, _ = io.ReadAll(r.Body)

				w.Header().Set(hdrContentTypeKey, "application/json; charset=utf-8")

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
	})
	if useTLS {
		return httptest.NewTLSServer(handler)
	}
	return httptest.NewServer(handler)
}

func createGenericServer(t *testing.T) *httptest.Server {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)

		if r.Method == MethodGet {
			switch r.URL.Path {
			case "/json-no-set":
				// Set empty header value for testing, since Go server sets to
				// text/plain; charset=utf-8
				w.Header().Set(hdrContentTypeKey, "")
				_, _ = w.Write([]byte(`{"response":"json response no content type set"}`))

			// Gzip
			case "/gzip-test":
				w.Header().Set(hdrContentTypeKey, plainTextType)
				w.Header().Set(hdrContentEncodingKey, "gzip")
				zw := gzip.NewWriter(w)
				_, _ = zw.Write([]byte("This is Gzip response testing"))
				zw.Close()
			case "/gzip-test-gziped-empty-body":
				w.Header().Set(hdrContentTypeKey, plainTextType)
				w.Header().Set(hdrContentEncodingKey, "gzip")
				zw := gzip.NewWriter(w)
				// write gziped empty body
				_, _ = zw.Write([]byte(""))
				zw.Close()
			case "/gzip-test-no-gziped-body":
				w.Header().Set(hdrContentTypeKey, plainTextType)
				w.Header().Set(hdrContentEncodingKey, "gzip")
				// don't write body

			// Deflate
			case "/deflate-test":
				w.Header().Set(hdrContentTypeKey, plainTextType)
				w.Header().Set(hdrContentEncodingKey, "deflate")
				zw, _ := flate.NewWriter(w, flate.BestSpeed)
				_, _ = zw.Write([]byte("This is Deflate response testing"))
				zw.Close()
			case "/deflate-test-empty-body":
				w.Header().Set(hdrContentTypeKey, plainTextType)
				w.Header().Set(hdrContentEncodingKey, "deflate")
				zw, _ := flate.NewWriter(w, flate.BestSpeed)
				// write deflate empty body
				_, _ = zw.Write([]byte(""))
				zw.Close()
			case "/deflate-test-no-body":
				w.Header().Set(hdrContentTypeKey, plainTextType)
				w.Header().Set(hdrContentEncodingKey, "deflate")
				// don't write body

			// LZW
			case "/lzw-test":
				w.Header().Set(hdrContentTypeKey, plainTextType)
				w.Header().Set(hdrContentEncodingKey, "compress")
				zw := lzw.NewWriter(w, lzw.LSB, 8)
				_, _ = zw.Write([]byte("This is LZW response testing"))
				zw.Close()
			case "/lzw-test-empty-body":
				w.Header().Set(hdrContentTypeKey, plainTextType)
				w.Header().Set(hdrContentEncodingKey, "compress")
				zw := lzw.NewWriter(w, lzw.LSB, 8)
				// write lzw empty body
				_, _ = zw.Write([]byte(""))
				zw.Close()
			case "/lzw-test-no-body":
				w.Header().Set(hdrContentTypeKey, plainTextType)
				w.Header().Set(hdrContentEncodingKey, "compress")
				// don't write body
			}

			return
		}

		if r.Method == MethodPut {
			if r.URL.Path == "/plaintext" {
				_, _ = w.Write([]byte("TestPut: plain text response"))
			} else if r.URL.Path == "/json" {
				w.Header().Set(hdrContentTypeKey, "application/json; charset=utf-8")
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

		if r.Method == "REPORT" && r.URL.Path == "/report" {
			body, _ := io.ReadAll(r.Body)
			if len(body) == 0 {
				w.WriteHeader(http.StatusOK)
			}
			return
		}

		if r.Method == MethodTrace && r.URL.Path == "/trace" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == MethodDelete && r.URL.Path == "/delete" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("Error: could not read get body: %s", err.Error())
			}
			_, _ = w.Write(body)
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
						http.Redirect(w, r, fmt.Sprintf("/redirect-host-check-%d", cnt+1), http.StatusTemporaryRedirect)
					}
				}
			} else if strings.HasPrefix(r.URL.Path, "/redirect-") {
				cntStr := strings.SplitAfter(r.URL.Path, "-")[1]
				cnt, _ := strconv.Atoi(cntStr)

				http.Redirect(w, r, fmt.Sprintf("/redirect-%d", cnt+1), http.StatusTemporaryRedirect)
			}
		}
	})

	return ts
}

func createUnixSocketEchoServer(t *testing.T) string {
	socketPath := filepath.Join(os.TempDir(), strconv.FormatInt(time.Now().Unix(), 10)) + ".sock"

	// Create a Unix domain socket and listen for incoming connections.
	socket, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}

	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hi resty client from a server running on Unix domain socket!\n"))
	})

	m.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello resty client from a server running on endpoint /hello!\n"))
	})

	go func(t *testing.T) {
		server := http.Server{Handler: m}
		if err := server.Serve(socket); err != nil {
			t.Error(err)
		}
	}(t)

	return socketPath
}

func createDigestServer(t *testing.T, conf *digestServerConfig) *httptest.Server {
	if conf == nil {
		conf = defaultDigestServerConf()
	}

	setWWWAuthHeader := func(w http.ResponseWriter, v string) {
		w.Header().Set("WWW-Authenticate", v)
		w.WriteHeader(http.StatusUnauthorized)
	}
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)

		switch r.URL.Path {
		case "/bad":
			setWWWAuthHeader(w, "Bad Challenge")
			return
		case "/unknown_param":
			setWWWAuthHeader(w, "Digest unknown_param=true")
			return
		case "/missing_value":
			setWWWAuthHeader(w, `Digest realm="hello", domain`)
			return
		case "/unclosed_quote":
			setWWWAuthHeader(w, `Digest realm="hello, qop=auth`)
			return
		case "/no_challenge":
			setWWWAuthHeader(w, "")
			return
		case "/status_500":
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set(hdrContentTypeKey, "application/json; charset=utf-8")

		if authorizationHeaderValid(t, r, conf) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{ "id": "success", "message": "login successful" }`))
		} else {
			setWWWAuthHeader(w,
				fmt.Sprintf(`Digest realm="%s", domain="%s", qop="%s", algorithm=%s, nonce="%s", opaque="%s", userhash=true, charset=%s, stale=FALSE, nc=%s`,
					conf.realm, conf.uri, conf.qop, conf.algo, conf.nonce, conf.opaque, conf.charset, conf.nc))
			_, _ = w.Write([]byte(`{ "id": "unauthorized", "message": "Invalid credentials" }`))
		}
	})

	return ts
}

func authorizationHeaderValid(t *testing.T, r *http.Request, conf *digestServerConfig) bool {
	input := r.Header.Get(hdrAuthorizationKey)
	if input == "" {
		return false
	}

	const ws = " \n\r\t"
	const qs = `"`
	s := strings.Trim(input, ws)
	assertEqual(t, true, strings.HasPrefix(s, "Digest "))
	s = strings.Trim(s[7:], ws)
	sl := strings.Split(s, ", ")

	pairs := make(map[string]string, len(sl))
	for i := range sl {
		pair := strings.SplitN(sl[i], "=", 2)
		pairs[pair[0]] = strings.Trim(pair[1], qs)
	}

	assertEqual(t, conf.algo, pairs["algorithm"])
	h := func(data string) string {
		h := newHashFunc(pairs["algorithm"])
		_, _ = h.Write([]byte(data))
		return hex.EncodeToString(h.Sum(nil))
	}

	assertEqual(t, conf.opaque, pairs["opaque"])
	assertEqual(t, "true", pairs["userhash"])

	userHash := h(fmt.Sprintf("%s:%s", conf.username, conf.realm))
	assertEqual(t, userHash, pairs["username"])

	ha1 := h(fmt.Sprintf("%s:%s:%s", conf.username, conf.realm, conf.password))
	if strings.HasSuffix(conf.algo, "-sess") {
		ha1 = h(fmt.Sprintf("%s:%s:%s", ha1, pairs["nonce"], pairs["cnonce"]))
	}
	ha2 := h(fmt.Sprintf("%s:%s", r.Method, conf.uri))

	qop := pairs["qop"]
	if qop == "" {
		kd := h(fmt.Sprintf("%s:%s:%s", ha1, pairs["nonce"], ha2))
		return kd == pairs["response"]
	}

	nonceCount, err := strconv.Atoi(pairs["nc"])
	assertError(t, err)

	// auth scenario
	if qop == qopAuth {
		kd := h(fmt.Sprintf("%s:%s", ha1, fmt.Sprintf("%s:%08x:%s:%s:%s",
			pairs["nonce"], nonceCount, pairs["cnonce"], pairs["qop"], ha2)))
		return kd == pairs["response"]
	}

	// auth-int scenario
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	assertError(t, err)
	bodyHash := ""
	if len(body) > 0 {
		bodyHash = h(string(body))
	}

	ha2 = h(fmt.Sprintf("%s:%s:%s", r.Method, conf.uri, bodyHash))
	kd := h(fmt.Sprintf("%s:%s", ha1, fmt.Sprintf("%s:%08x:%s:%s:%s",
		pairs["nonce"], nonceCount, pairs["cnonce"], pairs["qop"], ha2)))
	return kd == pairs["response"]
}

func createTestServer(fn func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(fn))
}

func createTestTLSServer(fn func(w http.ResponseWriter, r *http.Request), certPath, certKeyPath string) *httptest.Server {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(fn))
	ts.TLS = &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certPath, certKeyPath)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	}
	ts.StartTLS()
	return ts
}

func dcnl() *Client {
	c := New().
		outputLogTo(io.Discard)
	return c
}

func dcnld() *Client {
	return dcnl().EnableDebug()
}

func dcldb() (*Client, *bytes.Buffer) {
	logBuf := acquireBuffer()
	c := New().
		EnableDebug().
		outputLogTo(logBuf)
	return c, logBuf
}

func dcnlr() *Request {
	return dcnl().R()
}

func dcnldr() *Request {
	c := dcnl().
		SetDebug(true)
	return c.R()
}

func assertNil(t *testing.T, v any) {
	t.Helper()
	if !isNil(v) {
		t.Errorf("[%v] was expected to be nil", v)
	}
}

func assertNotNil(t *testing.T, v any) {
	t.Helper()
	if isNil(v) {
		t.Errorf("[%v] was expected to be non-nil", v)
	}
}

func assertType(t *testing.T, typ, v any) {
	t.Helper()
	if reflect.DeepEqual(reflect.TypeOf(typ), reflect.TypeOf(v)) {
		t.Errorf("Expected type %t, got %t", typ, v)
	}
}

func assertError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("Error occurred [%v]", err)
	}
}

func assertErrorIs(t *testing.T, e, g error) (r bool) {
	t.Helper()
	if !errors.Is(g, e) {
		t.Errorf("Expected [%v], got [%v]", e, g)
	}

	return true
}

func assertEqual(t *testing.T, e, g any) (r bool) {
	t.Helper()
	if !equal(e, g) {
		t.Errorf("Expected [%v], got [%v]", e, g)
	}

	return
}

func assertNotEqual(t *testing.T, e, g any) (r bool) {
	t.Helper()
	if equal(e, g) {
		t.Errorf("Expected [%v], got [%v]", e, g)
	} else {
		r = true
	}

	return
}

func equal(expected, got any) bool {
	return reflect.DeepEqual(expected, got)
}

func isNil(v any) bool {
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
	t.Helper()
	t.Logf("Response Status: %v", resp.Status())
	t.Logf("Response Duration: %v", resp.Duration())
	t.Logf("Response Headers: %v", resp.Header())
	t.Logf("Response Cookies: %v", resp.Cookies())
	t.Logf("Response Body: %v", resp)
}

func cleanupFiles(files ...string) {
	pwd, _ := os.Getwd()

	for _, f := range files {
		if filepath.IsAbs(f) {
			_ = os.RemoveAll(f)
		} else {
			_ = os.RemoveAll(filepath.Join(pwd, f))
		}
	}
}

func createBinFile(fileName string, size int64) string {
	fp := filepath.Join(getTestDataPath(), fileName)
	f, _ := os.Create(fp)
	_ = f.Truncate(size)
	_ = f.Close()
	return fp
}
