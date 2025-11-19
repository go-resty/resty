// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func Test_parseRequestURL(t *testing.T) {
	for _, tt := range []struct {
		name        string
		initClient  func(c *Client)
		initRequest func(r *Request)
		expectedURL string
	}{
		{
			name: "apply client path parameters",
			initClient: func(c *Client) {
				c.SetPathParams(map[string]string{
					"foo": "1",
					"bar": "2/3",
				})
			},
			initRequest: func(r *Request) {
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/1/2%2F3",
		},
		{
			name: "apply request path parameters",
			initRequest: func(r *Request) {
				r.SetPathParams(map[string]string{
					"foo": "4",
					"bar": "5/6",
				})
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/4/5%2F6",
		},
		{
			name: "apply request and client path parameters",
			initClient: func(c *Client) {
				c.SetPathParams(map[string]string{
					"foo": "1", // ignored, because of the request's "foo"
					"bar": "2/3",
				})
			},
			initRequest: func(r *Request) {
				r.SetPathParams(map[string]string{
					"foo": "4/5",
				})
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/4%2F5/2%2F3",
		},
		{
			name: "apply client raw path parameters",
			initClient: func(c *Client) {
				c.SetRawPathParams(map[string]string{
					"foo": "1/2",
					"bar": "3",
				})
			},
			initRequest: func(r *Request) {
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/1/2/3",
		},
		{
			name: "apply request raw path parameters",
			initRequest: func(r *Request) {
				r.SetRawPathParams(map[string]string{
					"foo": "4",
					"bar": "5/6",
				})
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/4/5/6",
		},
		{
			name: "apply request and client raw path parameters",
			initClient: func(c *Client) {
				c.SetRawPathParams(map[string]string{
					"foo": "1", // ignored, because of the request's "foo"
					"bar": "2/3",
				})
			},
			initRequest: func(r *Request) {
				r.SetRawPathParams(map[string]string{
					"foo": "4/5",
				})
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/4/5/2/3",
		},
		{
			name: "apply request path and raw path parameters",
			initRequest: func(r *Request) {
				r.SetPathParams(map[string]string{
					"foo": "4/5",
				}).SetRawPathParams(map[string]string{
					"foo": "4/5", // it gets overwritten since same key name
					"bar": "6/7",
				})
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/4/5/6/7",
		},
		{
			name: "empty path parameter in URL",
			initRequest: func(r *Request) {
				r.SetPathParams(map[string]string{
					"bar": "4",
				})
				r.URL = "https://example.com/{}/{bar}"
			},
			expectedURL: "https://example.com/%7B%7D/4",
		},
		{
			name: "not closed path parameter in URL",
			initRequest: func(r *Request) {
				r.SetPathParams(map[string]string{
					"foo": "4",
				})
				r.URL = "https://example.com/{foo}/{bar/1"
			},
			expectedURL: "https://example.com/4/%7Bbar/1",
		},
		{
			name: "extra path parameter in URL",
			initRequest: func(r *Request) {
				r.SetPathParams(map[string]string{
					"foo": "1",
				})
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/1/%7Bbar%7D",
		},
		{
			name: " path parameter with remainder",
			initRequest: func(r *Request) {
				r.SetPathParams(map[string]string{
					"foo": "1",
				})
				r.URL = "https://example.com/{foo}/2"
			},
			expectedURL: "https://example.com/1/2",
		},
		{
			name: "using base url with path param at index 0",
			initClient: func(c *Client) {
				c.SetBaseURL("https://example.com/prefix")
			},
			initRequest: func(r *Request) {
				r.SetPathParam("first", "1").
					SetPathParam("second", "2")
				r.URL = "{first}/{second}"
			},
			expectedURL: "https://example.com/prefix/1/2",
		},
		{
			name: "using BaseURL with absolute URL in request",
			initClient: func(c *Client) {
				c.SetBaseURL("https://foo.bar") // ignored
			},
			initRequest: func(r *Request) {
				r.URL = "https://example.com/"
			},
			expectedURL: "https://example.com/",
		},
		{
			name: "using BaseURL with relative path in request URL without leading slash",
			initClient: func(c *Client) {
				c.SetBaseURL("https://example.com")
			},
			initRequest: func(r *Request) {
				r.URL = "foo/bar"
			},
			expectedURL: "https://example.com/foo/bar",
		},
		{
			name: "using BaseURL with relative path in request URL with leading slash",
			initClient: func(c *Client) {
				c.SetBaseURL("https://example.com")
			},
			initRequest: func(r *Request) {
				r.URL = "/foo/bar"
			},
			expectedURL: "https://example.com/foo/bar",
		},
		{
			name: "using deprecated HostURL with relative path in request URL",
			initClient: func(c *Client) {
				c.SetBaseURL("https://example.com")
			},
			initRequest: func(r *Request) {
				r.URL = "foo/bar"
			},
			expectedURL: "https://example.com/foo/bar",
		},
		{
			name: "request URL without scheme",
			initRequest: func(r *Request) {
				r.URL = "example.com/foo/bar"
			},
			expectedURL: "/example.com/foo/bar",
		},
		{
			name: "BaseURL without scheme",
			initClient: func(c *Client) {
				c.SetBaseURL("example.com")
			},
			initRequest: func(r *Request) {
				r.URL = "foo/bar"
			},
			expectedURL: "example.com/foo/bar",
		},
		{
			name: "using SetScheme and BaseURL without scheme",
			initClient: func(c *Client) {
				c.SetBaseURL("example.com").
					SetScheme("https")
			},
			initRequest: func(r *Request) {
				r.URL = "foo/bar"
			},
			expectedURL: "https://example.com/foo/bar",
		},
		{
			name: "adding query parameters by client",
			initClient: func(c *Client) {
				c.SetQueryParams(map[string]string{
					"foo": "1",
					"bar": "2",
				})
			},
			initRequest: func(r *Request) {
				r.URL = "https://example.com/"
			},
			expectedURL: "https://example.com/?foo=1&bar=2",
		},
		{
			name: "adding query parameters by request",
			initRequest: func(r *Request) {
				r.SetQueryParams(map[string]string{
					"foo": "1",
					"bar": "2",
				})
				r.URL = "https://example.com/"
			},
			expectedURL: "https://example.com/?foo=1&bar=2",
		},
		{
			name: "adding query parameters by client and request",
			initClient: func(c *Client) {
				c.SetQueryParams(map[string]string{
					"foo": "1", // ignored, because of the "foo" parameter in request
					"bar": "2",
				})
			},
			initRequest: func(r *Request) {
				r.SetQueryParams(map[string]string{
					"foo": "3",
				})
				r.URL = "https://example.com/"
			},
			expectedURL: "https://example.com/?foo=3&bar=2",
		},
		{
			name: "adding query parameters by request to URL with existent",
			initRequest: func(r *Request) {
				r.SetQueryParams(map[string]string{
					"bar": "2",
				})
				r.URL = "https://example.com/?foo=1"
			},
			expectedURL: "https://example.com/?foo=1&bar=2",
		},
		{
			name: "adding query parameters by request with multiple values",
			initRequest: func(r *Request) {
				r.QueryParams.Add("foo", "1")
				r.QueryParams.Add("foo", "2")
				r.URL = "https://example.com/"
			},
			expectedURL: "https://example.com/?foo=1&foo=2",
		},
		{
			name: "unescape query params",
			initClient: func(c *Client) {
				c.SetBaseURL("https://example.com/").
					SetUnescapeQueryParams(true). // this line is just code coverage; I will restructure this test in v3 for the client and request the respective init method
					SetQueryParam("fromclient", "hey unescape").
					SetQueryParam("initone", "cáfe")
			},
			initRequest: func(r *Request) {
				r.SetUnescapeQueryParams(true) // this line takes effect
				r.SetQueryParams(
					map[string]string{
						"registry": "nacos://test:6801", // GH #797
					},
				)
			},
			expectedURL: "https://example.com?initone=cáfe&fromclient=hey+unescape&registry=nacos://test:6801",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := New()
			if tt.initClient != nil {
				tt.initClient(c)
			}

			r := c.R()
			if tt.initRequest != nil {
				tt.initRequest(r)
			}
			if err := parseRequestURL(c, r); err != nil {
				t.Errorf("parseRequestURL() error = %v", err)
			}

			// compare URLs without query parameters first
			// then compare query parameters, because the order of the items in a map is not guarantied
			expectedURL, _ := url.Parse(tt.expectedURL)
			expectedQuery := expectedURL.Query()
			expectedURL.RawQuery = ""
			actualURL, _ := url.Parse(r.URL)
			actualQuery := actualURL.Query()
			actualURL.RawQuery = ""
			if expectedURL.String() != actualURL.String() {
				t.Errorf("r.URL = %q does not match expected %q", r.URL, tt.expectedURL)
			}
			if !reflect.DeepEqual(expectedQuery, actualQuery) {
				t.Errorf("r.URL = %q does not match expected %q", r.URL, tt.expectedURL)
			}
		})
	}
}

func Test_parseRequestHeader(t *testing.T) {
	for _, tt := range []struct {
		name           string
		init           func(c *Client, r *Request)
		expectedHeader http.Header
	}{
		{
			name: "headers in request",
			init: func(c *Client, r *Request) {
				r.SetHeaders(map[string]string{
					"foo": "1",
					"bar": "2",
				})
			},
			expectedHeader: http.Header{
				http.CanonicalHeaderKey("foo"): []string{"1"},
				http.CanonicalHeaderKey("bar"): []string{"2"},
				hdrUserAgentKey:                []string{hdrUserAgentValue},
			},
		},
		{
			name: "headers in client",
			init: func(c *Client, r *Request) {
				c.SetHeaders(map[string]string{
					"foo": "1",
					"bar": "2",
				})
			},
			expectedHeader: http.Header{
				http.CanonicalHeaderKey("foo"): []string{"1"},
				http.CanonicalHeaderKey("bar"): []string{"2"},
				hdrUserAgentKey:                []string{hdrUserAgentValue},
			},
		},
		{
			name: "headers in client and request",
			init: func(c *Client, r *Request) {
				c.SetHeaders(map[string]string{
					"foo": "1", // ignored, because of the same header in the request
					"bar": "2",
				})
				r.SetHeaders(map[string]string{
					"foo": "3",
					"xyz": "4",
				})
			},
			expectedHeader: http.Header{
				http.CanonicalHeaderKey("foo"): []string{"3"},
				http.CanonicalHeaderKey("bar"): []string{"2"},
				http.CanonicalHeaderKey("xyz"): []string{"4"},
				hdrUserAgentKey:                []string{hdrUserAgentValue},
			},
		},
		{
			name: "no headers",
			init: func(c *Client, r *Request) {},
			expectedHeader: http.Header{
				hdrUserAgentKey: []string{hdrUserAgentValue},
			},
		},
		{
			name: "user agent",
			init: func(c *Client, r *Request) {
				c.SetHeader(hdrUserAgentKey, "foo bar")
			},
			expectedHeader: http.Header{
				http.CanonicalHeaderKey(hdrUserAgentKey): []string{"foo bar"},
			},
		},
		{
			name: "json content type",
			init: func(c *Client, r *Request) {
				c.SetHeader(hdrContentTypeKey, "application/json")
			},
			expectedHeader: http.Header{
				hdrContentTypeKey: []string{"application/json"},
				hdrUserAgentKey:   []string{hdrUserAgentValue},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := New()
			r := c.R()
			tt.init(c, r)

			// add common expected headers from client into expectedHeader
			tt.expectedHeader.Set(hdrAcceptEncodingKey, c.ContentDecompresserKeys())

			if err := parseRequestHeader(c, r); err != nil {
				t.Errorf("parseRequestHeader() error = %v", err)
			}
			if !reflect.DeepEqual(tt.expectedHeader, r.Header) {
				t.Errorf("r.Header = %#+v does not match expected %#+v", r.Header, tt.expectedHeader)
			}
		})
	}
}

func TestParseRequestBody(t *testing.T) {
	for _, tt := range []struct {
		name                  string
		initClient            func(c *Client)
		initRequest           func(r *Request)
		expectedBodyBuf       []byte
		expectedContentLength string
		expectedContentType   string
		wantErr               bool
	}{
		{
			name: "empty body",
		},
		{
			name: "empty body with SetContentLength by request",
			initRequest: func(r *Request) {
				r.SetContentLength(true)
			},
			expectedContentLength: "0",
		},
		{
			name: "empty body with SetContentLength by client",
			initClient: func(c *Client) {
				c.SetContentLength(true)
			},
			expectedContentLength: "0",
		},
		{
			name: "string body",
			initRequest: func(r *Request) {
				r.SetMethod(MethodPost).
					SetBody("foo")
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with GET method",
			initRequest: func(r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodGet
			},
		},
		{
			name: "string body with GET method and AllowMethodGetPayload by client",
			initClient: func(c *Client) {
				c.SetAllowMethodGetPayload(true)
			},
			initRequest: func(r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodGet
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with GET method and AllowMethodGetPayload by request",
			initRequest: func(r *Request) {
				r.SetAllowMethodGetPayload(true)
				r.SetBody("foo")
				r.Method = http.MethodGet
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with HEAD method",
			initRequest: func(r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodHead
			},
		},
		{
			name: "string body with OPTIONS method",
			initRequest: func(r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodOptions
			},
		},
		{
			name: "string body with POST method",
			initRequest: func(r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodPost
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with PATCH method",
			initRequest: func(r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodPatch
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with PUT method",
			initRequest: func(r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodPut
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with DELETE method",
			initRequest: func(r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodDelete
			},
			expectedBodyBuf:     nil,
			expectedContentType: "",
		},
		{
			name: "string body with DELETE method with AllowMethodDeletePayload by request",
			initRequest: func(r *Request) {
				r.SetAllowMethodDeletePayload(true)
				r.SetBody("foo")
				r.Method = http.MethodDelete
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with CONNECT method",
			initRequest: func(r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodConnect
			},
			expectedBodyBuf:     nil,
			expectedContentType: "",
		},
		{
			name: "string body with TRACE method",
			initRequest: func(r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodTrace
			},
			expectedBodyBuf:     nil,
			expectedContentType: "",
		},
		{
			name: "byte body with method post",
			initRequest: func(r *Request) {
				r.SetMethod(MethodPost).
					SetBody([]byte("foo"))
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "io.Reader body, no bodyBuf with method put",
			initRequest: func(r *Request) {
				r.SetMethod(MethodPut).
					SetBody(bytes.NewBufferString("foo"))
			},
			expectedContentType: jsonContentType,
		},
		{
			name: "form data by request with method post",
			initRequest: func(r *Request) {
				r.SetMethod(MethodPost).
					SetFormData(map[string]string{
						"foo": "1",
						"bar": "2",
					})
			},
			expectedBodyBuf:     []byte("foo=1&bar=2"),
			expectedContentType: formContentType,
		},
		{
			name: "form data by client with method patch",
			initClient: func(c *Client) {
				c.SetFormData(map[string]string{
					"foo": "1",
					"bar": "2",
				})
			},
			initRequest: func(r *Request) {
				r.SetMethod(MethodPatch)
			},
			expectedBodyBuf:     []byte("foo=1&bar=2"),
			expectedContentType: formContentType,
		},
		{
			name: "form data by client and request",
			initClient: func(c *Client) {
				c.SetFormData(map[string]string{
					"foo": "1",
					"bar": "2",
				})
			},
			initRequest: func(r *Request) {
				r.SetMethod(MethodPatch).
					SetFormData(map[string]string{
						"foo": "3",
						"baz": "4",
					})
			},
			expectedBodyBuf:     []byte("foo=3&bar=2&baz=4"),
			expectedContentType: formContentType,
		},
		{
			name: "json from struct",
			initRequest: func(r *Request) {
				r.SetMethod(MethodPut)
				r.SetBody(struct {
					Foo string `json:"foo"`
					Bar string `json:"bar"`
				}{
					Foo: "1",
					Bar: "2",
				}).SetContentLength(true)
			},
			expectedBodyBuf:       append([]byte(`{"foo":"1","bar":"2"}`), '\n'),
			expectedContentType:   jsonContentType,
			expectedContentLength: "22",
		},
		{
			name: "json from slice",
			initRequest: func(r *Request) {
				r.SetMethod(MethodPost).
					SetBody([]string{"foo", "bar"}).
					SetContentLength(true)
			},
			expectedBodyBuf:       append([]byte(`["foo","bar"]`), '\n'),
			expectedContentType:   jsonContentType,
			expectedContentLength: "14",
		},
		{
			name: "json from map",
			initRequest: func(r *Request) {
				r.SetMethod(MethodPost).
					SetBody(map[string]any{
						"foo": "1",
						"bar": []int{1, 2, 3},
						"baz": map[string]string{
							"qux": "4",
						},
						"xyz": nil,
					}).
					SetContentLength(true)
			},
			expectedBodyBuf:       append([]byte(`{"bar":[1,2,3],"baz":{"qux":"4"},"foo":"1","xyz":null}`), '\n'),
			expectedContentType:   jsonContentType,
			expectedContentLength: "55",
		},
		{
			name: "json from map",
			initRequest: func(r *Request) {
				r.SetMethod(MethodPut).
					SetBody(map[string]any{
						"foo": "1",
						"bar": []int{1, 2, 3},
						"baz": map[string]string{
							"qux": "4",
						},
						"xyz": nil,
					}).
					SetContentLength(true)
			},
			expectedBodyBuf:       append([]byte(`{"bar":[1,2,3],"baz":{"qux":"4"},"foo":"1","xyz":null}`), '\n'),
			expectedContentType:   jsonContentType,
			expectedContentLength: "55",
		},
		{
			name: "json from map",
			initRequest: func(r *Request) {
				r.SetMethod(MethodPost).
					SetBody(map[string]any{
						"foo": "1",
						"bar": []int{1, 2, 3},
						"baz": map[string]string{
							"qux": "4",
						},
						"xyz": nil,
					}).
					SetContentLength(true)
			},
			expectedBodyBuf:       append([]byte(`{"bar":[1,2,3],"baz":{"qux":"4"},"foo":"1","xyz":null}`), '\n'),
			expectedContentType:   jsonContentType,
			expectedContentLength: "55",
		},
		{
			name: "xml from struct",
			initRequest: func(r *Request) {
				type FooBar struct {
					Foo string `xml:"foo"`
					Bar string `xml:"bar"`
				}
				r.SetMethod(MethodPatch).
					SetBody(FooBar{
						Foo: "1",
						Bar: "2",
					}).
					SetContentLength(true).
					SetHeader(hdrContentTypeKey, "text/xml")
			},
			expectedBodyBuf:       []byte(`<FooBar><foo>1</foo><bar>2</bar></FooBar>`),
			expectedContentType:   "text/xml",
			expectedContentLength: "41",
		},
		{
			name: "unsupported type",
			initRequest: func(r *Request) {
				r.SetMethod(MethodPost).
					SetBody(1)
			},
			wantErr: true,
		},
		{
			name: "unsupported xml",
			initRequest: func(r *Request) {
				r.SetMethod(MethodPut).
					SetBody(struct {
						Foo string `xml:"foo"`
						Bar string `xml:"bar"`
					}{
						Foo: "1",
						Bar: "2",
					}).
					SetHeader(hdrContentTypeKey, "text/xml")
			},
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := New()
			if tt.initClient != nil {
				tt.initClient(c)
			}

			r := c.R()
			if tt.initRequest != nil {
				tt.initRequest(r)
			}

			if err := parseRequestBody(c, r); err != nil {
				if tt.wantErr {
					return
				}
				t.Errorf("parseRequestBody() error = %v", err)
			} else if tt.wantErr {
				t.Errorf("wanted error, but got nil")
			}
			switch {
			case r.bodyBuf == nil && tt.expectedBodyBuf != nil:
				t.Errorf("bodyBuf is nil, but expected: %s", string(tt.expectedBodyBuf))
			case r.bodyBuf != nil && tt.expectedBodyBuf == nil:
				t.Errorf("bodyBuf is not nil, but expected nil: %s", r.bodyBuf.String())
			case r.bodyBuf != nil && tt.expectedBodyBuf != nil:
				var actual, expected any = r.bodyBuf.Bytes(), tt.expectedBodyBuf
				if r.isFormData {
					var err error
					actual, err = url.ParseQuery(r.bodyBuf.String())
					if err != nil {
						t.Errorf("ParseQuery(r.bodyBuf) error = %v", err)
					}
					expected, err = url.ParseQuery(string(tt.expectedBodyBuf))
					if err != nil {
						t.Errorf("ParseQuery(tt.expectedBodyBuf) error = %v", err)
					}
				} else if r.isMultiPart {
					_, params, err := mime.ParseMediaType(r.Header.Get(hdrContentTypeKey))
					if err != nil {
						t.Errorf("ParseMediaType(hdrContentTypeKey) error = %v", err)
					}
					boundary, ok := params["boundary"]
					if !ok {
						t.Errorf("boundary not found in Content-Type header")
					}
					reader := multipart.NewReader(r.bodyBuf, boundary)
					body := make(map[string]any)
					for part, perr := reader.NextPart(); perr != io.EOF; part, perr = reader.NextPart() {
						if perr != nil {
							t.Errorf("NextPart() error = %v", perr)
						}
						name := part.FormName()
						if name == "" {
							name = part.FileName()
						}
						data, err := io.ReadAll(part)
						if err != nil {
							t.Errorf("ReadAll(part) error = %v", err)
						}
						body[name] = string(data)
					}
					actual = body
					expected = nil
					if err := json.Unmarshal(tt.expectedBodyBuf, &expected); err != nil {
						t.Errorf("json.Unmarshal(tt.expectedBodyBuf) error = %v", err)
					}
					t.Logf(`in case of an error, the expected body should be set as json for object: %#+v`, actual)
				}
				if !reflect.DeepEqual(actual, expected) {
					t.Errorf("bodyBuf = %q does not match expected %q", r.bodyBuf.String(), string(tt.expectedBodyBuf))
				}
			}
			if tt.expectedContentLength != r.Header.Get(hdrContentLengthKey) {
				t.Errorf("Content-Length header = %q does not match expected %q", r.Header.Get(hdrContentLengthKey), tt.expectedContentLength)
			}
			if ct := r.Header.Get(hdrContentTypeKey); !((tt.expectedContentType == "" && ct != "") || strings.Contains(ct, tt.expectedContentType)) {
				t.Errorf("Content-Type header = %q does not match expected %q", r.Header.Get(hdrContentTypeKey), tt.expectedContentType)
			}
		})
	}
}

func TestMiddlewareSaveToFileErrorCases(t *testing.T) {
	c := dcnl()
	tempDir := t.TempDir()

	errDirMsg := "test dir error"
	mkdirAll = func(_ string, _ os.FileMode) error {
		return errors.New(errDirMsg)
	}
	errFileMsg := "test file error"
	createFile = func(_ string) (*os.File, error) {
		return nil, errors.New(errFileMsg)
	}
	t.Cleanup(func() {
		mkdirAll = os.MkdirAll
		createFile = os.Create
	})

	// dir create error
	req1 := c.R()
	req1.SetOutputFileName(filepath.Join(tempDir, "new-res-dir", "sample.txt"))
	err1 := SaveToFileResponseMiddleware(c, &Response{Request: req1})
	assertEqual(t, errDirMsg, err1.Error())

	// file create error
	req2 := c.R()
	req2.SetOutputFileName(filepath.Join(tempDir, "sample.txt"))
	err2 := SaveToFileResponseMiddleware(c, &Response{Request: req2})
	assertEqual(t, errFileMsg, err2.Error())
}

func TestMiddlewareSaveToFileCopyError(t *testing.T) {
	c := dcnl()
	tempDir := t.TempDir()

	errCopyMsg := "test copy error"
	ioCopy = func(dst io.Writer, src io.Reader) (written int64, err error) {
		return 0, errors.New(errCopyMsg)
	}
	t.Cleanup(func() {
		ioCopy = io.Copy
	})

	// copy error
	req1 := c.R()
	req1.SetOutputFileName(filepath.Join(tempDir, "new-res-dir", "sample.txt"))
	err1 := SaveToFileResponseMiddleware(c, &Response{Request: req1, Body: io.NopCloser(bytes.NewBufferString("Test context"))})
	assertEqual(t, errCopyMsg, err1.Error())
}

func TestRequestURL_GH797(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()
	c := dcnl().
		SetBaseURL(ts.URL).
		SetUnescapeQueryParams(true). // this line is just code coverage; I will restructure this test in v3 for the client and request the respective init method
		SetQueryParam("fromclient", "hey unescape").
		SetQueryParam("initone", "cáfe")
	resp, err := c.R().
		SetUnescapeQueryParams(true). // this line takes effect
		SetQueryParams(
			map[string]string{
				"registry": "nacos://test:6801", // GH #797
			},
		).
		Get("/unescape-query-params")
	assertError(t, err)
	assertEqual(t, "query params looks good", resp.String())
}

func TestMiddlewareCoverage(t *testing.T) {
	c := dcnl()

	req1 := c.R()
	req1.URL = "//invalid-url  .local"
	err1 := createRawRequest(c, req1)
	assertEqual(t, true, strings.Contains(err1.Error(), "invalid character"))
}
