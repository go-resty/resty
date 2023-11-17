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
	"reflect"
	"strings"
	"testing"
)

func Test_parseRequestURL(t *testing.T) {
	for _, tt := range []struct {
		name        string
		init        func(c *Client, r *Request)
		expectedURL string
	}{
		{
			name: "apply client path parameters",
			init: func(c *Client, r *Request) {
				c.SetPathParams(map[string]string{
					"foo": "1",
					"bar": "2/3",
				})
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/1/2%2F3",
		},
		{
			name: "apply request path parameters",
			init: func(c *Client, r *Request) {
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
			init: func(c *Client, r *Request) {
				c.SetPathParams(map[string]string{
					"foo": "1", // ignored, because of the request's "foo"
					"bar": "2/3",
				})
				r.SetPathParams(map[string]string{
					"foo": "4/5",
				})
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/4%2F5/2%2F3",
		},
		{
			name: "apply client raw path parameters",
			init: func(c *Client, r *Request) {
				c.SetRawPathParams(map[string]string{
					"foo": "1/2",
					"bar": "3",
				})
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/1/2/3",
		},
		{
			name: "apply request raw path parameters",
			init: func(c *Client, r *Request) {
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
			init: func(c *Client, r *Request) {
				c.SetRawPathParams(map[string]string{
					"foo": "1", // ignored, because of the request's "foo"
					"bar": "2/3",
				})
				r.SetRawPathParams(map[string]string{
					"foo": "4/5",
				})
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/4/5/2/3",
		},
		{
			name: "apply request path and raw path parameters",
			init: func(c *Client, r *Request) {
				r.SetPathParams(map[string]string{
					"foo": "4/5",
				}).SetRawPathParams(map[string]string{
					"foo": "4/5", // ignored, because the PathParams takes precedence over the RawPathParams
					"bar": "6/7",
				})
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/4%2F5/6/7",
		},
		{
			name: "empty path parameter in URL",
			init: func(c *Client, r *Request) {
				r.SetPathParams(map[string]string{
					"bar": "4",
				})
				r.URL = "https://example.com/{}/{bar}"
			},
			expectedURL: "https://example.com/%7B%7D/4",
		},
		{
			name: "not closed path parameter in URL",
			init: func(c *Client, r *Request) {
				r.SetPathParams(map[string]string{
					"foo": "4",
				})
				r.URL = "https://example.com/{foo}/{bar/1"
			},
			expectedURL: "https://example.com/4/%7Bbar/1",
		},
		{
			name: "extra path parameter in URL",
			init: func(c *Client, r *Request) {
				r.SetPathParams(map[string]string{
					"foo": "1",
				})
				r.URL = "https://example.com/{foo}/{bar}"
			},
			expectedURL: "https://example.com/1/%7Bbar%7D",
		},
		{
			name: " path parameter with remainder",
			init: func(c *Client, r *Request) {
				r.SetPathParams(map[string]string{
					"foo": "1",
				})
				r.URL = "https://example.com/{foo}/2"
			},
			expectedURL: "https://example.com/1/2",
		},
		{
			name: "using BaseURL with absolute URL in request",
			init: func(c *Client, r *Request) {
				c.SetBaseURL("https://foo.bar") // ignored
				r.URL = "https://example.com/"
			},
			expectedURL: "https://example.com/",
		},
		{
			name: "using BaseURL with relative path in request URL without leading slash",
			init: func(c *Client, r *Request) {
				c.SetBaseURL("https://example.com")
				r.URL = "foo/bar"
			},
			expectedURL: "https://example.com/foo/bar",
		},
		{
			name: "using BaseURL with relative path in request URL wit leading slash",
			init: func(c *Client, r *Request) {
				c.SetBaseURL("https://example.com")
				r.URL = "/foo/bar"
			},
			expectedURL: "https://example.com/foo/bar",
		},
		{
			name: "using deprecated HostURL with relative path in request URL",
			init: func(c *Client, r *Request) {
				c.HostURL = "https://example.com"
				r.URL = "foo/bar"
			},
			expectedURL: "https://example.com/foo/bar",
		},
		{
			name: "request URL without scheme",
			init: func(c *Client, r *Request) {
				r.URL = "example.com/foo/bar"
			},
			expectedURL: "/example.com/foo/bar",
		},
		{
			name: "BaseURL without scheme",
			init: func(c *Client, r *Request) {
				c.SetBaseURL("example.com")
				r.URL = "foo/bar"
			},
			expectedURL: "example.com/foo/bar",
		},
		{
			name: "using SetScheme and BaseURL without scheme",
			init: func(c *Client, r *Request) {
				c.SetBaseURL("example.com").SetScheme("https")
				r.URL = "foo/bar"
			},
			expectedURL: "https://example.com/foo/bar",
		},
		{
			name: "adding query parameters by client",
			init: func(c *Client, r *Request) {
				c.SetQueryParams(map[string]string{
					"foo": "1",
					"bar": "2",
				})
				r.URL = "https://example.com/"
			},
			expectedURL: "https://example.com/?foo=1&bar=2",
		},
		{
			name: "adding query parameters by request",
			init: func(c *Client, r *Request) {
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
			init: func(c *Client, r *Request) {
				c.SetQueryParams(map[string]string{
					"foo": "1", // ignored, because of the "foo" parameter in request
					"bar": "2",
				})
				r.SetQueryParams(map[string]string{
					"foo": "3",
				})
				r.URL = "https://example.com/"
			},
			expectedURL: "https://example.com/?foo=3&bar=2",
		},
		{
			name: "adding query parameters by request to URL with existent",
			init: func(c *Client, r *Request) {
				r.SetQueryParams(map[string]string{
					"bar": "2",
				})
				r.URL = "https://example.com/?foo=1"
			},
			expectedURL: "https://example.com/?foo=1&bar=2",
		},
		{
			name: "adding query parameters by request with multiple values",
			init: func(c *Client, r *Request) {
				r.QueryParam.Add("foo", "1")
				r.QueryParam.Add("foo", "2")
				r.URL = "https://example.com/"
			},
			expectedURL: "https://example.com/?foo=1&foo=2",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := New()
			r := c.R()
			tt.init(c, r)
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

func Benchmark_parseRequestURL_PathParams(b *testing.B) {
	c := New().SetPathParams(map[string]string{
		"foo": "1",
		"bar": "2",
	}).SetRawPathParams(map[string]string{
		"foo": "3",
		"xyz": "4",
	})
	r := c.R().SetPathParams(map[string]string{
		"foo": "5",
		"qwe": "6",
	}).SetRawPathParams(map[string]string{
		"foo": "7",
		"asd": "8",
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.URL = "https://example.com/{foo}/{bar}/{xyz}/{qwe}/{asd}"
		if err := parseRequestURL(c, r); err != nil {
			b.Errorf("parseRequestURL() error = %v", err)
		}
	}
}

func Benchmark_parseRequestURL_QueryParams(b *testing.B) {
	c := New().SetQueryParams(map[string]string{
		"foo": "1",
		"bar": "2",
	})
	r := c.R().SetQueryParams(map[string]string{
		"foo": "5",
		"qwe": "6",
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.URL = "https://example.com/"
		if err := parseRequestURL(c, r); err != nil {
			b.Errorf("parseRequestURL() error = %v", err)
		}
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
				http.CanonicalHeaderKey("foo"):           []string{"1"},
				http.CanonicalHeaderKey("bar"):           []string{"2"},
				http.CanonicalHeaderKey(hdrUserAgentKey): []string{hdrUserAgentValue},
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
				http.CanonicalHeaderKey("foo"):           []string{"1"},
				http.CanonicalHeaderKey("bar"):           []string{"2"},
				http.CanonicalHeaderKey(hdrUserAgentKey): []string{hdrUserAgentValue},
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
				http.CanonicalHeaderKey("foo"):           []string{"3"},
				http.CanonicalHeaderKey("bar"):           []string{"2"},
				http.CanonicalHeaderKey("xyz"):           []string{"4"},
				http.CanonicalHeaderKey(hdrUserAgentKey): []string{hdrUserAgentValue},
			},
		},
		{
			name: "no headers",
			init: func(c *Client, r *Request) {},
			expectedHeader: http.Header{
				http.CanonicalHeaderKey(hdrUserAgentKey): []string{hdrUserAgentValue},
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
				http.CanonicalHeaderKey(hdrContentTypeKey): []string{"application/json"},
				http.CanonicalHeaderKey(hdrAcceptKey):      []string{"application/json"},
				http.CanonicalHeaderKey(hdrUserAgentKey):   []string{hdrUserAgentValue},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := New()
			r := c.R()
			tt.init(c, r)
			if err := parseRequestHeader(c, r); err != nil {
				t.Errorf("parseRequestHeader() error = %v", err)
			}
			if !reflect.DeepEqual(tt.expectedHeader, r.Header) {
				t.Errorf("r.Header = %#+v does not match expected %#+v", r.Header, tt.expectedHeader)
			}
		})
	}
}

func Benchmark_parseRequestHeader(b *testing.B) {
	c := New()
	r := c.R()
	c.SetHeaders(map[string]string{
		"foo": "1", // ignored, because of the same header in the request
		"bar": "2",
	})
	r.SetHeaders(map[string]string{
		"foo": "3",
		"xyz": "4",
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestHeader(c, r); err != nil {
			b.Errorf("parseRequestHeader() error = %v", err)
		}
	}
}

type errorReader struct{}

func (errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("fake")
}

func Test_parseRequestBody(t *testing.T) {
	for _, tt := range []struct {
		name                  string
		init                  func(c *Client, r *Request)
		expectedBodyBuf       []byte
		expectedContentLength string
		expectedContentType   string
		wantErr               bool
	}{
		{
			name: "empty body",
			init: func(c *Client, r *Request) {},
		},
		{
			name: "empty body with SetContentLength by request",
			init: func(c *Client, r *Request) {
				r.SetContentLength(true)
			},
			expectedContentLength: "0",
		},
		{
			name: "empty body with SetContentLength by client",
			init: func(c *Client, r *Request) {
				c.SetContentLength(true)
			},
			expectedContentLength: "0",
		},
		{
			name: "string body",
			init: func(c *Client, r *Request) {
				r.SetBody("foo")
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with GET method",
			init: func(c *Client, r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodGet
			},
		},
		{
			name: "string body with GET method and AllowGetMethodPayload",
			init: func(c *Client, r *Request) {
				c.SetAllowGetMethodPayload(true)
				r.SetBody("foo")
				r.Method = http.MethodGet
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with HEAD method",
			init: func(c *Client, r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodHead
			},
		},
		{
			name: "string body with OPTIONS method",
			init: func(c *Client, r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodOptions
			},
		},
		{
			name: "string body with POST method",
			init: func(c *Client, r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodPost
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with PATCH method",
			init: func(c *Client, r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodPatch
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with PUT method",
			init: func(c *Client, r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodPut
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with DELETE method",
			init: func(c *Client, r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodDelete
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with CONNECT method",
			init: func(c *Client, r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodConnect
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with TRACE method",
			init: func(c *Client, r *Request) {
				r.SetBody("foo")
				r.Method = http.MethodTrace
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "string body with BAR method",
			init: func(c *Client, r *Request) {
				r.SetBody("foo")
				r.Method = "BAR"
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "byte body",
			init: func(c *Client, r *Request) {
				r.SetBody([]byte("foo"))
			},
			expectedBodyBuf:     []byte("foo"),
			expectedContentType: plainTextType,
		},
		{
			name: "io.Reader body, no bodyBuf",
			init: func(c *Client, r *Request) {
				r.SetBody(bytes.NewBufferString("foo"))
			},
			expectedContentType: jsonContentType,
		},
		{
			name: "io.Reader body with SetContentLength by request",
			init: func(c *Client, r *Request) {
				r.SetBody(bytes.NewBufferString("foo")).
					SetContentLength(true)
			},
			expectedBodyBuf:       []byte("foo"),
			expectedContentLength: "3",
			expectedContentType:   jsonContentType,
		},
		{
			name: "io.Reader body with SetContentLength by client",
			init: func(c *Client, r *Request) {
				c.SetContentLength(true)
				r.SetBody(bytes.NewBufferString("foo"))
			},
			expectedBodyBuf:       []byte("foo"),
			expectedContentLength: "3",
			expectedContentType:   jsonContentType,
		},
		{
			name: "form data by request",
			init: func(c *Client, r *Request) {
				r.SetFormData(map[string]string{
					"foo": "1",
					"bar": "2",
				})
			},
			expectedBodyBuf:     []byte("foo=1&bar=2"),
			expectedContentType: formContentType,
		},
		{
			name: "form data by client",
			init: func(c *Client, r *Request) {
				c.SetFormData(map[string]string{
					"foo": "1",
					"bar": "2",
				})
			},
			expectedBodyBuf:     []byte("foo=1&bar=2"),
			expectedContentType: formContentType,
		},
		{
			name: "form data by client and request",
			init: func(c *Client, r *Request) {
				c.SetFormData(map[string]string{
					"foo": "1",
					"bar": "2",
				})
				r.SetFormData(map[string]string{
					"foo": "3",
					"baz": "4",
				})
			},
			expectedBodyBuf:     []byte("foo=3&bar=2&baz=4"),
			expectedContentType: formContentType,
		},
		{
			name: "json from struct",
			init: func(c *Client, r *Request) {
				r.SetBody(struct {
					Foo string `json:"foo"`
					Bar string `json:"bar"`
				}{
					Foo: "1",
					Bar: "2",
				}).SetContentLength(true)
			},
			expectedBodyBuf:       []byte(`{"foo":"1","bar":"2"}`),
			expectedContentType:   jsonContentType,
			expectedContentLength: "21",
		},
		{
			name: "json from slice",
			init: func(c *Client, r *Request) {
				r.SetBody([]string{"foo", "bar"}).SetContentLength(true)
			},
			expectedBodyBuf:       []byte(`["foo","bar"]`),
			expectedContentType:   jsonContentType,
			expectedContentLength: "13",
		},
		{
			name: "json from map",
			init: func(c *Client, r *Request) {
				r.SetBody(map[string]interface{}{
					"foo": "1",
					"bar": []int{1, 2, 3},
					"baz": map[string]string{
						"qux": "4",
					},
					"xyz": nil,
				}).SetContentLength(true)
			},
			expectedBodyBuf:       []byte(`{"bar":[1,2,3],"baz":{"qux":"4"},"foo":"1","xyz":null}`),
			expectedContentType:   jsonContentType,
			expectedContentLength: "54",
		},
		{
			name: "json from map",
			init: func(c *Client, r *Request) {
				r.SetBody(map[string]interface{}{
					"foo": "1",
					"bar": []int{1, 2, 3},
					"baz": map[string]string{
						"qux": "4",
					},
					"xyz": nil,
				}).SetContentLength(true)
			},
			expectedBodyBuf:       []byte(`{"bar":[1,2,3],"baz":{"qux":"4"},"foo":"1","xyz":null}`),
			expectedContentType:   jsonContentType,
			expectedContentLength: "54",
		},
		{
			name: "json from map",
			init: func(c *Client, r *Request) {
				r.SetBody(map[string]interface{}{
					"foo": "1",
					"bar": []int{1, 2, 3},
					"baz": map[string]string{
						"qux": "4",
					},
					"xyz": nil,
				}).SetContentLength(true)
			},
			expectedBodyBuf:       []byte(`{"bar":[1,2,3],"baz":{"qux":"4"},"foo":"1","xyz":null}`),
			expectedContentType:   jsonContentType,
			expectedContentLength: "54",
		},
		{
			name: "xml from struct",
			init: func(c *Client, r *Request) {
				type FooBar struct {
					Foo string `xml:"foo"`
					Bar string `xml:"bar"`
				}
				r.SetBody(FooBar{
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
			name: "mulipart form data",
			init: func(c *Client, r *Request) {
				c.SetFormData(map[string]string{
					"foo": "1",
					"bar": "2",
				})
				r.SetFormData(map[string]string{
					"foo": "3",
					"baz": "4",
				})
				r.SetMultipartFormData(map[string]string{
					"foo": "5",
					"xyz": "6",
				}).SetContentLength(true)
			},
			expectedBodyBuf:       []byte(`{"bar":"2", "baz":"4", "foo":"5", "xyz":"6"}`),
			expectedContentType:   "multipart/form-data; boundary=",
			expectedContentLength: "744",
		},
		{
			name: "mulipart fields",
			init: func(c *Client, r *Request) {
				r.SetMultipartFields(
					&MultipartField{
						Param:       "foo",
						ContentType: "text/plain",
						Reader:      strings.NewReader("1"),
					},
					&MultipartField{
						Param:       "bar",
						ContentType: "text/plain",
						Reader:      strings.NewReader("2"),
					},
				).SetContentLength(true)
			},
			expectedBodyBuf:       []byte(`{"bar":"2","foo":"1"}`),
			expectedContentType:   "multipart/form-data; boundary=",
			expectedContentLength: "344",
		},
		{
			name: "mulipart files",
			init: func(c *Client, r *Request) {
				r.SetFileReader("foo", "foo.txt", strings.NewReader("1")).
					SetFileReader("bar", "bar.txt", strings.NewReader("2")).
					SetContentLength(true)
			},
			expectedBodyBuf:       []byte(`{"bar":"2","foo":"1"}`),
			expectedContentType:   "multipart/form-data; boundary=",
			expectedContentLength: "412",
		},
		{
			name: "body with errorReader",
			init: func(c *Client, r *Request) {
				r.SetBody(&errorReader{}).SetContentLength(true)
			},
			wantErr: true,
		},
		{
			name: "unsupported type",
			init: func(c *Client, r *Request) {
				r.SetBody(1)
			},
			wantErr: true,
		},
		{
			name: "unsupported xml",
			init: func(c *Client, r *Request) {
				r.SetBody(struct {
					Foo string `xml:"foo"`
					Bar string `xml:"bar"`
				}{
					Foo: "1",
					Bar: "2",
				}).Header.Set(hdrContentTypeKey, "text/xml")
			},
			wantErr: true,
		},
		{
			name: "multipart fields with errorReader",
			init: func(c *Client, r *Request) {
				r.SetMultipartFields(&MultipartField{
					Param:       "foo",
					ContentType: "text/plain",
					Reader:      &errorReader{},
				})
			},
			wantErr: true,
		},
		{
			name: "multipart files with errorReader",
			init: func(c *Client, r *Request) {
				r.SetFileReader("foo", "foo.txt", &errorReader{})
			},
			wantErr: true,
		},
		{
			name: "multipart with file not found",
			init: func(c *Client, r *Request) {
				r.SetFormData(map[string]string{
					"@foo": "foo.txt",
				})
				r.isMultiPart = true
			},
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := New()
			r := c.R()
			tt.init(c, r)
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
				var actual, expected interface{} = r.bodyBuf.Bytes(), tt.expectedBodyBuf
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
					body := make(map[string]interface{})
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

func Benchmark_parseRequestBody_string(b *testing.B) {
	c := New()
	r := c.R()
	r.SetBody("foo").SetContentLength(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_byte(b *testing.B) {
	c := New()
	r := c.R()
	r.SetBody([]byte("foo")).SetContentLength(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_reader_with_SetContentLength(b *testing.B) {
	c := New()
	r := c.R()
	r.SetBody(bytes.NewBufferString("foo")).SetContentLength(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_reader_without_SetContentLength(b *testing.B) {
	c := New()
	r := c.R()
	r.SetBody(bytes.NewBufferString("foo"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_struct(b *testing.B) {
	type FooBar struct {
		Foo string `json:"foo"`
		Bar string `json:"bar"`
	}
	c := New()
	r := c.R()
	r.SetBody(FooBar{Foo: "1", Bar: "2"}).SetContentLength(true).SetHeader(hdrContentTypeKey, jsonContentType)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_struct_xml(b *testing.B) {
	type FooBar struct {
		Foo string `xml:"foo"`
		Bar string `xml:"bar"`
	}
	c := New()
	r := c.R()
	r.SetBody(FooBar{Foo: "1", Bar: "2"}).SetContentLength(true).SetHeader(hdrContentTypeKey, "text/xml")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_map(b *testing.B) {
	c := New()
	r := c.R()
	r.SetBody(map[string]string{
		"foo": "1",
		"bar": "2",
	}).SetContentLength(true).SetHeader(hdrContentTypeKey, jsonContentType)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_slice(b *testing.B) {
	c := New()
	r := c.R()
	r.SetBody([]string{"1", "2"}).SetContentLength(true).SetHeader(hdrContentTypeKey, jsonContentType)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_FormData(b *testing.B) {
	c := New()
	r := c.R()
	c.SetFormData(map[string]string{"foo": "1", "bar": "2"})
	r.SetFormData(map[string]string{"foo": "3", "baz": "4"}).SetContentLength(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_MultiPart(b *testing.B) {
	c := New()
	r := c.R()
	c.SetFormData(map[string]string{"foo": "1", "bar": "2"})
	r.SetFormData(map[string]string{"foo": "3", "baz": "4"}).
		SetMultipartFormData(map[string]string{"foo": "5", "xyz": "6"}).
		SetFileReader("qwe", "qwe.txt", strings.NewReader("7")).
		SetMultipartFields(
			&MultipartField{
				Param:       "sdj",
				ContentType: "text/plain",
				Reader:      strings.NewReader("8"),
			},
		).
		SetContentLength(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}
