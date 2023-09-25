package resty

import (
	"net/url"
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
				c.SetQueryParams(map[string]string{
					"foo": "3",
				})
				r.URL = "https://example.com/"
			},
			expectedURL: "https://example.com/?foo=3&bar=2",
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
			if len(expectedQuery) != len(actualQuery) {
				t.Errorf("r.URL = %q does not match expected %q", r.URL, tt.expectedURL)
			}
			for name, expected := range expectedQuery {
				actual, ok := actualQuery[name]
				if !ok {
					t.Errorf("r.URL = %q does not match expected %q", r.URL, tt.expectedURL)
				}
				if len(expected) != len(actual) {
					t.Errorf("r.URL = %q does not match expected %q", r.URL, tt.expectedURL)
				}
				for i, v := range expected {
					if v != actual[i] {
						t.Errorf("r.URL = %q does not match expected %q", r.URL, tt.expectedURL)
					}
				}
			}
		})
	}
}
