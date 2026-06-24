// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// MethodGet is the HTTP GET method.
	MethodGet = "GET"

	// MethodPost is the HTTP POST method.
	MethodPost = "POST"

	// MethodPut is the HTTP PUT method.
	MethodPut = "PUT"

	// MethodDelete is the HTTP DELETE method.
	MethodDelete = "DELETE"

	// MethodPatch is the HTTP PATCH method.
	MethodPatch = "PATCH"

	// MethodHead is the HTTP HEAD method.
	MethodHead = "HEAD"

	// MethodOptions is the HTTP OPTIONS method.
	MethodOptions = "OPTIONS"

	// MethodTrace is the HTTP TRACE method.
	MethodTrace = "TRACE"
)

const (
	defaultWatcherPoolingInterval = 24 * time.Hour
)

var (
	// ErrNotHttpTransportType is returned when the underlying transport is not an [http.Transport].
	ErrNotHttpTransportType = errors.New("resty: not a http.Transport type")

	// ErrUnsupportedRequestBodyKind is returned when the request body is of an unsupported kind.
	ErrUnsupportedRequestBodyKind = errors.New("resty: unsupported request body kind")

	// ErrReaderNotSeekable is returned when a non-seekable request body reader is
	// used on a retry attempt. This applies to both generic [io.Reader] request
	// bodies (see [Request.SetBody]) and to [MultipartField.Reader] when retrying.
	ErrReaderNotSeekable = errors.New("resty: reader is not seekable on request retry")

	hdrUserAgentKey       = http.CanonicalHeaderKey("User-Agent")
	hdrAcceptKey          = http.CanonicalHeaderKey("Accept")
	hdrAcceptEncodingKey  = http.CanonicalHeaderKey("Accept-Encoding")
	hdrContentTypeKey     = http.CanonicalHeaderKey("Content-Type")
	hdrContentLengthKey   = http.CanonicalHeaderKey("Content-Length")
	hdrContentEncodingKey = http.CanonicalHeaderKey("Content-Encoding")
	hdrContentDisposition = http.CanonicalHeaderKey("Content-Disposition")
	hdrAuthorizationKey   = http.CanonicalHeaderKey("Authorization")
	hdrWwwAuthenticateKey = http.CanonicalHeaderKey("WWW-Authenticate")
	hdrRetryAfterKey      = http.CanonicalHeaderKey("Retry-After")
	hdrCookieKey          = http.CanonicalHeaderKey("Cookie")

	plainTextType   = "text/plain; charset=utf-8"
	jsonContentType = "application/json"
	formContentType = "application/x-www-form-urlencoded"

	jsonKey = "json"
	xmlKey  = "xml"

	defaultAuthScheme = "Bearer"

	hdrUserAgentValue = "go-resty/" + Version + " (https://resty.dev)"
	bufPool           = &sync.Pool{New: func() any { return &bytes.Buffer{} }}
)

type (
	// RequestMiddleware is a type of middleware that is executed during the request
	// processing phase before Resty sends the request to the server.
	//
	// It is ideal for:
	//   - Intercept Request instance for manipulation
	//   - Terminate the Request early by returning non-nil error
	//   - etc.
	// See methods [Client.AddRequestMiddleware], [Client.SetRequestMiddlewares].
	//
	// Resty provides some built-in request middlewares such as:
	//   - [PrepareRequestMiddleware]: creates the [http.Request] instance using the Resty [Request] instance.
	RequestMiddleware func(*Client, *Request) error

	// ResponseMiddleware is a type of middleware that is called after a response
	// has been received. All the response middlewares are executed with a [Response] instance
	// before returning the response to the caller.
	//
	// NOTE:
	//   - In v3, all response middleware is executed irrespective of the error.
	//     The error details are passed down to the subsequent response middleware through
	//     the [Response].CascadeError field.
	//   - Before processing your middleware, ensure to check [Response].CascadeError.
	//
	// See methods [Client.AddResponseMiddleware], [Client.SetResponseMiddlewares].
	//
	// Resty provides some built-in response middlewares such as:
	//   - [AutoParseResponseMiddleware]: automatically parses the response body into the provided
	//      struct in [Request.SetResult] or [Request.SetResultError] based on response status code.
	//   - [SaveToFileResponseMiddleware]: saves the response body to a file when [Request.SetOutputFileName]
	//      or [Request.SetSaveResponse] is used.
	ResponseMiddleware func(*Client, *Response) error

	// ErrorHook is a type used to handle request errors. It’s used as a type in the
	// Client.OnError, Client.OnInvalid, and Client.OPanic hooks.
	//
	// These hooks are called once during the request and response lifecycle.
	ErrorHook func(*Request, error)

	// SuccessHook is called after a request completes successfully.
	SuccessHook func(*Client, *Response)

	// CloseHook is called when the [Client] is closed.
	CloseHook func()

	// RequestFunc is a function type for extended manipulation of a [Request] instance.
	RequestFunc func(*Request) *Request

	// TLSClientConfiger interface is to configure TLS Client configuration on custom transport
	// implemented using [http.RoundTripper]
	TLSClientConfiger interface {
		TLSClientConfig() *tls.Config
		SetTLSClientConfig(*tls.Config) error
	}
)

// TransportSettings struct is used to define custom dialer and transport
// values for the Resty client. Please refer to individual
// struct fields to know the default values.
//
// Also, refer to https://pkg.go.dev/net/http#Transport for more details.
type TransportSettings struct {
	// DialerTimeout, default value is `30` seconds.
	DialerTimeout time.Duration

	// DialerKeepAlive, default value is `30` seconds.
	DialerKeepAlive time.Duration

	// IdleConnTimeout, default value is `90` seconds.
	IdleConnTimeout time.Duration

	// TLSHandshakeTimeout, default value is `10` seconds.
	TLSHandshakeTimeout time.Duration

	// ExpectContinueTimeout, default value is `1` seconds.
	ExpectContinueTimeout time.Duration

	// ResponseHeaderTimeout, added to provide ability to
	// set value. No default value in Resty, the Go
	// HTTP client default value applies.
	ResponseHeaderTimeout time.Duration

	// MaxIdleConns, default value is `100`.
	MaxIdleConns int

	// MaxIdleConnsPerHost, default value is `runtime.GOMAXPROCS(0) + 1`.
	MaxIdleConnsPerHost int

	// MaxConnsPerHost, default value is no limit.
	MaxConnsPerHost int

	// DisableKeepAlives, default value is `false`.
	DisableKeepAlives bool

	// MaxResponseHeaderBytes, added to provide ability to
	// set value. No default value in Resty, the Go
	// HTTP client default value applies.
	MaxResponseHeaderBytes int64

	// WriteBufferSize, added to provide ability to
	// set value. No default value in Resty, the Go
	// HTTP client default value applies.
	WriteBufferSize int

	// ReadBufferSize, added to provide ability to
	// set value. No default value in Resty, the Go
	// HTTP client default value applies.
	ReadBufferSize int
}

// Client struct is used to create a Resty client with client-level settings,
// these settings apply to all the requests raised from the client.
//
// Resty also provides an option to override most of the client settings
// at [Request] level.
type Client struct {
	lock                       *sync.RWMutex
	baseURL                    string
	queryParams                url.Values
	formData                   url.Values
	pathParams                 map[string]string
	header                     http.Header
	credentials                *credentials
	authToken                  string
	authScheme                 string
	cookies                    []*http.Cookie
	errorType                  reflect.Type
	debug                      bool
	disableWarn                bool
	isMethodGetAllowPayload    bool
	isMethodDeleteAllowPayload bool
	timeout                    time.Duration
	retryCount                 int
	retryWaitTime              time.Duration
	retryMaxWaitTime           time.Duration
	retryConditions            []RetryConditionFunc
	retryHooks                 []RetryHookFunc
	retryDelayStrategy         RetryDelayStrategyFunc
	isRetryDefaultConditions   bool
	isRetryAllowNonIdempotent  bool
	headerAuthorizationKey     string
	responseBodyLimit          int64
	resBodyUnlimitedReads      bool
	jsonEscapeHTML             bool
	closeConnection            bool
	isResponseDoNotParse       bool
	isTrace                    bool
	debugBodyLimit             int
	responseSaveDirectory      string
	isResponseSaveToFile       bool
	scheme                     string
	log                        Logger
	ctx                        context.Context
	httpClient                 *http.Client
	proxyURL                   *url.URL
	debugLogFormatter          DebugLogFormatterFunc
	debugLogCallback           DebugLogCallbackFunc
	isCurlCmdGenerate          bool
	isCurlCmdDebugLog          bool
	unescapeQueryParams        bool
	loadBalancer               LoadBalancer
	beforeRequest              []RequestMiddleware
	afterResponse              []ResponseMiddleware
	errorHooks                 []ErrorHook
	invalidHooks               []ErrorHook
	panicHooks                 []ErrorHook
	successHooks               []SuccessHook
	closeHooks                 []CloseHook
	contentTypeEncoders        map[string]ContentTypeEncoder
	contentTypeDecoders        map[string]ContentTypeDecoder
	contentDecompresserKeys    []string
	contentDecompressers       map[string]ContentDecompresser
	certWatcherStopChan        chan bool
	isClosed                   bool
	circuitBreaker             CircuitBreaker
	hedging                    Hedger
	rateLimiter                RateLimiter
}

// CertWatcherOptions configures the certificate file watcher that reloads TLS
// certificates dynamically. See [Client.SetRootCertificatesWatcher],
// [Client.SetClientRootCertificatesWatcher].
type CertWatcherOptions struct {
	// PoolInterval is the frequency at which resty will check if the PEM file needs to be reloaded.
	// Default is 24 hours.
	PoolInterval time.Duration
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Client methods
//___________________________________

// BaseURL method returns the Base URL value from the client instance.
func (c *Client) BaseURL() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.baseURL
}

// SetBaseURL method sets the Base URL in the client instance. It will be used with a request
// raised from this client with a relative URL
//
//	// Setting HTTP address
//	client.SetBaseURL("http://myjeeva.com")
//
//	// Setting HTTPS address
//	client.SetBaseURL("https://myjeeva.com")
func (c *Client) SetBaseURL(url string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.baseURL = strings.TrimRight(url, "/")
	return c
}

// LoadBalancer method returns the load balancer set on the client, or nil if none is set.
func (c *Client) LoadBalancer() LoadBalancer {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.loadBalancer
}

// SetLoadBalancer method sets the load balancer used for request routing.
func (c *Client) SetLoadBalancer(b LoadBalancer) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.loadBalancer = b
	return c
}

// Header method returns the headers from the client instance.
func (c *Client) Header() http.Header {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.header
}

// SetHeader method sets a single header and its value in the client instance.
// These headers will be applied to all requests raised from the client instance.
// Also, it can be overridden by request-level header options.
//
// For Example: To set `Content-Type` and `Accept` as `application/json`
//
//	client.
//		SetHeader("Content-Type", "application/json").
//		SetHeader("Accept", "application/json")
//
// See [Request.SetHeader] or [Request.SetHeaders].
func (c *Client) SetHeader(header, value string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.header.Set(header, value)
	return c
}

// SetHeaderAny method sets a single header field and its value in the client instance
// for all requests raised from the client.
//
// It is similar to [Client.SetHeader] but accepts any type as the value and converts
// it to a string using predefined formatting rules (integers, bools, time.Time, etc.).
//
// For Example: To set `X-Request-Id` with an integer value
//
//	client.SetHeaderAny("X-Request-Id", 12345)
//
// See [Request.SetHeaderAny] or [Client.SetHeader].
func (c *Client) SetHeaderAny(header string, value any) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	strVal := formatAnyToString(value)
	c.header.Set(header, strVal)
	return c
}

// SetHeaders method sets multiple headers and their values at one go, and
// these headers will be applied to all requests raised from the client instance.
// Also, it can be overridden at request-level headers options.
//
// For Example: To set `Content-Type` and `Accept` as `application/json`
//
//	client.SetHeaders(map[string]string{
//		"Content-Type": "application/json",
//		"Accept": "application/json",
//	})
//
// See [Request.SetHeaders] or [Request.SetHeader].
func (c *Client) SetHeaders(headers map[string]string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	for h, v := range headers {
		c.header.Set(h, v)
	}
	return c
}

// SetHeaderVerbatim method is used to set the HTTP header key and value verbatim in the current request.
// It is typically helpful for legacy applications or servers that require HTTP headers in a certain way
//
// For Example: To set header key as `all_lowercase`, `UPPERCASE`, and `x-cloud-trace-id`
//
//	client.
//		SetHeaderVerbatim("all_lowercase", "available").
//		SetHeaderVerbatim("UPPERCASE", "available").
//		SetHeaderVerbatim("x-cloud-trace-id", "798e94019e5fc4d57fbb8901eb4c6cae")
//
// See [Request.SetHeaderVerbatim].
func (c *Client) SetHeaderVerbatim(header, value string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.header[header] = []string{value}
	return c
}

// SetHeaderVerbatimAny method sets the HTTP header key and value verbatim in the client instance
// for all requests raised from the client.
//
// It is similar to [Client.SetHeaderVerbatim] but accepts any type as the value and converts
// it to a string using predefined formatting rules (integers, bools, time.Time, etc.).
//
// For Example: To set header key as `x-trace-id` with an integer value
//
//	client.SetHeaderVerbatimAny("x-trace-id", 798940)
//
// See [Request.SetHeaderVerbatimAny] or [Client.SetHeaderVerbatim].
func (c *Client) SetHeaderVerbatimAny(header string, value any) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	strVal := formatAnyToString(value)
	c.header[header] = []string{strVal}
	return c
}

// Context method returns the [context.Context] from the client instance.
func (c *Client) Context() context.Context {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.ctx
}

// SetContext method sets the context on the client instance; it is attached
// to every [Request] raised from this client.
func (c *Client) SetContext(ctx context.Context) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.ctx = ctx
	return c
}

// CookieJar method returns the HTTP cookie jar instance from the underlying Go HTTP Client.
func (c *Client) CookieJar() http.CookieJar {
	return c.Client().Jar
}

// SetCookieJar method sets the cookie jar on the client, replacing any existing jar.
//
// For Example, sometimes we don't want to save cookies in API mode so that we can remove the default
// CookieJar in resty client.
//
//	client.SetCookieJar(nil)
func (c *Client) SetCookieJar(jar http.CookieJar) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.httpClient.Jar = jar
	return c
}

// Cookies method returns all cookies registered in the client instance.
func (c *Client) Cookies() []*http.Cookie {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.cookies
}

// SetCookie method appends a single cookie to the client instance.
// These cookies will be added to all the requests from this client instance.
//
//	client.SetCookie(&http.Cookie{
//		Name:"go-resty",
//		Value:"This is cookie value",
//	})
func (c *Client) SetCookie(hc *http.Cookie) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.cookies = append(c.cookies, hc)
	return c
}

// SetCookies method sets an array of cookies in the client instance.
// These cookies will be added to all the requests from this client instance.
//
//	cookies := []*http.Cookie{
//		&http.Cookie{
//			Name:"go-resty-1",
//			Value:"This is cookie 1 value",
//		},
//		&http.Cookie{
//			Name:"go-resty-2",
//			Value:"This is cookie 2 value",
//		},
//	}
//
//	// Setting a cookies into resty
//	client.SetCookies(cookies)
func (c *Client) SetCookies(cs []*http.Cookie) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.cookies = append(c.cookies, cs...)
	return c
}

// QueryParams method returns all query parameters and their values from the client instance.
func (c *Client) QueryParams() url.Values {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.queryParams
}

// SetQueryParam method sets a single parameter and its value in the client instance.
// It will be formed as a query string for the request.
//
//	For Example: `search=kitchen%20papers&size=large`
//
// In the URL after the `?` mark. These query params will be added to all the requests raised from
// this client instance. Also, it can be overridden at the request level.
//
// See [Request.SetQueryParam] or [Request.SetQueryParams].
//
//	client.
//		SetQueryParam("search", "kitchen papers").
//		SetQueryParam("size", "large")
func (c *Client) SetQueryParam(param, value string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.queryParams.Set(param, value)
	return c
}

// SetQueryParamAny method sets a single query parameter and its value in the client instance.
// It will be formed as a query string for the request.
//
// It is similar to [Client.SetQueryParam] but accepts any type as the value and converts
// it to a string using predefined formatting rules (integers, bools, time.Time, etc.).
//
// For Example: To set `page` and `active` query parameters
//
//	client.
//		SetQueryParamAny("page", 5).
//		SetQueryParamAny("active", true)
//
// See [Request.SetQueryParamAny] or [Client.SetQueryParam].
func (c *Client) SetQueryParamAny(param string, value any) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	strVal := formatAnyToString(value)
	c.queryParams.Set(param, strVal)
	return c
}

// SetQueryParams method sets multiple parameters and their values at one go in the client instance.
// It will be formed as a query string for the request.
//
//	For Example: `search=kitchen%20papers&size=large`
//
// In the URL after the `?` mark. These query params will be added to all the requests raised from this
// client instance. Also, it can be overridden at the request level.
//
// See [Request.SetQueryParams] or [Request.SetQueryParam].
//
//	client.SetQueryParams(map[string]string{
//		"search": "kitchen papers",
//		"size": "large",
//	})
func (c *Client) SetQueryParams(params map[string]string) *Client {
	// Do not lock here since there is potential deadlock.
	for p, v := range params {
		c.SetQueryParam(p, v)
	}
	return c
}

// FormData method returns the form parameters and their values from the client instance.
func (c *Client) FormData() url.Values {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.formData
}

// SetFormData method sets Form parameters and their values in the client instance.
// The request content type would be set as `application/x-www-form-urlencoded`.
// The client-level form data gets added to all the requests. Also, it can be
// overridden at the request level.
//
// See [Request.SetFormData].
//
//	client.SetFormData(map[string]string{
//		"access_token": "BC594900-518B-4F7E-AC75-BD37F019E08F",
//		"user_id": "3455454545",
//	})
func (c *Client) SetFormData(data map[string]string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	for k, v := range data {
		c.formData.Set(k, v)
	}
	return c
}

// SetBasicAuth method sets the basic authentication header in the HTTP request.
//
//	Authorization: Basic <base64-encoded-value>
//
// For example: To set the header for username "go-resty" and password "welcome"
//
//	client.SetBasicAuth("go-resty", "welcome")
//
// This basic auth information is added to all requests from this client instance.
// It can also be overridden at the request level.
//
// See [Request.SetBasicAuth].
func (c *Client) SetBasicAuth(username, password string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.credentials = &credentials{Username: username, Password: password}
	return c
}

// AuthToken method returns the auth token value registered in the client instance.
func (c *Client) AuthToken() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.authToken
}

// HeaderAuthorizationKey method returns the HTTP header name for Authorization from the client instance.
func (c *Client) HeaderAuthorizationKey() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.headerAuthorizationKey
}

// SetHeaderAuthorizationKey method sets the given HTTP header name for Authorization in the client instance.
//
// It can be overridden at the request level; see [Request.SetHeaderAuthorizationKey].
//
//	client.SetHeaderAuthorizationKey("X-Custom-Authorization")
func (c *Client) SetHeaderAuthorizationKey(k string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.headerAuthorizationKey = k
	return c
}

// SetAuthToken method sets the auth token of the Authorization header for all HTTP requests.
// The default auth scheme is Bearer; it can be customized via [Client.SetAuthScheme].
//
//	Authorization: <auth-scheme> <auth-token-value>
//
// For Example: To set auth token BC594900518B4F7EAC75BD37F019E08FBC594900518B4F7EAC75BD37F019E08F
//
//	client.SetAuthToken("BC594900518B4F7EAC75BD37F019E08FBC594900518B4F7EAC75BD37F019E08F")
//
// This auth token gets added to all the requests raised from this client instance.
// Also, it can be overridden at the request level.
//
// See [Request.SetAuthToken].
func (c *Client) SetAuthToken(token string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.authToken = token
	return c
}

// AuthScheme method returns the auth scheme name set in the client instance.
//
// See [Client.SetAuthScheme], [Request.SetAuthScheme].
func (c *Client) AuthScheme() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.authScheme
}

// SetAuthScheme method sets the auth scheme type in the HTTP request. For Example:
//
//	Authorization: <auth-scheme-value> <auth-token-value>
//
// For Example: To set the scheme to use OAuth
//
//	client.SetAuthScheme("OAuth")
//
// This auth scheme gets added to all the requests raised from this client instance.
// Also, it can be overridden at the request level.
//
// Information about auth schemes can be found in [RFC 7235], IANA [HTTP Auth schemes].
//
// See [Request.SetAuthScheme].
//
// [RFC 7235]: https://tools.ietf.org/html/rfc7235
// [HTTP Auth schemes]: https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml#authschemes
func (c *Client) SetAuthScheme(scheme string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.authScheme = scheme
	return c
}

// SetDigestAuth method sets the Digest Auth transport with provided credentials in the client.
// If a server responds with 401 and sends a Digest challenge in the header `WWW-Authenticate`,
// the request will be resent with the appropriate digest `Authorization` header.
//
// For Example: To set the Digest scheme with user "Mufasa" and password "Circle Of Life"
//
//	client.SetDigestAuth("Mufasa", "Circle Of Life")
//
// Information about Digest Access Authentication can be found in [RFC 7616].
//
// NOTE:
//   - On the QOP `auth-int` scenario, the request body is read into memory to
//     compute the body hash that increases memory usage.
//   - Create a dedicated client instance to use digest auth,
//     as it does digest auth for all the requests raised by the client.
//
// [RFC 7616]: https://datatracker.ietf.org/doc/html/rfc7616
func (c *Client) SetDigestAuth(username, password string) *Client {
	dt := &digestTransport{
		credentials: &credentials{username, password},
		transport:   c.Transport(),
	}
	c.SetTransport(dt)
	return c
}

// R method creates and returns a new [Request] instance for building and executing HTTP requests.
func (c *Client) R() *Request {
	c.lock.RLock()
	defer c.lock.RUnlock()
	r := &Request{
		QueryParams:                  url.Values{},
		FormData:                     url.Values{},
		Header:                       http.Header{},
		Cookies:                      make([]*http.Cookie, 0),
		PathParams:                   make(map[string]string),
		Timeout:                      c.timeout,
		IsDebug:                      c.debug,
		IsTrace:                      c.isTrace,
		IsResponseSaveToFile:         c.isResponseSaveToFile,
		AuthScheme:                   c.authScheme,
		AuthToken:                    c.authToken,
		RetryCount:                   c.retryCount,
		RetryWaitTime:                c.retryWaitTime,
		RetryMaxWaitTime:             c.retryMaxWaitTime,
		RetryDelayStrategy:           c.retryDelayStrategy,
		IsRetryDefaultConditions:     c.isRetryDefaultConditions,
		IsCloseConnection:            c.closeConnection,
		IsResponseDoNotParse:         c.isResponseDoNotParse,
		DebugBodyLimit:               c.debugBodyLimit,
		ResponseBodyLimit:            c.responseBodyLimit,
		IsResponseBodyUnlimitedReads: c.resBodyUnlimitedReads,
		IsMethodGetAllowPayload:      c.isMethodGetAllowPayload,
		IsMethodDeleteAllowPayload:   c.isMethodDeleteAllowPayload,
		IsRetryAllowNonIdempotent:    c.isRetryAllowNonIdempotent,
		HeaderAuthorizationKey:       c.headerAuthorizationKey,

		mu:                  new(sync.Mutex),
		client:              c,
		baseURL:             c.baseURL,
		multipartFields:     make([]*MultipartField, 0),
		jsonEscapeHTML:      c.jsonEscapeHTML,
		log:                 c.log,
		isCurlCmdGenerate:   c.isCurlCmdGenerate,
		isCurlCmdDebugLog:   c.isCurlCmdDebugLog,
		unescapeQueryParams: c.unescapeQueryParams,
		credentials:         c.credentials,
	}

	if c.ctx != nil {
		r.ctx = context.WithoutCancel(c.ctx) // refer to godoc for more info about this function
	}

	return r
}

// NewRequest method is an alias for [Client.R].
func (c *Client) NewRequest() *Request {
	return c.R()
}

// AddRequestMiddleware method appends a request middleware to the request chain.
// Method accepts a function of type [RequestMiddleware]. All the request middlewares are applied;
// before sending the request to the server.
//
// It is ideal for:
//   - Intercept Request instance for manipulation
//   - Terminate the Request early by returning non-nil error
//   - etc.
//
// See methods [Client.SetRequestMiddlewares].
//
//	client.AddRequestMiddleware(func(c *resty.Client, r *resty.Request) error {
//		// Now you have access to the Client and Request instance
//		// manipulate it as per your need
//
//		return nil 	// if it’s successful otherwise return error
//	})
//
// Resty provides some built-in request middlewares such as:
//   - [PrepareRequestMiddleware]: creates the [http.Request] instance using the Resty [Request] instance.
func (c *Client) AddRequestMiddleware(m RequestMiddleware) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	idx := len(c.beforeRequest) - 1
	c.beforeRequest = slices.Insert(c.beforeRequest, idx, m)
	return c
}

// SetRequestMiddlewares method allows Resty users to override the default request
// middleware sequence or execution chain.
//
// Method accepts a function of type [RequestMiddleware]. All the request middlewares are applied;
// before sending the request to the server.
//
//	client.SetRequestMiddlewares(
//		Custom1RequestMiddleware,
//		Custom2RequestMiddleware,
//		resty.PrepareRequestMiddleware, // after this, `Request.RawRequest` instance is available
//		Custom3RequestMiddleware,
//		Custom4RequestMiddleware,
//	)
//
// See [Client.AddRequestMiddleware] for more details.
//
// NOTE:
//   - It overwrites the existing request middleware list.
//   - Be sure to include Resty request middlewares in the request chain at the appropriate spot.
func (c *Client) SetRequestMiddlewares(middlewares ...RequestMiddleware) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.beforeRequest = middlewares
	return c
}

func (c *Client) requestMiddlewares() []RequestMiddleware {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.beforeRequest
}

// AddResponseMiddleware method appends a response middleware to the after-response chain.
// All the response middlewares are executed with a [Response] instance
// before returning the response to the caller.
//
// NOTE:
//   - In v3, all response middleware is executed irrespective of the error.
//     The error details are passed down to the subsequent response middleware through
//     the [Response].CascadeError field.
//   - Before processing your middleware, ensure to check [Response].CascadeError.
//
// Method accepts a function of type [ResponseMiddleware].
//
//	client.AddResponseMiddleware(func(c *resty.Client, r *resty.Response) error {
//		// Now you have access to the Client and Response instance
//		// Also, you could access request via Response.Request i.e., r.Request
//		// manipulate it as per your need
//
//		return nil 	// if it’s successful otherwise return error
//	})
func (c *Client) AddResponseMiddleware(m ResponseMiddleware) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.afterResponse = append(c.afterResponse, m)
	return c
}

// SetResponseMiddlewares method allows Resty users to override the default response
// middleware sequence or execution chain.
//
// Method accepts a function of type [ResponseMiddleware]. All the response middlewares are executed
// with a [Response] instance before returning the response to the caller.
//
//	client.SetResponseMiddlewares(
//		Custom1ResponseMiddleware,
//		Custom2ResponseMiddleware,
//		resty.AutoParseResponseMiddleware, // before this, the body is not read except on the debug flow
//		Custom3ResponseMiddleware,
//		resty.SaveToFileResponseMiddleware, // See, Request.SetOutputFileName, Request.SetSaveResponse
//		Custom4ResponseMiddleware,
//		Custom5ResponseMiddleware,
//	)
//
// See, [Client.AddResponseMiddleware]
//
// NOTE:
//   - It overwrites the existing response middleware list.
//   - Be sure to include Resty response middlewares in the response chain at the appropriate spot.
func (c *Client) SetResponseMiddlewares(middlewares ...ResponseMiddleware) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.afterResponse = middlewares
	return c
}

func (c *Client) responseMiddlewares() []ResponseMiddleware {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.afterResponse
}

// OnError method adds a callback that will be run whenever a request execution fails.
// This is called after all retries have been attempted (if any).
// If there was a response from the server, the error will be wrapped in [ResponseError]
// which has the last response received from the server.
//
//	client.OnError(func(req *resty.Request, err error) {
//		if v, ok := err.(*resty.ResponseError); ok {
//			// Do something with v.Response
//		}
//		// Log the error, increment a metric, etc...
//	})
//
// Out of the [Client.OnSuccess], [Client.OnError], [Client.OnInvalid], [Client.OnPanic]
// callbacks, exactly one set will be invoked for each call to [Request.Execute] that completes.
//
// NOTE:
//   - Do not use [Client] setter methods within OnError hooks; deadlock will happen.
func (c *Client) OnError(hooks ...ErrorHook) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.errorHooks = append(c.errorHooks, hooks...)
	return c
}

// OnSuccess method adds a callback that will be run whenever a request execution
// succeeds.  This is called after all retries have been attempted (if any).
//
// Out of the [Client.OnSuccess], [Client.OnError], [Client.OnInvalid], [Client.OnPanic]
// callbacks, exactly one set will be invoked for each call to [Request.Execute] that completes.
//
// NOTE:
//   - Do not use [Client] setter methods within OnSuccess hooks; deadlock will happen.
func (c *Client) OnSuccess(hooks ...SuccessHook) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.successHooks = append(c.successHooks, hooks...)
	return c
}

// OnInvalid method adds a callback that will be run whenever a request execution
// fails before it starts because the request is invalid.
//
// Out of the [Client.OnSuccess], [Client.OnError], [Client.OnInvalid], [Client.OnPanic]
// callbacks, exactly one set will be invoked for each call to [Request.Execute] that completes.
//
// NOTE:
//   - Do not use [Client] setter methods within OnInvalid hooks; deadlock will happen.
func (c *Client) OnInvalid(hooks ...ErrorHook) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.invalidHooks = append(c.invalidHooks, hooks...)
	return c
}

// OnPanic method adds a callback that will be run whenever a request execution
// panics.
//
// Out of the [Client.OnSuccess], [Client.OnError], [Client.OnInvalid], [Client.OnPanic]
// callbacks, exactly one set will be invoked for each call to [Request.Execute] that completes.
//
// If an [Client.OnSuccess], [Client.OnError], or [Client.OnInvalid] callback panics,
// then exactly one rule can be violated.
//
// NOTE:
//   - Do not use [Client] setter methods within OnPanic hooks; deadlock will happen.
func (c *Client) OnPanic(hooks ...ErrorHook) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.panicHooks = append(c.panicHooks, hooks...)
	return c
}

// OnClose method adds a callback that will be run whenever the client is closed.
// The hooks are executed in the order they were registered.
func (c *Client) OnClose(hooks ...CloseHook) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.closeHooks = append(c.closeHooks, hooks...)
	return c
}

// ContentTypeEncoders method returns all the registered content type encoders.
func (c *Client) ContentTypeEncoders() map[string]ContentTypeEncoder {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.contentTypeEncoders
}

// AddContentTypeEncoder method adds a Content-Type encoder to the client.
//
// NOTE: It overwrites the encoder function if the given Content-Type key already exists.
func (c *Client) AddContentTypeEncoder(ct string, e ContentTypeEncoder) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.contentTypeEncoders[strings.ToLower(ct)] = e
	return c
}

func (c *Client) inferContentTypeEncoder(ct ...string) (ContentTypeEncoder, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	for _, v := range ct {
		if d, f := c.contentTypeEncoders[v]; f {
			return d, f
		}
	}
	return nil, false
}

// ContentTypeDecoders method returns all the registered content type decoders.
func (c *Client) ContentTypeDecoders() map[string]ContentTypeDecoder {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.contentTypeDecoders
}

// AddContentTypeDecoder method adds a Content-Type decoder to the client.
//
// NOTE: It overwrites the decoder function if the given Content-Type key already exists.
func (c *Client) AddContentTypeDecoder(ct string, d ContentTypeDecoder) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.contentTypeDecoders[strings.ToLower(ct)] = d
	return c
}

func (c *Client) inferContentTypeDecoder(ct ...string) (ContentTypeDecoder, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	for _, v := range ct {
		if d, f := c.contentTypeDecoders[v]; f {
			return d, f
		}
	}
	return nil, false
}

// ContentDecompressers method returns all the registered content-encoding Decompressers.
func (c *Client) ContentDecompressers() map[string]ContentDecompresser {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.contentDecompressers
}

// AddContentDecompresser method adds a Content-Encoding ([RFC 9110]) decompresser
// and its directive to the client.
//
// NOTE: It overwrites the Decompresser function if the given Content-Encoding directive already exists.
//
// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
func (c *Client) AddContentDecompresser(k string, d ContentDecompresser) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	lk := strings.ToLower(k)
	if !slices.Contains(c.contentDecompresserKeys, lk) {
		c.contentDecompresserKeys = slices.Insert(c.contentDecompresserKeys, 0, lk)
	}
	c.contentDecompressers[lk] = d
	return c
}

// ContentDecompresserKeys method returns all the registered content-encoding Decompressers
// keys as comma-separated string.
func (c *Client) ContentDecompresserKeys() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return strings.Join(c.contentDecompresserKeys, ", ")
}

// SetContentDecompresserKeys method sets given Content-Encoding ([RFC 9110]) directives into the client instance.
//
// It checks the given Content-Encoding exists in the [ContentDecompresser] list before assigning it,
// if it does not exist, it will skip that directive.
//
// Use this method to overwrite the default order. If a new content Decompresser is added,
// that directive will be the first.
//
// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
func (c *Client) SetContentDecompresserKeys(keys []string) *Client {
	result := make([]string, 0)
	decoders := c.ContentDecompressers()
	for _, k := range keys {
		k = strings.ToLower(k)
		if _, f := decoders[k]; f {
			result = append(result, k)
		}
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	c.contentDecompresserKeys = result
	return c
}

// SetCircuitBreaker method sets the [CircuitBreaker] on the client to prevent
// sending requests that are likely to fail.
//
// For example, to use a count-based circuit breaker:
//
//	client.SetCircuitBreaker(NewCircuitBreakerCount(5, 1, 30*time.Second))
func (c *Client) SetCircuitBreaker(cb CircuitBreaker) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.circuitBreaker = cb
	return c
}

// RateLimiter method returns the [RateLimiter] configured on the client, or nil if none is set.
func (c *Client) RateLimiter() RateLimiter {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.rateLimiter
}

// SetRateLimiter method sets the [RateLimiter] on the client. The rate limiter is consulted
// before every request; if it returns an error the request is aborted with that error.
//
// Use [NewRateLimitTokenBucket] to create a standard token-bucket limiter,
// [NewRateLimitSlidingWindow] for sliding-window semantics, or supply any
// implementation of the [RateLimiter] interface for custom strategies.
//
// For example, to allow at most 100 requests per second with a burst of 10:
//
//	client.SetRateLimiter(resty.NewRateLimitTokenBucket(100, 10))
//
// Pass nil to remove a previously configured rate limiter.
func (c *Client) SetRateLimiter(l RateLimiter) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.rateLimiter = l
	return c
}

// IsDebug method returns `true` if the client is in debug mode; otherwise, it is `false`.
func (c *Client) IsDebug() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.debug
}

// SetDebug method is used to turn on/off the debug mode on the Resty client instance. It logs details
// of every request and response when enabled.
//
//	client.SetDebug(true)
//
// Also, it can be enabled at the request level for a particular request; see [Request.SetDebug].
//   - For [Request], it logs information such as HTTP verb, Relative URL path,
//     Host, Headers, and Body if it has one.
//   - For [Response], it logs information such as Status, Response Time, Headers,
//     and Body if it has one.
func (c *Client) SetDebug(d bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.debug = d
	return c
}

// DebugBodyLimit method returns the debug body size limit set on the client.
func (c *Client) DebugBodyLimit() int {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.debugBodyLimit
}

// SetDebugBodyLimit sets the maximum size in bytes for which the response and
// request body will be logged in debug mode.
//
//	client.SetDebugBodyLimit(1000000)
func (c *Client) SetDebugBodyLimit(sl int) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.debugBodyLimit = sl
	return c
}

func (c *Client) debugLogCallbackFunc() DebugLogCallbackFunc {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.debugLogCallback
}

// OnDebugLog method sets the debug-log callback on the client instance.
// The registered callback is invoked before Resty logs each debug entry.
func (c *Client) OnDebugLog(dlc DebugLogCallbackFunc) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.debugLogCallback != nil {
		c.log.Warnf("Overwriting an existing on-debug-log callback from=%s to=%s",
			functionName(c.debugLogCallback), functionName(dlc))
	}
	c.debugLogCallback = dlc
	return c
}

func (c *Client) debugLogFormatterFunc() DebugLogFormatterFunc {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.debugLogFormatter
}

// SetDebugLogFormatter method sets the debug log formatter on the client instance.
func (c *Client) SetDebugLogFormatter(df DebugLogFormatterFunc) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.debugLogFormatter = df
	return c
}

// IsDisableWarn method returns `true` if the warning message is disabled; otherwise, it is `false`.
func (c *Client) IsDisableWarn() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.disableWarn
}

// SetLoggerWarnLevel method controls whether warning log messages are emitted.
// When d is true, warnings are suppressed. For example, Resty normally warns
// when BasicAuth is used over a non-TLS connection.
//
//	client.SetLoggerWarnLevel(true)
func (c *Client) SetLoggerWarnLevel(d bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.disableWarn = d
	return c
}

// IsMethodGetAllowPayload method returns true if the GET method is allowed to
// carry a payload; otherwise false.
func (c *Client) IsMethodGetAllowPayload() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.isMethodGetAllowPayload
}

// SetMethodGetAllowPayload method allows or disallows a payload with the GET method.
// By default, Resty does not allow a payload with GET requests.
//
//	client.SetMethodGetAllowPayload(true)
//
// It can be overridden at the request level. See [Request.SetMethodGetAllowPayload]
func (c *Client) SetMethodGetAllowPayload(allow bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.isMethodGetAllowPayload = allow
	return c
}

// IsMethodDeleteAllowPayload method returns true if the DELETE method is allowed to
// carry a payload; otherwise false.
//
// More info, refer to GH#881
func (c *Client) IsMethodDeleteAllowPayload() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.isMethodDeleteAllowPayload
}

// SetMethodDeleteAllowPayload method allows or disallows a payload with the DELETE method.
// By default, Resty does not allow a payload with DELETE requests.
//
//	client.SetMethodDeleteAllowPayload(true)
//
// More info, refer to GH#881
//
// It can be overridden at the request level. See [Request.SetMethodDeleteAllowPayload]
func (c *Client) SetMethodDeleteAllowPayload(allow bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.isMethodDeleteAllowPayload = allow
	return c
}

// Logger method returns the logger instance used by the client instance.
func (c *Client) Logger() Logger {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.log
}

// SetLogger method sets the logger used by the client for request and response details.
// The provided value must implement the [Logger] interface.
func (c *Client) SetLogger(l Logger) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.log = l
	return c
}

// Timeout method returns the request timeout duration set on the client.
func (c *Client) Timeout() time.Duration {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.timeout
}

// SetTimeout method is used to set a timeout for a request raised by the client.
//
//	client.SetTimeout(1 * time.Minute)
//
// It can be overridden at the request level. See [Request.SetTimeout]
//
// NOTE: Resty uses [context.WithTimeout] on the request, it does not use [http.Client].Timeout
func (c *Client) SetTimeout(timeout time.Duration) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.timeout = timeout
	return c
}

// ResultError method returns the common error type registered on the client, or nil if none is set.
func (c *Client) ResultError() reflect.Type {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.errorType
}

// SetResultError method registers a common error type on the client instance,
// used for automatic unmarshalling when the response status code is greater
// than 399 and the content type is JSON or XML.
// It can be a pointer or a non-pointer.
//
//	client.SetResultError(&LoginErrorResponse{})
//	// OR
//	client.SetResultError(LoginErrorResponse{})
func (c *Client) SetResultError(v any) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.errorType = inferType(v)
	return c
}

func (c *Client) newErrorInterface() any {
	e := c.ResultError()
	if e == nil {
		return e
	}
	return reflect.New(e).Interface()
}

// SetRedirectPolicy method sets the redirect policy for the client. Resty provides ready-to-use
// redirect policies. To implement a custom policy, see [RedirectPolicy].
//
//	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(20))
//
//	// Need multiple redirect policies together
//	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(20), resty.DomainCheckRedirectPolicy("host1.com", "host2.net"))
//
// NOTE: It overwrites the previous redirect policies in the client instance.
func (c *Client) SetRedirectPolicy(policies ...RedirectPolicy) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		for _, p := range policies {
			if err := p.Apply(req, via); err != nil {
				return err
			}
		}
		return nil // looks good, go ahead
	}
	return c
}

// RetryCount method returns the retry count value from the client instance.
func (c *Client) RetryCount() int {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryCount
}

// SetRetryCount method sets the maximum number of retry attempts.
//
//	first attempt + retry count = total attempts
//
// See [Request.SetRetryDelayStrategy]
//
// NOTE:
//   - By default, Resty only does retry on idempotent HTTP verb, [RFC 9110 Section 9.2.2], [RFC 9110 Section 18.2]
//
// [RFC 9110 Section 9.2.2]: https://datatracker.ietf.org/doc/html/rfc9110.html#name-idempotent-methods
// [RFC 9110 Section 18.2]: https://datatracker.ietf.org/doc/html/rfc9110.html#name-method-registration
func (c *Client) SetRetryCount(count int) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.retryCount = count
	return c
}

// RetryWaitTime method returns the minimum wait time between retry attempts.
func (c *Client) RetryWaitTime() time.Duration {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryWaitTime
}

// SetRetryWaitTime method sets the minimum wait time between retry attempts.
//
// Default is 100 milliseconds.
func (c *Client) SetRetryWaitTime(waitTime time.Duration) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.retryWaitTime = waitTime
	return c
}

// RetryMaxWaitTime method returns the maximum wait time between retry attempts.
func (c *Client) RetryMaxWaitTime() time.Duration {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryMaxWaitTime
}

// SetRetryMaxWaitTime method sets the maximum wait time between retry attempts.
//
// Default is 2 seconds.
func (c *Client) SetRetryMaxWaitTime(maxWaitTime time.Duration) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.retryMaxWaitTime = maxWaitTime
	return c
}

// RetryDelayStrategy method returns the custom retry delay strategy function,
// or nil if none is set.
//
// See [Client.SetRetryDelayStrategy]
func (c *Client) RetryDelayStrategy() RetryDelayStrategyFunc {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryDelayStrategy
}

// SetRetryDelayStrategy method sets a custom [RetryDelayStrategyFunc] that determines
// the wait time before each retry attempt.
// It can be overridden at the request level; see [Request.SetRetryDelayStrategy].
//
// By default, Resty uses capped exponential backoff with jitter.
func (c *Client) SetRetryDelayStrategy(rs RetryDelayStrategyFunc) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.retryDelayStrategy = rs
	return c
}

// IsRetryDefaultConditions method reports whether the default retry conditions are enabled.
//
// The default is true.
func (c *Client) IsRetryDefaultConditions() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.isRetryDefaultConditions
}

// SetRetryDefaultConditions method enables or disables the built-in retry conditions,
// which check for transport, header, and URL errors.
//
// Enabled by default.
//
// It can be overridden at the request level; see [Request.SetRetryDefaultConditions].
func (c *Client) SetRetryDefaultConditions(b bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.isRetryDefaultConditions = b
	return c
}

// IsRetryAllowNonIdempotent method reports whether retry is allowed for
// non-idempotent HTTP methods. The default is false.
func (c *Client) IsRetryAllowNonIdempotent() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.isRetryAllowNonIdempotent
}

// SetRetryAllowNonIdempotent method enables or disables retry for non-idempotent HTTP
// methods. By default, Resty only retries idempotent HTTP methods; see
// [RFC 9110 Section 9.2.2], [RFC 9110 Section 18.2]
//
// It can be overridden at the request level; see [Request.SetRetryAllowNonIdempotent].
//
// [RFC 9110 Section 9.2.2]: https://datatracker.ietf.org/doc/html/rfc9110.html#name-idempotent-methods
// [RFC 9110 Section 18.2]: https://datatracker.ietf.org/doc/html/rfc9110.html#name-method-registration
func (c *Client) SetRetryAllowNonIdempotent(b bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.isRetryAllowNonIdempotent = b
	return c
}

// RetryConditions method returns all the retry condition functions.
func (c *Client) RetryConditions() []RetryConditionFunc {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryConditions
}

// AddRetryConditions method adds one or more retry condition functions to the client.
// These retry conditions are executed to determine if the request can be retried.
// The request will retry if any functions return `true`, otherwise return `false`.
//
// NOTE:
//   - Retry conditions are executed on each retry attempt.
//   - Default retry conditions are executed first.
//   - Client-level retry conditions are applied to all requests.
//   - Request-level retry conditions are executed before client-level retry conditions.
//     See [Request.AddRetryConditions], [Request.SetRetryConditions]
//   - Once a retry condition returns true, the remaining retry conditions are not executed.
//   - Retry conditions are executed in the order in which they are added.
func (c *Client) AddRetryConditions(conditions ...RetryConditionFunc) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.retryConditions = append(c.retryConditions, conditions...)
	return c
}

// RetryHooks method returns all the retry hook functions.
func (c *Client) RetryHooks() []RetryHookFunc {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryHooks
}

// AddRetryHooks method appends one or more retry hook functions to the client;
// each hook is called on every retry attempt.
//
// NOTE:
//   - Retry hooks are executed on each retry attempt.
//   - The request-level retry hooks are executed first before client-level hooks.
//     See [Request.AddRetryHooks], [Request.SetRetryHooks]
//   - Retry hooks are executed in the order in which they are added.
func (c *Client) AddRetryHooks(hooks ...RetryHookFunc) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.retryHooks = append(c.retryHooks, hooks...)
	return c
}

// isHedgingEnabled method returns true if hedging is enabled.
func (c *Client) isHedgingEnabled() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.hedging != nil
}

// Hedging method returns the [Hedger] implementation set on the client,
// or nil if hedging is disabled.
func (c *Client) Hedging() Hedger {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.hedging
}

// SetHedging method sets the [Hedger] implementation on the client. Passing nil disables hedging.
//
// See [NewHedging] for more details about the default [Hedging] implementation.
func (c *Client) SetHedging(h Hedger) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()

	// if nil is passed, we disable hedging
	// by reverting the transport instance
	if h == nil {
		if ht, ok := c.httpClient.Transport.(Hedger); ok {
			c.httpClient.Transport = ht.Transport()
			c.hedging = nil
		}
		return c
	}

	// enable hedging if its not already enabled

	currentTransport := c.httpClient.Transport
	if currentTransport == nil {
		currentTransport = createTransport(nil, nil)
	}

	// If current transport is already a Hedger instance, unwrap it
	// to avoid double-wrapping (e.g., when SetHedging is called multiple times)
	if hedging, ok := currentTransport.(Hedger); ok {
		currentTransport = hedging.Transport()
	}

	// Disable retry by default when hedging is enabled.
	// Users can re-enable retry if they want it as a fallback mechanism.
	if c.retryCount > 0 {
		c.log.Warnf("Disabling retry (count: %d) as hedging is now enabled."+
			" You can re-enable retry with SetRetryCount() if you really want it as a fallback."+
			" otherwise, hedging and retry requests can overwhelm the server.", c.retryCount)
		c.retryCount = 0
	}

	h.SetTransport(currentTransport)
	c.httpClient.Transport = h
	c.hedging = h

	return c
}

// TLSClientConfig method returns the [tls.Config] from the underlying transport,
// or nil if the transport does not expose TLS configuration.
func (c *Client) TLSClientConfig() *tls.Config {
	cfg, err := c.tlsConfig()
	if err != nil {
		c.Logger().Errorf("%v", err)
	}
	return cfg
}

// SetTLSClientConfig method sets TLSClientConfig for underlying client Transport.
//
// Values supported by https://pkg.go.dev/crypto/tls#Config can be configured.
//
//	// Disable SSL cert verification for local development
//	client.SetTLSClientConfig(&tls.Config{
//		InsecureSkipVerify: true
//	})
//
// NOTE: This method overwrites existing [http.Transport.TLSClientConfig]
func (c *Client) SetTLSClientConfig(tlsConfig *tls.Config) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()

	// TLSClientConfiger interface handling
	if tc, ok := c.httpClient.Transport.(TLSClientConfiger); ok {
		if err := tc.SetTLSClientConfig(tlsConfig); err != nil {
			c.log.Errorf("%v", err)
		}
		return c
	}

	// default standard transport handling
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		c.log.Errorf("SetTLSClientConfig: %v", ErrNotHttpTransportType)
		return c
	}
	transport.TLSClientConfig = tlsConfig

	return c
}

// ProxyURL method returns the proxy URL if set otherwise nil.
func (c *Client) ProxyURL() *url.URL {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.proxyURL
}

// SetProxy method sets the proxy URL on the client.
// The proxy type is determined by the URL scheme. "http",
// "https", and "socks5" are supported. If the scheme is empty,
// "http" is assumed.
//
//	// HTTP/HTTPS proxy
//	client.SetProxy("http://proxyserver:8888")
//
//	// SOCKS5 Proxy
//	client.SetProxy("socks5://127.0.0.1:1080")
//
// You can also set the Proxy URL using the environment variable `HTTP_PROXY`.
// See [http.ProxyFromEnvironment] for more details.
func (c *Client) SetProxy(proxyURL string) *Client {
	transport, err := c.HTTPTransport()
	if err != nil {
		c.Logger().Errorf("%v", err)
		return c
	}

	pURL, err := url.Parse(proxyURL)
	if err != nil {
		c.Logger().Errorf("%v", err)
		return c
	}

	c.lock.Lock()
	c.proxyURL = pURL
	transport.Proxy = http.ProxyURL(c.proxyURL)
	c.lock.Unlock()
	return c
}

// RemoveProxy method removes the proxy configuration from the Resty client
//
//	client.RemoveProxy()
func (c *Client) RemoveProxy() *Client {
	transport, err := c.HTTPTransport()
	if err != nil {
		c.Logger().Errorf("%v", err)
		return c
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	c.proxyURL = nil
	transport.Proxy = nil
	return c
}

// SetCertificateFromFile method sets client certificates into Resty
// from cert and key files to perform SSL client authentication.
//
//	client.SetCertificateFromFile("certs/client.pem", "certs/client.key")
func (c *Client) SetCertificateFromFile(certFilePath, certKeyFilePath string) *Client {
	cert, err := tls.LoadX509KeyPair(certFilePath, certKeyFilePath)
	if err != nil {
		c.Logger().Errorf("client certificate/key parsing error: %v", err)
		return c
	}
	c.SetCertificates(cert)
	return c
}

// SetCertificateFromString method sets client certificates into Resty
// from strings to perform SSL client authentication.
//
//	myClientCertStr := `-----BEGIN CERTIFICATE-----
//	... cert content ...
//	-----END CERTIFICATE-----`
//
//	myClientCertKeyStr := `-----BEGIN PRIVATE KEY-----
//	... cert key content ...
//	-----END PRIVATE KEY-----`
//
//	client.SetCertificateFromString(myClientCertStr, myClientCertKeyStr)
func (c *Client) SetCertificateFromString(certStr, certKeyStr string) *Client {
	cert, err := tls.X509KeyPair([]byte(certStr), []byte(certKeyStr))
	if err != nil {
		c.Logger().Errorf("client certificate/key parsing error: %v", err)
		return c
	}
	c.SetCertificates(cert)
	return c
}

// SetCertificates method sets one or more client certificates into Resty
// for SSL client authentication.
//
//	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
//	if err != nil {
//		log.Printf("ERROR client certificate/key parsing error: %v", err)
//		return
//	}
//
//	client.SetCertificates(cert)
func (c *Client) SetCertificates(certs ...tls.Certificate) *Client {
	config, err := c.tlsConfig()
	if err != nil {
		c.Logger().Errorf("%v", err)
		return c
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	config.Certificates = append(config.Certificates, certs...)
	return c
}

// SetRootCertificates method helps to add one or more root certificate files
// into the Resty client
//
//	// one pem file path
//	client.SetRootCertificates("/path/to/root/pemFile.pem")
//
//	// one or more pem file path(s)
//	client.SetRootCertificates(
//	    "/path/to/root/pemFile1.pem",
//	    "/path/to/root/pemFile2.pem"
//	    "/path/to/root/pemFile3.pem"
//	)
//
//	// if you happen to have string slices
//	client.SetRootCertificates(certs...)
func (c *Client) SetRootCertificates(pemFilePaths ...string) *Client {
	for _, fp := range pemFilePaths {
		rootPemData, err := os.ReadFile(fp)
		if err != nil {
			c.Logger().Errorf("%v", err)
			return c
		}
		c.handleCAs("root", rootPemData)
	}
	return c
}

// SetRootCertificatesWatcher method enables dynamic reloading of one or more root certificate files.
// It is designed for scenarios involving long-running Resty clients where certificates may be renewed.
//
//	client.SetRootCertificatesWatcher(
//		&resty.CertWatcherOptions{
//			PoolInterval: 24 * time.Hour,
//		},
//		"root-ca.pem",
//	)
func (c *Client) SetRootCertificatesWatcher(options *CertWatcherOptions, pemFilePaths ...string) *Client {
	c.SetRootCertificates(pemFilePaths...)
	for _, fp := range pemFilePaths {
		c.initCertWatcher(fp, "root", options)
	}
	return c
}

// SetRootCertificateFromString method helps to add root certificate from the string
// into the Resty client
//
//	myRootCertStr := `-----BEGIN CERTIFICATE-----
//	... cert content ...
//	-----END CERTIFICATE-----`
//
//	client.SetRootCertificateFromString(myRootCertStr)
func (c *Client) SetRootCertificateFromString(pemCerts string) *Client {
	c.handleCAs("root", []byte(pemCerts))
	return c
}

// SetClientRootCertificates method helps to add one or more client root
// certificate files into the Resty client
//
//	// one pem file path
//	client.SetClientRootCertificates("/path/to/client-root/pemFile.pem")
//
//	// one or more pem file path(s)
//	client.SetClientRootCertificates(
//	    "/path/to/client-root/pemFile1.pem",
//	    "/path/to/client-root/pemFile2.pem"
//	    "/path/to/client-root/pemFile3.pem"
//	)
//
//	// if you happen to have string slices
//	client.SetClientRootCertificates(certs...)
func (c *Client) SetClientRootCertificates(pemFilePaths ...string) *Client {
	for _, fp := range pemFilePaths {
		pemData, err := os.ReadFile(fp)
		if err != nil {
			c.Logger().Errorf("%v", err)
			return c
		}
		c.handleCAs("client-root", pemData)
	}
	return c
}

// SetClientRootCertificatesWatcher method enables dynamic reloading of one or more client root certificate files.
// It is designed for scenarios involving long-running Resty clients where certificates may be renewed.
//
//	client.SetClientRootCertificatesWatcher(
//		&resty.CertWatcherOptions{
//			PoolInterval: 24 * time.Hour,
//		},
//		"client-root-ca.pem",
//	)
func (c *Client) SetClientRootCertificatesWatcher(options *CertWatcherOptions, pemFilePaths ...string) *Client {
	c.SetClientRootCertificates(pemFilePaths...)
	for _, fp := range pemFilePaths {
		c.initCertWatcher(fp, "client-root", options)
	}
	return c
}

// SetClientRootCertificateFromString method helps to add a client root certificate
// from the string into the Resty client
//
//	myClientRootCertStr := `-----BEGIN CERTIFICATE-----
//	... cert content ...
//	-----END CERTIFICATE-----`
//
//	client.SetClientRootCertificateFromString(myClientRootCertStr)
func (c *Client) SetClientRootCertificateFromString(pemCerts string) *Client {
	c.handleCAs("client-root", []byte(pemCerts))
	return c
}

func (c *Client) handleCAs(scope string, permCerts []byte) {
	config, err := c.tlsConfig()
	if err != nil {
		c.Logger().Errorf("%v", err)
		return
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	switch scope {
	case "root":
		if config.RootCAs == nil {
			config.RootCAs = x509.NewCertPool()
		}
		config.RootCAs.AppendCertsFromPEM(permCerts)
	case "client-root":
		if config.ClientCAs == nil {
			config.ClientCAs = x509.NewCertPool()
		}
		config.ClientCAs.AppendCertsFromPEM(permCerts)
	}
}

func (c *Client) initCertWatcher(pemFilePath, scope string, options *CertWatcherOptions) {
	tickerDuration := defaultWatcherPoolingInterval
	if options != nil && options.PoolInterval > 0 {
		tickerDuration = options.PoolInterval
	}

	go func() {
		ticker := time.NewTicker(tickerDuration)
		st, err := os.Stat(pemFilePath)
		if err != nil {
			c.Logger().Errorf("%v", err)
			return
		}

		modTime := st.ModTime().UTC()

		for {
			select {
			case <-c.certWatcherStopChan:
				ticker.Stop()
				return
			case <-ticker.C:

				c.debugf("Checking if cert %s has changed...", pemFilePath)

				st, err = os.Stat(pemFilePath)
				if err != nil {
					c.Logger().Errorf("%v", err)
					continue
				}
				newModTime := st.ModTime().UTC()

				if modTime.Equal(newModTime) {
					c.debugf("Cert %s hasn't changed.", pemFilePath)
					continue
				}

				modTime = newModTime

				c.debugf("Reloading cert %s ...", pemFilePath)

				switch scope {
				case "root":
					c.SetRootCertificates(pemFilePath)
				case "client-root":
					c.SetClientRootCertificates(pemFilePath)
				}

				c.debugf("Cert %s reloaded.", pemFilePath)
			}
		}
	}()
}

// ResponseSaveDirectory method returns the output directory value from the client.
func (c *Client) ResponseSaveDirectory() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.responseSaveDirectory
}

// SetResponseSaveDirectory method sets the output directory for saving HTTP responses to file.
// Resty creates the directory if it does not exist. This setting is optional and
// can be used together with the absolute path in [Request.SetResponseSaveFileName].
//
//	client.SetResponseSaveDirectory("/save/http/response/here")
func (c *Client) SetResponseSaveDirectory(dirPath string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.responseSaveDirectory = dirPath
	return c
}

// IsResponseSaveToFile method returns true if saving responses to file is enabled; otherwise false.
func (c *Client) IsResponseSaveToFile() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.isResponseSaveToFile
}

// SetResponseSaveToFile method enables or disables saving responses to file for all requests.
//
//	client.SetResponseSaveToFile(true)
//
// Resty determines the save filename in the following order -
//   - [Request.SetResponseSaveFileName]
//   - Content-Disposition header
//   - Request URL using [path.Base]
//   - Request URL hostname if path is empty or "/"
//
// It can be overridden at request level, see [Request.SetResponseSaveToFile]
func (c *Client) SetResponseSaveToFile(save bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.isResponseSaveToFile = save
	return c
}

// HTTPTransport method returns the underlying [http.Transport], or
// [ErrNotHttpTransportType] if the transport is not of that type.
func (c *Client) HTTPTransport() (*http.Transport, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		return transport, nil
	}
	return nil, ErrNotHttpTransportType
}

// Transport method returns the underlying [http.RoundTripper] used by the client.
func (c *Client) Transport() http.RoundTripper {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.httpClient.Transport
}

// SetTransport method sets custom [http.Transport] or any [http.RoundTripper]
// compatible interface implementation in the Resty client.
//
//	transport := &http.Transport{
//		// something like Proxying to httptest.Server, etc...
//		Proxy: func(req *http.Request) (*url.URL, error) {
//			return url.Parse(server.URL)
//		},
//	}
//	client.SetTransport(transport)
//
// NOTE:
//   - If transport is not the type of [http.Transport], you may lose the
//     ability to set a few Resty client settings. However, if you implement
//     [TLSClientConfiger] interface, then TLS client config is possible to set.
//   - It overwrites the Resty client transport instance and its configurations.
func (c *Client) SetTransport(transport http.RoundTripper) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	if transport != nil {
		c.httpClient.Transport = transport
	}
	return c
}

// Scheme method returns the URL scheme set on the client.
func (c *Client) Scheme() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.scheme
}

// SetScheme method sets the URL scheme used by the client when no scheme is present in the request URL.
//
//	client.SetScheme("http")
func (c *Client) SetScheme(scheme string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	if !isStringEmpty(scheme) {
		c.scheme = strings.TrimSpace(scheme)
	}
	return c
}

// SetCloseConnection method sets the [http.Request].Close field on each request,
// instructing the transport to close the connection after the response.
//
// It can be overridden at the request level; see [Request.SetCloseConnection].
func (c *Client) SetCloseConnection(close bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.closeConnection = close
	return c
}

// SetResponseDoNotParse method instructs Resty not to parse the response body automatically.
//
// Resty exposes the raw response body as [io.ReadCloser]. If you use it, do not
// forget to close the body, otherwise, you might get into connection leaks, and connection
// reuse may not happen.
//
// NOTE: The default [Response] middlewares are not executed when using this option. User
// takes over the control of handling response body from Resty.
func (c *Client) SetResponseDoNotParse(notParse bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.isResponseDoNotParse = notParse
	return c
}

// PathParams method returns the path parameters set on the client.
func (c *Client) PathParams() map[string]string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.pathParams
}

// SetPathParam method sets a single URL path key-value pair in the
// Resty client instance.
//
//	client.SetPathParam("userId", "sample@sample.com")
//
//	Result:
//	   URL - /v1/users/{userId}/details
//	   Composed URL - /v1/users/sample@sample.com/details
//
// It replaces the value of the key while composing the request URL.
// The value will be escaped using [url.PathEscape] function.
//
// It can be overridden at the request level,
// see [Request.SetPathParam] or [Request.SetPathParams]
func (c *Client) SetPathParam(param, value string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.pathParams[param] = url.PathEscape(value)
	return c
}

// SetPathParamAny method sets a single URL path key-value pair in the
// Resty client instance.
//
// It is similar to [Client.SetPathParam] but accepts any type as the value and converts
// it to a string using predefined formatting rules (integers, bools, time.Time, etc.).
//
//	client.SetPathParamAny("userId", 12345)
//
//	Result:
//	   URL - /v1/users/{userId}/details
//	   Composed URL - /v1/users/12345/details
//
// It replaces the value of the key while composing the request URL.
// The value will be escaped using [url.PathEscape] function.
//
// It can be overridden at the request level,
// see [Request.SetPathParamAny] or [Request.SetPathParams]
func (c *Client) SetPathParamAny(param string, value any) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	strVal := formatAnyToString(value)
	c.pathParams[param] = url.PathEscape(strVal)
	return c
}

// SetPathParams method sets multiple URL path key-value pairs at one go in the
// Resty client instance.
//
//	client.SetPathParams(map[string]string{
//		"userId":       "sample@sample.com",
//		"subAccountId": "100002",
//		"path":         "groups/developers",
//	})
//
//	Result:
//	   URL - /v1/users/{userId}/{subAccountId}/{path}/details
//	   Composed URL - /v1/users/sample@sample.com/100002/groups%2Fdevelopers/details
//
// It replaces the value of the key while composing the request URL.
// The values will be escaped using [url.PathEscape] function.
//
// It can be overridden at the request level,
// see [Request.SetPathParam] or [Request.SetPathParams]
func (c *Client) SetPathParams(params map[string]string) *Client {
	for p, v := range params {
		c.SetPathParam(p, v)
	}
	return c
}

// SetPathRawParam method sets a single URL path key-value pair in the
// Resty client instance without path escape.
//
//	client.SetPathRawParam("path", "groups/developers")
//
//	Result:
//		URL - /v1/users/{path}/details
//		Composed URL - /v1/users/groups/developers/details
//
// It replaces the value of the key while composing the request URL.
// The value will be used as-is, no path escape applied.
//
// It can be overridden at the request level,
// see [Request.SetPathRawParam] or [Request.SetPathRawParams]
func (c *Client) SetPathRawParam(param, value string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.pathParams[param] = value
	return c
}

// SetPathRawParamAny method sets a single URL path key-value pair in the
// Resty client instance without path escape.
//
// It is similar to [Client.SetPathRawParam] but accepts any type as the value and converts
// it to a string using predefined formatting rules (integers, bools, time.Time, etc.).
//
//	client.SetPathRawParamAny("userId", 12345)
//
//	Result:
//	   URL - /v1/users/{userId}/details
//	   Composed URL - /v1/users/12345/details
//
// It replaces the value of the key while composing the request URL.
// The value will be used as-is, no path escape applied.
//
// It can be overridden at the request level,
// see [Request.SetPathRawParamAny] or [Request.SetPathRawParams]
func (c *Client) SetPathRawParamAny(param string, value any) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	strVal := formatAnyToString(value)
	c.pathParams[param] = strVal
	return c
}

// SetPathRawParams method sets multiple URL path key-value pairs at one go in the
// Resty client instance without path escape.
//
//	client.SetPathRawParams(map[string]string{
//		"userId":       "sample@sample.com",
//		"subAccountId": "100002",
//		"path":         "groups/developers",
//	})
//
//	Result:
//	   URL - /v1/users/{userId}/{subAccountId}/{path}/details
//	   Composed URL - /v1/users/sample@sample.com/100002/groups/developers/details
//
// It replaces the value of the key while composing the request URL.
// The value will be used as-is, no path escape applied.
//
// It can be overridden at the request level,
// see [Request.SetPathRawParam] or [Request.SetPathRawParams]
func (c *Client) SetPathRawParams(params map[string]string) *Client {
	for p, v := range params {
		c.SetPathRawParam(p, v)
	}
	return c
}

// SetJSONEscapeHTML method enables or disables the HTML escape on JSON marshal.
// By default, escape HTML is `true`.
//
// NOTE: This option only applies to the standard JSON Marshaller used by Resty.
//
// It can be overridden at the request level, see [Request.SetJSONEscapeHTML]
func (c *Client) SetJSONEscapeHTML(b bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.jsonEscapeHTML = b
	return c
}

// ResponseBodyLimit method returns the value max body size limit in bytes from
// the client instance.
func (c *Client) ResponseBodyLimit() int64 {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.responseBodyLimit
}

// SetResponseBodyLimit method sets a maximum body size limit in bytes on responses
// to avoid reading too much data into memory.
//
// Client will return [resty.ErrResponseBodyTooLarge] if the body size of the body
// in the uncompressed response is larger than the limit.
// Body size limit will not be enforced in the following cases:
//   - ResponseBodyLimit <= 0, which is the default behavior.
//   - [Request.SetResponseSaveFileName] is called to save response data to the file.
//   - "DoNotParseResponse" is set for client or request.
//
// It can be overridden at the request level; see [Request.SetResponseBodyLimit]
func (c *Client) SetResponseBodyLimit(v int64) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.responseBodyLimit = v
	return c
}

// IsTrace method returns true if the trace is enabled on the client instance; otherwise, it returns false.
func (c *Client) IsTrace() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.isTrace
}

// SetTrace method is used to turn on/off the trace capability in the Resty client instance.
// It provides an insight into the request lifecycle using [httptrace.ClientTrace].
//
//	client := resty.New().SetTrace(true)
//
//	resp, err := client.R().Get("https://httpbin.org/get")
//	fmt.Println("error:", err)
//	fmt.Println("Trace Info:", resp.Request.TraceInfo())
//
// The method [Request.SetTrace] is also available to get trace info for a single request.
func (c *Client) SetTrace(t bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.isTrace = t
	return c
}

// SetCurlCmdGenerate method is used to turn on/off the generate curl command at the
// client instance level.
//
// By default, Resty does not log the curl command in the debug log since it has the potential
// to leak sensitive data unless explicitly enabled via [Client.SetCurlCmdDebugLog] or
// [Request.SetCurlCmdDebugLog].
//
// NOTE: Use with care.
//   - Potential to leak sensitive data from [Request] and [Response] in the debug log
//     when the debug log option is enabled.
//   - Additional memory usage since the request body was reread.
//   - curl body is not generated for [io.Reader] and multipart request flow.
//
// It can be overridden at the request level; see [Request.SetCurlCmdGenerate]
func (c *Client) SetCurlCmdGenerate(b bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.isCurlCmdGenerate = b
	return c
}

// SetCurlCmdDebugLog method enables the curl command to be logged in the debug log.
//
// It can be overridden at the request level; see [Request.SetCurlCmdDebugLog]
func (c *Client) SetCurlCmdDebugLog(b bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.isCurlCmdDebugLog = b
	return c
}

// SetQueryParamsUnescape method sets the choice of unescape query parameters for the request URL.
// To prevent broken URL, Resty replaces space (" ") with "+" in the query parameters.
//
// See [Request.SetQueryParamsUnescape]
//
// NOTE: Request failure is possible due to non-standard usage of Unescaped Query Parameters.
func (c *Client) SetQueryParamsUnescape(unescape bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.unescapeQueryParams = unescape
	return c
}

// ResponseBodyUnlimitedReads method returns true if enabled. Otherwise, it returns false
func (c *Client) ResponseBodyUnlimitedReads() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.resBodyUnlimitedReads
}

// SetResponseBodyUnlimitedReads method enables or disables in-memory buffering of
// the response body, allowing unlimited reads.
//
// It can be overridden at the request level; see [Request.SetResponseBodyUnlimitedReads]
//
// Unlimited reads are possible in a few scenarios, even without enabling it.
//   - When debug mode is enabled
//
// NOTE: Use with care
//   - Turning on this feature keeps the response body in memory, which might cause additional memory usage.
func (c *Client) SetResponseBodyUnlimitedReads(b bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.resBodyUnlimitedReads = b
	return c
}

// IsProxySet method returns true if a proxy URL has been explicitly set on the client;
// otherwise false. By default, the proxy is determined from the environment;
// see [http.ProxyFromEnvironment].
func (c *Client) IsProxySet() bool {
	return c.ProxyURL() != nil
}

// Client method returns the underlying [http.Client].
func (c *Client) Client() *http.Client {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.httpClient
}

// Clone method returns a clone of the original client.
//
// NOTE: Use with care:
//   - Interface values are not deeply cloned. Thus, both the original and the
//     clone will use the same value.
//   - It is not safe for concurrent use. You should only use this method
//     when you are sure that any other concurrent process is not using the client
//     or client instance is protected by a mutex.
func (c *Client) Clone(ctx context.Context) *Client {
	cc := new(Client)
	// dereference the pointer and copy the value
	*cc = *c

	cc.ctx = ctx
	cc.queryParams = cloneURLValues(c.queryParams)
	cc.formData = cloneURLValues(c.formData)
	cc.header = c.header.Clone()
	cc.pathParams = maps.Clone(c.pathParams)

	if c.credentials != nil {
		cc.credentials = c.credentials.Clone()
	}

	cc.contentTypeEncoders = maps.Clone(c.contentTypeEncoders)
	cc.contentTypeDecoders = maps.Clone(c.contentTypeDecoders)
	cc.contentDecompressers = maps.Clone(c.contentDecompressers)
	copy(cc.contentDecompresserKeys, c.contentDecompresserKeys)

	if c.proxyURL != nil {
		cc.proxyURL, _ = url.Parse(c.proxyURL.String())
	}
	// clone cookies
	if l := len(c.cookies); l > 0 {
		cc.cookies = make([]*http.Cookie, 0, l)
		for _, cookie := range c.cookies {
			cc.cookies = append(cc.cookies, cloneCookie(cookie))
		}
	}

	// certain values need to be reset
	cc.lock = &sync.RWMutex{}
	cc.certWatcherStopChan = make(chan bool)
	cc.isClosed = false
	return cc
}

// Close method executes all registered [CloseHook] callbacks and releases client resources.
// It is safe to call Close multiple times; subsequent calls are no-op.
func (c *Client) Close() error {
	c.lock.Lock()
	alreadyClosed := c.isClosed
	c.isClosed = true
	c.lock.Unlock()
	if alreadyClosed {
		return nil
	}

	// Execute close hooks first
	c.onCloseHooks()

	if c.LoadBalancer() != nil {
		silently(c.LoadBalancer().Close())
	}
	close(c.certWatcherStopChan)

	return nil
}

func (c *Client) executeRequestMiddlewares(req *Request) (err error) {
	for _, f := range c.requestMiddlewares() {
		if err = f(c, req); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) cbRequestError() {
	if c.circuitBreaker != nil {
		if cbe, ok := c.circuitBreaker.(cbRequestErrorObserver); ok {
			cbe.onRequestError()
		}
	}
}

// Executes method executes the given `Request` object and returns
// response or error.
func (c *Client) execute(req *Request) (*Response, error) {
	if c.RateLimiter() != nil {
		if err := c.RateLimiter().Allow(req.Context()); err != nil {
			return nil, err
		}
	}

	if c.circuitBreaker != nil {
		if err := c.circuitBreaker.Allow(); err != nil {
			if cbo, ok := c.circuitBreaker.(CircuitBreakerObserver); ok {
				cbo.RunOnTriggerHooks(req, err)
			}
			return nil, err
		}
	}

	if err := c.executeRequestMiddlewares(req); err != nil {
		c.cbRequestError()
		return nil, err
	}

	if hostHeader := req.Header.Get("Host"); hostHeader != "" {
		req.RawRequest.Host = hostHeader
	}

	prepareRequestDebugInfo(c, req)

	req.StartTime = time.Now()
	resp, err := c.Client().Do(req.withTimeout())
	// Cancel multipart context for io.Copy to stop reading/writing further
	if req.isMultiPart && req.multipartCancelFunc != nil {
		req.multipartCancelFunc()
	}

	// Take ownership of the per-attempt timeout cancel func set by
	// withTimeout. It must fire once the response body is fully consumed,
	// so it is attached to the body's Close below. On a transport error
	// there is no body to read, so release it right away to avoid leaking
	// the context (and its timer) until the deadline elapses.
	cancel := req.ctxCancelFunc
	req.ctxCancelFunc = nil

	response := &Response{Request: req, RawResponse: resp}
	response.setReceivedAt()
	if err != nil {
		c.cbRequestError()
		if cancel != nil {
			cancel()
		}
		return response, err
	}
	if req.isMultiPart && req.multipartErrChan != nil {
		// read all multipart errors from channel
		for err = range req.multipartErrChan {
			response.CascadeError = wrapErrors(err, response.CascadeError)
		}
	}

	if resp != nil {
		if c.circuitBreaker != nil {
			c.circuitBreaker.ApplyPolicies(response)
		}

		response.Body = resp.Body
		// Release the request timeout context once the body is closed,
		// whether by the caller (do-not-parse) or by Resty while parsing
		// or draining the body. Wrapping innermost ensures cancel runs no
		// matter which outer reader closes the chain.
		if cancel != nil {
			response.Body = &cancelReadCloser{r: response.Body, cancel: cancel}
			cancel = nil
		}
		if err = response.wrapContentDecompresser(); err != nil {
			return response, response.wrapError(err, false)
		}

		response.wrapLimitReadCloser()

		if !req.IsResponseDoNotParse {
			if req.IsResponseBodyUnlimitedReads || req.IsDebug {
				response.wrapCopyReadCloser()

				if err = response.readAll(); err != nil {
					return response, response.wrapError(err, false)
				}
			}
		}
	}

	// No response body was available to attach the cancel to (e.g. resp is
	// nil); release the timeout context now so it does not leak.
	if cancel != nil {
		cancel()
	}

	debugLogger(c, response)

	// Apply Response middleware
	for _, f := range c.responseMiddlewares() {
		if err = f(c, response); err != nil {
			response.CascadeError = wrapErrors(err, response.CascadeError)
		}
	}

	return response, response.wrapError(nil, false)
}

// getting TLS client config if not exists then create one
func (c *Client) tlsConfig() (*tls.Config, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if tc, ok := c.httpClient.Transport.(TLSClientConfiger); ok {
		return tc.TLSClientConfig(), nil
	}

	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return nil, ErrNotHttpTransportType
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	return transport.TLSClientConfig, nil
}

// just an internal helper method
func (c *Client) outputLogTo(w io.Writer) *Client {
	c.Logger().(*logger).l.SetOutput(w)
	return c
}

// ResponseError pairs an error with the [Response] that triggered it.
// Neither field should be nil.
type ResponseError struct {
	Response *Response
	Err      error
}

func (e *ResponseError) Error() string {
	return e.Err.Error()
}

func (e *ResponseError) Unwrap() error {
	return e.Err
}

// Helper to run errorHooks hooks.
// It wraps the error in a [ResponseError] if the resp is not nil
// so hooks can access it.
func (c *Client) onErrorHooks(req *Request, res *Response, err error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if err != nil {
		if res != nil { // wrap with ResponseError
			err = &ResponseError{Response: res, Err: err}
		}
		for _, h := range c.errorHooks {
			h(req, err)
		}
	} else {
		for _, h := range c.successHooks {
			h(c, res)
		}
	}
}

// Helper to run panicHooks hooks.
func (c *Client) onPanicHooks(req *Request, err error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	for _, h := range c.panicHooks {
		h(req, err)
	}
}

// Helper to run invalidHooks hooks.
func (c *Client) onInvalidHooks(req *Request, err error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	for _, h := range c.invalidHooks {
		h(req, err)
	}
}

// Helper to run closeHooks hooks.
func (c *Client) onCloseHooks() {
	c.lock.RLock()
	defer c.lock.RUnlock()
	for _, h := range c.closeHooks {
		h()
	}
}

func (c *Client) debugf(format string, v ...any) {
	if c.IsDebug() {
		c.Logger().Debugf(format, v...)
	}
}
