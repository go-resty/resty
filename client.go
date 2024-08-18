// Copyright (c) 2015-2024 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// MethodGet HTTP method
	MethodGet = "GET"

	// MethodPost HTTP method
	MethodPost = "POST"

	// MethodPut HTTP method
	MethodPut = "PUT"

	// MethodDelete HTTP method
	MethodDelete = "DELETE"

	// MethodPatch HTTP method
	MethodPatch = "PATCH"

	// MethodHead HTTP method
	MethodHead = "HEAD"

	// MethodOptions HTTP method
	MethodOptions = "OPTIONS"
)

var (
	hdrUserAgentKey       = http.CanonicalHeaderKey("User-Agent")
	hdrAcceptKey          = http.CanonicalHeaderKey("Accept")
	hdrContentTypeKey     = http.CanonicalHeaderKey("Content-Type")
	hdrContentLengthKey   = http.CanonicalHeaderKey("Content-Length")
	hdrContentEncodingKey = http.CanonicalHeaderKey("Content-Encoding")
	hdrLocationKey        = http.CanonicalHeaderKey("Location")
	hdrAuthorizationKey   = http.CanonicalHeaderKey("Authorization")
	hdrWwwAuthenticateKey = http.CanonicalHeaderKey("WWW-Authenticate")

	plainTextType   = "text/plain; charset=utf-8"
	jsonContentType = "application/json"
	formContentType = "application/x-www-form-urlencoded"

	jsonCheck = regexp.MustCompile(`(?i:(application|text)/(.*json.*)(;|$))`)
	xmlCheck  = regexp.MustCompile(`(?i:(application|text)/(.*xml.*)(;|$))`)

	hdrUserAgentValue = "go-resty/" + Version + " (https://github.com/go-resty/resty)"
	bufPool           = &sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}
)

type (
	// RequestMiddleware type is for request middleware, called before a request is sent
	RequestMiddleware func(*Client, *Request) error

	// ResponseMiddleware type is for response middleware, called after a response has been received
	ResponseMiddleware func(*Client, *Response) error

	// PreRequestHook type is for the request hook, called right before the request is sent
	PreRequestHook func(*Client, *http.Request) error

	// RequestLogCallback type is for request logs, called before the request is logged
	RequestLogCallback func(*RequestLog) error

	// ResponseLogCallback type is for response logs, called before the response is logged
	ResponseLogCallback func(*ResponseLog) error

	// ErrorHook type is for reacting to request errors, called after all retries were attempted
	ErrorHook func(*Request, error)

	// SuccessHook type is for reacting to request success
	SuccessHook func(*Client, *Response)
)

// Client struct is used to create Resty client with client level settings,
// these settings are applicable to all the request raised from the client.
//
// Resty also provides an options to override most of the client settings
// at request level.
type Client struct {
	baseURL               string
	hostURL               string // Deprecated: use baseURL instead. To be removed in v3.0.0 release.
	queryParam            url.Values
	formData              url.Values
	pathParams            map[string]string
	rawPathParams         map[string]string
	header                http.Header
	userInfo              *User
	token                 string
	authScheme            string
	cookies               []*http.Cookie
	error                 reflect.Type
	debug                 bool
	disableWarn           bool
	allowGetMethodPayload bool
	retryCount            int
	retryWaitTime         time.Duration
	retryMaxWaitTime      time.Duration
	retryConditions       []RetryConditionFunc
	retryHooks            []OnRetryFunc
	retryAfter            RetryAfterFunc
	retryResetReaders     bool
	jsonMarshal           func(v interface{}) ([]byte, error)
	jsonUnmarshal         func(data []byte, v interface{}) error
	xmlMarshal            func(v interface{}) ([]byte, error)
	xmlUnmarshal          func(data []byte, v interface{}) error

	// headerAuthorizationKey is used to set/access Request Authorization header
	// value when `SetAuthToken` option is used.
	headerAuthorizationKey string

	jsonEscapeHTML      bool
	setContentLength    bool
	closeConnection     bool
	notParseResponse    bool
	trace               bool
	debugBodySizeLimit  int64
	outputDirectory     string
	scheme              string
	log                 Logger
	httpClient          *http.Client
	proxyURL            *url.URL
	beforeRequest       []RequestMiddleware
	udBeforeRequest     []RequestMiddleware
	udBeforeRequestLock *sync.RWMutex
	preReqHook          PreRequestHook
	successHooks        []SuccessHook
	afterResponse       []ResponseMiddleware
	afterResponseLock   *sync.RWMutex
	requestLog          RequestLogCallback
	responseLog         ResponseLogCallback
	errorHooks          []ErrorHook
	invalidHooks        []ErrorHook
	panicHooks          []ErrorHook
	rateLimiter         RateLimiter
	lock                *sync.RWMutex
}

// User type is to hold an username and password information
type User struct {
	Username, Password string
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Client methods
//___________________________________

// SetHostURL method is to set Host URL in the client instance. It will be used with request
// raised from this client with relative URL
//
//	// Setting HTTP address
//	client.SetHostURL("http://myjeeva.com")
//
//	// Setting HTTPS address
//	client.SetHostURL("https://myjeeva.com")
//
// Deprecated: use SetBaseURL instead. To be removed in v3.0.0 release.
func (c *Client) SetHostURL(url string) *Client {
	c.SetBaseURL(url)
	return c
}

// BaseURL method is to get Base URL in the client instance.
func (c *Client) BaseURL() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.baseURL
}

// SetBaseURL method is to set Base URL in the client instance. It will be used with request
// raised from this client with relative URL
//
//	// Setting HTTP address
//	client.SetBaseURL("http://myjeeva.com")
//
//	// Setting HTTPS address
//	client.SetBaseURL("https://myjeeva.com")
//
// Since v2.7.0
func (c *Client) SetBaseURL(url string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.baseURL = strings.TrimRight(url, "/")
	c.hostURL = c.baseURL
	return c
}

// Header method gets all header fields and its value in the client instance.
func (c *Client) Header() http.Header {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.header
}

// SetHeader method sets a single header field and its value in the client instance.
// These headers will be applied to all requests raised from this client instance.
// Also it can be overridden at request level header options.
//
// See `Request.SetHeader` or `Request.SetHeaders`.
//
// For Example: To set `Content-Type` and `Accept` as `application/json`
//
//	client.
//		SetHeader("Content-Type", "application/json").
//		SetHeader("Accept", "application/json")
func (c *Client) SetHeader(header, value string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.header.Set(header, value)
	return c
}

// SetHeaders method sets multiple headers field and its values at one go in the client instance.
// These headers will be applied to all requests raised from this client instance. Also it can be
// overridden at request level headers options.
//
// See `Request.SetHeaders` or `Request.SetHeader`.
//
// For Example: To set `Content-Type` and `Accept` as `application/json`
//
//	client.SetHeaders(map[string]string{
//			"Content-Type": "application/json",
//			"Accept": "application/json",
//		})
func (c *Client) SetHeaders(headers map[string]string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	for h, v := range headers {
		c.header.Set(h, v)
	}
	return c
}

// SetHeaderVerbatim method is to set a single header field and its value verbatim in the current request.
//
// For Example: To set `all_lowercase` and `UPPERCASE` as `available`.
//
//	client.R().
//		SetHeaderVerbatim("all_lowercase", "available").
//		SetHeaderVerbatim("UPPERCASE", "available")
//
// Also you can override header value, which was set at client instance level.
//
// Since v2.6.0
func (c *Client) SetHeaderVerbatim(header, value string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.header[header] = []string{value}
	return c
}

// SetCookieJar method sets custom http.CookieJar in the resty client. Its way to override default.
//
// For Example: sometimes we don't want to save cookies in api contacting, we can remove the default
// CookieJar in resty client.
//
//	client.SetCookieJar(nil)
func (c *Client) SetCookieJar(jar http.CookieJar) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.httpClient.Jar = jar
	return c
}

// SetCookie method appends a single cookie in the client instance.
// These cookies will be added to all the request raised from this client instance.
//
//	client.SetCookie(&http.Cookie{
//				Name:"go-resty",
//				Value:"This is cookie value",
//			})
func (c *Client) SetCookie(hc *http.Cookie) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.cookies = append(c.cookies, hc)
	return c
}

// Cookies method gets all cookies in the client instance.
func (c *Client) Cookies() []*http.Cookie {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.cookies
}

// SetCookies method sets an array of cookies in the client instance.
// These cookies will be added to all the request raised from this client instance.
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

// QueryParam method gets all parameters and their values in the client instance.
func (c *Client) QueryParam() url.Values {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.queryParam
}

// SetQueryParam method sets single parameter and its value in the client instance.
// It will be formed as query string for the request.
//
// For Example: `search=kitchen%20papers&size=large`
// in the URL after `?` mark. These query params will be added to all the request raised from
// this client instance. Also it can be overridden at request level Query Param options.
//
// See `Request.SetQueryParam` or `Request.SetQueryParams`.
//
//	client.
//		SetQueryParam("search", "kitchen papers").
//		SetQueryParam("size", "large")
func (c *Client) SetQueryParam(param, value string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.queryParam.Set(param, value)
	return c
}

// SetQueryParams method sets multiple parameters and their values at one go in the client instance.
// It will be formed as query string for the request.
//
// For Example: `search=kitchen%20papers&size=large`
// in the URL after `?` mark. These query params will be added to all the request raised from this
// client instance. Also it can be overridden at request level Query Param options.
//
// See `Request.SetQueryParams` or `Request.SetQueryParam`.
//
//	client.SetQueryParams(map[string]string{
//			"search": "kitchen papers",
//			"size": "large",
//		})
func (c *Client) SetQueryParams(params map[string]string) *Client {
	// Do not lock here since there is potential deadlock.
	for p, v := range params {
		c.SetQueryParam(p, v)
	}
	return c
}

// FormData method gets form parameters and their values in the client instance.
func (c *Client) FormData() url.Values {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.formData
}

// SetFormData method sets Form parameters and their values in the client instance.
// It's applicable only HTTP method `POST` and `PUT` and request content type would be set as
// `application/x-www-form-urlencoded`. These form data will be added to all the request raised from
// this client instance. Also it can be overridden at request level form data.
//
// See `Request.SetFormData`.
//
//	client.SetFormData(map[string]string{
//			"access_token": "BC594900-518B-4F7E-AC75-BD37F019E08F",
//			"user_id": "3455454545",
//		})
func (c *Client) SetFormData(data map[string]string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	for k, v := range data {
		c.formData.Set(k, v)
	}
	return c
}

// BasicAuth method gets the basic authentication header in the HTTP request.
func (c *Client) BasicAuth() *User {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.userInfo
}

// SetBasicAuth method sets the basic authentication header in the HTTP request. For Example:
//
//	Authorization: Basic <base64-encoded-value>
//
// For Example: To set the header for username "go-resty" and password "welcome"
//
//	client.SetBasicAuth("go-resty", "welcome")
//
// This basic auth information gets added to all the request raised from this client instance.
// Also it can be overridden or set one at the request level is supported.
//
// See `Request.SetBasicAuth`.
func (c *Client) SetBasicAuth(username, password string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.userInfo = &User{Username: username, Password: password}
	return c
}

// Token method gets the auth token of the `Authorization` header for all HTTP requests.
func (c *Client) Token() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.token
}

// SetAuthToken method sets the auth token of the `Authorization` header for all HTTP requests.
// The default auth scheme is `Bearer`, it can be customized with the method `SetAuthScheme`. For Example:
//
//	Authorization: <auth-scheme> <auth-token-value>
//
// For Example: To set auth token BC594900518B4F7EAC75BD37F019E08FBC594900518B4F7EAC75BD37F019E08F
//
//	client.SetAuthToken("BC594900518B4F7EAC75BD37F019E08FBC594900518B4F7EAC75BD37F019E08F")
//
// This auth token gets added to all the requests raised from this client instance.
// Also it can be overridden or set one at the request level is supported.
//
// See `Request.SetAuthToken`.
func (c *Client) SetAuthToken(token string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.token = token
	return c
}

// AuthScheme method gets the auth scheme type in the HTTP request.
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
// Also it can be overridden or set one at the request level is supported.
//
// Information about auth schemes can be found in RFC7235 which is linked to below
// along with the page containing the currently defined official authentication schemes:
//
//	https://tools.ietf.org/html/rfc7235
//	https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml#authschemes
//
// See `Request.SetAuthToken`.
func (c *Client) SetAuthScheme(scheme string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.authScheme = scheme
	return c
}

// SetDigestAuth method sets the Digest Access auth scheme for the client. If a server responds with 401 and sends
// a Digest challenge in the WWW-Authenticate header, requests will be resent with the appropriate Authorization header.
//
// For Example: To set the Digest scheme with user "Mufasa" and password "Circle Of Life"
//
//	client.SetDigestAuth("Mufasa", "Circle Of Life")
//
// Information about Digest Access Authentication can be found in RFC7616:
//
//	https://datatracker.ietf.org/doc/html/rfc7616
//
// See `Request.SetDigestAuth`.
func (c *Client) SetDigestAuth(username, password string) *Client {
	c.lock.Lock()
	oldTransport := c.httpClient.Transport
	c.lock.Unlock()
	// OnBeforeRequest and OnAfterResponse are thread-safe
	c.OnBeforeRequest(func(c *Client, _ *Request) error {
		c.httpClient.Transport = &digestTransport{
			digestCredentials: digestCredentials{username, password},
			transport:         oldTransport,
		}
		return nil
	})
	c.OnAfterResponse(func(c *Client, _ *Response) error {
		c.httpClient.Transport = oldTransport
		return nil
	})
	return c
}

// R method creates a new request instance, its used for Get, Post, Put, Delete, Patch, Head, Options, etc.
func (c *Client) R() *Request {
	r := &Request{
		QueryParam:    url.Values{},
		FormData:      url.Values{},
		Header:        http.Header{},
		Cookies:       make([]*http.Cookie, 0),
		PathParams:    map[string]string{},
		RawPathParams: map[string]string{},
		Debug:         c.debug,

		client:          c,
		multipartFiles:  []*File{},
		multipartFields: []*MultipartField{},
		jsonEscapeHTML:  c.jsonEscapeHTML,
		log:             c.log,
	}
	return r
}

// NewRequest is an alias for method `R()`. Creates a new request instance, its used for
// Get, Post, Put, Delete, Patch, Head, Options, etc.
func (c *Client) NewRequest() *Request {
	return c.R()
}

// OnBeforeRequest method appends a request middleware into the before request chain.
// The user defined middlewares get applied before the default Resty request middlewares.
// After all middlewares have been applied, the request is sent from Resty to the host server.
//
//	client.OnBeforeRequest(func(c *resty.Client, r *resty.Request) error {
//			// Now you have access to Client and Request instance
//			// manipulate it as per your need
//
//			return nil 	// if its success otherwise return error
//		})
func (c *Client) OnBeforeRequest(m RequestMiddleware) *Client {
	c.udBeforeRequestLock.Lock()
	defer c.udBeforeRequestLock.Unlock()

	c.udBeforeRequest = append(c.udBeforeRequest, m)

	return c
}

// OnAfterResponse method appends response middleware into the after response chain.
// Once we receive response from host server, default Resty response middleware
// gets applied and then user assigned response middlewares applied.
//
//	client.OnAfterResponse(func(c *resty.Client, r *resty.Response) error {
//			// Now you have access to Client and Response instance
//			// manipulate it as per your need
//
//			return nil 	// if its success otherwise return error
//		})
func (c *Client) OnAfterResponse(m ResponseMiddleware) *Client {
	c.afterResponseLock.Lock()
	defer c.afterResponseLock.Unlock()

	c.afterResponse = append(c.afterResponse, m)

	return c
}

// OnError method adds a callback that will be run whenever a request execution fails.
// This is called after all retries have been attempted (if any).
// If there was a response from the server, the error will be wrapped in *ResponseError
// which has the last response received from the server.
//
//	client.OnError(func(req *resty.Request, err error) {
//		if v, ok := err.(*resty.ResponseError); ok {
//			// Do something with v.Response
//		}
//		// Log the error, increment a metric, etc...
//	})
//
// Out of the OnSuccess, OnError, OnInvalid, OnPanic callbacks, exactly one
// set will be invoked for each call to Request.Execute() that completes.
func (c *Client) OnError(h ErrorHook) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.errorHooks = append(c.errorHooks, h)
	return c
}

// OnSuccess method adds a callback that will be run whenever a request execution
// succeeds.  This is called after all retries have been attempted (if any).
//
// Out of the OnSuccess, OnError, OnInvalid, OnPanic callbacks, exactly one
// set will be invoked for each call to Request.Execute() that completes.
//
// Since v2.8.0
func (c *Client) OnSuccess(h SuccessHook) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.successHooks = append(c.successHooks, h)
	return c
}

// OnInvalid method adds a callback that will be run whenever a request execution
// fails before it starts because the request is invalid.
//
// Out of the OnSuccess, OnError, OnInvalid, OnPanic callbacks, exactly one
// set will be invoked for each call to Request.Execute() that completes.
//
// Since v2.8.0
func (c *Client) OnInvalid(h ErrorHook) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.invalidHooks = append(c.invalidHooks, h)
	return c
}

// OnPanic method adds a callback that will be run whenever a request execution
// panics.
//
// Out of the OnSuccess, OnError, OnInvalid, OnPanic callbacks, exactly one
// set will be invoked for each call to Request.Execute() that completes.
// If an OnSuccess, OnError, or OnInvalid callback panics, then the exactly
// one rule can be violated.
//
// Since v2.8.0
func (c *Client) OnPanic(h ErrorHook) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.panicHooks = append(c.panicHooks, h)
	return c
}

// SetPreRequestHook method sets the given pre-request function into resty client.
// It is called right before the request is fired.
//
// Note: Only one pre-request hook can be registered. Use `client.OnBeforeRequest` for multiple.
func (c *Client) SetPreRequestHook(h PreRequestHook) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.preReqHook != nil {
		c.log.Warnf("Overwriting an existing pre-request hook: %s", functionName(h))
	}
	c.preReqHook = h
	return c
}

// Debug method gets if the Resty client is in debug mode.
func (c *Client) Debug() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.debug
}

// SetDebug method enables the debug mode on Resty client. Client logs details of every request and response.
// For `Request` it logs information such as HTTP verb, Relative URL path, Host, Headers, Body if it has one.
// For `Response` it logs information such as Status, Response Time, Headers, Body if it has one.
//
//	client.SetDebug(true)
//
// Also it can be enabled at request level for particular request, see `Request.SetDebug`.
func (c *Client) SetDebug(d bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.debug = d
	return c
}

// SetDebugBodyLimit sets the maximum size for which the response and request body will be logged in debug mode.
//
//	client.SetDebugBodyLimit(1000000)
func (c *Client) SetDebugBodyLimit(sl int64) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.debugBodySizeLimit = sl
	return c
}

// OnRequestLog method used to set request log callback into Resty. Registered callback gets
// called before the resty actually logs the information.
func (c *Client) OnRequestLog(rl RequestLogCallback) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.requestLog != nil {
		c.log.Warnf("Overwriting an existing on-request-log callback from=%s to=%s",
			functionName(c.requestLog), functionName(rl))
	}
	c.requestLog = rl
	return c
}

// OnResponseLog method used to set response log callback into Resty. Registered callback gets
// called before the resty actually logs the information.
func (c *Client) OnResponseLog(rl ResponseLogCallback) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.responseLog != nil {
		c.log.Warnf("Overwriting an existing on-response-log callback from=%s to=%s",
			functionName(c.responseLog), functionName(rl))
	}
	c.responseLog = rl
	return c
}

// DisableWarn method gets if the Resty client disables the warning message.
func (c *Client) DisableWarn() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.disableWarn
}

// SetDisableWarn method disables the warning message on Resty client.
//
// For Example: Resty warns the user when BasicAuth used on non-TLS mode.
//
//	client.SetDisableWarn(true)
func (c *Client) SetDisableWarn(d bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.disableWarn = d
	return c
}

// AllowGetMethodPayload method gets if the Resty client allows the GET method with payload.
func (c *Client) AllowGetMethodPayload() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.allowGetMethodPayload
}

// SetAllowGetMethodPayload method allows the GET method with payload on Resty client.
//
// For Example: Resty allows the user sends request with a payload on HTTP GET method.
//
//	client.SetAllowGetMethodPayload(true)
func (c *Client) SetAllowGetMethodPayload(a bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.allowGetMethodPayload = a
	return c
}

// SetLogger method sets given writer for logging Resty request and response details.
//
// Compliant to interface `resty.Logger`.
func (c *Client) SetLogger(l Logger) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.log = l
	return c
}

// SetContentLength method enables the HTTP header `Content-Length` value for every request.
// By default Resty won't set `Content-Length`.
//
//	client.SetContentLength(true)
//
// Also you have an option to enable for particular request. See `Request.SetContentLength`
func (c *Client) SetContentLength(l bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.setContentLength = l
	return c
}

// SetTimeout method sets timeout for request raised from client.
//
//	client.SetTimeout(time.Duration(1 * time.Minute))
func (c *Client) SetTimeout(timeout time.Duration) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.httpClient.Timeout = timeout
	return c
}

// Error method returns the global or client common `Error` object into Resty.
func (c *Client) Error() reflect.Type {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.error
}

// SetError method is to register the global or client common `Error` object into Resty.
// It is used for automatic unmarshalling if response status code is greater than 399 and
// content type either JSON or XML. Can be pointer or non-pointer.
//
//	client.SetError(&Error{})
//	// OR
//	client.SetError(Error{})
func (c *Client) SetError(err interface{}) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.error = typeOf(err)
	return c
}

// SetRedirectPolicy method sets the client redirect policy. Resty provides ready to use
// redirect policies. Wanna create one for yourself refer to `redirect.go`.
//
//	client.SetRedirectPolicy(FlexibleRedirectPolicy(20))
//
//	// Need multiple redirect policies together
//	client.SetRedirectPolicy(FlexibleRedirectPolicy(20), DomainCheckRedirectPolicy("host1.com", "host2.net"))
func (c *Client) SetRedirectPolicy(policies ...interface{}) *Client {
	for _, p := range policies {
		if _, ok := p.(RedirectPolicy); !ok {
			c.log.Errorf("%v does not implement resty.RedirectPolicy (missing Apply method)",
				functionName(p))
		}
	}
	c.lock.Lock()
	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		for _, p := range policies {
			if err := p.(RedirectPolicy).Apply(req, via); err != nil {
				return err
			}
		}
		return nil // looks good, go ahead
	}
	c.lock.Unlock()
	return c
}

// RetryCount method gets retry count in Resty client.
func (c *Client) RetryCount() int {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryCount
}

// SetRetryCount method enables retry on Resty client and allows you
// to set no. of retry count. Resty uses a Backoff mechanism.
func (c *Client) SetRetryCount(count int) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.retryCount = count
	return c
}

// RetryWaitTime gets default wait time to sleep before retrying requeset.
func (c *Client) RetryWaitTime() time.Duration {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryWaitTime
}

// SetRetryWaitTime method sets default wait time to sleep before retrying
// request.
//
// Default is 100 milliseconds.
func (c *Client) SetRetryWaitTime(waitTime time.Duration) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.retryWaitTime = waitTime
	return c
}

// RetryMaxWaitTime method gets max wait time to sleep before retrying request.
func (c *Client) RetryMaxWaitTime() time.Duration {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryMaxWaitTime
}

// SetRetryMaxWaitTime method sets max wait time to sleep before retrying
// request.
//
// Default is 2 seconds.
func (c *Client) SetRetryMaxWaitTime(maxWaitTime time.Duration) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.retryMaxWaitTime = maxWaitTime
	return c
}

// RetryAfter gets callback to calculate wait time between retries.
func (c *Client) RetryAfter() RetryAfterFunc {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryAfter
}

// SetRetryAfter sets callback to calculate wait time between retries.
// Default (nil) implies exponential backoff with jitter
func (c *Client) SetRetryAfter(callback RetryAfterFunc) *Client {
	c.lock.Lock()
	c.lock.Unlock()
	c.retryAfter = callback
	return c
}

// JSONMarshaler method gets the JSON marshaler function to marshal the request body.
func (c *Client) JSONMarshaler() func(v interface{}) ([]byte, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.jsonMarshal
}

// SetJSONMarshaler method sets the JSON marshaler function to marshal the request body.
// By default, Resty uses `encoding/json` package to marshal the request body.
//
// Since v2.8.0
func (c *Client) SetJSONMarshaler(marshaler func(v interface{}) ([]byte, error)) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.jsonMarshal = marshaler
	return c
}

// JSONUnmarshaler method gets the JSON unmarshaler function to unmarshal the response body.
func (c *Client) JSONUnmarshaler() func([]byte, interface{}) error {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.jsonUnmarshal
}

// SetJSONUnmarshaler method sets the JSON unmarshaler function to unmarshal the response body.
// By default, Resty uses `encoding/json` package to unmarshal the response body.
//
// Since v2.8.0
func (c *Client) SetJSONUnmarshaler(unmarshaler func(data []byte, v interface{}) error) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.jsonUnmarshal = unmarshaler
	return c
}

// XMLMarshaler method gets the XML marshaler function to marshal the request body.
func (c *Client) XMLMarshaler() func(interface{}) ([]byte, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.xmlMarshal
}

// SetXMLMarshaler method sets the XML marshaler function to marshal the request body.
// By default, Resty uses `encoding/xml` package to marshal the request body.
//
// Since v2.8.0
func (c *Client) SetXMLMarshaler(marshaler func(v interface{}) ([]byte, error)) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.xmlMarshal = marshaler
	return c
}

// XMLUnmarshaler method gets the XML unmarshaler function to unmarshal the response body.
func (c *Client) XMLUnmarshaler() func([]byte, interface{}) error {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.xmlUnmarshal
}

// SetXMLUnmarshaler method sets the XML unmarshaler function to unmarshal the response body.
// By default, Resty uses `encoding/xml` package to unmarshal the response body.
//
// Since v2.8.0
func (c *Client) SetXMLUnmarshaler(unmarshaler func(data []byte, v interface{}) error) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.xmlUnmarshal = unmarshaler
	return c
}

// HeaderAuthorizationKey gets the header authorization key in the Resty client.
func (c *Client) HeaderAuthorizationKey() string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.headerAuthorizationKey
}

// RetryConditions method gets all retry condition functions.
func (c *Client) RetryConditions() []RetryConditionFunc {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryConditions
}

// AddRetryCondition method adds a retry condition function to array of functions
// that are checked to determine if the request is retried. The request will
// retry if any of the functions return true and error is nil.
//
// Note: These retry conditions are applied on all Request made using this Client.
// For Request specific retry conditions check *Request.AddRetryCondition
func (c *Client) AddRetryCondition(condition RetryConditionFunc) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.retryConditions = append(c.retryConditions, condition)
	return c
}

// AddRetryAfterErrorCondition adds the basic condition of retrying after encountering
// an error from the http response
//
// Since v2.6.0
func (c *Client) AddRetryAfterErrorCondition() *Client {
	c.AddRetryCondition(func(response *Response, err error) bool {
		return response.IsError()
	})
	return c
}

// RetryHooks gets all retry hooks.
func (c *Client) RetryHooks() []OnRetryFunc {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryHooks
}

// AddRetryHook adds a side-effecting retry hook to an array of hooks
// that will be executed on each retry.
//
// Since v2.6.0
func (c *Client) AddRetryHook(hook OnRetryFunc) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.retryHooks = append(c.retryHooks, hook)
	return c
}

// RetryResetReaders method gets if the Resty client is enabled to seek the start
// of all file readers given as multipart files.
func (c *Client) RetryResetReaders() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.retryResetReaders
}

// SetRetryResetReaders method enables the Resty client to seek the start of all
// file readers given as multipart files, if the given object implements `io.ReadSeeker`.
//
// Since ...
func (c *Client) SetRetryResetReaders(b bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.retryResetReaders = b
	return c
}

// SetTLSClientConfig method sets TLSClientConfig for underling client Transport.
//
// For Example:
//
//	// One can set custom root-certificate. Refer: http://golang.org/pkg/crypto/tls/#example_Dial
//	client.SetTLSClientConfig(&tls.Config{ RootCAs: roots })
//
//	// or One can disable security check (https)
//	client.SetTLSClientConfig(&tls.Config{ InsecureSkipVerify: true })
//
// Note: This method overwrites existing `TLSClientConfig`.
func (c *Client) SetTLSClientConfig(config *tls.Config) *Client {
	transport, err := c.Transport()
	if err != nil {
		c.log.Errorf("%v", err)
		return c
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	transport.TLSClientConfig = config
	return c
}

// SetProxy method sets the Proxy URL and Port for Resty client.
//
//	client.SetProxy("http://proxyserver:8888")
//
// OR Without this `SetProxy` method, you could also set Proxy via environment variable.
//
// Refer to godoc `http.ProxyFromEnvironment`.
func (c *Client) SetProxy(proxyURL string) *Client {
	transport, err := c.Transport()
	if err != nil {
		c.log.Errorf("%v", err)
		return c
	}

	pURL, err := url.Parse(proxyURL)
	if err != nil {
		c.log.Errorf("%v", err)
		return c
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.proxyURL = pURL
	transport.Proxy = http.ProxyURL(c.proxyURL)
	return c
}

// RemoveProxy method removes the proxy configuration from Resty client
//
//	client.RemoveProxy()
func (c *Client) RemoveProxy() *Client {
	transport, err := c.Transport()
	if err != nil {
		c.log.Errorf("%v", err)
		return c
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.proxyURL = nil
	transport.Proxy = nil
	return c
}

// SetCertificates method helps to set client certificates into Resty conveniently.
func (c *Client) SetCertificates(certs ...tls.Certificate) *Client {
	config, err := c.tlsConfig()
	if err != nil {
		c.log.Errorf("%v", err)
		return c
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	config.Certificates = append(config.Certificates, certs...)
	return c
}

// SetRootCertificate method helps to add one or more root certificates into Resty client
//
//	client.SetRootCertificate("/path/to/root/pemFile.pem")
func (c *Client) SetRootCertificate(pemFilePath string) *Client {
	rootPemData, err := os.ReadFile(pemFilePath)
	if err != nil {
		c.log.Errorf("%v", err)
		return c
	}

	config, err := c.tlsConfig()
	if err != nil {
		c.log.Errorf("%v", err)
		return c
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if config.RootCAs == nil {
		config.RootCAs = x509.NewCertPool()
	}

	config.RootCAs.AppendCertsFromPEM(rootPemData)
	return c
}

// SetRootCertificateFromString method helps to add one or more root certificates into Resty client
//
//	client.SetRootCertificateFromString("pem file content")
func (c *Client) SetRootCertificateFromString(pemContent string) *Client {
	config, err := c.tlsConfig()
	if err != nil {
		c.log.Errorf("%v", err)
		return c
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if config.RootCAs == nil {
		config.RootCAs = x509.NewCertPool()
	}

	config.RootCAs.AppendCertsFromPEM([]byte(pemContent))
	return c
}

// SetOutputDirectory method sets output directory for saving HTTP response into file.
// If the output directory not exists then resty creates one. This setting is optional one,
// if you're planning using absolute path in `Request.SetOutput` and can used together.
//
//	client.SetOutputDirectory("/save/http/response/here")
func (c *Client) SetOutputDirectory(dirPath string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.outputDirectory = dirPath
	return c
}

// SetRateLimiter sets an optional `RateLimiter`. If set the rate limiter will control
// all requests made with this client.
//
// Since v2.9.0
func (c *Client) SetRateLimiter(rl RateLimiter) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.rateLimiter = rl
	return c
}

// SetTransport method sets custom `*http.Transport` or any `http.RoundTripper`
// compatible interface implementation in the resty client.
//
// Note:
//
// - If transport is not type of `*http.Transport` then you may not be able to
// take advantage of some of the Resty client settings.
//
// - It overwrites the Resty client transport instance and it's configurations.
//
//	transport := &http.Transport{
//		// something like Proxying to httptest.Server, etc...
//		Proxy: func(req *http.Request) (*url.URL, error) {
//			return url.Parse(server.URL)
//		},
//	}
//
//	client.SetTransport(transport)
func (c *Client) SetTransport(transport http.RoundTripper) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	if transport != nil {
		c.httpClient.Transport = transport
	}
	return c
}

// SetScheme method sets custom scheme in the Resty client. It's way to override default.
//
//	client.SetScheme("http")
func (c *Client) SetScheme(scheme string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	if !IsStringEmpty(scheme) {
		c.scheme = strings.TrimSpace(scheme)
	}
	return c
}

// SetCloseConnection method sets variable `Close` in http request struct with the given
// value. More info: https://golang.org/src/net/http/request.go
func (c *Client) SetCloseConnection(close bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.closeConnection = close
	return c
}

// SetDoNotParseResponse method instructs `Resty` not to parse the response body automatically.
// Resty exposes the raw response body as `io.ReadCloser`. Also do not forget to close the body,
// otherwise you might get into connection leaks, no connection reuse.
//
// Note: Response middlewares are not applicable, if you use this option. Basically you have
// taken over the control of response parsing from `Resty`.
func (c *Client) SetDoNotParseResponse(parse bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.notParseResponse = parse
	return c
}

// SetPathParam method sets single URL path key-value pair in the
// Resty client instance.
//
//	client.SetPathParam("userId", "sample@sample.com")
//
//	Result:
//	   URL - /v1/users/{userId}/details
//	   Composed URL - /v1/users/sample@sample.com/details
//
// It replaces the value of the key while composing the request URL.
// The value will be escaped using `url.PathEscape` function.
//
// Also it can be overridden at request level Path Params options,
// see `Request.SetPathParam` or `Request.SetPathParams`.
func (c *Client) SetPathParam(param, value string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.pathParams[param] = value
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
// The values will be escaped using `url.PathEscape` function.
//
// Also it can be overridden at request level Path Params options,
// see `Request.SetPathParam` or `Request.SetPathParams`.
func (c *Client) SetPathParams(params map[string]string) *Client {
	for p, v := range params {
		c.SetPathParam(p, v)
	}
	return c
}

// SetRawPathParam method sets single URL path key-value pair in the
// Resty client instance.
//
//	client.SetPathParam("userId", "sample@sample.com")
//
//	Result:
//	   URL - /v1/users/{userId}/details
//	   Composed URL - /v1/users/sample@sample.com/details
//
//	client.SetPathParam("path", "groups/developers")
//
//	Result:
//	   URL - /v1/users/{userId}/details
//	   Composed URL - /v1/users/groups%2Fdevelopers/details
//
// It replaces the value of the key while composing the request URL.
// The value will be used as it is and will not be escaped.
//
// Also it can be overridden at request level Path Params options,
// see `Request.SetPathParam` or `Request.SetPathParams`.
//
// Since v2.8.0
func (c *Client) SetRawPathParam(param, value string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.rawPathParams[param] = value
	return c
}

// SetRawPathParams method sets multiple URL path key-value pairs at one go in the
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
//	   Composed URL - /v1/users/sample@sample.com/100002/groups/developers/details
//
// It replaces the value of the key while composing the request URL.
// The values will be used as they are and will not be escaped.
//
// Also it can be overridden at request level Path Params options,
// see `Request.SetPathParam` or `Request.SetPathParams`.
//
// Since v2.8.0
func (c *Client) SetRawPathParams(params map[string]string) *Client {
	for p, v := range params {
		c.SetRawPathParam(p, v)
	}
	return c
}

// SetJSONEscapeHTML method is to enable/disable the HTML escape on JSON marshal.
//
// Note: This option only applicable to standard JSON Marshaller.
func (c *Client) SetJSONEscapeHTML(b bool) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.jsonEscapeHTML = b
	return c
}

// EnableTrace method enables the Resty client trace for the requests fired from
// the client using `httptrace.ClientTrace` and provides insights.
//
//	client := resty.New().EnableTrace()
//
//	resp, err := client.R().Get("https://httpbin.org/get")
//	fmt.Println("Error:", err)
//	fmt.Println("Trace Info:", resp.Request.TraceInfo())
//
// Also `Request.EnableTrace` available too to get trace info for single request.
//
// Since v2.0.0
func (c *Client) EnableTrace() *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.trace = true
	return c
}

// DisableTrace method disables the Resty client trace. Refer to `Client.EnableTrace`.
//
// Since v2.0.0
func (c *Client) DisableTrace() *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.trace = false
	return c
}

// IsProxySet method returns the true is proxy is set from resty client otherwise
// false. By default proxy is set from environment, refer to `http.ProxyFromEnvironment`.
func (c *Client) IsProxySet() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.proxyURL != nil
}

// GetClient method returns the current `http.Client` used by the resty client.
func (c *Client) GetClient() *http.Client {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.httpClient
}

// Clone returns a clone of the original client.
//
// Be careful when using this function:
// - Interface values are not deeply cloned. Thus, both the original and the clone will use the
// same value.
// - This function is not safe for concurrent use. You should only use this when you are sure that
// the client is not being used by any other goroutine.
//
// Since v2.12.0
func (c *Client) Clone() *Client {
	// dereference the pointer and copy the value
	cc := *c

	// lock values should not be copied - thus new values are used.
	cc.afterResponseLock = &sync.RWMutex{}
	cc.udBeforeRequestLock = &sync.RWMutex{}
	cc.lock = &sync.RWMutex{}
	return &cc
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Client Unexported methods
//_______________________________________________________________________

func (c *Client) executeBefore(req *Request) error {
	// Lock the user-defined pre-request hooks.
	c.udBeforeRequestLock.RLock()
	defer c.udBeforeRequestLock.RUnlock()

	// Lock the post-request hooks.
	c.afterResponseLock.RLock()
	defer c.afterResponseLock.RUnlock()

	// Apply Request middleware
	var err error

	// user defined on before request methods
	// to modify the *resty.Request object
	for _, f := range c.udBeforeRequest {
		if err = f(c, req); err != nil {
			return wrapNoRetryErr(err)
		}
	}

	// If there is a rate limiter set for this client, the Execute call
	// will return an error if the rate limit is exceeded.
	if req.client.rateLimiter != nil {
		if !req.client.rateLimiter.Allow() {
			return wrapNoRetryErr(ErrRateLimitExceeded)
		}
	}

	// resty middlewares
	for _, f := range c.beforeRequest {
		if err = f(c, req); err != nil {
			return wrapNoRetryErr(err)
		}
	}

	if hostHeader := req.Header.Get("Host"); hostHeader != "" {
		req.RawRequest.Host = hostHeader
	}

	// call pre-request if defined
	if c.preReqHook != nil {
		if err = c.preReqHook(c, req.RawRequest); err != nil {
			return wrapNoRetryErr(err)
		}
	}

	if err = requestLogger(c, req); err != nil {
		return wrapNoRetryErr(err)
	}

	req.RawRequest.Body = newRequestBodyReleaser(req.RawRequest.Body, req.bodyBuf)
	return nil
}

// Executes method executes the given `Request` object and returns response
// error.
func (c *Client) execute(req *Request) (*Response, error) {
	if err := c.executeBefore(req); err != nil {
		return nil, err
	}

	req.Time = time.Now()
	resp, err := c.httpClient.Do(req.RawRequest)

	response := &Response{
		Request:     req,
		RawResponse: resp,
	}

	if err != nil || req.notParseResponse || c.notParseResponse {
		response.setReceivedAt()
		return response, err
	}

	if !req.isSaveResponse {
		defer closeq(resp.Body)
		body := resp.Body

		// GitHub #142 & #187
		if strings.EqualFold(resp.Header.Get(hdrContentEncodingKey), "gzip") && resp.ContentLength != 0 {
			if _, ok := body.(*gzip.Reader); !ok {
				body, err = gzip.NewReader(body)
				if err != nil {
					response.setReceivedAt()
					return response, err
				}
				defer closeq(body)
			}
		}

		if response.body, err = io.ReadAll(body); err != nil {
			response.setReceivedAt()
			return response, err
		}

		response.size = int64(len(response.body))
	}

	response.setReceivedAt() // after we read the body

	// Apply Response middleware
	for _, f := range c.afterResponse {
		if err = f(c, response); err != nil {
			break
		}
	}

	return response, wrapNoRetryErr(err)
}

// getting TLS client config if not exists then create one
func (c *Client) tlsConfig() (*tls.Config, error) {
	transport, err := c.Transport()
	if err != nil {
		return nil, err
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	return transport.TLSClientConfig, nil
}

// Transport method returns `*http.Transport` currently in use or error
// in case currently used `transport` is not a `*http.Transport`.
//
// Since v2.8.0 become exported method.
func (c *Client) Transport() (*http.Transport, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		return transport, nil
	}
	return nil, errors.New("current transport is not an *http.Transport instance")
}

// just an internal helper method
func (c *Client) outputLogTo(w io.Writer) *Client {
	c.log.(*logger).l.SetOutput(w)
	return c
}

// ResponseError is a wrapper for including the server response with an error.
// Neither the err nor the response should be nil.
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
// It wraps the error in a ResponseError if the resp is not nil
// so hooks can access it.
func (c *Client) onErrorHooks(req *Request, resp *Response, err error) {
	if err != nil {
		if resp != nil { // wrap with ResponseError
			err = &ResponseError{Response: resp, Err: err}
		}
		for _, h := range c.errorHooks {
			h(req, err)
		}
	} else {
		for _, h := range c.successHooks {
			h(c, resp)
		}
	}
}

// Helper to run panicHooks hooks.
func (c *Client) onPanicHooks(req *Request, err error) {
	for _, h := range c.panicHooks {
		h(req, err)
	}
}

// Helper to run invalidHooks hooks.
func (c *Client) onInvalidHooks(req *Request, err error) {
	for _, h := range c.invalidHooks {
		h(req, err)
	}
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// File struct and its methods
//_______________________________________________________________________

// File struct represent file information for multipart request
type File struct {
	Name      string
	ParamName string
	io.Reader
}

// String returns string value of current file details
func (f *File) String() string {
	return fmt.Sprintf("ParamName: %v; FileName: %v", f.ParamName, f.Name)
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// MultipartField struct
//_______________________________________________________________________

// MultipartField struct represent custom data part for multipart request
type MultipartField struct {
	Param       string
	FileName    string
	ContentType string
	io.Reader
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Unexported package methods
//_______________________________________________________________________

func createClient(hc *http.Client) *Client {
	if hc.Transport == nil {
		hc.Transport = createTransport(nil)
	}

	c := &Client{ // not setting lang default values
		queryParam:             url.Values{},
		formData:               url.Values{},
		header:                 http.Header{},
		cookies:                make([]*http.Cookie, 0),
		retryWaitTime:          defaultWaitTime,
		retryMaxWaitTime:       defaultMaxWaitTime,
		pathParams:             make(map[string]string),
		rawPathParams:          make(map[string]string),
		jsonMarshal:            json.Marshal,
		jsonUnmarshal:          json.Unmarshal,
		xmlMarshal:             xml.Marshal,
		xmlUnmarshal:           xml.Unmarshal,
		headerAuthorizationKey: http.CanonicalHeaderKey("Authorization"),

		jsonEscapeHTML:      true,
		httpClient:          hc,
		debugBodySizeLimit:  math.MaxInt32,
		udBeforeRequestLock: &sync.RWMutex{},
		afterResponseLock:   &sync.RWMutex{},
		lock:                &sync.RWMutex{},
	}

	// Logger
	c.SetLogger(createLogger())

	// default before request middlewares
	c.beforeRequest = []RequestMiddleware{
		parseRequestURL,
		parseRequestHeader,
		parseRequestBody,
		createHTTPRequest,
		addCredentials,
		createCurlCmd,
	}

	// user defined request middlewares
	c.udBeforeRequest = []RequestMiddleware{}

	// default after response middlewares
	c.afterResponse = []ResponseMiddleware{
		responseLogger,
		parseResponseBody,
		saveResponseIntoFile,
	}

	return c
}
