// Copyright (c) 2015-2017 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
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
	hdrUserAgentKey     = http.CanonicalHeaderKey("User-Agent")
	hdrAcceptKey        = http.CanonicalHeaderKey("Accept")
	hdrContentTypeKey   = http.CanonicalHeaderKey("Content-Type")
	hdrContentLengthKey = http.CanonicalHeaderKey("Content-Length")
	hdrAuthorizationKey = http.CanonicalHeaderKey("Authorization")

	plainTextType   = "text/plain; charset=utf-8"
	jsonContentType = "application/json; charset=utf-8"
	formContentType = "application/x-www-form-urlencoded"

	jsonCheck = regexp.MustCompile("(?i:[application|text]/json)")
	xmlCheck  = regexp.MustCompile("(?i:[application|text]/xml)")

	hdrUserAgentValue = "go-resty v%s - https://github.com/go-resty/resty"
	bufPool           = &sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}
)

// Client type is used for HTTP/RESTful global values
// for all request raised from the client
type Client struct {
	HostURL          string
	QueryParam       url.Values
	FormData         url.Values
	Header           http.Header
	UserInfo         *User
	Token            string
	Cookies          []*http.Cookie
	Error            reflect.Type
	Debug            bool
	DisableWarn      bool
	Log              *log.Logger
	RetryCount       int
	RetryWaitTime    time.Duration
	RetryMaxWaitTime time.Duration
	RetryConditions  []RetryConditionFunc

	httpClient       *http.Client
	transport        *http.Transport
	setContentLength bool
	isHTTPMode       bool
	outputDirectory  string
	scheme           string
	proxyURL         *url.URL
	closeConnection  bool
	beforeRequest    []func(*Client, *Request) error
	udBeforeRequest  []func(*Client, *Request) error
	preReqHook       func(*Client, *Request) error
	afterResponse    []func(*Client, *Response) error
}

// User type is to hold an username and password information
type User struct {
	Username, Password string
}

// SetHostURL method is to set Host URL in the client instance. It will be used with request
// raised from this client with relative URL
//		// Setting HTTP address
//		resty.SetHostURL("http://myjeeva.com")
//
//		// Setting HTTPS address
//		resty.SetHostURL("https://myjeeva.com")
//
func (c *Client) SetHostURL(url string) *Client {
	c.HostURL = strings.TrimRight(url, "/")
	return c
}

// SetHeader method sets a single header field and its value in the client instance.
// These headers will be applied to all requests raised from this client instance.
// Also it can be overridden at request level header options, see `resty.R().SetHeader`
// or `resty.R().SetHeaders`.
//
// Example: To set `Content-Type` and `Accept` as `application/json`
//
// 		resty.
// 			SetHeader("Content-Type", "application/json").
// 			SetHeader("Accept", "application/json")
//
func (c *Client) SetHeader(header, value string) *Client {
	c.Header.Set(header, value)
	return c
}

// SetHeaders method sets multiple headers field and its values at one go in the client instance.
// These headers will be applied to all requests raised from this client instance. Also it can be
// overridden at request level headers options, see `resty.R().SetHeaders` or `resty.R().SetHeader`.
//
// Example: To set `Content-Type` and `Accept` as `application/json`
//
// 		resty.SetHeaders(map[string]string{
//				"Content-Type": "application/json",
//				"Accept": "application/json",
//			})
//
func (c *Client) SetHeaders(headers map[string]string) *Client {
	for h, v := range headers {
		c.Header.Set(h, v)
	}

	return c
}

// SetCookieJar method sets custom http.CookieJar in the resty client. Its way to override default.
// Example: sometimes we don't want to save cookies in api contacting, we can remove the default
// CookieJar in resty client.
//
//		resty.SetCookieJar(nil)
//
func (c *Client) SetCookieJar(jar http.CookieJar) *Client {
	c.httpClient.Jar = jar
	return c
}

// SetCookie method appends a single cookie in the client instance.
// These cookies will be added to all the request raised from this client instance.
// 		resty.SetCookie(&http.Cookie{
// 					Name:"go-resty",
//					Value:"This is cookie value",
//					Path: "/",
// 					Domain: "sample.com",
// 					MaxAge: 36000,
// 					HttpOnly: true,
//					Secure: false,
// 				})
//
func (c *Client) SetCookie(hc *http.Cookie) *Client {
	c.Cookies = append(c.Cookies, hc)
	return c
}

// SetCookies method sets an array of cookies in the client instance.
// These cookies will be added to all the request raised from this client instance.
// 		cookies := make([]*http.Cookie, 0)
//
//		cookies = append(cookies, &http.Cookie{
// 					Name:"go-resty-1",
//					Value:"This is cookie 1 value",
//					Path: "/",
// 					Domain: "sample.com",
// 					MaxAge: 36000,
// 					HttpOnly: true,
//					Secure: false,
// 				})
//
//		cookies = append(cookies, &http.Cookie{
// 					Name:"go-resty-2",
//					Value:"This is cookie 2 value",
//					Path: "/",
// 					Domain: "sample.com",
// 					MaxAge: 36000,
// 					HttpOnly: true,
//					Secure: false,
// 				})
//
//		// Setting a cookies into resty
// 		resty.SetCookies(cookies)
//
func (c *Client) SetCookies(cs []*http.Cookie) *Client {
	c.Cookies = append(c.Cookies, cs...)
	return c
}

// SetQueryParam method sets single parameter and its value in the client instance.
// It will be formed as query string for the request. For example: `search=kitchen%20papers&size=large`
// in the URL after `?` mark. These query params will be added to all the request raised from
// this client instance. Also it can be overridden at request level Query Param options,
// see `resty.R().SetQueryParam` or `resty.R().SetQueryParams`.
// 		resty.
//			SetQueryParam("search", "kitchen papers").
//			SetQueryParam("size", "large")
//
func (c *Client) SetQueryParam(param, value string) *Client {
	c.QueryParam.Set(param, value)
	return c
}

// SetQueryParams method sets multiple parameters and their values at one go in the client instance.
// It will be formed as query string for the request. For example: `search=kitchen%20papers&size=large`
// in the URL after `?` mark. These query params will be added to all the request raised from this
// client instance. Also it can be overridden at request level Query Param options,
// see `resty.R().SetQueryParams` or `resty.R().SetQueryParam`.
// 		resty.SetQueryParams(map[string]string{
//				"search": "kitchen papers",
//				"size": "large",
//			})
//
func (c *Client) SetQueryParams(params map[string]string) *Client {
	for p, v := range params {
		c.SetQueryParam(p, v)
	}

	return c
}

// SetFormData method sets Form parameters and their values in the client instance.
// It's applicable only HTTP method `POST` and `PUT` and requets content type would be set as
// `application/x-www-form-urlencoded`. These form data will be added to all the request raised from
// this client instance. Also it can be overridden at request level form data, see `resty.R().SetFormData`.
// 		resty.SetFormData(map[string]string{
//				"access_token": "BC594900-518B-4F7E-AC75-BD37F019E08F",
//				"user_id": "3455454545",
//			})
//
func (c *Client) SetFormData(data map[string]string) *Client {
	for k, v := range data {
		c.FormData.Set(k, v)
	}

	return c
}

// SetBasicAuth method sets the basic authentication header in the HTTP request. Example:
//		Authorization: Basic <base64-encoded-value>
//
// Example: To set the header for username "go-resty" and password "welcome"
// 		resty.SetBasicAuth("go-resty", "welcome")
//
// This basic auth information gets added to all the request rasied from this client instance.
// Also it can be overridden or set one at the request level is supported, see `resty.R().SetBasicAuth`.
//
func (c *Client) SetBasicAuth(username, password string) *Client {
	c.UserInfo = &User{Username: username, Password: password}
	return c
}

// SetAuthToken method sets bearer auth token header in the HTTP request. Example:
// 		Authorization: Bearer <auth-token-value-comes-here>
//
// Example: To set auth token BC594900518B4F7EAC75BD37F019E08FBC594900518B4F7EAC75BD37F019E08F
//
// 		resty.SetAuthToken("BC594900518B4F7EAC75BD37F019E08FBC594900518B4F7EAC75BD37F019E08F")
//
// This bearer auth token gets added to all the request rasied from this client instance.
// Also it can be overridden or set one at the request level is supported, see `resty.R().SetAuthToken`.
//
func (c *Client) SetAuthToken(token string) *Client {
	c.Token = token
	return c
}

// R method creates a request instance, its used for Get, Post, Put, Delete, Patch, Head and Options.
func (c *Client) R() *Request {
	r := &Request{
		URL:            "",
		Method:         "",
		QueryParam:     url.Values{},
		FormData:       url.Values{},
		Header:         http.Header{},
		Body:           nil,
		Result:         nil,
		Error:          nil,
		RawRequest:     nil,
		client:         c,
		bodyBuf:        nil,
		multipartFiles: []*File{},
	}

	return r
}

// OnBeforeRequest method appends request middleware into the before request chain.
// Its gets applied after default `go-resty` request middlewares and before request
// been sent from `go-resty` to host server.
// 		resty.OnBeforeRequest(func(c *resty.Client, r *resty.Request) error {
//				// Now you have access to Client and Request instance
//				// manipulate it as per your need
//
//				return nil 	// if its success otherwise return error
//			})
//
func (c *Client) OnBeforeRequest(m func(*Client, *Request) error) *Client {
	c.udBeforeRequest = append(c.udBeforeRequest, m)
	return c
}

// OnAfterResponse method appends response middleware into the after response chain.
// Once we receive response from host server, default `go-resty` response middleware
// gets applied and then user assigened response middlewares applied.
// 		resty.OnAfterResponse(func(c *resty.Client, r *resty.Response) error {
//				// Now you have access to Client and Response instance
//				// manipulate it as per your need
//
//				return nil 	// if its success otherwise return error
//			})
//
func (c *Client) OnAfterResponse(m func(*Client, *Response) error) *Client {
	c.afterResponse = append(c.afterResponse, m)
	return c
}

// SetPreRequestHook method sets the given pre-request function into resty client.
// It is called right before the request is fired.
//
// Note: Only one pre-request hook can be registered. Use `resty.OnBeforeRequest` for mutilple.
func (c *Client) SetPreRequestHook(h func(*Client, *Request) error) *Client {
	if c.preReqHook != nil {
		c.Log.Printf("Overwriting an existing pre-request hook: %s", functionName(h))
	}
	c.preReqHook = h
	return c
}

// SetDebug method enables the debug mode on `go-resty` client. Client logs details of every request and response.
// For `Request` it logs information such as HTTP verb, Relative URL path, Host, Headers, Body if it has one.
// For `Response` it logs information such as Status, Response Time, Headers, Body if it has one.
//		resty.SetDebug(true)
//
func (c *Client) SetDebug(d bool) *Client {
	c.Debug = d
	return c
}

// SetDisableWarn method disables the warning message on `go-resty` client.
// For example: go-resty warns the user when BasicAuth used on HTTP mode.
//		resty.SetDisableWarn(true)
//
func (c *Client) SetDisableWarn(d bool) *Client {
	c.DisableWarn = d
	return c
}

// SetLogger method sets given writer for logging go-resty request and response details.
// Default is os.Stderr
// 		file, _ := os.OpenFile("/Users/jeeva/go-resty.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
//
//		resty.SetLogger(file)
//
func (c *Client) SetLogger(w io.Writer) *Client {
	c.Log = getLogger(w)
	return c
}

// SetContentLength method enables the HTTP header `Content-Length` value for every request.
// By default go-resty won't set `Content-Length`.
// 		resty.SetContentLength(true)
//
// Also you have an option to enable for particular request. See `resty.R().SetContentLength`
//
func (c *Client) SetContentLength(l bool) *Client {
	c.setContentLength = l
	return c
}

// SetTimeout method sets timeout for request raised from client.
//		resty.SetTimeout(time.Duration(1 * time.Minute))
//
func (c *Client) SetTimeout(timeout time.Duration) *Client {
	c.httpClient.Timeout = timeout
	return c
}

// SetError method is to register the global or client common `Error` object into go-resty.
// It is used for automatic unmarshalling if response status code is greater than 399 and
// content type either JSON or XML. Can be pointer or non-pointer.
// 		resty.SetError(&Error{})
//		// OR
//		resty.SetError(Error{})
//
func (c *Client) SetError(err interface{}) *Client {
	c.Error = typeOf(err)
	return c
}

// SetRedirectPolicy method sets the client redirect poilicy. go-resty provides ready to use
// redirect policies. Wanna create one for yourself refer `redirect.go`.
//
//		resty.SetRedirectPolicy(FlexibleRedirectPolicy(20))
//
// 		// Need multiple redirect policies together
//		resty.SetRedirectPolicy(FlexibleRedirectPolicy(20), DomainCheckRedirectPolicy("host1.com", "host2.net"))
//
func (c *Client) SetRedirectPolicy(policies ...interface{}) *Client {
	for _, p := range policies {
		if _, ok := p.(RedirectPolicy); !ok {
			c.Log.Printf("ERORR: %v does not implement resty.RedirectPolicy (missing Apply method)",
				functionName(p))
		}
	}

	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		for _, p := range policies {
			if err := p.(RedirectPolicy).Apply(req, via); err != nil {
				return err
			}
		}
		return nil // looks good, go ahead
	}

	return c
}

// SetRetryCount method enables retry on `go-resty` client and allows you
// to set no. of retry count. Resty uses a Backoff mechanism.
func (c *Client) SetRetryCount(count int) *Client {
	c.RetryCount = count
	return c
}

// SetRetryWaitTime method sets default wait time to sleep before retrying
// request.
// Default is 100 milliseconds.
func (c *Client) SetRetryWaitTime(waitTime time.Duration) *Client {
	c.RetryWaitTime = waitTime
	return c
}

// SetRetryMaxWaitTime method sets max wait time to sleep before retrying
// request.
// Default is 2 seconds.
func (c *Client) SetRetryMaxWaitTime(maxWaitTime time.Duration) *Client {
	c.RetryMaxWaitTime = maxWaitTime
	return c
}

// AddRetryCondition method adds a retry condition function to array of functions
// that are checked to determine if the request is retried. The request will
// retry if any of the functions return true and error is nil.
func (c *Client) AddRetryCondition(condition RetryConditionFunc) *Client {
	c.RetryConditions = append(c.RetryConditions, condition)
	return c
}

// SetHTTPMode method sets go-resty mode into HTTP
func (c *Client) SetHTTPMode() *Client {
	return c.SetMode("http")
}

// SetRESTMode method sets go-resty mode into RESTful
func (c *Client) SetRESTMode() *Client {
	return c.SetMode("rest")
}

// SetMode method sets go-resty client mode to given value such as 'http' & 'rest'.
// 	RESTful:
//		- No Redirect
//		- Automatic response unmarshal if it is JSON or XML
//	HTML:
//		- Up to 10 Redirects
//		- No automatic unmarshall. Response will be treated as `response.String()`
//
// If you want more redirects, use FlexibleRedirectPolicy
//		resty.SetRedirectPolicy(FlexibleRedirectPolicy(20))
//
func (c *Client) SetMode(mode string) *Client {
	// HTTP
	if mode == "http" {
		c.isHTTPMode = true
		c.SetRedirectPolicy(FlexibleRedirectPolicy(10))
		c.afterResponse = []func(*Client, *Response) error{
			responseLogger,
			saveResponseIntoFile,
		}
		return c
	}

	// RESTful
	c.isHTTPMode = false
	c.SetRedirectPolicy(NoRedirectPolicy())
	c.afterResponse = []func(*Client, *Response) error{
		responseLogger,
		parseResponseBody,
		saveResponseIntoFile,
	}
	return c
}

// Mode method returns the current client mode. Typically its a "http" or "rest".
// Default is "rest"
func (c *Client) Mode() string {
	if c.isHTTPMode {
		return "http"
	}
	return "rest"
}

// SetTLSClientConfig method sets TLSClientConfig for underling client Transport.
//
// Example:
// 		// One can set custom root-certificate. Refer: http://golang.org/pkg/crypto/tls/#example_Dial
//		resty.SetTLSClientConfig(&tls.Config{ RootCAs: roots })
//
// 		// or One can disable security check (https)
//		resty.SetTLSClientConfig(&tls.Config{ InsecureSkipVerify: true })
// Note: This method overwrites existing `TLSClientConfig`.
//
func (c *Client) SetTLSClientConfig(config *tls.Config) *Client {
	c.transport.TLSClientConfig = config
	c.httpClient.Transport = c.transport
	return c
}

// SetProxy method sets the Proxy URL and Port for resty client.
//		resty.SetProxy("http://proxyserver:8888")
//
// Alternatives: At request level proxy, see `Request.SetProxy`.  OR Without this `SetProxy` method,
// you can also set Proxy via environment variable. By default `Go` uses setting from `HTTP_PROXY`.
//
func (c *Client) SetProxy(proxyURL string) *Client {
	if pURL, err := url.Parse(proxyURL); err == nil {
		c.proxyURL = pURL
		c.transport.Proxy = http.ProxyURL(c.proxyURL)
		c.httpClient.Transport = c.transport
	} else {
		c.Log.Printf("ERROR [%v]", err)
		c.RemoveProxy()
	}

	return c
}

// RemoveProxy method removes the proxy configuration from resty client
//		resty.RemoveProxy()
//
func (c *Client) RemoveProxy() *Client {
	c.proxyURL = nil
	c.transport.Proxy = nil
	c.httpClient.Transport = c.transport

	return c
}

// SetCertificates method helps to set client certificates into resty conveniently.
//
func (c *Client) SetCertificates(certs ...tls.Certificate) *Client {
	config := c.getTLSConfig()
	config.Certificates = append(config.Certificates, certs...)
	return c
}

// SetRootCertificate method helps to add one or more root certificates into resty client
// 		resty.SetRootCertificate("/path/to/root/pemFile.pem")
//
func (c *Client) SetRootCertificate(pemFilePath string) *Client {
	rootPemData, err := ioutil.ReadFile(pemFilePath)
	if err != nil {
		c.Log.Printf("ERROR [%v]", err)
		return c
	}

	config := c.getTLSConfig()
	if config.RootCAs == nil {
		config.RootCAs = x509.NewCertPool()
	}

	config.RootCAs.AppendCertsFromPEM(rootPemData)

	return c
}

// SetOutputDirectory method sets output directory for saving HTTP response into file.
// If the output directory not exists then resty creates one. This setting is optional one,
// if you're planning using absoule path in `Request.SetOutput` and can used together.
// 		resty.SetOutputDirectory("/save/http/response/here")
//
func (c *Client) SetOutputDirectory(dirPath string) *Client {
	err := createDirectory(dirPath)
	if err != nil {
		c.Log.Printf("ERROR [%v]", err)
	}

	c.outputDirectory = dirPath

	return c
}

// SetTransport method sets custom *http.Transport in the resty client. Its way to override default.
//
// **Note:** It overwrites the default resty transport instance and its configurations.
//		transport := &http.Transport{
//			// somthing like Proxying to httptest.Server, etc...
//			Proxy: func(req *http.Request) (*url.URL, error) {
//				return url.Parse(server.URL)
//			},
//		}
//
//		resty.SetTransport(transport)
//
func (c *Client) SetTransport(transport *http.Transport) *Client {
	if transport != nil {
		c.transport = transport
		c.httpClient.Transport = c.transport
	}

	return c
}

// SetScheme method sets custom scheme in the resty client. It's way to override default.
// 		resty.SetScheme("http")
//
func (c *Client) SetScheme(scheme string) *Client {
	if !IsStringEmpty(scheme) {
		c.scheme = scheme
	}

	return c
}

// SetCloseConnection method sets variable Close in http request struct with the given
// value. More info: https://golang.org/src/net/http/request.go
func (c *Client) SetCloseConnection(close bool) *Client {
	c.closeConnection = close
	return c
}

// IsProxySet method returns the true if proxy is set on client otherwise false.
func (c *Client) IsProxySet() bool {
	return c.proxyURL != nil
}

// executes the given `Request` object and returns response
func (c *Client) execute(req *Request) (*Response, error) {
	defer putBuffer(req.bodyBuf)
	// Apply Request middleware
	var err error

	// user defined on before request methods
	// to modify the *resty.Request object
	for _, f := range c.udBeforeRequest {
		if err = f(c, req); err != nil {
			return nil, err
		}
	}

	// resty middlewares
	for _, f := range c.beforeRequest {
		if err = f(c, req); err != nil {
			return nil, err
		}
	}

	// call pre-request if defined
	if c.preReqHook != nil {
		if err = c.preReqHook(c, req); err != nil {
			return nil, err
		}
	}

	req.Time = time.Now()
	resp, err := c.httpClient.Do(req.RawRequest)

	response := &Response{
		Request:     req,
		RawResponse: resp,
		receivedAt:  time.Now(),
	}

	if err != nil {
		return response, err
	}

	if !req.isSaveResponse {
		defer func() {
			_ = resp.Body.Close()
		}()

		if response.body, err = ioutil.ReadAll(resp.Body); err != nil {
			return response, err
		}

		response.size = int64(len(response.body))
	}

	// Apply Response middleware
	for _, f := range c.afterResponse {
		if err = f(c, response); err != nil {
			break
		}
	}

	return response, err
}

// enables a log prefix
func (c *Client) enableLogPrefix() {
	c.Log.SetFlags(log.LstdFlags)
	c.Log.SetPrefix("RESTY ")
}

// disables a log prefix
func (c *Client) disableLogPrefix() {
	c.Log.SetFlags(0)
	c.Log.SetPrefix("")
}

// getting TLS client config if not exists then create one
func (c *Client) getTLSConfig() *tls.Config {
	if c.transport.TLSClientConfig == nil {
		c.transport.TLSClientConfig = &tls.Config{}
		c.httpClient.Transport = c.transport
	}
	return c.transport.TLSClientConfig
}

//
// File
//

// File represent file information for multipart request
type File struct {
	Name      string
	ParamName string
	io.Reader
}

// String returns string value of current file details
func (f *File) String() string {
	return fmt.Sprintf("ParamName: %v; FileName: %v", f.ParamName, f.Name)
}

//
// Helper methods
//

// IsStringEmpty method tells whether given string is empty or not
func IsStringEmpty(str string) bool {
	return (len(strings.TrimSpace(str)) == 0)
}

// DetectContentType method is used to figure out `Request.Body` content type for request header
func DetectContentType(body interface{}) string {
	contentType := plainTextType
	kind := kindOf(body)
	switch kind {
	case reflect.Struct, reflect.Map:
		contentType = jsonContentType
	case reflect.String:
		contentType = plainTextType
	default:
		if b, ok := body.([]byte); ok {
			contentType = http.DetectContentType(b)
		} else if kind == reflect.Slice {
			contentType = jsonContentType
		}
	}

	return contentType
}

// IsJSONType method is to check JSON content type or not
func IsJSONType(ct string) bool {
	return jsonCheck.MatchString(ct)
}

// IsXMLType method is to check XML content type or not
func IsXMLType(ct string) bool {
	return xmlCheck.MatchString(ct)
}

// Unmarshal content into object from JSON or XML
func Unmarshal(ct string, b []byte, d interface{}) (err error) {
	if IsJSONType(ct) {
		err = json.Unmarshal(b, d)
	} else if IsXMLType(ct) {
		err = xml.Unmarshal(b, d)
	}

	return
}

func getLogger(w io.Writer) *log.Logger {
	return log.New(w, "RESTY ", log.LstdFlags)
}

func addFile(w *multipart.Writer, fieldName, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	part, err := w.CreateFormFile(fieldName, filepath.Base(path))
	if err != nil {
		return err
	}
	_, err = io.Copy(part, file)

	return err
}

func addFileReader(w *multipart.Writer, f *File) error {
	part, err := w.CreateFormFile(f.ParamName, f.Name)
	if err != nil {
		return err
	}
	_, err = io.Copy(part, f.Reader)

	return err
}

func getPointer(v interface{}) interface{} {
	vv := valueOf(v)
	if vv.Kind() == reflect.Ptr {
		return v
	}
	return reflect.New(vv.Type()).Interface()
}

func isPayloadSupported(m string) bool {
	return (m == MethodPost || m == MethodPut || m == MethodDelete || m == MethodPatch)
}

func typeOf(i interface{}) reflect.Type {
	return indirect(valueOf(i)).Type()
}

func valueOf(i interface{}) reflect.Value {
	return reflect.ValueOf(i)
}

func indirect(v reflect.Value) reflect.Value {
	return reflect.Indirect(v)
}

func kindOf(v interface{}) reflect.Kind {
	return typeOf(v).Kind()
}

func createDirectory(dir string) (err error) {
	if _, err = os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(dir, 0755); err != nil {
				return
			}
		}
	}
	return
}

func canJSONMarshal(contentType string, kind reflect.Kind) bool {
	return IsJSONType(contentType) && (kind == reflect.Struct || kind == reflect.Map)
}

func functionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

func getBuffer() *bytes.Buffer {
	return bufPool.Get().(*bytes.Buffer)
}

func putBuffer(buf *bytes.Buffer) {
	if buf != nil {
		buf.Reset()
		bufPool.Put(buf)
	}
}
