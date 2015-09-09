/*
Copyright (c) 2015 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.

resty source code and usage is governed by a MIT style
license that can be found in the LICENSE file.
*/
package resty

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const (
	GET     = "GET"
	POST    = "POST"
	PUT     = "PUT"
	DELETE  = "DELETE"
	PATCH   = "PATCH"
	HEAD    = "HEAD"
	OPTIONS = "OPTIONS"
)

var (
	hdrUserAgentKey     = http.CanonicalHeaderKey("User-Agent")
	hdrAcceptKey        = http.CanonicalHeaderKey("Accept")
	hdrContentTypeKey   = http.CanonicalHeaderKey("Content-Type")
	hdrContentLengthKey = http.CanonicalHeaderKey("Content-Length")
	hdrAuthorizationKey = http.CanonicalHeaderKey("Authorization")

	plainTextType   = "text/plain; charset=utf-8"
	jsonContentType = "application/json; charset=utf-8"

	plainTextCheck = regexp.MustCompile("(?i:text/plain)")
	jsonCheck      = regexp.MustCompile("(?i:[application|text]/json)")
	xmlCheck       = regexp.MustCompile("(?i:[application|text]/xml)")

	hdrUserAgentValue = "resty v%s - https://github.com/go-resty/resty"
)

type Client struct {
	HostUrl    string
	QueryParam url.Values
	FormData   url.Values
	Header     http.Header
	UserInfo   *User
	Token      string
	Cookies    []*http.Cookie
	Error      interface{}
	Debug      bool
	Log        *log.Logger

	httpClient    *http.Client
	transport     *http.Transport
	beforeRequest []func(*Client, *Request) error
	afterResponse []func(*Client, *Response) error
}

type User struct {
	Username, Password string
}

func (c *Client) SetHeader(header, value string) *Client {
	c.Header.Set(header, value)
	return c
}

func (c *Client) SetHeaders(headers map[string]string) *Client {
	for h, v := range headers {
		c.Header.Set(h, v)
	}

	return c
}

func (c *Client) SetCookie(hc *http.Cookie) *Client {
	c.Cookies = append(c.Cookies, hc)
	return c
}

func (c *Client) SetCookies(cs []*http.Cookie) *Client {
	c.Cookies = append(c.Cookies, cs...)
	return c
}

func (c *Client) SetQueryParam(param, value string) *Client {
	c.QueryParam.Add(param, value)
	return c
}

func (c *Client) SetQueryParams(params map[string]string) *Client {
	for p, v := range params {
		c.QueryParam.Add(p, v)
	}

	return c
}

func (c *Client) SetFormData(data map[string]string) *Client {
	for k, v := range data {
		c.FormData.Add(k, v)
	}

	return c
}

func (c *Client) SetBasicAuth(username, password string) *Client {
	c.UserInfo = &User{Username: username, Password: password}
	return c
}

func (c *Client) SetAuthToken(token string) *Client {
	c.Token = token
	return c
}

func (c *Client) R() *Request {
	r := &Request{
		Url:        "",
		Method:     "",
		QueryParam: url.Values{},
		FormData:   url.Values{},
		Header:     http.Header{},
		Body:       nil,
		Result:     nil,
		Error:      nil,
		RawRequest: nil,
		client:     c,
		bodyBuf:    nil,
	}

	return r
}

func (c *Client) OnBeforeRequest(m func(*Client, *Request) error) *Client {
	c.beforeRequest[len(c.beforeRequest)-1] = m
	c.beforeRequest = append(c.beforeRequest, requestLogger)

	return c
}

func (c *Client) OnAfterResponse(m func(*Client, *Response) error) *Client {
	c.afterResponse = append(c.afterResponse, m)
	return c
}

func (c *Client) SetDebug(d bool) *Client {
	c.Debug = d
	return c
}

func (c *Client) SetLogger(w io.Writer) *Client {
	c.Log = getLogger(w)
	return c
}

func (c *Client) execute(req *Request) (*Response, error) {
	// Apply Request middleware
	var err error
	for _, f := range c.beforeRequest {
		err = f(c, req)
		if err != nil {
			return nil, err
		}
	}

	req.Time = time.Now()
	c.httpClient.Transport = c.transport

	resp, err := c.httpClient.Do(req.RawRequest)
	if err != nil {
		return nil, err
	}

	response := &Response{
		Request:     req,
		ReceivedAt:  time.Now(),
		RawResponse: resp,
	}

	// Apply Response middleware
	for _, f := range c.afterResponse {
		err = f(c, response)
		if err != nil {
			break
		}
	}

	return response, err
}

func (c *Client) enableLogPrefix() {
	c.Log.SetFlags(log.LstdFlags)
	c.Log.SetPrefix("RESTY ")
}

func (c *Client) disableLogPrefix() {
	c.Log.SetFlags(0)
	c.Log.SetPrefix("")
}

//
// Request
//

// Type Request
type Request struct {
	Url        string
	Method     string
	QueryParam url.Values
	FormData   url.Values
	Header     http.Header
	UserInfo   *User
	Token      string
	Body       interface{}
	Result     interface{}
	Error      interface{}
	Time       time.Time
	RawRequest *http.Request

	client           *Client
	bodyBuf          *bytes.Buffer
	isMultiPart      bool
	setContentLength bool
}

func (r *Request) SetQueryParam(param, value string) *Request {
	r.QueryParam.Add(param, value)
	return r
}

func (r *Request) SetQueryParams(params map[string]string) *Request {
	for p, v := range params {
		r.QueryParam.Add(p, v)
	}

	return r
}

func (r *Request) SetHeader(header, value string) *Request {
	r.Header.Set(header, value)
	return r
}

func (r *Request) SetHeaders(headers map[string]string) *Request {
	for h, v := range headers {
		r.Header.Set(h, v)
	}

	return r
}

func (r *Request) SetFormData(data map[string]string) *Request {
	for k, v := range data {
		r.FormData.Add(k, v)
	}

	return r
}

func (r *Request) SetBody(body interface{}) *Request {
	r.Body = body
	return r
}

func (r *Request) SetResult(res interface{}) *Request {
	r.Result = res
	return r
}

func (r *Request) SetError(err interface{}) *Request {
	r.Error = err
	return r
}

func (r *Request) SetFile(param, filePath string) *Request {
	r.FormData.Set("@"+param, filePath)
	r.isMultiPart = true

	return r
}

func (r *Request) SetFiles(files map[string]string) *Request {
	for f, fp := range files {
		r.FormData.Set("@"+f, fp)
	}
	r.isMultiPart = true

	return r
}

func (r *Request) SetContentLength(l bool) *Request {
	r.setContentLength = true

	return r
}

func (r *Request) SetBasicAuth(username, password string) *Request {
	r.UserInfo = &User{Username: username, Password: password}
	return r
}

func (r *Request) SetAuthToken(token string) *Request {
	r.Token = token
	return r
}

//
// HTTP verb method starts here
//

func (r *Request) Get(url string) (*Response, error) {
	return r.execute(GET, url)
}

func (r *Request) Post(url string) (*Response, error) {
	return r.execute(POST, url)
}

func (r *Request) Put(url string) (*Response, error) {
	return r.execute(PUT, url)
}

func (r *Request) Delete(url string) (*Response, error) {
	return r.execute(DELETE, url)
}

func (r *Request) Patch(url string) (*Response, error) {
	return r.execute(PATCH, url)
}

func (r *Request) Head(url string) (*Response, error) {
	return r.execute(HEAD, url)
}

func (r *Request) Options(url string) (*Response, error) {
	return r.execute(OPTIONS, url)
}

func (r *Request) execute(method, url string) (*Response, error) {
	if r.isMultiPart && !(method == POST || method == PUT) {
		return nil, fmt.Errorf("File upload is not allowed in HTTP verb [%v]", method)
	}

	r.Method = method
	r.Url = url

	return r.client.execute(r)
}

//
// Response
//

// Type Response
type Response struct {
	Body        []byte
	ReceivedAt  time.Time
	Request     *Request
	RawResponse *http.Response
}

func (r *Response) Status() string {
	return r.RawResponse.Status
}

func (r *Response) StatusCode() int {
	return r.RawResponse.StatusCode
}

func (r *Response) Result() interface{} {
	return r.Request.Result
}

func (r *Response) Error() interface{} {
	return r.Request.Error
}

func (r *Response) Header() http.Header {
	return r.RawResponse.Header
}

func (r *Response) Cookies() []*http.Cookie {
	return r.RawResponse.Cookies()
}

func (r *Response) String() string {
	if r.Body == nil {
		return ""
	}

	return string(r.Body)
}

func (r *Response) Time() time.Duration {
	return r.ReceivedAt.Sub(r.Request.Time)
}

//
// Resty's handy redirect polices
//

func NoRedirectPolicy(req *http.Request, via []*http.Request) error {
	return errors.New("Auto redirect is disbaled")
}

func AllowRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("Stopped after 10 redirects")
	}

	return nil
}

//
// Helper methods
//

func getLogger(w io.Writer) *log.Logger {
	var l *log.Logger
	if w == nil {
		l = log.New(os.Stderr, "RESTY ", log.LstdFlags)
	} else {
		l = log.New(w, "RESTY ", log.LstdFlags)
	}

	return l
}

func isStringEmpty(str string) bool {
	return (len(strings.TrimSpace(str)) == 0)
}

func isMarshalRequired(body interface{}) bool {
	kind := reflect.ValueOf(body).Kind()
	return (kind == reflect.Struct || kind == reflect.Map)
}

func detectContentType(body interface{}) string {
	contentType := plainTextType
	kind := reflect.ValueOf(body).Kind()

	switch kind {
	case reflect.Struct, reflect.Map:
		contentType = jsonContentType
	case reflect.String:
		contentType = plainTextType
	default:
		contentType = http.DetectContentType(body.([]byte))
	}

	return contentType
}

func isJsonType(ct string) bool {
	return jsonCheck.MatchString(ct)
}

func isXmlType(ct string) bool {
	return xmlCheck.MatchString(ct)
}

func addFile(w *multipart.Writer, fieldName, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	part, err := w.CreateFormFile(fieldName, filepath.Base(path))
	if err != nil {
		return err
	}
	_, err = io.Copy(part, file)

	return err
}
