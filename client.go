/*
Copyright (c) 2015 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.

resty source code and usage is governed by a MIT style
license that can be found in the LICENSE file.
*/
package resty

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
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

type Client struct {
	HostUrl  string
	Param    url.Values
	Header   http.Header
	UserInfo *User
	Token    string
	Cookies  []*http.Cookie
	Error    interface{}
	Debug    bool
	Log      *log.Logger

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

func (c *Client) SetParam(param, value string) *Client {
	c.Param.Add(param, value)
	return c
}

func (c *Client) SetParams(params map[string]string) *Client {
	for p, v := range params {
		c.Param.Add(p, v)
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
		Param:      url.Values{},
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

func (c *Client) PrintMiddlewares() {
	var err error
	c.Log.Println("Request middleware")
	for _, f := range c.beforeRequest {
		err = f(c, nil)
		if err != nil {
			c.Log.Panicln(err)
		}
	}
	c.Log.Println(len(c.beforeRequest))
	c.Log.Println("")

	c.Log.Println("Response middleware")
	for _, f := range c.afterResponse {
		err = f(c, nil)
		if err != nil {
			break
		}
	}
	c.Log.Println(len(c.afterResponse))
}

//
// Request
//

// Type Request
type Request struct {
	Url        string
	Method     string
	Param      url.Values
	Header     http.Header
	Body       interface{}
	Result     interface{}
	Error      interface{}
	Time       time.Time
	RawRequest *http.Request

	client  *Client
	bodyBuf *bytes.Buffer
}

func (r *Request) SetParam(param, value string) *Request {
	r.Param.Add(param, value)
	return r
}

func (r *Request) SetParams(params map[string]string) *Request {
	for p, v := range params {
		r.Param.Add(p, v)
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

func Allow10RedirectPolicy(req *http.Request, via []*http.Request) error {
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
