/*
Copyright (c) 2015 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.

resty source code and usage is governed by a MIT style
license that can be found in the LICENSE file.
*/
package resty

import (
	"bytes"
	"log"
	"net/http"
	"net/url"
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

type User struct{ Username, Password string }

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

	httpClient *http.Client
	transport  *http.Transport
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
