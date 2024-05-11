// Copyright (c) 2015-2023 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

// Package resty provides Simple HTTP and REST client library for Go.
package resty

import (
	"encoding/json"
	"encoding/xml"
	"math"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"runtime"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Version # of resty
const Version = "3.0.0-dev"

var (
	defaultClientTimeout = &ClientTimeoutSetting{
		DialerTimeout:                  30 * time.Second,
		DialerKeepAlive:                30 * time.Second,
		TransportIdleConnTimeout:       90 * time.Second,
		TransportTLSHandshakeTimeout:   10 * time.Second,
		TransportExpectContinueTimeout: 1 * time.Second,
	}
)

// New method creates a new Resty client.
func New() *Client {
	return NewWithTimeout(defaultClientTimeout)
}

// NewWithTimeout method creates a new Resty client with provided
// timeout values.
//
// Since v3.0.0
func NewWithTimeout(timeoutSetting *ClientTimeoutSetting) *Client {
	return createClient(&http.Client{
		Jar: createCookieJar(),
		Transport: createTransport(
			createDialer(nil, timeoutSetting),
			timeoutSetting,
		),
	})
}

// NewWithClient method creates a new Resty client with given `http.Client`.
func NewWithClient(hc *http.Client) *Client {
	return createClient(hc)
}

// NewWithDialer method creates a new Resty client with given Local Address
// to dial from.
//
// Since v3.0.0
func NewWithDialer(dialer *net.Dialer) *Client {
	return createClient(&http.Client{
		Jar:       createCookieJar(),
		Transport: createTransport(dialer, defaultClientTimeout),
	})
}

// NewWithLocalAddr method creates a new Resty client with given Local Address
// to dial from.
func NewWithLocalAddr(localAddr net.Addr) *Client {
	return createClient(&http.Client{
		Jar: createCookieJar(),
		Transport: createTransport(
			createDialer(localAddr, defaultClientTimeout),
			defaultClientTimeout,
		),
	})
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Unexported methods
//_______________________________________________________________________

func createDialer(localAddr net.Addr, timeoutSetting *ClientTimeoutSetting) *net.Dialer {
	dialer := &net.Dialer{
		Timeout:   timeoutSetting.DialerTimeout,
		KeepAlive: timeoutSetting.DialerKeepAlive,
	}
	if localAddr != nil {
		dialer.LocalAddr = localAddr
	}
	return dialer
}

func createTransport(dialer *net.Dialer, timeoutSetting *ClientTimeoutSetting) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           transportDialContext(dialer),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       timeoutSetting.TransportIdleConnTimeout,
		TLSHandshakeTimeout:   timeoutSetting.TransportTLSHandshakeTimeout,
		ExpectContinueTimeout: timeoutSetting.TransportExpectContinueTimeout,
		MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
	}
}

func createCookieJar() *cookiejar.Jar {
	cookieJar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return cookieJar
}

func createClient(hc *http.Client) *Client {
	c := &Client{ // not setting language default values
		QueryParam:             url.Values{},
		FormData:               url.Values{},
		Header:                 http.Header{},
		Cookies:                make([]*http.Cookie, 0),
		RetryWaitTime:          defaultWaitTime,
		RetryMaxWaitTime:       defaultMaxWaitTime,
		PathParams:             make(map[string]string),
		RawPathParams:          make(map[string]string),
		JSONMarshal:            json.Marshal,
		JSONUnmarshal:          json.Unmarshal,
		XMLMarshal:             xml.Marshal,
		XMLUnmarshal:           xml.Unmarshal,
		HeaderAuthorizationKey: http.CanonicalHeaderKey("Authorization"),

		jsonEscapeHTML:      true,
		httpClient:          hc,
		debugBodySizeLimit:  math.MaxInt32,
		udBeforeRequestLock: &sync.RWMutex{},
		afterResponseLock:   &sync.RWMutex{},
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
