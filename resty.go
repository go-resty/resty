// Copyright (c) 2015-2024 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
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

// New method creates a new Resty client.
func New() *Client {
	return NewWithTransportSettings(nil)
}

// NewWithTransportSettings method creates a new Resty client with provided
// timeout values.
func NewWithTransportSettings(transportSettings *TransportSettings) *Client {
	return NewWithDialerAndTransportSettings(nil, transportSettings)
}

// NewWithClient method creates a new Resty client with given `http.Client`.
func NewWithClient(hc *http.Client) *Client {
	return createClient(hc)
}

// NewWithDialer method creates a new Resty client with given Local Address
// to dial from.
func NewWithDialer(dialer *net.Dialer) *Client {
	return NewWithDialerAndTransportSettings(dialer, nil)
}

// NewWithLocalAddr method creates a new Resty client with given Local Address
// to dial from.
func NewWithLocalAddr(localAddr net.Addr) *Client {
	return NewWithDialerAndTransportSettings(
		&net.Dialer{LocalAddr: localAddr},
		nil,
	)
}

// NewWithDialerAndTransportSettings method creates a new Resty client with given Local Address
// to dial from.
func NewWithDialerAndTransportSettings(dialer *net.Dialer, transportSettings *TransportSettings) *Client {
	return createClient(&http.Client{
		Jar:       createCookieJar(),
		Transport: createTransport(dialer, transportSettings),
	})
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Unexported methods
//_______________________________________________________________________

func createTransport(dialer *net.Dialer, transportSettings *TransportSettings) *http.Transport {
	if transportSettings == nil {
		transportSettings = &TransportSettings{}
	}

	// Dialer

	if dialer == nil {
		dialer = &net.Dialer{}
	}

	if transportSettings.DialerTimeout > 0 {
		dialer.Timeout = transportSettings.DialerTimeout
	} else {
		dialer.Timeout = 30 * time.Second
	}

	if transportSettings.DialerKeepAlive > 0 {
		dialer.KeepAlive = transportSettings.DialerKeepAlive
	} else {
		dialer.KeepAlive = 30 * time.Second
	}

	// Transport
	t := &http.Transport{
		Proxy:              http.ProxyFromEnvironment,
		DialContext:        transportDialContext(dialer),
		DisableKeepAlives:  transportSettings.DisableKeepAlives,
		DisableCompression: transportSettings.DisableCompression,
		ForceAttemptHTTP2:  true,
	}

	if transportSettings.IdleConnTimeout > 0 {
		t.IdleConnTimeout = transportSettings.IdleConnTimeout
	} else {
		t.IdleConnTimeout = 90 * time.Second
	}

	if transportSettings.TLSHandshakeTimeout > 0 {
		t.TLSHandshakeTimeout = transportSettings.TLSHandshakeTimeout
	} else {
		t.TLSHandshakeTimeout = 10 * time.Second
	}

	if transportSettings.ExpectContinueTimeout > 0 {
		t.ExpectContinueTimeout = transportSettings.ExpectContinueTimeout
	} else {
		t.ExpectContinueTimeout = 1 * time.Second
	}

	if transportSettings.MaxIdleConns > 0 {
		t.MaxIdleConns = transportSettings.MaxIdleConns
	} else {
		t.MaxIdleConns = 100
	}

	if transportSettings.MaxIdleConnsPerHost > 0 {
		t.MaxIdleConnsPerHost = transportSettings.MaxIdleConnsPerHost
	} else {
		t.MaxIdleConnsPerHost = runtime.GOMAXPROCS(0) + 1
	}

	//
	// No default value in Resty for following settings, added to
	// provide ability to set value otherwise the Go HTTP client
	// default value applies.
	//

	if transportSettings.ResponseHeaderTimeout > 0 {
		t.ResponseHeaderTimeout = transportSettings.ResponseHeaderTimeout
	}

	if transportSettings.MaxResponseHeaderBytes > 0 {
		t.MaxResponseHeaderBytes = transportSettings.MaxResponseHeaderBytes
	}

	if transportSettings.WriteBufferSize > 0 {
		t.WriteBufferSize = transportSettings.WriteBufferSize
	}

	if transportSettings.ReadBufferSize > 0 {
		t.ReadBufferSize = transportSettings.ReadBufferSize
	}

	return t
}

func createCookieJar() *cookiejar.Jar {
	cookieJar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return cookieJar
}

func createClient(hc *http.Client) *Client {
	c := &Client{ // not setting language default values
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
