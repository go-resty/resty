// Copyright (c) 2015-2019 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

// Package resty provides Simple HTTP and REST client library for Go.
package resty

import (
	"net/http"
	"net/http/cookiejar"

	"golang.org/x/net/publicsuffix"
)

// Version # of resty
const Version = "2.0.0-alpha.1"

// New method creates a new go-resty client.
func New() *Client {
	cookieJar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return createClient(&http.Client{Jar: cookieJar})
}

// NewWithClient method create a new go-resty client with given `http.Client`.
func NewWithClient(hc *http.Client) *Client {
	return createClient(hc)
}
