/*
Copyright (c) 2015 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.

resty source code and usage is governed by a MIT style
license that can be found in the LICENSE file.
*/
package resty

import (
	"net/http"
	"net/url"
)

func New() *Client {
	c := &Client{
		HostUrl:    "",
		Param:      url.Values{},
		Header:     http.Header{},
		UserInfo:   nil,
		Token:      "",
		Cookies:    make([]*http.Cookie, 0),
		Debug:      false,
		Log:        getLogger(nil),
		httpClient: &http.Client{},
		transport:  &http.Transport{},
	}

	return c
}
