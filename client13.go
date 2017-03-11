// +build go1.3

// Copyright (c) 2015-2017 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import "time"

// SetTimeout method sets timeout for request raised from client
//		resty.SetTimeout(time.Duration(1 * time.Minute))
//
func (c *Client) SetTimeout(timeout time.Duration) *Client {
	c.httpClient.Timeout = timeout
	return c
}
