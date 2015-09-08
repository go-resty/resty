/*
Copyright (c) 2015 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.

resty source code and usage is governed by a MIT style
license that can be found in the LICENSE file.
*/
package resty

//
// Request Middleware(s)
//

func parseRequestUrl(c *Client, r *Request) error {
	c.Log.Println("parseRequestUrl")

	return nil
}

func parseRequestHeader(c *Client, r *Request) error {
	c.Log.Println("parseRequestHeader")

	return nil
}

func parseRequestBody(c *Client, r *Request) error {
	c.Log.Println("parseRequestBody")

	return nil
}

func createHttpRequest(c *Client, r *Request) error {
	c.Log.Println("createHttpRequest")

	return nil
}

func addCredentials(c *Client, r *Request) error {
	c.Log.Println("addCredentials")

	return nil
}

func requestLogger(c *Client, r *Request) error {
	c.Log.Println("requestLogger")

	return nil
}

//
// Response Middleware(s)
//

func readResponseBody(c *Client, res *Response) error {
	c.Log.Println("readResponseBody")

	return nil
}

func responseLogger(c *Client, res *Response) error {
	c.Log.Println("responseLogger")

	return nil
}

func parseResponseBody(c *Client, resp *Response) error {
	c.Log.Println("parseResponseBody")

	return nil
}
