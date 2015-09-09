/*
Copyright (c) 2015 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.

resty source code and usage is governed by a MIT style
license that can be found in the LICENSE file.
*/
package resty

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

//
// Request Middleware(s)
//

func parseRequestUrl(c *Client, r *Request) error {
	c.Log.Println("parseRequestUrl")
	// Parsing request URL
	reqUrl, err := url.Parse(r.Url)
	if err != nil {
		return err
	}

	// If Request.Url is relative path then added c.HostUrl into
	// the request URL otherwise Request.Url will be used as-is
	if !reqUrl.IsAbs() {
		if !strings.HasPrefix(r.Url, "/") {
			r.Url = "/" + r.Url
		}

		reqUrl, err = url.Parse(c.HostUrl + r.Url)
		if err != nil {
			return err
		}
	}

	// Adding Query Param
	query := reqUrl.Query()
	for k, v := range c.QueryParam {
		for _, pv := range v {
			query.Add(k, pv)
		}
	}
	for k, v := range r.QueryParam {
		for _, pv := range v {
			query.Add(k, pv)
		}
	}

	reqUrl.RawQuery = query.Encode()
	r.Url = reqUrl.String()

	return nil
}

func parseRequestHeader(c *Client, r *Request) error {
	c.Log.Println("parseRequestHeader")

	hdr := http.Header{}
	for k := range c.Header {
		hdr.Set(k, c.Header.Get(k))
	}
	for k := range r.Header {
		hdr.Set(k, r.Header.Get(k))
	}

	if isStringEmpty(hdr.Get(hdrUserAgentKey)) {
		hdr.Set(hdrUserAgentKey, fmt.Sprintf(hdrUserAgentValue, Version))
	} else {
		hdr.Set("X-"+hdrUserAgentKey, fmt.Sprintf(hdrUserAgentValue, Version))
	}

	if isStringEmpty(hdr.Get(hdrAcceptKey)) && !isStringEmpty(hdr.Get(hdrContentTypeKey)) {
		hdr.Set(hdrAcceptKey, hdr.Get(hdrContentTypeKey))
	}

	r.Header = hdr

	return nil
}

func parseRequestBody(c *Client, r *Request) (err error) {
	c.Log.Println("parseRequestBody")
	// Handling Multipart
	if r.isMultiPart && (r.Method == POST || r.Method == PUT) { // multipart/form-data
		r.bodyBuf = &bytes.Buffer{}
		w := multipart.NewWriter(r.bodyBuf)
		for p := range r.FormData {
			if strings.HasPrefix(p, "@") { // file
				err = addFile(w, p[1:], r.FormData.Get(p))
				if err != nil {
					return
				}
			} else { // form value
				w.WriteField(p, r.FormData.Get(p))
			}
		}

		r.Header.Set(hdrContentTypeKey, w.FormDataContentType())
		err = w.Close()

		return
	}

	// Handling Request body scenario
	if r.Body != nil && (r.Method == POST || r.Method == PUT || r.Method == PATCH) {
		contentType := r.Header.Get(hdrContentTypeKey)
		if isStringEmpty(contentType) {
			contentType = detectContentType(r.Body)
			r.Header.Set(hdrContentTypeKey, contentType)
		}

		var bodyBytes []byte
		isMarshal := isMarshalRequired(r.Body)
		if isJsonType(contentType) && isMarshal {
			bodyBytes, err = json.Marshal(&r.Body)
		} else if isXmlType(contentType) && isMarshal {
			bodyBytes, err = xml.Marshal(&r.Body)
		} else if b, ok := r.Body.(string); ok {
			bodyBytes = []byte(b)
		} else if b, ok := r.Body.([]byte); ok {
			bodyBytes = b
		}

		if err != nil {
			return
		}

		// []byte into Buffer
		if bodyBytes != nil {
			r.bodyBuf = bytes.NewBuffer(bodyBytes)
		}
	}

	if r.setContentLength { // by default resty won't set content length
		r.Header.Set(hdrContentLengthKey, fmt.Sprintf("%d", r.bodyBuf.Len()))
	}

	return
}

func createHttpRequest(c *Client, r *Request) (err error) {
	c.Log.Println("createHttpRequest")

	if r.bodyBuf == nil {
		r.RawRequest, err = http.NewRequest(r.Method, r.Url, nil)
	} else {
		r.RawRequest, err = http.NewRequest(r.Method, r.Url, r.bodyBuf)
	}

	// Add headers into http request
	r.RawRequest.Header = r.Header

	// Add cookies into http request
	for _, cookie := range c.Cookies {
		r.RawRequest.AddCookie(cookie)
	}

	return
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

func readResponseBody(c *Client, res *Response) (err error) {
	c.Log.Println("readResponseBody")
	defer res.RawResponse.Body.Close()

	res.Body, err = ioutil.ReadAll(res.RawResponse.Body)
	if err != nil {
		return
	}

	return
}

func responseLogger(c *Client, res *Response) error {
	c.Log.Println("responseLogger")

	return nil
}

func parseResponseBody(c *Client, res *Response) error {
	c.Log.Println("parseResponseBody")

	return nil
}
