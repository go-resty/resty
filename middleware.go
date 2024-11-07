// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

const debugRequestLogKey = "__restyDebugRequestLog"

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Request Middleware(s)
//_______________________________________________________________________

// PrepareRequestMiddleware method is used to prepare HTTP requests from
// user provides request values. Request preparation fails if any error occurs
func PrepareRequestMiddleware(c *Client, r *Request) error {
	var err error

	if err = parseRequestURL(c, r); err != nil {
		return err
	}

	// no error returned
	parseRequestHeader(c, r)

	if err = parseRequestBody(c, r); err != nil {
		return err
	}

	if err = createHTTPRequest(c, r); err != nil {
		return err
	}

	// last one doesn't need if condition
	return addCredentials(c, r)
}

// GenerateCurlRequestMiddleware method is used to perform CURL command
// generation during a request preparation
//
// See, [Client.SetGenerateCurlOnDebug], [Request.SetGenerateCurlOnDebug]
func GenerateCurlRequestMiddleware(c *Client, r *Request) (err error) {
	if r.Debug && r.generateCurlOnDebug {
		if r.resultCurlCmd == nil {
			r.resultCurlCmd = new(string)
		}
		*r.resultCurlCmd = buildCurlCmd(r)
	}
	return nil
}

func parseRequestURL(c *Client, r *Request) error {
	if l := len(c.PathParams()) + len(c.RawPathParams()) + len(r.PathParams) + len(r.RawPathParams); l > 0 {
		params := make(map[string]string, l)

		// GitHub #103 Path Params
		for p, v := range r.PathParams {
			params[p] = url.PathEscape(v)
		}
		for p, v := range c.PathParams() {
			if _, ok := params[p]; !ok {
				params[p] = url.PathEscape(v)
			}
		}

		// GitHub #663 Raw Path Params
		for p, v := range r.RawPathParams {
			if _, ok := params[p]; !ok {
				params[p] = v
			}
		}
		for p, v := range c.RawPathParams() {
			if _, ok := params[p]; !ok {
				params[p] = v
			}
		}

		if len(params) > 0 {
			var prev int
			buf := acquireBuffer()
			defer releaseBuffer(buf)
			// search for the next or first opened curly bracket
			for curr := strings.Index(r.URL, "{"); curr == 0 || curr > prev; curr = prev + strings.Index(r.URL[prev:], "{") {
				// write everything from the previous position up to the current
				if curr > prev {
					buf.WriteString(r.URL[prev:curr])
				}
				// search for the closed curly bracket from current position
				next := curr + strings.Index(r.URL[curr:], "}")
				// if not found, then write the remainder and exit
				if next < curr {
					buf.WriteString(r.URL[curr:])
					prev = len(r.URL)
					break
				}
				// special case for {}, without parameter's name
				if next == curr+1 {
					buf.WriteString("{}")
				} else {
					// check for the replacement
					key := r.URL[curr+1 : next]
					value, ok := params[key]
					/// keep the original string if the replacement not found
					if !ok {
						value = r.URL[curr : next+1]
					}
					buf.WriteString(value)
				}

				// set the previous position after the closed curly bracket
				prev = next + 1
				if prev >= len(r.URL) {
					break
				}
			}
			if buf.Len() > 0 {
				// write remainder
				if prev < len(r.URL) {
					buf.WriteString(r.URL[prev:])
				}
				r.URL = buf.String()
			}
		}
	}

	// Parsing request URL
	reqURL, err := url.Parse(r.URL)
	if err != nil {
		return &invalidRequestError{Err: err}
	}

	// If [Request.URL] is a relative path, then the following
	// gets evaluated in the order
	//	1. [Client.LoadBalancer] is used to obtain the base URL if not nil
	//	2. [Client.BaseURL] is used to obtain the base URL
	//	3. Otherwise [Request.URL] is used as-is
	if !reqURL.IsAbs() {
		r.URL = reqURL.String()
		if len(r.URL) > 0 && r.URL[0] != '/' {
			r.URL = "/" + r.URL
		}

		if r.client.LoadBalancer() != nil {
			r.baseURL, err = r.client.LoadBalancer().Next()
			if err != nil {
				return &invalidRequestError{Err: err}
			}
		}

		reqURL, err = url.Parse(r.baseURL + r.URL)
		if err != nil {
			return &invalidRequestError{Err: err}
		}
	}

	// GH #407 && #318
	if reqURL.Scheme == "" && len(c.Scheme()) > 0 {
		reqURL.Scheme = c.Scheme()
	}

	// Adding Query Param
	if len(c.QueryParams())+len(r.QueryParams) > 0 {
		for k, v := range c.QueryParams() {
			// skip query parameter if it was set in request
			if _, ok := r.QueryParams[k]; ok {
				continue
			}

			r.QueryParams[k] = v[:]
		}

		// GitHub #123 Preserve query string order partially.
		// Since not feasible in `SetQuery*` resty methods, because
		// standard package `url.Encode(...)` sorts the query params
		// alphabetically
		if len(r.QueryParams) > 0 {
			if isStringEmpty(reqURL.RawQuery) {
				reqURL.RawQuery = r.QueryParams.Encode()
			} else {
				reqURL.RawQuery = reqURL.RawQuery + "&" + r.QueryParams.Encode()
			}
		}
	}

	// GH#797 Unescape query parameters (non-standard - not recommended)
	if r.unescapeQueryParams && len(reqURL.RawQuery) > 0 {
		// at this point, all errors caught up in the above operations
		// so ignore the return error on query unescape; I realized
		// while writing the unit test
		unescapedQuery, _ := url.QueryUnescape(reqURL.RawQuery)
		reqURL.RawQuery = strings.ReplaceAll(unescapedQuery, " ", "+") // otherwise request becomes bad request
	}

	r.URL = reqURL.String()

	return nil
}

func parseRequestHeader(c *Client, r *Request) error {
	for k, v := range c.Header() {
		if _, ok := r.Header[k]; ok {
			continue
		}
		r.Header[k] = v[:]
	}

	if !r.isHeaderExists(hdrUserAgentKey) {
		r.Header.Set(hdrUserAgentKey, hdrUserAgentValue)
	}

	if !r.isHeaderExists(hdrAcceptKey) {
		ct := r.Header.Get(hdrContentTypeKey)
		if isJSONContentType(ct) || isXMLContentType(ct) {
			r.Header.Set(hdrAcceptKey, ct)
		}
	}

	if !r.isHeaderExists(hdrAcceptEncodingKey) {
		r.Header.Set(hdrAcceptEncodingKey, r.client.ContentDecompressorKeys())
	}

	return nil
}

func parseRequestBody(c *Client, r *Request) error {
	if r.isMultiPart && !(r.Method == MethodPost || r.Method == MethodPut || r.Method == MethodPatch) {
		err := fmt.Errorf("resty: multipart is not allowed in HTTP verb: %v", r.Method)
		return &invalidRequestError{Err: err}
	}

	if r.isPayloadSupported() {
		switch {
		case r.isMultiPart: // Handling Multipart
			if err := handleMultipart(c, r); err != nil {
				return &invalidRequestError{Err: err}
			}
		case len(c.FormData()) > 0 || len(r.FormData) > 0: // Handling Form Data
			handleFormData(c, r)
		case r.Body != nil: // Handling Request body
			if err := handleRequestBody(c, r); err != nil {
				return &invalidRequestError{Err: err}
			}
		}
	} else {
		r.Body = nil // if the payload is not supported by HTTP verb, set explicit nil
	}

	// by default resty won't set content length, you can if you want to :)
	if r.setContentLength {
		if r.bodyBuf == nil && r.Body == nil {
			r.Header.Set(hdrContentLengthKey, "0")
		} else if r.bodyBuf != nil {
			r.Header.Set(hdrContentLengthKey, strconv.Itoa(r.bodyBuf.Len()))
		}
	}

	return nil
}

func createHTTPRequest(c *Client, r *Request) (err error) {
	// init client trace if enabled
	r.initTraceIfEnabled()

	if r.bodyBuf == nil {
		if reader, ok := r.Body.(io.Reader); ok {
			r.RawRequest, err = http.NewRequestWithContext(r.Context(), r.Method, r.URL, reader)
		} else {
			r.RawRequest, err = http.NewRequestWithContext(r.Context(), r.Method, r.URL, nil)
		}
	} else {
		r.RawRequest, err = http.NewRequestWithContext(r.Context(), r.Method, r.URL, r.bodyBuf)
	}

	if err != nil {
		return &invalidRequestError{Err: err}
	}

	// get the context reference back from underlying RawRequest
	r.ctx = r.RawRequest.Context()

	// Assign close connection option
	r.RawRequest.Close = r.CloseConnection

	// Add headers into http request
	r.RawRequest.Header = r.Header

	// Add cookies from client instance into http request
	for _, cookie := range c.Cookies() {
		r.RawRequest.AddCookie(cookie)
	}

	// Add cookies from request instance into http request
	for _, cookie := range r.Cookies {
		r.RawRequest.AddCookie(cookie)
	}

	return
}

func addCredentials(c *Client, r *Request) error {
	var isBasicAuth bool
	// Basic Auth
	if r.UserInfo != nil {
		r.RawRequest.SetBasicAuth(r.UserInfo.Username, r.UserInfo.Password)
		isBasicAuth = true
	}

	if !c.IsDisableWarn() {
		if isBasicAuth && !strings.HasPrefix(r.URL, "https") {
			r.log.Warnf("Using Basic Auth in HTTP mode is not secure, use HTTPS")
		}
	}

	// Build the token Auth header
	if !isStringEmpty(r.AuthToken) {
		var authScheme string
		if isStringEmpty(r.AuthScheme) {
			authScheme = "Bearer"
		} else {
			authScheme = r.AuthScheme
		}
		r.RawRequest.Header.Set(c.HeaderAuthorizationKey(), authScheme+" "+r.AuthToken)
	}

	return nil
}

func handleMultipart(c *Client, r *Request) error {
	for k, v := range c.FormData() {
		if _, ok := r.FormData[k]; ok {
			continue
		}
		r.FormData[k] = v[:]
	}

	mfLen := len(r.multipartFields)
	if mfLen == 0 {
		r.bodyBuf = acquireBuffer()
		mw := multipart.NewWriter(r.bodyBuf)

		// set boundary if it is provided by the user
		if !isStringEmpty(r.multipartBoundary) {
			if err := mw.SetBoundary(r.multipartBoundary); err != nil {
				return err
			}
		}

		if err := r.writeFormData(mw); err != nil {
			return err
		}

		r.Header.Set(hdrContentTypeKey, mw.FormDataContentType())
		closeq(mw)

		return nil
	}

	// multipart streaming
	bodyReader, bodyWriter := io.Pipe()
	mw := multipart.NewWriter(bodyWriter)
	r.Body = bodyReader
	r.multipartErrChan = make(chan error, 1)

	// set boundary if it is provided by the user
	if !isStringEmpty(r.multipartBoundary) {
		if err := mw.SetBoundary(r.multipartBoundary); err != nil {
			return err
		}
	}

	go func() {
		defer close(r.multipartErrChan)
		if err := createMultipart(mw, r); err != nil {
			r.multipartErrChan <- err
		}
		closeq(mw)
		closeq(bodyWriter)
	}()

	r.Header.Set(hdrContentTypeKey, mw.FormDataContentType())
	return nil
}

func createMultipart(w *multipart.Writer, r *Request) error {
	if err := r.writeFormData(w); err != nil {
		return err
	}

	for _, mf := range r.multipartFields {
		if err := mf.openFileIfRequired(); err != nil {
			return err
		}

		p := make([]byte, 512)
		size, err := mf.Reader.Read(p)
		if err != nil && err != io.EOF {
			return err
		}
		// auto detect content type if empty
		if isStringEmpty(mf.ContentType) {
			mf.ContentType = http.DetectContentType(p[:size])
		}

		partWriter, err := w.CreatePart(mf.createHeader())
		if err != nil {
			return err
		}

		partWriter = mf.wrapProgressCallbackIfPresent(partWriter)

		if _, err = partWriter.Write(p[:size]); err != nil {
			return err
		}
		_, err = ioCopy(partWriter, mf.Reader)
		if err != nil {
			return err
		}
	}

	return nil
}

func handleFormData(c *Client, r *Request) {
	for k, v := range c.FormData() {
		if _, ok := r.FormData[k]; ok {
			continue
		}
		r.FormData[k] = v[:]
	}

	r.bodyBuf = acquireBuffer()
	r.bodyBuf.WriteString(r.FormData.Encode())
	r.Header.Set(hdrContentTypeKey, formContentType)
	r.isFormData = true
}

func handleRequestBody(c *Client, r *Request) error {
	contentType := r.Header.Get(hdrContentTypeKey)
	if isStringEmpty(contentType) {
		// it is highly recommended that the user provide a request content-type
		// so that we can minimize memory allocation and compute.
		contentType = detectContentType(r.Body)
	}
	if !r.isHeaderExists(hdrContentTypeKey) {
		r.Header.Set(hdrContentTypeKey, contentType)
	}

	r.bodyBuf = acquireBuffer()

	switch body := r.Body.(type) {
	case io.Reader: // Resty v3 onwards io.Reader used as-is with the request body
		releaseBuffer(r.bodyBuf)
		r.bodyBuf = nil
		return nil
	case []byte:
		r.bodyBuf.Write(body)
	case string:
		r.bodyBuf.Write([]byte(body))
	default:
		encKey := inferContentTypeMapKey(contentType)
		if jsonKey == encKey {
			if !r.jsonEscapeHTML {
				return encodeJSONEscapeHTML(r.bodyBuf, r.Body, r.jsonEscapeHTML)
			}
		} else if xmlKey == encKey {
			if inferKind(r.Body) != reflect.Struct {
				releaseBuffer(r.bodyBuf)
				r.bodyBuf = nil
				return ErrUnsupportedRequestBodyKind
			}
		}

		// user registered encoders with resty fallback key
		encFunc, found := c.inferContentTypeEncoder(contentType, encKey)
		if !found {
			releaseBuffer(r.bodyBuf)
			r.bodyBuf = nil
			return fmt.Errorf("resty: content-type encoder not found for %s", contentType)
		}
		if err := encFunc(r.bodyBuf, r.Body); err != nil {
			releaseBuffer(r.bodyBuf)
			r.bodyBuf = nil
			return err
		}
	}

	return nil
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Response Middleware(s)
//_______________________________________________________________________

// AutoParseResponseMiddleware method is used to parse the response body automatically
// based on registered HTTP response `Content-Type` decoder, see [Client.AddContentTypeDecoder];
// if [Request.SetResult], [Request.SetError], or [Client.SetError] is used
func AutoParseResponseMiddleware(c *Client, res *Response) (err error) {
	if res.Err != nil || res.Request.DoNotParseResponse {
		return // move on
	}

	if res.StatusCode() == http.StatusNoContent {
		res.Request.Error = nil
		return
	}

	rct := firstNonEmpty(
		res.Request.ForceResponseContentType,
		res.Header().Get(hdrContentTypeKey),
		res.Request.ExpectResponseContentType,
	)
	decKey := inferContentTypeMapKey(rct)
	decFunc, found := c.inferContentTypeDecoder(rct, decKey)
	if !found {
		// the Content-Type decoder is not found; just read all the body bytes
		err = res.readAll()
		return
	}

	// HTTP status code > 199 and < 300, considered as Result
	if res.IsSuccess() && res.Request.Result != nil {
		res.Request.Error = nil
		defer closeq(res.Body)
		err = decFunc(res.Body, res.Request.Result)
		res.IsRead = true
		return
	}

	// HTTP status code > 399, considered as Error
	if res.IsError() {
		// global error type registered at client-instance
		if res.Request.Error == nil {
			res.Request.Error = c.newErrorInterface()
		}

		if res.Request.Error != nil {
			defer closeq(res.Body)
			err = decFunc(res.Body, res.Request.Error)
			res.IsRead = true
			return
		}
	}

	return
}

// SaveToFileResponseMiddleware method used to write HTTP response body into
// given file details via [Request.SetOutputFile]
func SaveToFileResponseMiddleware(c *Client, res *Response) error {
	if res.Err != nil || !res.Request.isSaveResponse {
		return nil
	}

	file := ""

	if len(c.OutputDirectory()) > 0 && !filepath.IsAbs(res.Request.OutputFile) {
		file += c.OutputDirectory() + string(filepath.Separator)
	}

	file = filepath.Clean(file + res.Request.OutputFile)
	if err := createDirectory(filepath.Dir(file)); err != nil {
		return err
	}

	outFile, err := createFile(file)
	if err != nil {
		return err
	}

	defer func() {
		closeq(outFile)
		closeq(res.Body)
	}()

	// io.Copy reads maximum 32kb size, it is perfect for large file download too
	res.size, err = ioCopy(outFile, res.Body)

	return err
}
