// Copyright (c) 2015-2023 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const debugRequestLogKey = "__restyDebugRequestLog"

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Request Middleware(s)
//_______________________________________________________________________

func parseRequestURL(c *Client, r *Request) error {
	// GitHub #103 Path Params
	if len(r.PathParams) > 0 {
		for p, v := range r.PathParams {
			r.URL = strings.Replace(r.URL, "{"+p+"}", url.PathEscape(v), -1)
		}
	}
	if len(c.PathParams) > 0 {
		for p, v := range c.PathParams {
			r.URL = strings.Replace(r.URL, "{"+p+"}", url.PathEscape(v), -1)
		}
	}

	// GitHub #663 Raw Path Params
	if len(r.RawPathParams) > 0 {
		for p, v := range r.RawPathParams {
			r.URL = strings.Replace(r.URL, "{"+p+"}", v, -1)
		}
	}
	if len(c.RawPathParams) > 0 {
		for p, v := range c.RawPathParams {
			r.URL = strings.Replace(r.URL, "{"+p+"}", v, -1)
		}
	}

	// Parsing request URL
	reqURL, err := url.Parse(r.URL)
	if err != nil {
		return err
	}

	// If Request.URL is relative path then added c.HostURL into
	// the request URL otherwise Request.URL will be used as-is
	if !reqURL.IsAbs() {
		r.URL = reqURL.String()
		if len(r.URL) > 0 && r.URL[0] != '/' {
			r.URL = "/" + r.URL
		}

		// TODO: change to use c.BaseURL only in v3.0.0
		baseURL := c.BaseURL
		if len(baseURL) == 0 {
			baseURL = c.HostURL
		}
		reqURL, err = url.Parse(baseURL + r.URL)
		if err != nil {
			return err
		}
	}

	// GH #407 && #318
	if reqURL.Scheme == "" && len(c.scheme) > 0 {
		reqURL.Scheme = c.scheme
	}

	// Adding Query Param
	query := make(url.Values)
	for k, v := range c.QueryParam {
		for _, iv := range v {
			query.Add(k, iv)
		}
	}

	for k, v := range r.QueryParam {
		// remove query param from client level by key
		// since overrides happens for that key in the request
		query.Del(k)

		for _, iv := range v {
			query.Add(k, iv)
		}
	}

	// GitHub #123 Preserve query string order partially.
	// Since not feasible in `SetQuery*` resty methods, because
	// standard package `url.Encode(...)` sorts the query params
	// alphabetically
	if len(query) > 0 {
		if IsStringEmpty(reqURL.RawQuery) {
			reqURL.RawQuery = query.Encode()
		} else {
			reqURL.RawQuery = reqURL.RawQuery + "&" + query.Encode()
		}
	}

	r.URL = reqURL.String()

	return nil
}

func parseRequestHeader(c *Client, r *Request) error {
	for k, v := range c.Header {
		if _, ok := r.Header[k]; ok {
			continue
		}
		r.Header[k] = v[:]
	}

	if IsStringEmpty(r.Header.Get(hdrUserAgentKey)) {
		r.Header.Set(hdrUserAgentKey, hdrUserAgentValue)
	}

	if ct := r.Header.Get(hdrContentTypeKey); IsStringEmpty(r.Header.Get(hdrAcceptKey)) && !IsStringEmpty(ct) && (IsJSONType(ct) || IsXMLType(ct)) {
		r.Header.Set(hdrAcceptKey, r.Header.Get(hdrContentTypeKey))
	}

	return nil
}

func parseRequestBody(c *Client, r *Request) (err error) {
	if isPayloadSupported(r.Method, c.AllowGetMethodPayload) {
		// Handling Multipart
		if r.isMultiPart {
			if err = handleMultipart(c, r); err != nil {
				return
			}

			goto CL
		}

		// Handling Form Data
		if len(c.FormData) > 0 || len(r.FormData) > 0 {
			handleFormData(c, r)

			goto CL
		}

		// Handling Request body
		if r.Body != nil {
			handleContentType(c, r)

			if err = handleRequestBody(c, r); err != nil {
				return
			}
		}
	}

CL:
	// by default resty won't set content length, you can if you want to :)
	if c.setContentLength || r.setContentLength {
		if r.bodyBuf == nil {
			r.Header.Set(hdrContentLengthKey, "0")
		} else {
			r.Header.Set(hdrContentLengthKey, fmt.Sprintf("%d", r.bodyBuf.Len()))
		}
	}

	return
}

func createHTTPRequest(c *Client, r *Request) (err error) {
	if r.bodyBuf == nil {
		if reader, ok := r.Body.(io.Reader); ok && isPayloadSupported(r.Method, c.AllowGetMethodPayload) {
			r.RawRequest, err = http.NewRequest(r.Method, r.URL, reader)
		} else if c.setContentLength || r.setContentLength {
			r.RawRequest, err = http.NewRequest(r.Method, r.URL, http.NoBody)
		} else {
			r.RawRequest, err = http.NewRequest(r.Method, r.URL, nil)
		}
	} else {
		// fix data race: must deep copy.
		bodyBuf := bytes.NewBuffer(append([]byte{}, r.bodyBuf.Bytes()...))
		r.RawRequest, err = http.NewRequest(r.Method, r.URL, bodyBuf)
	}

	if err != nil {
		return
	}

	// Assign close connection option
	r.RawRequest.Close = c.closeConnection

	// Add headers into http request
	r.RawRequest.Header = r.Header

	// Add cookies from client instance into http request
	for _, cookie := range c.Cookies {
		r.RawRequest.AddCookie(cookie)
	}

	// Add cookies from request instance into http request
	for _, cookie := range r.Cookies {
		r.RawRequest.AddCookie(cookie)
	}

	// Enable trace
	if c.trace || r.trace {
		r.clientTrace = &clientTrace{}
		r.ctx = r.clientTrace.createContext(r.Context())
	}

	// Use context if it was specified
	if r.ctx != nil {
		r.RawRequest = r.RawRequest.WithContext(r.ctx)
	}

	bodyCopy, err := getBodyCopy(r)
	if err != nil {
		return err
	}

	// assign get body func for the underlying raw request instance
	r.RawRequest.GetBody = func() (io.ReadCloser, error) {
		if bodyCopy != nil {
			return io.NopCloser(bytes.NewReader(bodyCopy.Bytes())), nil
		}
		return nil, nil
	}

	return
}

func addCredentials(c *Client, r *Request) error {
	var isBasicAuth bool
	// Basic Auth
	if r.UserInfo != nil { // takes precedence
		r.RawRequest.SetBasicAuth(r.UserInfo.Username, r.UserInfo.Password)
		isBasicAuth = true
	} else if c.UserInfo != nil {
		r.RawRequest.SetBasicAuth(c.UserInfo.Username, c.UserInfo.Password)
		isBasicAuth = true
	}

	if !c.DisableWarn {
		if isBasicAuth && !strings.HasPrefix(r.URL, "https") {
			r.log.Warnf("Using Basic Auth in HTTP mode is not secure, use HTTPS")
		}
	}

	// Set the Authorization Header Scheme
	var authScheme string
	if !IsStringEmpty(r.AuthScheme) {
		authScheme = r.AuthScheme
	} else if !IsStringEmpty(c.AuthScheme) {
		authScheme = c.AuthScheme
	} else {
		authScheme = "Bearer"
	}

	// Build the Token Auth header
	if !IsStringEmpty(r.Token) { // takes precedence
		r.RawRequest.Header.Set(c.HeaderAuthorizationKey, authScheme+" "+r.Token)
	} else if !IsStringEmpty(c.Token) {
		r.RawRequest.Header.Set(c.HeaderAuthorizationKey, authScheme+" "+c.Token)
	}

	return nil
}

func requestLogger(c *Client, r *Request) error {
	if r.Debug {
		rr := r.RawRequest
		rl := &RequestLog{Header: copyHeaders(rr.Header), Body: r.fmtBodyString(c.debugBodySizeLimit)}
		if c.requestLog != nil {
			if err := c.requestLog(rl); err != nil {
				return err
			}
		}
		// fmt.Sprintf("COOKIES:\n%s\n", composeCookies(c.GetClient().Jar, *rr.URL)) +

		reqLog := "\n==============================================================================\n" +
			"~~~ REQUEST ~~~\n" +
			fmt.Sprintf("%s  %s  %s\n", r.Method, rr.URL.RequestURI(), rr.Proto) +
			fmt.Sprintf("HOST   : %s\n", rr.URL.Host) +
			fmt.Sprintf("HEADERS:\n%s\n", composeHeaders(c, r, rl.Header)) +
			fmt.Sprintf("BODY   :\n%v\n", rl.Body) +
			"------------------------------------------------------------------------------\n"

		r.initValuesMap()
		r.values[debugRequestLogKey] = reqLog
	}

	return nil
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Response Middleware(s)
//_______________________________________________________________________

func responseLogger(c *Client, res *Response) error {
	if res.Request.Debug {
		rl := &ResponseLog{Header: copyHeaders(res.Header()), Body: res.fmtBodyString(c.debugBodySizeLimit)}
		if c.responseLog != nil {
			if err := c.responseLog(rl); err != nil {
				return err
			}
		}

		debugLog := res.Request.values[debugRequestLogKey].(string)
		debugLog += "~~~ RESPONSE ~~~\n" +
			fmt.Sprintf("STATUS       : %s\n", res.Status()) +
			fmt.Sprintf("PROTO        : %s\n", res.RawResponse.Proto) +
			fmt.Sprintf("RECEIVED AT  : %v\n", res.ReceivedAt().Format(time.RFC3339Nano)) +
			fmt.Sprintf("TIME DURATION: %v\n", res.Time()) +
			"HEADERS      :\n" +
			composeHeaders(c, res.Request, rl.Header) + "\n"
		if res.Request.isSaveResponse {
			debugLog += "BODY         :\n***** RESPONSE WRITTEN INTO FILE *****\n"
		} else {
			debugLog += fmt.Sprintf("BODY         :\n%v\n", rl.Body)
		}
		debugLog += "==============================================================================\n"

		res.Request.log.Debugf("%s", debugLog)
	}

	return nil
}

func parseResponseBody(c *Client, res *Response) (err error) {
	if res.StatusCode() == http.StatusNoContent {
		res.Request.Error = nil
		return
	}
	// Handles only JSON or XML content type
	ct := firstNonEmpty(res.Request.forceContentType, res.Header().Get(hdrContentTypeKey), res.Request.fallbackContentType)
	if IsJSONType(ct) || IsXMLType(ct) {
		// HTTP status code > 199 and < 300, considered as Result
		if res.IsSuccess() {
			res.Request.Error = nil
			if res.Request.Result != nil {
				err = Unmarshalc(c, ct, res.body, res.Request.Result)
				return
			}
		}

		// HTTP status code > 399, considered as Error
		if res.IsError() {
			// global error interface
			if res.Request.Error == nil && c.Error != nil {
				res.Request.Error = reflect.New(c.Error).Interface()
			}

			if res.Request.Error != nil {
				unmarshalErr := Unmarshalc(c, ct, res.body, res.Request.Error)
				if unmarshalErr != nil {
					c.log.Warnf("Cannot unmarshal response body: %s", unmarshalErr)
				}
			}
		}
	}

	return
}

func handleMultipart(c *Client, r *Request) (err error) {
	r.bodyBuf = acquireBuffer()
	w := multipart.NewWriter(r.bodyBuf)

	for k, v := range c.FormData {
		for _, iv := range v {
			if err = w.WriteField(k, iv); err != nil {
				return err
			}
		}
	}

	for k, v := range r.FormData {
		for _, iv := range v {
			if strings.HasPrefix(k, "@") { // file
				err = addFile(w, k[1:], iv)
				if err != nil {
					return
				}
			} else { // form value
				if err = w.WriteField(k, iv); err != nil {
					return err
				}
			}
		}
	}

	// #21 - adding io.Reader support
	if len(r.multipartFiles) > 0 {
		for _, f := range r.multipartFiles {
			err = addFileReader(w, f)
			if err != nil {
				return
			}
		}
	}

	// GitHub #130 adding multipart field support with content type
	if len(r.multipartFields) > 0 {
		for _, mf := range r.multipartFields {
			if err = addMultipartFormField(w, mf); err != nil {
				return
			}
		}
	}

	r.Header.Set(hdrContentTypeKey, w.FormDataContentType())
	err = w.Close()

	return
}

func handleFormData(c *Client, r *Request) {
	formData := url.Values{}

	for k, v := range c.FormData {
		for _, iv := range v {
			formData.Add(k, iv)
		}
	}

	for k, v := range r.FormData {
		// remove form data field from client level by key
		// since overrides happens for that key in the request
		formData.Del(k)

		for _, iv := range v {
			formData.Add(k, iv)
		}
	}

	r.bodyBuf = bytes.NewBuffer([]byte(formData.Encode()))
	r.Header.Set(hdrContentTypeKey, formContentType)
	r.isFormData = true
}

func handleContentType(c *Client, r *Request) {
	contentType := r.Header.Get(hdrContentTypeKey)
	if IsStringEmpty(contentType) {
		contentType = DetectContentType(r.Body)
		r.Header.Set(hdrContentTypeKey, contentType)
	}
}

func handleRequestBody(c *Client, r *Request) (err error) {
	var bodyBytes []byte
	contentType := r.Header.Get(hdrContentTypeKey)
	kind := kindOf(r.Body)
	r.bodyBuf = nil

	if reader, ok := r.Body.(io.Reader); ok {
		if c.setContentLength || r.setContentLength { // keep backward compatibility
			r.bodyBuf = acquireBuffer()
			_, err = r.bodyBuf.ReadFrom(reader)
			r.Body = nil
		} else {
			// Otherwise buffer less processing for `io.Reader`, sounds good.
			return
		}
	} else if b, ok := r.Body.([]byte); ok {
		bodyBytes = b
	} else if s, ok := r.Body.(string); ok {
		bodyBytes = []byte(s)
	} else if IsJSONType(contentType) &&
		(kind == reflect.Struct || kind == reflect.Map || kind == reflect.Slice) {
		r.bodyBuf, err = jsonMarshal(c, r, r.Body)
		if err != nil {
			return
		}
	} else if IsXMLType(contentType) && (kind == reflect.Struct) {
		bodyBytes, err = c.XMLMarshal(r.Body)
		if err != nil {
			return
		}
	}

	if bodyBytes == nil && r.bodyBuf == nil {
		err = errors.New("unsupported 'Body' type/value")
	}

	// if any errors during body bytes handling, return it
	if err != nil {
		return
	}

	// []byte into Buffer
	if bodyBytes != nil && r.bodyBuf == nil {
		r.bodyBuf = acquireBuffer()
		_, _ = r.bodyBuf.Write(bodyBytes)
	}

	return
}

func saveResponseIntoFile(c *Client, res *Response) error {
	if res.Request.isSaveResponse {
		file := ""

		if len(c.outputDirectory) > 0 && !filepath.IsAbs(res.Request.outputFile) {
			file += c.outputDirectory + string(filepath.Separator)
		}

		file = filepath.Clean(file + res.Request.outputFile)
		if err := createDirectory(filepath.Dir(file)); err != nil {
			return err
		}

		outFile, err := os.Create(file)
		if err != nil {
			return err
		}
		defer closeq(outFile)

		// io.Copy reads maximum 32kb size, it is perfect for large file download too
		defer closeq(res.RawResponse.Body)

		written, err := io.Copy(outFile, res.RawResponse.Body)
		if err != nil {
			return err
		}

		res.size = written
	}

	return nil
}

func getBodyCopy(r *Request) (*bytes.Buffer, error) {
	// If r.bodyBuf present, return the copy
	if r.bodyBuf != nil {
		bodyCopy := acquireBuffer()
		if _, err := io.Copy(bodyCopy, bytes.NewReader(r.bodyBuf.Bytes())); err != nil {
			// cannot use io.Copy(bodyCopy, r.bodyBuf) because io.Copy reset r.bodyBuf
			return nil, err
		}
		return bodyCopy, nil
	}

	// Maybe body is `io.Reader`.
	// Note: Resty user have to watchout for large body size of `io.Reader`
	if r.RawRequest.Body != nil {
		b, err := io.ReadAll(r.RawRequest.Body)
		if err != nil {
			return nil, err
		}

		// Restore the Body
		closeq(r.RawRequest.Body)
		r.RawRequest.Body = io.NopCloser(bytes.NewBuffer(b))

		// Return the Body bytes
		return bytes.NewBuffer(b), nil
	}
	return nil, nil
}
