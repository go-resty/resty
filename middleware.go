// Copyright (c) 2015-2024 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
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
	"strconv"
	"strings"
	"time"
)

const debugRequestLogKey = "__restyDebugRequestLog"

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Request Middleware(s)
//_______________________________________________________________________

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
		return err
	}

	// If Request.URL is relative path then added c.HostURL into
	// the request URL otherwise Request.URL will be used as-is
	if !reqURL.IsAbs() {
		r.URL = reqURL.String()
		if len(r.URL) > 0 && r.URL[0] != '/' {
			r.URL = "/" + r.URL
		}

		reqURL, err = url.Parse(c.BaseURL() + r.URL)
		if err != nil {
			return err
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
			if IsStringEmpty(reqURL.RawQuery) {
				reqURL.RawQuery = r.QueryParams.Encode()
			} else {
				reqURL.RawQuery = reqURL.RawQuery + "&" + r.QueryParams.Encode()
			}
		}
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

	if IsStringEmpty(r.Header.Get(hdrUserAgentKey)) {
		r.Header.Set(hdrUserAgentKey, hdrUserAgentValue)
	}

	if ct := r.Header.Get(hdrContentTypeKey); IsStringEmpty(r.Header.Get(hdrAcceptKey)) && !IsStringEmpty(ct) && (IsJSONType(ct) || IsXMLType(ct)) {
		r.Header.Set(hdrAcceptKey, r.Header.Get(hdrContentTypeKey))
	}

	return nil
}

func parseRequestBody(c *Client, r *Request) error {
	if isPayloadSupported(r.Method, c.AllowGetMethodPayload()) {
		switch {
		case r.isMultiPart: // Handling Multipart
			if err := handleMultipart(c, r); err != nil {
				return err
			}
		case len(c.FormData()) > 0 || len(r.FormData) > 0: // Handling Form Data
			handleFormData(c, r)
		case r.Body != nil: // Handling Request body
			if err := handleRequestBody(c, r); err != nil {
				return err
			}
		}
	}

	// by default resty won't set content length, you can if you want to :)
	if r.setContentLength {
		if r.bodyBuf == nil {
			r.Header.Set(hdrContentLengthKey, "0")
		} else {
			r.Header.Set(hdrContentLengthKey, strconv.Itoa(r.bodyBuf.Len()))
		}
	}

	return nil
}

func createHTTPRequest(c *Client, r *Request) (err error) {
	if r.bodyBuf == nil {
		if reader, ok := r.Body.(io.Reader); ok && isPayloadSupported(r.Method, c.AllowGetMethodPayload()) {
			r.RawRequest, err = http.NewRequest(r.Method, r.URL, reader)
		} else if r.setContentLength {
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

	// Enable trace
	if r.IsTrace {
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
	if !IsStringEmpty(r.AuthToken) {
		var authScheme string
		if IsStringEmpty(r.AuthScheme) {
			authScheme = "Bearer"
		} else {
			authScheme = r.AuthScheme
		}
		r.RawRequest.Header.Set(c.HeaderAuthorizationKey(), authScheme+" "+r.AuthToken)
	}

	return nil
}

func createCurlCmd(c *Client, r *Request) (err error) {
	if r.Debug && r.generateCurlOnDebug {
		if r.resultCurlCmd == nil {
			r.resultCurlCmd = new(string)
		}
		*r.resultCurlCmd = buildCurlRequest(r.RawRequest, c.Client().Jar)
	}
	return nil
}

func requestLogger(c *Client, r *Request) error {
	if r.Debug {
		rr := r.RawRequest
		rh := rr.Header.Clone()
		if c.Client().Jar != nil {
			for _, cookie := range c.Client().Jar.Cookies(r.RawRequest.URL) {
				s := fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)
				if c := rh.Get("Cookie"); c != "" {
					rh.Set("Cookie", c+"; "+s)
				} else {
					rh.Set("Cookie", s)
				}
			}
		}
		rl := &RequestLog{Header: rh, Body: r.fmtBodyString(r.DebugBodyLimit)}
		if c.requestLog != nil {
			if err := c.requestLog(rl); err != nil {
				return err
			}
		}

		reqLog := "\n==============================================================================\n"

		if r.Debug && r.generateCurlOnDebug {
			reqLog += "~~~ REQUEST(CURL) ~~~\n" +
				fmt.Sprintf("	%v\n", *r.resultCurlCmd)
		}

		reqLog += "~~~ REQUEST ~~~\n" +
			fmt.Sprintf("%s  %s  %s\n", r.Method, rr.URL.RequestURI(), rr.Proto) +
			fmt.Sprintf("HOST   : %s\n", rr.URL.Host) +
			fmt.Sprintf("HEADERS:\n%s\n", composeHeaders(rl.Header)) +
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
		rl := &ResponseLog{Header: res.Header().Clone(), Body: res.fmtBodyString(res.Request.DebugBodyLimit)}
		if c.responseLog != nil {
			c.lock.RLock()
			defer c.lock.RUnlock()
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
			composeHeaders(rl.Header) + "\n"
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
	if res.Request.isSaveResponse {
		return // move on
	}

	if res.StatusCode() == http.StatusNoContent {
		res.Request.Error = nil
		return
	}

	// TODO Attention Required when working on Compression

	rct := firstNonEmpty(
		res.Request.ForceResponseContentType,
		res.Header().Get(hdrContentTypeKey),
		res.Request.ExpectResponseContentType,
	)
	decKey := inferContentTypeMapKey(rct)
	decFunc, found := c.inferContentTypeDecoder(rct, decKey)
	if !found {
		// the Content-Type decoder is not found; just read all the body bytes
		err = res.readAllBytes()
		return
	}

	// HTTP status code > 199 and < 300, considered as Result
	if res.IsSuccess() && res.Request.Result != nil {
		res.Request.Error = nil
		defer closeq(res.Body)
		err = decFunc(res.Body, res.Request.Result)
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
			return
		}
	}

	// read all bytes when auto-unmarshal didn't take place
	err = res.readAllBytes()
	return
}

func handleMultipart(c *Client, r *Request) error {
	r.bodyBuf = acquireBuffer()
	w := multipart.NewWriter(r.bodyBuf)

	// Set boundary if not set by user
	if r.multipartBoundary != "" {
		if err := w.SetBoundary(r.multipartBoundary); err != nil {
			return err
		}
	}

	for k, v := range c.FormData() {
		for _, iv := range v {
			if err := w.WriteField(k, iv); err != nil {
				return err
			}
		}
	}

	for k, v := range r.FormData {
		for _, iv := range v {
			if strings.HasPrefix(k, "@") { // file
				if err := addFile(w, k[1:], iv); err != nil {
					return err
				}
			} else { // form value
				if err := w.WriteField(k, iv); err != nil {
					return err
				}
			}
		}
	}

	// #21 - adding io.Reader support
	for _, f := range r.multipartFiles {
		if err := addFileReader(w, f); err != nil {
			return err
		}
	}

	// GitHub #130 adding multipart field support with content type
	for _, mf := range r.multipartFields {
		if err := addMultipartFormField(w, mf); err != nil {
			return err
		}
	}

	r.Header.Set(hdrContentTypeKey, w.FormDataContentType())
	return w.Close()
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

var ErrUnsupportedRequestBodyKind = errors.New("resty: unsupported request body kind")

func handleRequestBody(c *Client, r *Request) error {
	contentType := r.Header.Get(hdrContentTypeKey)
	if IsStringEmpty(contentType) {
		// it is highly recommended that the user provide a request content-type
		contentType = DetectContentType(r.Body)
		r.Header.Set(hdrContentTypeKey, contentType)
	}

	r.bodyBuf = acquireBuffer()

	switch body := r.Body.(type) {
	case io.Reader:
		// TODO create pass through reader to capture content-length
		if r.setContentLength { // keep backward compatibility
			if _, err := r.bodyBuf.ReadFrom(body); err != nil {
				releaseBuffer(r.bodyBuf)
				return err
			}
			r.Body = nil
		} else {
			// Otherwise buffer less processing for `io.Reader`, sounds good.
			releaseBuffer(r.bodyBuf)
			r.bodyBuf = nil
			return nil
		}
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
				return ErrUnsupportedRequestBodyKind
			}
		}

		// user registered encoders with resty fallback key
		encFunc, found := c.inferContentTypeEncoder(contentType, encKey)
		if !found {
			releaseBuffer(r.bodyBuf)
			return fmt.Errorf("resty: content-type encoder not found for %s", contentType)
		}
		if err := encFunc(r.bodyBuf, r.Body); err != nil {
			releaseBuffer(r.bodyBuf)
			return err
		}
	}

	return nil
}

func saveResponseIntoFile(c *Client, res *Response) error {
	if res.Request.isSaveResponse {
		file := ""

		if len(c.OutputDirectory()) > 0 && !filepath.IsAbs(res.Request.OutputFile) {
			file += c.OutputDirectory() + string(filepath.Separator)
		}

		file = filepath.Clean(file + res.Request.OutputFile)
		if err := createDirectory(filepath.Dir(file)); err != nil {
			return err
		}

		outFile, err := os.Create(file)
		if err != nil {
			return err
		}
		defer closeq(outFile)

		// io.Copy reads maximum 32kb size, it is perfect for large file download too
		defer closeq(res.Body)

		written, err := io.Copy(outFile, res.Body)
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
