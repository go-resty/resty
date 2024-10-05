// Copyright (c) 2015-2024 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
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
			if isStringEmpty(reqURL.RawQuery) {
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
	// init client trace if enabled
	r.initClientTrace()

	if r.bodyBuf == nil {
		if reader, ok := r.Body.(io.Reader); ok && isPayloadSupported(r.Method, c.AllowGetMethodPayload()) {
			r.RawRequest, err = http.NewRequestWithContext(r.Context(), r.Method, r.URL, reader)
		} else if r.setContentLength {
			r.RawRequest, err = http.NewRequestWithContext(r.Context(), r.Method, r.URL, http.NoBody)
		} else {
			r.RawRequest, err = http.NewRequestWithContext(r.Context(), r.Method, r.URL, nil)
		}
	} else {
		// fix data race: must deep copy.
		// TODO investigate in details and remove this copy line
		bodyBuf := bytes.NewBuffer(append([]byte{}, r.bodyBuf.Bytes()...))
		r.RawRequest, err = http.NewRequestWithContext(r.Context(), r.Method, r.URL, bodyBuf)
	}

	if err != nil {
		return
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

func createCurlCmd(c *Client, r *Request) (err error) {
	if r.Debug && r.generateCurlOnDebug {
		if r.resultCurlCmd == nil {
			r.resultCurlCmd = new(string)
		}
		*r.resultCurlCmd = buildCurlRequest(r)
	}
	return nil
}

func requestDebugLogger(c *Client, r *Request) error {
	if !r.Debug {
		return nil
	}

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

	return nil
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Response Middleware(s)
//_______________________________________________________________________

func responseDebugLogger(c *Client, res *Response) error {
	if !res.Request.Debug {
		return nil
	}

	bodyStr, err := res.fmtBodyString(res.Request.DebugBodyLimit)
	if err != nil {
		return err
	}

	rl := &ResponseLog{Header: res.Header().Clone(), Body: bodyStr}
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

	return nil
}

func parseResponseBody(c *Client, res *Response) (err error) {
	if res.Request.DoNotParseResponse || res.Request.isSaveResponse {
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

	// read all bytes when auto-unmarshal didn't take place
	err = res.readAll()
	return
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
		_, err = io.Copy(partWriter, mf.Reader)
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
	case io.Reader:
		// TODO create pass through reader to capture content-length, really needed??
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
