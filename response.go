// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Response struct and methods
//_______________________________________________________________________

// Response holds response values for an executed request.
type Response struct {
	Request     *Request
	Body        io.ReadCloser
	RawResponse *http.Response
	IsRead      bool

	// CascadeError field used to cascade the response processing and
	// middleware execution errors
	CascadeError error

	bodyBytes  []byte
	size       int64
	receivedAt time.Time
}

// Status method returns the HTTP status string for the executed request.
//
//	Example: 200 OK
func (r *Response) Status() string {
	if r.RawResponse == nil {
		return ""
	}
	return r.RawResponse.Status
}

// StatusCode method returns the HTTP status code for the executed request.
//
//	Example: 200
func (r *Response) StatusCode() int {
	if r.RawResponse == nil {
		return 0
	}
	return r.RawResponse.StatusCode
}

// Proto method returns the HTTP response protocol used for the request.
func (r *Response) Proto() string {
	if r.RawResponse == nil {
		return ""
	}
	return r.RawResponse.Proto
}

// Result method returns the unmarshalled result response object if it exists,
// otherwise nil.
//
//	client := resty.New()
//	defer client.Close()
//
//	res, err := client.R().
//	   SetBody(User{
//	     Username: "testuser",
//	     Password: "testpass",
//	   }).
//	   SetResult(&LoginResponse{}).      // or SetResult(LoginResponse{}).
//	   SetResultError(&LoginErrorResponse{}).  // or SetResultError(LoginErrorResponse{}).
//	   Post("https://myapp.com/login")
//
//	fmt.Println(err, res)
//	fmt.Println(res.Result().(*LoginResponse))
//	fmt.Println(res.ResultError().(*LoginErrorResponse))
//
// See [Request.SetResult]
func (r *Response) Result() any {
	return r.Request.Result
}

// ResultError method returns the unmarshalled result error object if it exists,
// otherwise nil.
//
//	client := resty.New()
//	defer client.Close()
//
//	res, err := client.R().
//	   SetBody(User{
//	     Username: "testuser",
//	     Password: "testpass",
//	   }).
//	   SetResult(&LoginResponse{}).            // or SetResult(LoginResponse{}).
//	   SetResultError(&LoginErrorResponse{}).  // or SetResultError(LoginErrorResponse{}).
//	   Post("https://myapp.com/login")
//
//	fmt.Println(err, res)
//	fmt.Println(res.Result().(*LoginResponse))
//	fmt.Println(res.ResultError().(*LoginErrorResponse))
//
// See [Request.SetResultError], [Client.SetResultError]
func (r *Response) ResultError() any {
	return r.Request.ResultError
}

// Header method returns the response headers.
func (r *Response) Header() http.Header {
	if r.RawResponse == nil {
		return http.Header{}
	}
	return r.RawResponse.Header
}

// Cookies method returns all response cookies.
func (r *Response) Cookies() []*http.Cookie {
	if r.RawResponse == nil {
		return make([]*http.Cookie, 0)
	}
	return r.RawResponse.Cookies()
}

// String method returns the body of the HTTP response as a `string`.
// It returns an empty string if it is nil or the body is zero length.
//
// NOTE:
//   - Returns an empty string on auto-unmarshal scenarios, unless
//     [Client.SetResponseBodyUnlimitedReads] or [Request.SetResponseBodyUnlimitedReads] is enabled.
//   - Returns an empty string when [Client.SetResponseDoNotParse] or [Request.SetResponseDoNotParse] is enabled.
func (r *Response) String() string {
	r.readIfRequired()
	return strings.TrimSpace(string(r.bodyBytes))
}

// Bytes method returns the body of the HTTP response as a byte slice.
// It returns an empty byte slice if it is nil or the body is zero length.
//
// NOTE:
//   - Returns an empty byte slice on auto-unmarshal scenarios, unless
//     [Client.SetResponseBodyUnlimitedReads] or [Request.SetResponseBodyUnlimitedReads] is enabled.
//   - Returns an empty byte slice when [Client.SetResponseDoNotParse] or [Request.SetResponseDoNotParse] is enabled.
func (r *Response) Bytes() []byte {
	r.readIfRequired()
	return r.bodyBytes
}

// Duration method returns the end-to-end duration from request start to response completion.
//
// See [Response.ReceivedAt] to know when the client received a response and see
// [Request.StartTime] to know when the client sent the request.
func (r *Response) Duration() time.Duration {
	if r.Request.trace != nil {
		return r.Request.TraceInfo().TotalTime
	}
	return r.receivedAt.Sub(r.Request.StartTime)
}

// ReceivedAt method returns the time we received a response from the server for the request.
func (r *Response) ReceivedAt() time.Time {
	return r.receivedAt
}

// Size method returns the HTTP response size in bytes.
//
// The HTTP Content-Length header can be unavailable or inaccurate for chunked
// transfer and compressed responses. Resty captures response size while reading
// the response body so callers can retrieve the actual processed byte count.
func (r *Response) Size() int64 {
	r.readIfRequired()
	return r.size
}

// IsStatusSuccess method returns true if HTTP status `code >= 200 and <= 299` otherwise false.
//
// Example: 200, 201, 204, etc.
func (r *Response) IsStatusSuccess() bool {
	return r.StatusCode() > 199 && r.StatusCode() < 300
}

// IsStatusFailure method returns true if HTTP status `code >= 400` otherwise false.
//
// Example: 400, 500, etc.
func (r *Response) IsStatusFailure() bool {
	return r.StatusCode() > 399
}

// RedirectHistory method returns redirect history entries with URL and status code.
func (r *Response) RedirectHistory() []*RedirectInfo {
	if r.RawResponse == nil {
		return nil
	}

	redirects := make([]*RedirectInfo, 0)
	res := r.RawResponse
	for res != nil {
		req := res.Request
		redirects = append(redirects, &RedirectInfo{
			StatusCode: res.StatusCode,
			URL:        req.URL.String(),
		})
		res = req.Response
	}

	return redirects
}

func (r *Response) setReceivedAt() {
	r.receivedAt = time.Now()
	if r.Request.trace != nil {
		r.Request.trace.endTime = r.receivedAt
	}
}

func (r *Response) fmtBodyString(sl int) string {
	if r.Request.IsResponseDoNotParse {
		return "***** DO NOT PARSE RESPONSE - Enabled *****"
	}

	if r.Request.IsResponseSaveToFile {
		return "***** RESPONSE WRITTEN INTO FILE *****"
	}

	bl := len(r.bodyBytes)
	if r.IsRead && bl == 0 {
		return "***** RESPONSE BODY IS ALREADY READ - see Response.{Result()/Error()} *****"
	}

	if bl > 0 {
		if bl > sl {
			return fmt.Sprintf("***** RESPONSE TOO LARGE (size - %d) *****", bl)
		}

		ct := r.Header().Get(hdrContentTypeKey)
		ctKey := inferContentTypeMapKey(ct)
		if jsonKey == ctKey {
			out := acquireBuffer()
			defer releaseBuffer(out)
			err := json.Indent(out, r.bodyBytes, "", "   ")
			if err != nil {
				r.Request.log.Errorf("DebugLog: Response.fmtBodyString: %v", err)
				return ""
			}
			return out.String()
		}
		return r.String()
	}

	return "***** NO CONTENT *****"
}

func (r *Response) readIfRequired() {
	if len(r.bodyBytes) == 0 && !r.Request.IsResponseDoNotParse {
		_ = r.readAll()
	}
}

var ioReadAll = io.ReadAll

// auto-unmarshal didn't happen, so fallback to
// old behavior of reading response as body bytes
func (r *Response) readAll() (err error) {
	if r.Body == nil || r.IsRead {
		return nil
	}

	if _, ok := r.Body.(*copyReadCloser); ok {
		_, err = ioReadAll(r.Body)
	} else {
		r.bodyBytes, err = ioReadAll(r.Body)
		closeq(r.Body)
		r.Body = &nopReadCloser{r: bytes.NewReader(r.bodyBytes), resetOnEOF: true}
	}
	if err == io.ErrUnexpectedEOF {
		// content-encoding scenario's - empty/no response body from server
		err = nil
	}

	r.IsRead = true
	return
}

func (r *Response) wrapLimitReadCloser() {
	r.Body = &limitReadCloser{
		r: r.Body,
		l: r.Request.ResponseBodyLimit,
		f: func(s int64) {
			r.size = s
		},
	}
}

func (r *Response) wrapCopyReadCloser() {
	r.Body = &copyReadCloser{
		s: r.Body,
		t: acquireBuffer(),
		f: func(b *bytes.Buffer) {
			r.bodyBytes = append([]byte{}, b.Bytes()...)
			closeq(r.Body)
			r.Body = &nopReadCloser{r: bytes.NewReader(r.bodyBytes), resetOnEOF: true}
			releaseBuffer(b)
		},
	}
}

func (r *Response) wrapContentDecompresser() error {
	ce := r.Header().Get(hdrContentEncodingKey)
	if isStringEmpty(ce) {
		return nil
	}

	if decFunc, f := r.Request.client.ContentDecompressers()[strings.ToLower(ce)]; f {
		dec, err := decFunc(r.Body)
		if err != nil {
			if err == io.EOF {
				// empty/no response body from server
				err = nil
			}
			return err
		}

		r.Body = dec
		r.Header().Del(hdrContentEncodingKey)
		r.Header().Del(hdrContentLengthKey)
		r.RawResponse.ContentLength = -1
	} else if r.Request.IsResponseDoNotParse {
		// GH#1168 Don't return an error if DoNotParse is enabled and the content
		// decompresser is not found. Possibly the user is handling content decompression
		// in their own way, so instead of returning an error and breaking the response
		// processing, just log it and let the caller handle it when they try to read the body.
		r.Request.log.Warnf("Response.wrapContentDecompresser: DoNotParse is enabled and the content"+
			" decompresser is not found for encoding '%s', just log it and let the caller handle it", ce)
		return nil
	} else {
		return ErrContentDecompresserNotFound
	}

	return nil
}

func (r *Response) wrapError(err error, preserve bool) error {
	r.CascadeError = wrapErrors(err, r.CascadeError)
	if preserve {
		return nil
	}
	e := r.CascadeError
	r.CascadeError = nil
	return e
}
