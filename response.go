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

// Response struct holds response values of executed requests.
type Response struct {
	Request     *Request
	Body        io.ReadCloser
	RawResponse *http.Response
	IsRead      bool

	// Err field used to cascade the response middleware error
	// in the chain
	Err error

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

// Result method returns the response value as an object if it has one
//
// See [Request.SetResult]
func (r *Response) Result() any {
	return r.Request.Result
}

// Error method returns the error object if it has one
//
// See [Request.SetError], [Client.SetError]
func (r *Response) Error() any {
	return r.Request.Error
}

// Header method returns the response headers
func (r *Response) Header() http.Header {
	if r.RawResponse == nil {
		return http.Header{}
	}
	return r.RawResponse.Header
}

// Cookies method to returns all the response cookies
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
//     [Client.SetResponseBodyUnlimitedReads] or [Request.SetResponseBodyUnlimitedReads] set.
//   - Returns an empty string when [Client.SetDoNotParseResponse] or [Request.SetDoNotParseResponse] set
func (r Response) String() string {
	if len(r.bodyBytes) == 0 && !r.Request.DoNotParseResponse {
		_ = r.readAll()
	}
	return strings.TrimSpace(string(r.bodyBytes))
}

// Time method returns the duration of HTTP response time from the request we sent
// and received a request.
//
// See [Response.ReceivedAt] to know when the client received a response and see
// `Response.Request.Time` to know when the client sent a request.
func (r *Response) Time() time.Duration {
	if r.Request.trace != nil {
		return r.Request.TraceInfo().TotalTime
	}
	return r.receivedAt.Sub(r.Request.Time)
}

// ReceivedAt method returns the time we received a response from the server for the request.
func (r *Response) ReceivedAt() time.Time {
	return r.receivedAt
}

// Size method returns the HTTP response size in bytes. Yeah, you can rely on HTTP `Content-Length`
// header, however it won't be available for chucked transfer/compressed response.
// Since Resty captures response size details when processing the response body
// when possible. So that users get the actual size of response bytes.
func (r *Response) Size() int64 {
	return r.size
}

// IsSuccess method returns true if HTTP status `code >= 200 and <= 299` otherwise false.
func (r *Response) IsSuccess() bool {
	return r.StatusCode() > 199 && r.StatusCode() < 300
}

// IsError method returns true if HTTP status `code >= 400` otherwise false.
func (r *Response) IsError() bool {
	return r.StatusCode() > 399
}

func (r *Response) setReceivedAt() {
	r.receivedAt = time.Now()
	if r.Request.trace != nil {
		r.Request.trace.endTime = r.receivedAt
	}
}

func (r *Response) fmtBodyString(sl int) (string, error) {
	if r.Request.DoNotParseResponse {
		return "***** DO NOT PARSE RESPONSE - Enabled *****", nil
	}

	bl := len(r.bodyBytes)
	if r.IsRead && bl == 0 {
		return "***** RESPONSE BODY IS ALREADY READ - see Response.{Result()/Error()} *****", nil
	}

	if bl > 0 {
		if bl > sl {
			return fmt.Sprintf("***** RESPONSE TOO LARGE (size - %d) *****", bl), nil
		}

		ct := r.Header().Get(hdrContentTypeKey)
		ctKey := inferContentTypeMapKey(ct)
		if jsonKey == ctKey {
			out := acquireBuffer()
			defer releaseBuffer(out)
			err := json.Indent(out, r.bodyBytes, "", "   ")
			if err != nil {
				return "", err
			}
			return out.String(), nil
		}
		return r.String(), nil
	}

	return "***** NO CONTENT *****", nil
}

// auto-unmarshal didn't happen, so fallback to
// old behavior of reading response as body bytes
func (r *Response) readAll() (err error) {
	if r.Body == nil || r.IsRead {
		return nil
	}

	if _, ok := r.Body.(*copyReadCloser); ok {
		_, err = io.ReadAll(r.Body)
	} else {
		r.bodyBytes, err = io.ReadAll(r.Body)
		closeq(r.Body)
		r.Body = &nopReadCloser{r: bytes.NewReader(r.bodyBytes)}
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
			r.Body = &nopReadCloser{r: bytes.NewReader(r.bodyBytes)}
			releaseBuffer(b)
		},
	}
}

func (r *Response) wrapContentDecompressor() error {
	ce := r.Header().Get(hdrContentEncodingKey)
	if isStringEmpty(ce) {
		return nil
	}

	if decFunc, f := r.Request.client.ContentDecompressors()[ce]; f {
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
	} else {
		return ErrContentDecompressorNotFound
	}

	return nil
}
