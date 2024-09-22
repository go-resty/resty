// Copyright (c) 2015-2024 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

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

	bodyBytes  []byte
	size       int64
	receivedAt time.Time
}

// BodyBytes method returns the HTTP response as `[]byte` slice for the executed request.
//
// NOTE:
//   - [Response.BodyBytes] might be `nil` if [Request.SetOutput], [Request.SetDoNotParseResponse],
//     [Client.SetDoNotParseResponse] method is used.
//   - [Response.BodyBytes] might be `nil` if [Response].Body is already auto-unmarshal performed.
func (r *Response) BodyBytes() []byte {
	if r.RawResponse == nil {
		return []byte{}
	}
	return r.bodyBytes
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
//   - Returns an empty string on auto-unmarshal scenarios
func (r *Response) String() string {
	if len(r.bodyBytes) == 0 {
		return ""
	}
	return strings.TrimSpace(string(r.bodyBytes))
}

// Time method returns the duration of HTTP response time from the request we sent
// and received a request.
//
// See [Response.ReceivedAt] to know when the client received a response and see
// `Response.Request.Time` to know when the client sent a request.
func (r *Response) Time() time.Duration {
	if r.Request.clientTrace != nil {
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
	if r.Request.clientTrace != nil {
		r.Request.clientTrace.endTime = r.receivedAt
	}
}

func (r *Response) fmtBodyString(sl int) string {
	if r.Request.NotParseResponse {
		return "***** DO NOT PARSE RESPONSE - Enabled *****"
	}
	if len(r.bodyBytes) > 0 {
		if len(r.bodyBytes) > sl {
			return fmt.Sprintf("***** RESPONSE TOO LARGE (size - %d) *****", len(r.bodyBytes))
		}
		ct := r.Header().Get(hdrContentTypeKey)
		if IsJSONType(ct) {
			out := acquireBuffer()
			defer releaseBuffer(out)
			err := json.Indent(out, r.bodyBytes, "", "   ")
			if err != nil {
				return fmt.Sprintf("*** Error: Unable to format response body - \"%s\" ***\n\nLog Body as-is:\n%s", err, r.String())
			}
			return out.String()
		}
		return r.String()
	}

	return "***** NO CONTENT *****"
}

// auto-unmarshal didn't happen, so fallback to
// old behavior of reading response as body bytes
func (r *Response) readAllBytes() (err error) {
	defer closeq(r.Body)
	r.bodyBytes, err = io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(r.bodyBytes))
	return
}
