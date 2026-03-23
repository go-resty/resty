// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"fmt"
	"net/http"
	"time"
)

type (
	// DebugLogCallbackFunc is called with the fully-populated [DebugLog] before
	// Resty formats or writes the debug output. Use it to inspect or mutate the
	// log entry, for example to add custom fields.
	//
	// See [Client.OnDebugLog].
	DebugLogCallbackFunc func(*DebugLog)

	// DebugLogFormatterFunc formats a [DebugLog] into a string for debug output.
	// See the built-in implementations [DebugLogFormatter] and [DebugLogJSONFormatter].
	//
	// See [Client.SetDebugLogFormatter].
	DebugLogFormatterFunc func(*DebugLog) string

	// DebugLog holds the request, response, and optional trace details captured
	// during a single Resty request execution for debug logging.
	DebugLog struct {
		Request   *DebugLogRequest  `json:"request"`
		Response  *DebugLogResponse `json:"response"`
		TraceInfo *TraceInfo        `json:"trace_info"`
	}

	// DebugLogRequest captures debug information about a [Request].
	DebugLogRequest struct {
		// CorrelationID is the request correlation ID (see [Request.SetCorrelationID]).
		CorrelationID string `json:"correlation_id"`
		// Host is the target host of the request.
		Host string `json:"host"`
		// URI is the request URI including path and query string.
		URI string `json:"uri"`
		// Method is the HTTP method of the request.
		Method string `json:"method"`
		// Proto is the HTTP protocol version, e.g. "HTTP/1.1".
		Proto string `json:"proto"`
		// Header contains the outgoing request headers (sensitive values are redacted).
		Header http.Header `json:"header"`
		// CurlCmd is the equivalent curl command string, populated when curl command
		// generation and debug logging are both enabled.
		CurlCmd string `json:"curl_cmd"`
		// Attempt is the current attempt number (1 = initial, >1 = retry).
		Attempt int `json:"attempt"`
		// Body is the request body as a string, truncated to DebugBodyLimit if set.
		Body string `json:"body"`
	}

	// DebugLogResponse captures debug information about a [Response].
	DebugLogResponse struct {
		// StatusCode is the HTTP response status code.
		StatusCode int `json:"status_code"`
		// Status is the HTTP response status text, e.g. "200 OK".
		Status string `json:"status"`
		// Proto is the HTTP protocol version, e.g. "HTTP/1.1".
		Proto string `json:"proto"`
		// ReceivedAt is the time at which the response was received.
		ReceivedAt time.Time `json:"received_at"`
		// Duration is the time elapsed from sending the request to receiving the response.
		Duration time.Duration `json:"duration"`
		// Size is the number of bytes in the response body.
		Size int64 `json:"size"`
		// Header contains the response headers (sensitive values are redacted).
		Header http.Header `json:"header"`
		// Body is the response body as a string, truncated to DebugBodyLimit if set.
		Body string `json:"body"`
	}
)

// DebugLogFormatter formats a [DebugLog] as a human-readable multi-line string.
//
// This is the default debug log formatter used by Resty.
func DebugLogFormatter(dl *DebugLog) string {
	debugLog := "\n==============================================================================\n"

	req := dl.Request
	if len(req.CurlCmd) > 0 {
		debugLog += "~~~ REQUEST(CURL) ~~~\n" +
			fmt.Sprintf("	%v\n", req.CurlCmd)
	}
	debugLog += "~~~ REQUEST ~~~\n" +
		fmt.Sprintf("CORRELATION ID: %s\n", req.CorrelationID) +
		fmt.Sprintf("%s  %s  %s\n", req.Method, req.URI, req.Proto) +
		fmt.Sprintf("HOST   : %s\n", req.Host) +
		fmt.Sprintf("HEADERS:\n%s\n", composeHeaders(req.Header)) +
		fmt.Sprintf("BODY   :\n%v\n", req.Body) +
		fmt.Sprintf("ATTEMPT       : %d\n", req.Attempt) +
		"------------------------------------------------------------------------------\n"

	res := dl.Response
	debugLog += "~~~ RESPONSE ~~~\n" +
		fmt.Sprintf("STATUS       : %s\n", res.Status) +
		fmt.Sprintf("PROTO        : %s\n", res.Proto) +
		fmt.Sprintf("RECEIVED AT  : %v\n", res.ReceivedAt.Format(time.RFC3339Nano)) +
		fmt.Sprintf("DURATION     : %v\n", res.Duration) +
		"HEADERS      :\n" +
		composeHeaders(res.Header) + "\n" +
		fmt.Sprintf("BODY         :\n%v\n", res.Body)
	if dl.TraceInfo != nil {
		debugLog += "------------------------------------------------------------------------------\n"
		debugLog += fmt.Sprintf("%v\n", dl.TraceInfo)
	}
	debugLog += "==============================================================================\n"

	return debugLog
}

// DebugLogJSONFormatter formats a [DebugLog] as a JSON string.
func DebugLogJSONFormatter(dl *DebugLog) string {
	return toJSON(dl)
}

func debugLogger(c *Client, res *Response) {
	req := res.Request
	if !req.IsDebug {
		return
	}

	rdl := &DebugLogResponse{
		StatusCode: res.StatusCode(),
		Status:     res.Status(),
		Proto:      res.Proto(),
		ReceivedAt: res.ReceivedAt(),
		Duration:   res.Duration(),
		Size:       res.Size(),
		Header:     sanitizeHeaders(res.Header().Clone()),
		Body:       res.fmtBodyString(res.Request.DebugBodyLimit),
	}

	dl := &DebugLog{
		Request:  req.values[debugRequestLogKey].(*DebugLogRequest),
		Response: rdl,
	}

	if res.Request.IsTrace {
		ti := req.TraceInfo()
		dl.TraceInfo = &ti
	}

	dblCallback := c.debugLogCallbackFunc()
	if dblCallback != nil {
		dblCallback(dl)
	}

	formatterFunc := c.debugLogFormatterFunc()
	if formatterFunc != nil {
		debugLog := formatterFunc(dl)
		req.log.Debugf("%s", debugLog)
	}
}

const debugRequestLogKey = "__restyDebugRequestLog"

func prepareRequestDebugInfo(c *Client, r *Request) {
	if !r.IsDebug {
		return
	}

	rr := r.RawRequest
	rh := rr.Header.Clone()
	if c.Client().Jar != nil {
		for _, cookie := range c.Client().Jar.Cookies(r.RawRequest.URL) {
			s := fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)
			if c := rh.Get(hdrCookieKey); isStringEmpty(c) {
				rh.Set(hdrCookieKey, s)
			} else {
				rh.Set(hdrCookieKey, c+"; "+s)
			}
		}
	}

	rdl := &DebugLogRequest{
		CorrelationID: r.CorrelationID,
		Host:          rr.URL.Host,
		URI:           rr.URL.RequestURI(),
		Method:        r.Method,
		Proto:         rr.Proto,
		Header:        sanitizeHeaders(rh),
		Attempt:       r.Attempt,
		Body:          r.fmtBodyString(r.DebugBodyLimit),
	}
	if r.isCurlCmdGenerate && r.isCurlCmdDebugLog {
		rdl.CurlCmd = r.curlCmdString
	}

	r.initValuesMap()
	r.values[debugRequestLogKey] = rdl
}
