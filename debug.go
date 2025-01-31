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
	// DebugLogCallbackFunc function type is for request and response debug log callback purposes.
	// It gets called before Resty logs it
	DebugLogCallbackFunc func(*DebugLog)

	// DebugLogFormatterFunc function type is used to implement debug log formatting.
	// See out of the box [DebugLogStringFormatter], [DebugLogJSONFormatter]
	DebugLogFormatterFunc func(*DebugLog) string

	// DebugLog struct is used to collect details from Resty request and response
	// for debug logging callback purposes.
	DebugLog struct {
		Request   *DebugLogRequest  `json:"request"`
		Response  *DebugLogResponse `json:"response"`
		TraceInfo *TraceInfo        `json:"trace_info"`
	}

	// DebugLogRequest type used to capture debug info about the [Request].
	DebugLogRequest struct {
		Host         string      `json:"host"`
		URI          string      `json:"uri"`
		Method       string      `json:"method"`
		Proto        string      `json:"proto"`
		Header       http.Header `json:"header"`
		CurlCmd      string      `json:"curl_cmd"`
		RetryTraceID string      `json:"retry_trace_id"`
		Attempt      int         `json:"attempt"`
		Body         string      `json:"body"`
	}

	// DebugLogResponse type used to capture debug info about the [Response].
	DebugLogResponse struct {
		StatusCode int           `json:"status_code"`
		Status     string        `json:"status"`
		Proto      string        `json:"proto"`
		ReceivedAt time.Time     `json:"received_at"`
		Duration   time.Duration `json:"duration"`
		Size       int64         `json:"size"`
		Header     http.Header   `json:"header"`
		Body       string        `json:"body"`
	}
)

// DebugLogFormatter function formats the given debug log info in human readable
// format.
//
// This is the default debug log formatter in the Resty.
func DebugLogFormatter(dl *DebugLog) string {
	debugLog := "\n==============================================================================\n"

	req := dl.Request
	if len(req.CurlCmd) > 0 {
		debugLog += "~~~ REQUEST(CURL) ~~~\n" +
			fmt.Sprintf("	%v\n", req.CurlCmd)
	}
	debugLog += "~~~ REQUEST ~~~\n" +
		fmt.Sprintf("%s  %s  %s\n", req.Method, req.URI, req.Proto) +
		fmt.Sprintf("HOST   : %s\n", req.Host) +
		fmt.Sprintf("HEADERS:\n%s\n", composeHeaders(req.Header)) +
		fmt.Sprintf("BODY   :\n%v\n", req.Body) +
		"------------------------------------------------------------------------------\n"
	if len(req.RetryTraceID) > 0 {
		debugLog += fmt.Sprintf("RETRY TRACE ID: %s\n", req.RetryTraceID) +
			fmt.Sprintf("ATTEMPT       : %d\n", req.Attempt) +
			"------------------------------------------------------------------------------\n"
	}

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

// DebugLogJSONFormatter function formats the given debug log info in JSON format.
func DebugLogJSONFormatter(dl *DebugLog) string {
	return toJSON(dl)
}

func debugLogger(c *Client, res *Response) {
	req := res.Request
	if !req.Debug {
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
	if !r.Debug {
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
		Host:   rr.URL.Host,
		URI:    rr.URL.RequestURI(),
		Method: r.Method,
		Proto:  rr.Proto,
		Header: sanitizeHeaders(rh),
		Body:   r.fmtBodyString(r.DebugBodyLimit),
	}
	if r.generateCurlCmd && r.debugLogCurlCmd {
		rdl.CurlCmd = r.resultCurlCmd
	}
	if len(r.RetryTraceID) > 0 {
		rdl.Attempt = r.Attempt
		rdl.RetryTraceID = r.RetryTraceID
	}

	r.initValuesMap()
	r.values[debugRequestLogKey] = rdl
}
