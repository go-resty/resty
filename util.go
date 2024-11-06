// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"
)

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Logger interface
//_______________________________________________________________________

// Logger interface is to abstract the logging from Resty. Gives control to
// the Resty users, choice of the logger.
type Logger interface {
	Errorf(format string, v ...any)
	Warnf(format string, v ...any)
	Debugf(format string, v ...any)
}

func createLogger() *logger {
	l := &logger{l: log.New(os.Stderr, "", log.Ldate|log.Lmicroseconds)}
	return l
}

var _ Logger = (*logger)(nil)

type logger struct {
	l *log.Logger
}

func (l *logger) Errorf(format string, v ...any) {
	l.output("ERROR RESTY "+format, v...)
}

func (l *logger) Warnf(format string, v ...any) {
	l.output("WARN RESTY "+format, v...)
}

func (l *logger) Debugf(format string, v ...any) {
	l.output("DEBUG RESTY "+format, v...)
}

func (l *logger) output(format string, v ...any) {
	if len(v) == 0 {
		l.l.Print(format)
		return
	}
	l.l.Printf(format, v...)
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Package Helper methods
//_______________________________________________________________________

// isStringEmpty method tells whether given string is empty or not
func isStringEmpty(str string) bool {
	return len(strings.TrimSpace(str)) == 0
}

// detectContentType method is used to figure out `Request.Body` content type for request header
func detectContentType(body any) string {
	contentType := plainTextType
	kind := inferKind(body)
	switch kind {
	case reflect.Struct, reflect.Map:
		contentType = jsonContentType
	case reflect.String:
		contentType = plainTextType
	default:
		if b, ok := body.([]byte); ok {
			contentType = http.DetectContentType(b)
		} else if kind == reflect.Slice { // check slice here to differentiate between any slice vs byte slice
			contentType = jsonContentType
		}
	}

	return contentType
}

func isJSONContentType(ct string) bool {
	return strings.Contains(ct, jsonKey)
}

func isXMLContentType(ct string) bool {
	return strings.Contains(ct, xmlKey)
}

func inferContentTypeMapKey(v string) string {
	if isJSONContentType(v) {
		return jsonKey
	} else if isXMLContentType(v) {
		return xmlKey
	}
	return ""
}

// DebugLog struct is used to collect details from Resty request and response
// for debug logging callback purposes.
type DebugLog struct {
	Header http.Header
	Body   string
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if !isStringEmpty(s) {
			return s
		}
	}
	return ""
}

var (
	mkdirAll   = os.MkdirAll
	createFile = os.Create
	ioCopy     = io.Copy
)

func createDirectory(dir string) (err error) {
	if _, err = os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			if err = mkdirAll(dir, 0755); err != nil {
				return
			}
		}
	}
	return
}

func getPointer(v any) any {
	if v == nil {
		return nil
	}
	vv := reflect.ValueOf(v)
	if vv.Kind() == reflect.Ptr {
		return v
	}
	return reflect.New(vv.Type()).Interface()
}

func inferType(v any) reflect.Type {
	return reflect.Indirect(reflect.ValueOf(v)).Type()
}

func inferKind(v any) reflect.Kind {
	return inferType(v).Kind()
}

func newInterface(v any) any {
	if v == nil {
		return nil
	}
	return reflect.New(inferType(v)).Interface()
}

func functionName(i any) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

func acquireBuffer() *bytes.Buffer {
	buf := bufPool.Get().(*bytes.Buffer)
	if buf.Len() == 0 {
		buf.Reset()
		return buf
	}
	bufPool.Put(buf)
	return new(bytes.Buffer)
}

func releaseBuffer(buf *bytes.Buffer) {
	if buf != nil {
		buf.Reset()
		bufPool.Put(buf)
	}
}

func backToBufPool(buf *bytes.Buffer) {
	if buf != nil {
		bufPool.Put(buf)
	}
}

func closeq(v any) {
	if c, ok := v.(io.Closer); ok {
		silently(c.Close())
	}
}

func silently(_ ...any) {}

var sanitizeHeaderToken = []string{
	"authorization",
	"auth",
	"token",
}

func isSanitizeHeader(k string) bool {
	kk := strings.ToLower(k)
	for _, v := range sanitizeHeaderToken {
		if strings.Contains(kk, v) {
			return true
		}
	}
	return false
}

func sanitizeHeaders(hdr http.Header) http.Header {
	for k := range hdr {
		if isSanitizeHeader(k) {
			hdr[k] = []string{"********************"}
		}
	}
	return hdr
}

func composeHeaders(hdr http.Header) string {
	str := make([]string, 0, len(hdr))
	for _, k := range sortHeaderKeys(hdr) {
		str = append(str, "\t"+strings.TrimSpace(fmt.Sprintf("%25s: %s", k, strings.Join(hdr[k], ", "))))
	}
	return strings.Join(str, "\n")
}

func sortHeaderKeys(hdr http.Header) []string {
	keys := make([]string, 0, len(hdr))
	for key := range hdr {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func wrapErrors(n error, inner error) error {
	if n == nil && inner == nil {
		return nil
	}
	if inner == nil {
		return n
	}
	if n == nil {
		return inner
	}
	return &restyError{
		err:   n,
		inner: inner,
	}
}

type restyError struct {
	err   error
	inner error
}

func (e *restyError) Error() string {
	return e.err.Error()
}

func (e *restyError) Unwrap() error {
	return e.inner
}

// cloneURLValues is a helper function to deep copy url.Values.
func cloneURLValues(v url.Values) url.Values {
	if v == nil {
		return nil
	}
	return url.Values(http.Header(v).Clone())
}

func cloneCookie(c *http.Cookie) *http.Cookie {
	return &http.Cookie{
		Name:       c.Name,
		Value:      c.Value,
		Path:       c.Path,
		Domain:     c.Domain,
		Expires:    c.Expires,
		RawExpires: c.RawExpires,
		MaxAge:     c.MaxAge,
		Secure:     c.Secure,
		HttpOnly:   c.HttpOnly,
		SameSite:   c.SameSite,
		Raw:        c.Raw,
		Unparsed:   c.Unparsed,
	}
}

type invalidRequestError struct {
	Err error
}

func (ire *invalidRequestError) Error() string {
	return ire.Err.Error()
}

func drainBody(res *Response) {
	if res != nil && res.Body != nil {
		defer closeq(res.Body)
		_, _ = io.Copy(io.Discard, res.Body)
	}
}

func requestDebugLogger(c *Client, r *Request) {
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
	rl := &DebugLog{Header: sanitizeHeaders(rh), Body: r.fmtBodyString(r.DebugBodyLimit)}
	c.lock.RLock()
	if c.requestDebugLog != nil {
		c.requestDebugLog(rl)
	}
	c.lock.RUnlock()

	reqLog := "\n==============================================================================\n"

	if r.Debug && r.generateCurlOnDebug {
		reqLog += "~~~ REQUEST(CURL) ~~~\n" +
			fmt.Sprintf("	%v\n", *r.resultCurlCmd)
	}

	reqLog += "~~~ REQUEST ~~~\n" +
		fmt.Sprintf("%s  %s  %s\n", r.Method, rr.URL.RequestURI(), rr.Proto) +
		fmt.Sprintf("HOST   : %s\n", rr.URL.Host) +
		fmt.Sprintf("ATTEMPT: %d\n", r.Attempt) +
		fmt.Sprintf("HEADERS:\n%s\n", composeHeaders(rl.Header)) +
		fmt.Sprintf("BODY   :\n%v\n", rl.Body) +
		"------------------------------------------------------------------------------\n"

	r.initValuesMap()
	r.values[debugRequestLogKey] = reqLog
}

func responseDebugLogger(c *Client, res *Response) {
	if !res.Request.Debug {
		return
	}

	bodyStr := res.fmtBodyString(res.Request.DebugBodyLimit)

	rl := &DebugLog{Header: sanitizeHeaders(res.Header().Clone()), Body: bodyStr}
	c.lock.RLock()
	if c.responseDebugLog != nil {
		c.responseDebugLog(rl)
	}
	c.lock.RUnlock()

	debugLog := res.Request.values[debugRequestLogKey].(string)
	debugLog += "~~~ RESPONSE ~~~\n" +
		fmt.Sprintf("STATUS       : %s\n", res.Status()) +
		fmt.Sprintf("PROTO        : %s\n", res.Proto()) +
		fmt.Sprintf("RECEIVED AT  : %v\n", res.ReceivedAt().Format(time.RFC3339Nano)) +
		fmt.Sprintf("TIME DURATION: %v\n", res.Time()) +
		"HEADERS      :\n" +
		composeHeaders(rl.Header) + "\n"
	if res.Request.isSaveResponse {
		debugLog += "BODY         :\n***** RESPONSE WRITTEN INTO FILE *****\n"
	} else {
		debugLog += fmt.Sprintf("BODY         :\n%v\n", rl.Body)
	}
	if res.Request.IsTrace {
		debugLog += "------------------------------------------------------------------------------\n"
		debugLog += fmt.Sprintf("%v\n", res.Request.TraceInfo())
	}
	debugLog += "==============================================================================\n"

	res.Request.log.Debugf("%s", debugLog)
}
