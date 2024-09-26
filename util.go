// Copyright (c) 2015-2024 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
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
// Rate Limiter interface
//_______________________________________________________________________

var ErrRateLimitExceeded = errors.New("resty: rate limit exceeded")

type RateLimiter interface {
	Allow() bool
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

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// RequestLog and ResponseLog type
//_______________________________________________________________________

// RequestLog struct is used to collected information from resty request
// instance for debug logging. It sent to request log callback before resty
// actually logs the information.
type RequestLog struct {
	Header http.Header
	Body   string
}

// ResponseLog struct is used to collected information from resty response
// instance for debug logging. It sent to response log callback before resty
// actually logs the information.
type ResponseLog struct {
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

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

func createMultipartHeader(param, fileName, contentType string) textproto.MIMEHeader {
	hdr := make(textproto.MIMEHeader)

	var contentDispositionValue string
	if isStringEmpty(fileName) {
		contentDispositionValue = fmt.Sprintf(`form-data; name="%s"`, param)
	} else {
		contentDispositionValue = fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
			param, escapeQuotes(fileName))
	}
	hdr.Set("Content-Disposition", contentDispositionValue)

	if !isStringEmpty(contentType) {
		hdr.Set(hdrContentTypeKey, contentType)
	}
	return hdr
}

func addMultipartFormField(w *multipart.Writer, mf *MultipartField) error {
	partWriter, err := w.CreatePart(createMultipartHeader(mf.Param, mf.FileName, mf.ContentType))
	if err != nil {
		return err
	}

	_, err = io.Copy(partWriter, mf.Reader)
	return err
}

func writeMultipartFormFile(w *multipart.Writer, fieldName, fileName string, r io.Reader) error {
	// Auto detect actual multipart content type
	cbuf := make([]byte, 512)
	size, err := r.Read(cbuf)
	if err != nil && err != io.EOF {
		return err
	}

	partWriter, err := w.CreatePart(createMultipartHeader(fieldName, fileName, http.DetectContentType(cbuf[:size])))
	if err != nil {
		return err
	}

	if _, err = partWriter.Write(cbuf[:size]); err != nil {
		return err
	}

	_, err = io.Copy(partWriter, r)
	return err
}

func addFile(w *multipart.Writer, fieldName, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer closeq(file)
	return writeMultipartFormFile(w, fieldName, filepath.Base(path), file)
}

func addFileReader(w *multipart.Writer, f *File) error {
	return writeMultipartFormFile(w, f.ParamName, f.Name, f.Reader)
}

func isPayloadSupported(m string, allowMethodGet bool) bool {
	return !(m == MethodHead || m == MethodOptions || (m == MethodGet && !allowMethodGet))
}

func createDirectory(dir string) (err error) {
	if _, err = os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(dir, 0755); err != nil {
				return
			}
		}
	}
	return
}

func getPointer(v any) any {
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

func functionName(i any) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

func acquireBuffer() *bytes.Buffer {
	return bufPool.Get().(*bytes.Buffer)
}

func releaseBuffer(buf *bytes.Buffer) {
	if buf != nil {
		buf.Reset()
		bufPool.Put(buf)
	}
}

func wrapRequestBufferReleaser(r *Request) io.ReadCloser {
	if r.bodyBuf == nil {
		return r.RawRequest.Body
	}
	return &requestBufferReleaser{
		reqBuf:     r.bodyBuf,
		ReadCloser: r.RawRequest.Body,
	}
}

var _ io.ReadCloser = (*requestBufferReleaser)(nil)

// requestBufferReleaser wraps request body and implements custom Close for it.
// The Close method closes original body and releases request body back to sync.Pool.
type requestBufferReleaser struct {
	releaseOnce sync.Once
	reqBuf      *bytes.Buffer
	io.ReadCloser
}

func (rr *requestBufferReleaser) Close() error {
	err := rr.ReadCloser.Close()
	rr.releaseOnce.Do(func() {
		releaseBuffer(rr.reqBuf)
	})

	return err
}

func closeq(v any) {
	if c, ok := v.(io.Closer); ok {
		silently(c.Close())
	}
}

func silently(_ ...any) {}

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

type noRetryErr struct {
	err error
}

func (e *noRetryErr) Error() string {
	return e.err.Error()
}

func wrapNoRetryErr(err error) error {
	if err != nil {
		err = &noRetryErr{err: err}
	}
	return err
}

func unwrapNoRetryErr(err error) error {
	if e, ok := err.(*noRetryErr); ok {
		err = e.err
	}
	return err
}

// cloneURLValues is a helper function to deep copy url.Values.
func cloneURLValues(v url.Values) url.Values {
	if v == nil {
		return nil
	}
	return url.Values(http.Header(v).Clone())
}
