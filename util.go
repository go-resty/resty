// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
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
	"sync/atomic"
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

// credentials type is to hold an username and password information
type credentials struct {
	Username, Password string
}

// Clone method returns clone of c.
func (c *credentials) Clone() *credentials {
	cc := new(credentials)
	*cc = *c
	return cc
}

// String method returns masked value of username and password
func (c credentials) String() string {
	return "Username: **********, Password: **********"
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

func toJSON(v any) string {
	buf := acquireBuffer()
	defer releaseBuffer(buf)
	_ = encodeJSON(buf, v)
	return buf.String()
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// GUID generation
// Code inspired from mgo/bson ObjectId
// Code obtained from https://github.com/go-aah/aah/blob/edge/essentials/guid.go
//___________________________________

var (
	// guidCounter is atomically incremented when generating a new GUID
	// using UniqueID() function. It's used as a counter part of an id.
	guidCounter = readRandomUint32()

	// machineID stores machine id generated once and used in subsequent calls
	// to UniqueId function.
	machineID = readMachineID()

	// processID is current Process Id
	processID = os.Getpid()
)

// newGUID method returns a new Globally Unique Identifier (GUID).
//
// The 12-byte `UniqueId` consists of-
//   - 4-byte value representing the seconds since the Unix epoch,
//   - 3-byte machine identifier,
//   - 2-byte process id, and
//   - 3-byte counter, starting with a random value.
//
// Uses Mongo Object ID algorithm to generate globally unique ids -
// https://docs.mongodb.com/manual/reference/method/ObjectId/
func newGUID() string {
	var b [12]byte
	// Timestamp, 4 bytes, big endian
	binary.BigEndian.PutUint32(b[:], uint32(time.Now().Unix()))

	// Machine, first 3 bytes of md5(hostname)
	b[4], b[5], b[6] = machineID[0], machineID[1], machineID[2]

	// Pid, 2 bytes, specs don't specify endianness, but we use big endian.
	b[7], b[8] = byte(processID>>8), byte(processID)

	// Increment, 3 bytes, big endian
	i := atomic.AddUint32(&guidCounter, 1)
	b[9], b[10], b[11] = byte(i>>16), byte(i>>8), byte(i)

	return hex.EncodeToString(b[:])
}

var ioReadFull = io.ReadFull

// readRandomUint32 returns a random guidCounter.
func readRandomUint32() uint32 {
	var b [4]byte
	if _, err := ioReadFull(rand.Reader, b[:]); err == nil {
		return (uint32(b[0]) << 0) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16) | (uint32(b[3]) << 24)
	}

	// To initialize package unexported variable 'guidCounter'.
	// This panic would happen at program startup, so no worries at runtime panic.
	panic(errors.New("resty - guid: unable to generate random object id"))
}

var osHostname = os.Hostname

// readMachineID generates and returns a machine id.
// If this function fails to get the hostname it will cause a runtime error.
func readMachineID() []byte {
	var sum [3]byte
	id := sum[:]

	if hostname, err := osHostname(); err == nil {
		hw := md5.New()
		_, _ = hw.Write([]byte(hostname))
		copy(id, hw.Sum(nil))
		return id
	}

	if _, err := ioReadFull(rand.Reader, id); err == nil {
		return id
	}

	// To initialize package unexported variable 'machineID'.
	// This panic would happen at program startup, so no worries at runtime panic.
	panic(errors.New("resty - guid: unable to get hostname and random bytes"))
}
