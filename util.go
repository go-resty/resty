// Copyright (c) 2015-2018 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
)

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Package Helper methods
//___________________________________

// IsStringEmpty method tells whether given string is empty or not
func IsStringEmpty(str string) bool {
	return (len(strings.TrimSpace(str)) == 0)
}

// DetectContentType method is used to figure out `Request.Body` content type for request header
func DetectContentType(body interface{}) string {
	contentType := plainTextType
	kind := kindOf(body)
	switch kind {
	case reflect.Struct, reflect.Map:
		contentType = jsonContentType
	case reflect.String:
		contentType = plainTextType
	default:
		if b, ok := body.([]byte); ok {
			contentType = http.DetectContentType(b)
		} else if kind == reflect.Slice {
			contentType = jsonContentType
		}
	}

	return contentType
}

// IsJSONType method is to check JSON content type or not
func IsJSONType(ct string) bool {
	return jsonCheck.MatchString(ct)
}

// IsXMLType method is to check XML content type or not
func IsXMLType(ct string) bool {
	return xmlCheck.MatchString(ct)
}

// Unmarshal content into object from JSON or XML
// Deprecated: kept for backward compatibility
func Unmarshal(ct string, b []byte, d interface{}) (err error) {
	if IsJSONType(ct) {
		err = json.Unmarshal(b, d)
	} else if IsXMLType(ct) {
		err = xml.Unmarshal(b, d)
	}

	return
}

// Unmarshalc content into object from JSON or XML
func Unmarshalc(c *Client, ct string, b []byte, d interface{}) (err error) {
	if IsJSONType(ct) {
		err = c.JSONUnmarshal(b, d)
	} else if IsXMLType(ct) {
		err = xml.Unmarshal(b, d)
	}

	return
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Package Unexported methods
//___________________________________

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if !IsStringEmpty(s) {
			return s
		}
	}
	return ""
}

func getLogger(w io.Writer) *log.Logger {
	return log.New(w, "RESTY ", log.LstdFlags)
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

func writeMultipartFormFile(w *multipart.Writer, fieldName, fileName string, r io.Reader) error {
	// Auto detect actual multipart content type
	cbuf := make([]byte, 512)
	size, err := r.Read(cbuf)
	if err != nil {
		return err
	}

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
		escapeQuotes(fieldName), escapeQuotes(fileName)))
	h.Set("Content-Type", http.DetectContentType(cbuf))
	partWriter, err := w.CreatePart(h)
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
	defer func() {
		_ = file.Close()
	}()

	return writeMultipartFormFile(w, fieldName, filepath.Base(path), file)
}

func addFileReader(w *multipart.Writer, f *File) error {
	return writeMultipartFormFile(w, f.ParamName, f.Name, f.Reader)
}

func getPointer(v interface{}) interface{} {
	vv := valueOf(v)
	if vv.Kind() == reflect.Ptr {
		return v
	}
	return reflect.New(vv.Type()).Interface()
}

func isPayloadSupported(m string, allowMethodGet bool) bool {
	return (m == MethodPost || m == MethodPut || m == MethodDelete || m == MethodPatch || (allowMethodGet && m == MethodGet))
}

func typeOf(i interface{}) reflect.Type {
	return indirect(valueOf(i)).Type()
}

func valueOf(i interface{}) reflect.Value {
	return reflect.ValueOf(i)
}

func indirect(v reflect.Value) reflect.Value {
	return reflect.Indirect(v)
}

func kindOf(v interface{}) reflect.Kind {
	return typeOf(v).Kind()
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

func canJSONMarshal(contentType string, kind reflect.Kind) bool {
	return IsJSONType(contentType) && (kind == reflect.Struct || kind == reflect.Map)
}

func functionName(i interface{}) string {
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

func composeRequestURL(pathURL string, c *Client, r *Request) string {
	if !strings.HasPrefix(pathURL, "/") {
		pathURL = "/" + pathURL
	}

	hasTrailingSlash := false
	if strings.HasSuffix(pathURL, "/") && len(pathURL) > 1 {
		hasTrailingSlash = true
	}

	reqURL := "/"
	for _, segment := range strings.Split(pathURL, "/") {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			key := segment[1 : len(segment)-1]
			if val, found := r.pathParams[key]; found {
				reqURL = path.Join(reqURL, val)
				continue
			}

			if val, found := c.pathParams[key]; found {
				reqURL = path.Join(reqURL, val)
				continue
			}
		}

		reqURL = path.Join(reqURL, segment)
	}

	if hasTrailingSlash {
		reqURL = reqURL + "/"
	}

	return reqURL
}
