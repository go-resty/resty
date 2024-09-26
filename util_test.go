// Copyright (c) 2015-2024 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/url"
	"strings"
	"testing"
)

func TestIsJSONContentType(t *testing.T) {
	for _, test := range []struct {
		input  string
		expect bool
	}{
		{"application/json", true},
		{"application/xml+json", true},
		{"application/vnd.foo+json", true},

		{"application/json; charset=utf-8", true},
		{"application/vnd.foo+json; charset=utf-8", true},

		{"text/json", true},
		{"text/vnd.foo+json", true},

		{"application/foo-json", true},
		{"application/foo.json", true},
		{"application/vnd.foo-json", true},
		{"application/vnd.foo.json", true},
		{"application/x-amz-json-1.1", true},

		{"text/foo-json", true},
		{"text/foo.json", true},
		{"text/vnd.foo-json", true},
		{"text/vnd.foo.json", true},
	} {
		result := isJSONContentType(test.input)

		if result != test.expect {
			t.Errorf("failed on %q: want %v, got %v", test.input, test.expect, result)
		}
	}
}

func TestIsXMLContentType(t *testing.T) {
	for _, test := range []struct {
		input  string
		expect bool
	}{
		{"application/xml", true},
		{"application/vnd.foo+xml", true},

		{"application/xml; charset=utf-8", true},
		{"application/vnd.foo+xml; charset=utf-8", true},

		{"text/xml", true},
		{"text/vnd.foo+xml", true},

		{"application/foo-xml", true},
		{"application/foo.xml", true},
		{"application/vnd.foo-xml", true},
		{"application/vnd.foo.xml", true},

		{"text/foo-xml", true},
		{"text/foo.xml", true},
		{"text/vnd.foo-xml", true},
		{"text/vnd.foo.xml", true},
	} {
		result := isXMLContentType(test.input)

		if result != test.expect {
			t.Errorf("failed on %q: want %v, got %v", test.input, test.expect, result)
		}
	}
}

func TestWriteMultipartFormFileReaderEmpty(t *testing.T) {
	w := multipart.NewWriter(bytes.NewBuffer(nil))
	defer func() { _ = w.Close() }()
	if err := writeMultipartFormFile(w, "foo", "bar", bytes.NewReader(nil)); err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
}

func TestWriteMultipartFormFileReaderError(t *testing.T) {
	err := writeMultipartFormFile(nil, "", "", &brokenReadCloser{})
	assertNotNil(t, err)
	assertEqual(t, "read error", err.Error())
}

func TestCloneURLValues(t *testing.T) {
	v := url.Values{}
	v.Add("foo", "bar")
	v.Add("foo", "baz")
	v.Add("qux", "quux")

	c := cloneURLValues(v)
	nilUrl := cloneURLValues(nil)
	assertEqual(t, v, c)
	assertNil(t, nilUrl)
}

func TestRestyErrorFuncs(t *testing.T) {
	ne1 := errors.New("new error 1")
	nie1 := errors.New("inner error 1")

	assertNil(t, wrapErrors(nil, nil))

	e := wrapErrors(ne1, nie1)
	assertEqual(t, "new error 1", e.Error())
	assertEqual(t, "inner error 1", errors.Unwrap(e).Error())

	e = wrapErrors(ne1, nil)
	assertEqual(t, "new error 1", e.Error())

	e = wrapErrors(nil, nie1)
	assertEqual(t, "inner error 1", e.Error())
}

// This test methods exist for test coverage purpose
// to validate the getter and setter
func TestUtilMiscTestCoverage(t *testing.T) {
	l := &limitReadCloser{r: strings.NewReader("hello test close for no io.Closer")}
	assertNil(t, l.Close())

	r := &readCopier{s: strings.NewReader("hello test close for no io.Closer")}
	assertNil(t, r.Close())

	v := struct {
		ID      string `json:"id"`
		Message string `json:"message"`
	}{}
	err := decodeJSON(bytes.NewReader([]byte(`{\"  \": \"some value\"}`)), &v)
	assertEqual(t, "invalid character '\\\\' looking for beginning of object key string", err.Error())

	err = &noRetryErr{err: errors.New("hey error")}
	assertEqual(t, "hey error", err.Error())
}
