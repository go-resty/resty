// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
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

func Test_createDirectory(t *testing.T) {
	errMsg := "test dir error"
	mkdirAll = func(path string, perm os.FileMode) error {
		return errors.New(errMsg)
	}
	t.Cleanup(func() {
		mkdirAll = os.MkdirAll
	})

	tempDir := filepath.Join(t.TempDir(), "test-dir")
	err := createDirectory(tempDir)
	assertEqual(t, errMsg, err.Error())
}

func TestUtil_readRandomUint32(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			// panic: resty - guid: unable to generate random object id
			t.Errorf("The code did not panic")
		}
	}()
	errMsg := "read full error"
	ioReadFull = func(_ io.Reader, _ []byte) (int, error) {
		return 0, errors.New(errMsg)
	}
	t.Cleanup(func() {
		ioReadFull = io.ReadFull
	})

	readRandomUint32()
}

func TestUtil_readMachineID(t *testing.T) {
	t.Run("hostname error", func(t *testing.T) {
		errHostMsg := "hostname error"
		osHostname = func() (string, error) {
			return "", errors.New(errHostMsg)
		}
		t.Cleanup(func() {
			osHostname = os.Hostname
		})

		readMachineID()
	})

	t.Run("hostname and read full error", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				// panic: resty - guid: unable to get hostname and random bytes
				t.Errorf("The code did not panic")
			}
		}()
		errHostMsg := "hostname error"
		osHostname = func() (string, error) {
			return "", errors.New(errHostMsg)
		}
		errReadMsg := "read full error"
		ioReadFull = func(_ io.Reader, _ []byte) (int, error) {
			return 0, errors.New(errReadMsg)
		}
		t.Cleanup(func() {
			osHostname = os.Hostname
			ioReadFull = io.ReadFull
		})

		readMachineID()
	})
}

// This test methods exist for test coverage purpose
// to validate the getter and setter
func TestUtilMiscTestCoverage(t *testing.T) {
	l := &limitReadCloser{r: strings.NewReader("hello test close for no io.Closer")}
	assertNil(t, l.Close())

	r := &copyReadCloser{s: strings.NewReader("hello test close for no io.Closer")}
	assertNil(t, r.Close())

	v := struct {
		ID      string `json:"id"`
		Message string `json:"message"`
	}{}
	err := decodeJSON(bytes.NewReader([]byte(`{\"  \": \"some value\"}`)), &v)
	assertEqual(t, "invalid character '\\\\' looking for beginning of object key string", err.Error())

	ireErr := &invalidRequestError{Err: errors.New("test coverage")}
	assertEqual(t, "test coverage", ireErr.Error())
}
