// Copyright (c) 2015-2023 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"mime/multipart"
	"testing"
)

func TestIsJSONType(t *testing.T) {
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
		result := IsJSONType(test.input)

		if result != test.expect {
			t.Errorf("failed on %q: want %v, got %v", test.input, test.expect, result)
		}
	}
}

func TestIsXMLType(t *testing.T) {
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
		result := IsXMLType(test.input)

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
