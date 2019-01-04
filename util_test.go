// Copyright (c) 2015-2019 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
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
		{"text/xml+json", true},
		{"text/vnd.foo+json", true},

		{"application/foo-json", false},
		{"application/foo.json", false},
		{"application/vnd.foo-json", false},
		{"application/vnd.foo.json", false},
		{"application/json+xml", false},

		{"text/foo-json", false},
		{"text/foo.json", false},
		{"text/vnd.foo-json", false},
		{"text/vnd.foo.json", false},
		{"text/json+xml", false},
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
		{"application/json+xml", true},
		{"application/vnd.foo+xml", true},

		{"application/xml; charset=utf-8", true},
		{"application/vnd.foo+xml; charset=utf-8", true},

		{"text/xml", true},
		{"text/json+xml", true},
		{"text/vnd.foo+xml", true},

		{"application/foo-xml", false},
		{"application/foo.xml", false},
		{"application/vnd.foo-xml", false},
		{"application/vnd.foo.xml", false},
		{"application/xml+json", false},

		{"text/foo-xml", false},
		{"text/foo.xml", false},
		{"text/vnd.foo-xml", false},
		{"text/vnd.foo.xml", false},
		{"text/xml+json", false},
	} {
		result := IsXMLType(test.input)

		if result != test.expect {
			t.Errorf("failed on %q: want %v, got %v", test.input, test.expect, result)
		}
	}
}
