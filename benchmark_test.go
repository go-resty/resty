// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"strings"
	"testing"
)

func Benchmark_parseRequestURL_PathParams(b *testing.B) {
	c := New().SetPathParams(map[string]string{
		"foo": "1",
		"bar": "2",
	}).SetRawPathParams(map[string]string{
		"foo": "3",
		"xyz": "4",
	})
	r := c.R().SetPathParams(map[string]string{
		"foo": "5",
		"qwe": "6",
	}).SetRawPathParams(map[string]string{
		"foo": "7",
		"asd": "8",
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.URL = "https://example.com/{foo}/{bar}/{xyz}/{qwe}/{asd}"
		if err := parseRequestURL(c, r); err != nil {
			b.Errorf("parseRequestURL() error = %v", err)
		}
	}
}

func Benchmark_parseRequestURL_QueryParams(b *testing.B) {
	c := New().SetQueryParams(map[string]string{
		"foo": "1",
		"bar": "2",
	})
	r := c.R().SetQueryParams(map[string]string{
		"foo": "5",
		"qwe": "6",
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.URL = "https://example.com/"
		if err := parseRequestURL(c, r); err != nil {
			b.Errorf("parseRequestURL() error = %v", err)
		}
	}
}

func Benchmark_parseRequestHeader(b *testing.B) {
	c := New()
	r := c.R()
	c.SetHeaders(map[string]string{
		"foo": "1", // ignored, because of the same header in the request
		"bar": "2",
	})
	r.SetHeaders(map[string]string{
		"foo": "3",
		"xyz": "4",
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestHeader(c, r); err != nil {
			b.Errorf("parseRequestHeader() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_string(b *testing.B) {
	c := New()
	r := c.R()
	r.SetBody("foo").SetContentLength(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_byte(b *testing.B) {
	c := New()
	r := c.R()
	r.SetBody([]byte("foo")).SetContentLength(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_reader(b *testing.B) {
	c := New()
	r := c.R()
	r.SetBody(bytes.NewBufferString("foo"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_struct(b *testing.B) {
	type FooBar struct {
		Foo string `json:"foo"`
		Bar string `json:"bar"`
	}
	c := New()
	r := c.R()
	r.SetBody(FooBar{Foo: "1", Bar: "2"}).SetContentLength(true).SetHeader(hdrContentTypeKey, jsonContentType)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_struct_xml(b *testing.B) {
	type FooBar struct {
		Foo string `xml:"foo"`
		Bar string `xml:"bar"`
	}
	c := New()
	r := c.R()
	r.SetBody(FooBar{Foo: "1", Bar: "2"}).SetContentLength(true).SetHeader(hdrContentTypeKey, "text/xml")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_map(b *testing.B) {
	c := New()
	r := c.R()
	r.SetBody(map[string]string{
		"foo": "1",
		"bar": "2",
	}).SetContentLength(true).SetHeader(hdrContentTypeKey, jsonContentType)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_slice(b *testing.B) {
	c := New()
	r := c.R()
	r.SetBody([]string{"1", "2"}).SetContentLength(true).SetHeader(hdrContentTypeKey, jsonContentType)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_FormData(b *testing.B) {
	c := New()
	r := c.R()
	c.SetFormData(map[string]string{"foo": "1", "bar": "2"})
	r.SetFormData(map[string]string{"foo": "3", "baz": "4"}).SetContentLength(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

func Benchmark_parseRequestBody_MultiPart(b *testing.B) {
	c := New()
	r := c.R()
	c.SetFormData(map[string]string{"foo": "1", "bar": "2"})
	r.SetFormData(map[string]string{"foo": "3", "baz": "4"}).
		SetMultipartFormData(map[string]string{"foo": "5", "xyz": "6"}).
		SetFileReader("qwe", "qwe.txt", strings.NewReader("7")).
		SetMultipartFields(
			&MultipartField{
				Name:        "sdj",
				ContentType: "text/plain",
				Reader:      strings.NewReader("8"),
			},
		).
		SetContentLength(true).
		SetMethod(MethodPost)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}
