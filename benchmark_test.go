// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"strings"
	"testing"
	"time"
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
	r.SetBody("foo")
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
	r.SetBody([]byte("foo"))
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
	r.SetBody(FooBar{Foo: "1", Bar: "2"}).SetHeader(hdrContentTypeKey, jsonContentType)
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
	r.SetBody(FooBar{Foo: "1", Bar: "2"}).SetHeader(hdrContentTypeKey, "text/xml")
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
	}).SetHeader(hdrContentTypeKey, jsonContentType)
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
	r.SetBody([]string{"1", "2"}).SetHeader(hdrContentTypeKey, jsonContentType)
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
	r.SetFormData(map[string]string{"foo": "3", "baz": "4"})
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
		SetMethod(MethodPost)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := parseRequestBody(c, r); err != nil {
			b.Errorf("parseRequestBody() error = %v", err)
		}
	}
}

// benchmarkStringer implements fmt.Stringer for benchmarking
type benchmarkStringer struct {
	value string
}

func (s benchmarkStringer) String() string {
	return s.value
}

// Tier 1: most common URL types
func Benchmark_formatAnyToString_string(b *testing.B) {
	v := "hello world"
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_int(b *testing.B) {
	v := 12345
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_bool(b *testing.B) {
	v := true
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_int64(b *testing.B) {
	v := int64(9223372036854775807)
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_stringSlice(b *testing.B) {
	v := []string{"a", "b", "c"}
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

// Tier 2: common stdlib types
func Benchmark_formatAnyToString_time(b *testing.B) {
	v := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_byteSlice(b *testing.B) {
	v := []byte("binary data")
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_float64(b *testing.B) {
	v := 3.14159265359
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

// Tier 3: less common integers (signed)
func Benchmark_formatAnyToString_int32(b *testing.B) {
	v := int32(2147483647)
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_int16(b *testing.B) {
	v := int16(32767)
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_int8(b *testing.B) {
	v := int8(127)
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

// Tier 4: less common integers (unsigned)
func Benchmark_formatAnyToString_uint64(b *testing.B) {
	v := uint64(18446744073709551615)
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_uint32(b *testing.B) {
	v := uint32(4294967295)
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_uint16(b *testing.B) {
	v := uint16(65535)
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_uint8(b *testing.B) {
	v := uint8(255)
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_uint(b *testing.B) {
	v := uint(12345)
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

// Tier 5: rare types and fallbacks
func Benchmark_formatAnyToString_float32(b *testing.B) {
	v := float32(3.14)
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_stringer(b *testing.B) {
	v := benchmarkStringer{value: "custom value"}
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}

func Benchmark_formatAnyToString_default(b *testing.B) {
	v := struct{ Name string }{Name: "test"}
	for i := 0; i < b.N; i++ {
		_ = formatAnyToString(v)
	}
}
