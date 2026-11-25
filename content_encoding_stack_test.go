// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResponseContentEncodingEmptyElements(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []string
		gzip    bool
	}{
		{"empty header after gzip", []string{"gzip", ""}, true},
		{"only empty headers", []string{"", ""}, false},
		{"trailing comma", []string{"gzip,"}, true},
		{"leading comma", []string{", gzip"}, true},
		{"empty members with whitespace", []string{" ,\t, gzip, ,\t"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte("response body")
			if tc.gzip {
				body = stackGzipBody(t, body, 1)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for _, value := range tc.headers {
					w.Header().Add("Content-Encoding", value)
				}
				_, _ = w.Write(body)
			}))
			defer server.Close()
			client := New()
			defer client.Close()
			response, err := client.R().Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			if got := response.String(); got != "response body" {
				t.Fatalf("decoded body = %q", got)
			}
		})
	}
}

func TestResponseContentEncodingDepthLimit(t *testing.T) {
	for _, depth := range []int{5, 6, 100} {
		for _, separateHeaders := range []bool{false, true} {
			for _, doNotParse := range []bool{false, true} {
				name := fmt.Sprintf("depth=%d/separate_headers=%t/do_not_parse=%t", depth, separateHeaders, doNotParse)
				t.Run(name, func(t *testing.T) {
					body := stackGzipBody(t, []byte("response body"), depth)
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						if separateHeaders {
							for i := 0; i < depth; i++ {
								w.Header().Add("Content-Encoding", "gzip")
							}
						} else {
							w.Header().Set("Content-Encoding", strings.Repeat("gzip,", depth-1)+"gzip")
						}
						_, _ = w.Write(body)
					}))
					defer server.Close()
					client := New().SetResponseBodyLimit(1 << 20)
					defer client.Close()
					decoders := 0
					client.AddContentDecompresser("gzip", func(r io.ReadCloser) (io.ReadCloser, error) {
						decoders++
						return decompressGzip(r)
					})
					response, err := client.R().SetResponseDoNotParse(doNotParse).Get(server.URL)
					if depth > 5 && !doNotParse {
						if err != ErrContentDecompresserNotFound {
							t.Errorf("over-limit error = %v", err)
						}
						if response != nil && response.Body != nil {
							_ = response.Body.Close()
						}
					} else {
						if err != nil {
							t.Fatal(err)
						}
						got := response.Bytes()
						if doNotParse {
							defer response.Body.Close()
							got, err = io.ReadAll(response.Body)
							if err != nil {
								t.Fatal(err)
							}
						}
						want := []byte("response body")
						if depth > 5 {
							want = body
						}
						if !bytes.Equal(got, want) {
							t.Errorf("response body was not preserved or decoded as expected")
						}
					}
					wantDecoders := depth
					if depth > 5 {
						wantDecoders = 0
					}
					if decoders != wantDecoders {
						t.Errorf("created %d decoders, want %d", decoders, wantDecoders)
					}
				})
			}
		}
	}
}

func stackGzipBody(t *testing.T, body []byte, depth int) []byte {
	t.Helper()
	for i := 0; i < depth; i++ {
		var encoded bytes.Buffer
		writer := gzip.NewWriter(&encoded)
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		body = encoded.Bytes()
	}
	return body
}

func TestResponseStackedContentEncoding(t *testing.T) {
	for _, tc := range []struct {
		name    string
		codings []string
		headers []string
	}{
		{"same coding twice", []string{"gzip", "gzip"}, []string{"gzip, gzip"}},
		{"different codings", []string{"gzip", "deflate"}, []string{"GZip, Deflate"}},
		{"separate header lines", []string{"deflate", "gzip"}, []string{"deflate", "gzip"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"name":"stacked response"}`)
			for _, coding := range tc.codings {
				var encoded bytes.Buffer
				var writer io.WriteCloser
				if coding == "gzip" {
					writer = gzip.NewWriter(&encoded)
				} else {
					writer = zlib.NewWriter(&encoded)
				}
				if _, err := writer.Write(data); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				data = encoded.Bytes()
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				for _, value := range tc.headers {
					w.Header().Add("Content-Encoding", value)
				}
				_, _ = w.Write(data)
			}))
			defer server.Close()
			client := New()
			defer client.Close()
			var result struct{ Name string }
			response, err := client.R().SetResult(&result).Get(server.URL)
			if err != nil {
				t.Fatalf("decode %s: %v", strings.Join(tc.headers, ", "), err)
			}
			if result.Name != "stacked response" {
				t.Fatalf("decoded result = %#v", result)
			}
			if got := response.Header().Get("Content-Encoding"); got != "" {
				t.Fatalf("decoded response still declares encoding %q", got)
			}
		})
	}
}

func TestResponseStackedUnsupportedContentEncoding(t *testing.T) {
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	if _, err := writer.Write([]byte("caller-managed body")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "unsupported, gzip")
		_, _ = w.Write(encoded.Bytes())
	}))
	defer server.Close()
	client := New()
	defer client.Close()

	if _, err := client.R().Get(server.URL); err != ErrContentDecompresserNotFound {
		t.Fatalf("unsupported encoding error = %v", err)
	}
	response, err := client.R().SetResponseDoNotParse(true).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, encoded.Bytes()) {
		t.Fatal("unsupported encoding stack was partially decoded")
	}
	if got := response.Header().Get("Content-Encoding"); got != "unsupported, gzip" {
		t.Fatalf("original encoding header = %q", got)
	}
}
