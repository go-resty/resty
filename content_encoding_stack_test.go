// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
