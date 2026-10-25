// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"testing"
)

// Benchmark the complete request path, including encoding and buffer cleanup.
// The synchronous transport consumes the body and returns an empty response,
// so network latency is excluded.
func BenchmarkExecuteBody(b *testing.B) {
	for _, kind := range []string{"bytes", "string", "json", "form", "reader"} {
		for _, size := range []int{1024, 16384, 1 << 20} {
			b.Run(kind+"/"+strconv.Itoa(size), func(b *testing.B) {
				data := bytes.Repeat([]byte("x"), size)
				value := string(data)
				object := map[string]string{"value": value}
				client := New().SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
					_, err := io.Copy(io.Discard, req.Body)
					closeErr := req.Body.Close()
					if err != nil {
						return nil, err
					}
					if closeErr != nil {
						return nil, closeErr
					}
					return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
				}))
				defer client.Close()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					req := client.R().SetRetryCount(0)
					switch kind {
					case "bytes":
						req.SetHeader("Content-Type", "application/octet-stream").SetBody(data)
					case "string":
						req.SetHeader("Content-Type", "application/octet-stream").SetBody(value)
					case "json":
						req.SetHeader("Content-Type", "application/json").SetBody(object)
					case "form":
						req.SetFormData(object)
					case "reader":
						req.SetHeader("Content-Type", "application/octet-stream").SetBody(bytes.NewReader(data))
					}
					response, err := req.Post("http://resty.test/body")
					if err != nil {
						b.Fatal(err)
					}
					if response.Body != nil {
						if err = response.Body.Close(); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}
