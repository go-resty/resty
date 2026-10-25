// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"testing"
)

func BenchmarkCreateRawRequestBody(b *testing.B) {
	for _, size := range []struct {
		name string
		n    int
	}{{"1KiB", 1 << 10}, {"16KiB", 16 << 10}, {"1MiB", 1 << 20}} {
		for _, buffered := range []bool{true, false} {
			name := "reader/"
			if buffered {
				name = "buffered/"
			}
			b.Run(name+size.name, func(b *testing.B) {
				client := New()
				defer client.Close()
				payload := bytes.Repeat([]byte("x"), size.n)
				request := client.R()
				request.Method, request.URL = MethodPost, "http://resty.test/body"
				if buffered {
					request.bodyBuf = bytes.NewBuffer(payload)
				} else {
					request.Body = bytes.NewReader(payload)
				}
				b.ReportAllocs()
				b.SetBytes(int64(size.n))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := createRawRequest(client, request); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
