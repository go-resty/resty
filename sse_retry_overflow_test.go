// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSSESourceRetryDurationOverflow(t *testing.T) {
	for _, tt := range []struct {
		name  string
		retry string
		want  time.Duration
	}{
		{"zero", "0", 0},
		{"milliseconds", "250", 250 * time.Millisecond},
		{"above 32-bit integer", "2147483648", 2147483648 * time.Millisecond},
		{"largest whole milliseconds", "9223372036854", 9223372036854 * time.Millisecond},
		{"first overflowing milliseconds", "9223372036855", time.Duration(math.MaxInt64)},
		{"overflow wraps positive", "18446744073710", time.Duration(math.MaxInt64)},
		{"largest signed integer", "9223372036854775807", time.Duration(math.MaxInt64)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := NewSSESource()
			source.serverSentRetry = time.Second
			var messages []string
			var parseErrors []error
			source.OnMessage(func(value any) {
				messages = append(messages, value.(*SSE).Data)
			}, nil)
			source.OnError(func(err error) { parseErrors = append(parseErrors, err) })
			response := &http.Response{Body: io.NopCloser(strings.NewReader(
				"retry: " + tt.retry + "\ndata: message\n\n",
			))}

			assertErrorIs(t, io.EOF, source.listenStream(response))
			assertEqual(t, tt.want, source.serverSentRetry)
			assertEqual(t, []string{"message"}, messages)
			assertEqual(t, 0, len(parseErrors))
		})
	}
}
