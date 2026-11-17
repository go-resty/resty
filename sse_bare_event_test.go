// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// A field without a colon has an empty value. A bare event field therefore
// clears the event type set by an earlier event field in the same block.
func TestSSESourceBareEventField(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		for _, tc := range []struct {
			name   string
			fields []string
			want   string
		}{
			{name: "bare resets named event", fields: []string{"event: custom", "event"}},
			{name: "bare resets repeated named event", fields: []string{"event: first", "event: custom", "event"}},
			{name: "colon resets named event", fields: []string{"event: custom", "event:"}},
			{name: "bare default event", fields: []string{"event"}},
			{name: "named event after bare", fields: []string{"event", "event: custom"}, want: "custom"},
			{name: "unrelated field", fields: []string{"event: custom", "events"}, want: "custom"},
			{name: "case sensitive field", fields: []string{"event: custom", "Event"}, want: "custom"},
			{name: "leading space is significant", fields: []string{"event: custom", " event"}, want: "custom"},
		} {
			t.Run(tc.name+"/"+strings.ReplaceAll(strings.ReplaceAll(ending, "\r", "CR"), "\n", "LF"), func(t *testing.T) {
				es := NewSSESource()
				var got []SSE
				collect := func(value any) { got = append(got, *value.(*SSE)) }
				es.OnMessage(collect, nil)
				es.AddEventListener("custom", collect, nil)
				es.AddEventListener("first", collect, nil)
				stream := strings.Join(append(tc.fields, "data: payload", "", ""), ending)
				res := &http.Response{Body: io.NopCloser(strings.NewReader(stream))}

				assertErrorIs(t, io.EOF, es.listenStream(res))
				assertEqual(t, []SSE{{Name: tc.want, Data: "payload"}}, got)
			})
		}
	}
}
