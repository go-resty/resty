// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBufferedRequestBodyOutlivesExecute(t *testing.T) {
	transportErr := errors.New("round trip failed")
	for _, body := range []struct {
		name      string
		configure func(*Request)
		want      string
	}{
		{"bytes", func(r *Request) { r.SetBody([]byte("request payload")) }, "request payload"},
		{"string", func(r *Request) { r.SetBody("request payload") }, "request payload"},
		{"json", func(r *Request) { r.SetBody(map[string]string{"value": "payload"}) }, `{"value":"payload"}`},
		{"form", func(r *Request) { r.SetFormData(map[string]string{"value": "payload"}) }, "value=payload"},
		{"reader", func(r *Request) { r.SetBody(strings.NewReader("request payload")) }, "request payload"},
	} {
		for _, outcome := range []struct {
			name   string
			status int
			err    error
			cancel bool
		}{
			{name: "response", status: http.StatusOK},
			{name: "rejection", status: http.StatusUnprocessableEntity},
			{name: "transport_error", err: transportErr},
			{name: "canceled", err: context.Canceled, cancel: true},
		} {
			t.Run(body.name+"/"+outcome.name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var upload io.ReadCloser
				t.Cleanup(func() {
					if upload != nil {
						_ = upload.Close()
					}
				})
				client := New().SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
					// RoundTripper may retain and close the request body after returning.
					upload = request.Body
					if outcome.cancel {
						cancel()
					}
					if outcome.err != nil {
						return nil, outcome.err
					}
					return &http.Response{StatusCode: outcome.status, Body: http.NoBody, Request: request}, nil
				}))
				defer client.Close()
				request := client.R().SetContext(ctx).SetRetryCount(0)
				body.configure(request)
				_, err := request.Post("http://resty.test/body")
				if !errors.Is(err, outcome.err) {
					t.Fatalf("request error = %v, want %v", err, outcome.err)
				}
				if upload == nil {
					t.Fatal("transport did not receive a body")
				}
				got, err := io.ReadAll(upload)
				if err != nil {
					t.Fatal(err)
				}
				if strings.TrimSpace(string(got)) != body.want {
					t.Fatalf("body after Execute = %q, want %q", got, body.want)
				}
			})
		}
	}
}

func TestCreateRawRequestKeepsBodyAndReplayIndependentOfBuffer(t *testing.T) {
	for _, payload := range []string{"", "original payload"} {
		t.Run(strconv.Itoa(len(payload)), func(t *testing.T) {
			client := New()
			defer client.Close()
			buffer := bytes.NewBufferString(payload)
			request := client.R()
			request.Method, request.URL = MethodPost, "http://resty.test/body"
			request.bodyBuf = buffer
			if err := createRawRequest(client, request); err != nil {
				t.Fatal(err)
			}
			if request.RawRequest.ContentLength != int64(len(payload)) {
				t.Fatalf("ContentLength = %d, want %d", request.RawRequest.ContentLength, len(payload))
			}
			if payload == "" && request.RawRequest.Body != http.NoBody {
				t.Fatal("empty buffered body must remain http.NoBody")
			}
			// Reuse the original storage without depending on sync.Pool scheduling.
			buffer.Reset()
			buffer.WriteString("recycled payload")
			readers := []io.ReadCloser{request.RawRequest.Body}
			if request.RawRequest.GetBody == nil {
				t.Fatal("buffered request must support replay")
			}
			for range 2 {
				replay, err := request.RawRequest.GetBody()
				if err != nil {
					t.Fatal(err)
				}
				readers = append(readers, replay)
			}
			for index, reader := range readers {
				got, err := io.ReadAll(reader)
				_ = reader.Close()
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != payload {
					t.Errorf("reader %d = %q, want %q", index, got, payload)
				}
			}
		})
	}
}

func TestCreateRawRequestBodyMetadata(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       func() any
		buffered   bool
		want       string
		wantLength int64
		wantNil    bool
		wantNoBody bool
		wantReplay bool
	}{
		{name: "absent", body: func() any { return nil }, wantNil: true},
		{name: "nil bytes", body: func() any { return []byte(nil) }, wantNoBody: true, wantReplay: true},
		{name: "empty bytes", body: func() any { return []byte{} }, wantNoBody: true, wantReplay: true},
		{name: "empty string", body: func() any { return "" }, wantNoBody: true, wantReplay: true},
		{name: "empty buffer", body: func() any { return nil }, buffered: true, wantNoBody: true, wantReplay: true},
		{name: "bytes", body: func() any { return []byte("payload") }, want: "payload", wantLength: 7, wantReplay: true},
		{name: "string", body: func() any { return "payload" }, want: "payload", wantLength: 7, wantReplay: true},
		{name: "buffer", body: func() any { return "ignored input" }, buffered: true, want: "payload", wantLength: 7, wantReplay: true},
		{name: "reader", body: func() any { return strings.NewReader("payload") }, want: "payload", wantLength: 7, wantReplay: true},
		{name: "empty reader", body: func() any { return strings.NewReader("") }, wantNoBody: true, wantReplay: true},
		{name: "read closer", body: func() any { return io.NopCloser(strings.NewReader("payload")) }, want: "payload"},
		{name: "no body reader", body: func() any { return http.NoBody }, wantNoBody: true},
	} {
		for _, override := range []struct {
			name  string
			set   bool
			value int64
		}{
			{name: "inferred"},
			{name: "negative", set: true, value: -1},
			{name: "zero", set: true},
			{name: "positive", set: true, value: 99},
		} {
			t.Run(tc.name+"/"+override.name, func(t *testing.T) {
				client := New()
				defer client.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				request := client.R().SetContext(ctx).SetBody(tc.body()).SetHeader("X-Body-Test", "preserved")
				request.Method, request.URL = MethodPost, "http://resty.test/body"
				if tc.buffered {
					request.bodyBuf = bytes.NewBufferString(tc.want)
				}
				wantLength := tc.wantLength
				if override.set {
					request.SetContentLength(override.value)
					wantLength = override.value
				}
				if err := createRawRequest(client, request); err != nil {
					t.Fatal(err)
				}
				raw := request.RawRequest
				if raw.ContentLength != wantLength || request.contentLength != wantLength {
					t.Fatalf("ContentLength = %d, stored = %d, want %d", raw.ContentLength, request.contentLength, wantLength)
				}
				if (raw.Body == nil) != tc.wantNil || (raw.Body == http.NoBody) != tc.wantNoBody {
					t.Fatalf("Body = %T, want nil = %v, http.NoBody = %v", raw.Body, tc.wantNil, tc.wantNoBody)
				}
				if (raw.GetBody != nil) != tc.wantReplay {
					t.Fatalf("GetBody present = %v, want %v", raw.GetBody != nil, tc.wantReplay)
				}
				if original, ok := request.Body.(io.ReadCloser); ok && raw.Body != original {
					t.Fatal("caller-provided ReadCloser must pass through unchanged")
				}
				if raw.Context() != ctx || raw.Header.Get("X-Body-Test") != "preserved" {
					t.Fatal("request context or header changed")
				}
				var readers []io.ReadCloser
				if raw.Body != nil {
					readers = append(readers, raw.Body)
				}
				if raw.GetBody != nil {
					for range 2 {
						replay, err := raw.GetBody()
						if err != nil {
							t.Fatal(err)
						}
						if tc.wantNoBody && replay != http.NoBody {
							t.Fatal("empty replay must remain http.NoBody")
						}
						readers = append(readers, replay)
					}
				}
				for index, reader := range readers {
					got, err := io.ReadAll(reader)
					closeq(reader)
					if err != nil || string(got) != tc.want {
						t.Fatalf("reader %d = %q, %v, want %q", index, got, err, tc.want)
					}
				}
			})
		}
	}
}

func TestRequestBodyReaderInterfaces(t *testing.T) {
	for _, tc := range []struct {
		name string
		body any
	}{
		{name: "bytes", body: []byte("payload")},
		{name: "string", body: "payload"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := New()
			defer client.Close()
			request := client.R().SetBody(tc.body)
			request.Method, request.URL = MethodPost, "http://resty.test/body"
			if err := createRawRequest(client, request); err != nil {
				t.Fatal(err)
			}
			replay, err := request.RawRequest.GetBody()
			if err != nil {
				t.Fatal(err)
			}
			for index, reader := range []io.ReadCloser{request.RawRequest.Body, replay} {
				writerTo, ok := reader.(io.WriterTo)
				if !ok {
					t.Fatal("body must retain io.WriterTo")
				}
				if _, ok := reader.(io.Seeker); ok {
					t.Fatal("body must not expose the underlying reader's io.Seeker")
				}
				for range 2 {
					if err := reader.Close(); err != nil {
						t.Fatal(err)
					}
				}
				prefix := make([]byte, 3)
				if n, err := io.ReadFull(reader, prefix); n != len(prefix) || err != nil || string(prefix) != "pay" {
					t.Fatalf("reader %d prefix = %q, %d, %v", index, prefix, n, err)
				}
				pipeReader, pipeWriter := io.Pipe()
				_ = pipeReader.Close()
				n, err := writerTo.WriteTo(pipeWriter)
				_ = pipeWriter.Close()
				if n != 0 || !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("reader %d failed WriteTo = %d, %v", index, n, err)
				}
				var remainder bytes.Buffer
				n, err = writerTo.WriteTo(&remainder)
				if n != 4 || err != nil || remainder.String() != "load" {
					t.Fatalf("reader %d remainder = %q, %d, %v", index, remainder.String(), n, err)
				}
				if n, err := reader.Read(prefix); n != 0 || err != io.EOF {
					t.Fatalf("reader %d EOF = %d, %v", index, n, err)
				}
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestRequestBodyConcurrentReplayAndClose(t *testing.T) {
	payload := strings.Repeat("payload ", 4096)
	for _, tc := range []struct {
		name string
		body any
	}{
		{name: "bytes", body: []byte(payload)},
		{name: "string", body: payload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := New()
			defer client.Close()
			request := client.R().SetBody(tc.body)
			request.Method, request.URL = MethodPost, "http://resty.test/body"
			if err := createRawRequest(client, request); err != nil {
				t.Fatal(err)
			}
			raw := request.RawRequest
			var workers sync.WaitGroup
			for index := range 8 {
				workers.Add(1)
				go func() {
					defer workers.Done()
					reader := raw.Body
					if index != 0 {
						var err error
						reader, err = raw.GetBody()
						if err != nil {
							t.Error(err)
							return
						}
					}
					if err := raw.Body.Close(); err != nil {
						t.Error(err)
					}
					got, err := io.ReadAll(reader)
					closeq(reader)
					if err != nil || string(got) != payload {
						t.Errorf("reader %d body length = %d, error = %v, want %d", index, len(got), err, len(payload))
					}
				}()
			}
			workers.Wait()
		})
	}
}

func TestBufferedRequestBodyReplayOnRedirectAndRetry(t *testing.T) {
	payload := strings.Repeat("payload ", 1024)
	for _, scenario := range []struct {
		name   string
		status int
		retry  bool
		body   any
	}{
		{name: "bytes/307", status: http.StatusTemporaryRedirect, body: []byte(payload)},
		{name: "bytes/308", status: http.StatusPermanentRedirect, body: []byte(payload)},
		{name: "bytes/retry", status: http.StatusServiceUnavailable, retry: true, body: []byte(payload)},
		{name: "string/307", status: http.StatusTemporaryRedirect, body: payload},
		{name: "string/308", status: http.StatusPermanentRedirect, body: payload},
		{name: "string/retry", status: http.StatusServiceUnavailable, retry: true, body: payload},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var bodies []string
			client := New().SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(request.Body)
				_ = request.Body.Close()
				if err != nil {
					return nil, err
				}
				bodies = append(bodies, string(body))
				response := &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header), Request: request}
				if len(bodies) == 1 {
					response.StatusCode = scenario.status
					response.Header.Set("Location", "/replayed")
				}
				return response, nil
			}))
			defer client.Close()
			request := client.R().SetBody(scenario.body)
			if scenario.retry {
				request.SetRetryCount(1).SetRetryWaitTime(time.Nanosecond).SetRetryMaxWaitTime(time.Nanosecond).
					AddRetryConditions(func(response *Response, _ error) bool { return response.StatusCode() == http.StatusServiceUnavailable })
			}
			response, err := request.Put("http://resty.test/body")
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode() != http.StatusOK || len(bodies) != 2 {
				t.Fatalf("status = %d, attempts = %d", response.StatusCode(), len(bodies))
			}
			for index, body := range bodies {
				if body != payload {
					t.Errorf("attempt %d body length = %d, want %d", index+1, len(body), len(payload))
				}
			}
		})
	}
}

func TestRawInputBodyRetainsReplayAfterCallerReuse(t *testing.T) {
	for _, tc := range []struct {
		name string
		body any
		want string
	}{
		{name: "bytes", body: []byte("original payload"), want: "original payload"},
		{name: "string", body: "original payload", want: "original payload"},
		{name: "empty bytes", body: []byte{}},
		{name: "nil bytes", body: []byte(nil)},
		{name: "empty string", body: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := New().outputLogTo(io.Discard).SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: request}, nil
			}))
			defer client.Close()
			request := client.R().SetBody(tc.body).SetDebug(true).SetCurlCmdGenerate(true)
			_, err := request.Post("http://resty.test/body")
			if err != nil {
				t.Fatal(err)
			}
			switch body := request.Body.(type) {
			case []byte:
				original, ok := tc.body.([]byte)
				if !ok || !bytes.Equal(body, original) || (len(body) > 0 && &body[0] != &original[0]) {
					t.Fatal("Request.Body must retain the caller's byte slice")
				}
				clear(body)
			case string:
				if body != tc.body {
					t.Fatal("Request.Body must retain the caller's string")
				}
			default:
				t.Fatalf("Request.Body type changed to %T", request.Body)
			}
			if request.RawRequest.ContentLength != int64(len(tc.want)) {
				t.Fatalf("ContentLength = %d, want %d", request.RawRequest.ContentLength, len(tc.want))
			}
			if tc.want == "" && request.RawRequest.Body != http.NoBody {
				t.Fatal("empty input must use http.NoBody")
			}
			got, err := io.ReadAll(request.RawRequest.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("body after input reuse = %q, want %q", got, tc.want)
			}
			if err := request.RawRequest.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if request.RawRequest.GetBody == nil {
				t.Fatal("raw input must support replay")
			}
			for range 2 {
				replay, err := request.RawRequest.GetBody()
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(replay)
				closeq(replay)
				if err != nil || string(got) != tc.want {
					t.Fatalf("replay after Close = %q, %v, want %q", got, err, tc.want)
				}
			}
			if !strings.Contains(request.CurlCmd(), "-d "+cmdQuote(tc.want)) {
				t.Fatalf("curl command lost original body: %s", request.CurlCmd())
			}
		})
	}
}

func TestRequestRetryReplacesBufferedBody(t *testing.T) {
	for _, initial := range []string{"json", "form"} {
		for _, next := range []struct {
			name string
			body func() any
			want string
		}{
			{name: "bytes", body: func() any { return []byte("replacement") }, want: "replacement"},
			{name: "string", body: func() any { return "replacement" }, want: "replacement"},
			{name: "reader", body: func() any { return strings.NewReader("replacement") }, want: "replacement"},
			{name: "json", body: func() any { return map[string]string{"next": "value"} }, want: "{\"next\":\"value\"}\n"},
			{name: "empty string", body: func() any { return "" }},
			{name: "nil", body: func() any { return nil }},
		} {
			t.Run(initial+" to "+next.name, func(t *testing.T) {
				var attempts []*http.Request
				client := New().outputLogTo(io.Discard).SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
					attempts = append(attempts, request)
					return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody, Request: request}, nil
				}))
				defer client.Close()
				request := client.R().SetDebug(true).SetBody(map[string]string{"original": "value"}).
					SetRetryCount(1).SetRetryWaitTime(time.Nanosecond).SetRetryMaxWaitTime(time.Nanosecond).
					AddRetryConditions(func(*Response, error) bool { return true })
				wantFirst := "{\"original\":\"value\"}\n"
				if initial == "form" {
					request.SetFormData(map[string]string{"original": "value"})
					wantFirst = "original=value"
				}
				request.AddRetryHooks(func(*Response, error) {
					request.FormData = nil
					request.Header.Del(hdrContentTypeKey)
					request.SetBody(next.body())
				})
				if _, err := request.Put("http://resty.test/body"); err != nil {
					t.Fatal(err)
				}
				if len(attempts) != 2 {
					t.Fatalf("attempts = %d, want 2", len(attempts))
				}
				for index, want := range []string{wantFirst, next.want} {
					raw := attempts[index]
					var got []byte
					if raw.Body != nil {
						var err error
						got, err = io.ReadAll(raw.Body)
						closeq(raw.Body)
						if err != nil {
							t.Fatal(err)
						}
					}
					if string(got) != want || raw.ContentLength != int64(len(want)) {
						t.Fatalf("attempt %d body = %q, ContentLength = %d, want %q", index+1, got, raw.ContentLength, want)
					}
					if raw.GetBody != nil {
						replay, err := raw.GetBody()
						if err != nil {
							t.Fatal(err)
						}
						got, err = io.ReadAll(replay)
						closeq(replay)
						if err != nil || string(got) != want {
							t.Fatalf("attempt %d replay = %q, %v, want %q", index+1, got, err, want)
						}
					}
				}
			})
		}
	}
}

func TestRawInputCloneRetainsBodyReferenceAndIndependentReplay(t *testing.T) {
	client := New().SetTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: request}, nil
	}))
	defer client.Close()
	input := []byte("original")
	request := client.R().SetBody(input)
	if _, err := request.Post("http://resty.test/body"); err != nil {
		t.Fatal(err)
	}
	clone := request.Clone(context.Background())
	copy(input, "replaced")
	if _, err := clone.Post("http://resty.test/body"); err != nil {
		t.Fatal(err)
	}
	for index, tc := range []struct {
		request *Request
		want    string
	}{{request, "original"}, {clone, "replaced"}} {
		if got, ok := tc.request.Body.([]byte); !ok || &got[0] != &input[0] {
			t.Fatal("Clone must preserve the documented shared Body reference")
		}
		closeq(tc.request.RawRequest.Body)
		replay, err := tc.request.RawRequest.GetBody()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(replay)
		closeq(replay)
		if err != nil || string(got) != tc.want {
			t.Fatalf("request %d replay = %q, %v, want %q", index, got, err, tc.want)
		}
	}
}
