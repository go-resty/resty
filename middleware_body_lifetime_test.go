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

func TestBufferedRequestBodyReplayOnRedirectAndRetry(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		status int
		retry  bool
	}{
		{name: "307", status: http.StatusTemporaryRedirect},
		{name: "308", status: http.StatusPermanentRedirect},
		{name: "retry", status: http.StatusServiceUnavailable, retry: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			payload := strings.Repeat("payload ", 1024)
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
			request := client.R().SetBody([]byte(payload))
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
