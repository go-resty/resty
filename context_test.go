// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// 2016 Andrew Grigorev (https://github.com/ei-grad)
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientSetContext(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dcnl()

	assertNil(t, c.Context())

	c.SetContext(context.Background())

	resp, err := c.R().Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
}

func TestRequestSetContext(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcnl().R().
		SetContext(context.Background()).
		Get(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "200 OK", resp.Status())
	assertEqual(t, "TestGet: text response", resp.String())

	logResponse(t, resp)
}

func TestSetContextWithError(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	resp, err := dcnlr().
		SetContext(context.Background()).
		Get(ts.URL + "/mypage")

	assertError(t, err)
	assertEqual(t, http.StatusBadRequest, resp.StatusCode(), "expected bad request status code")
	assertEqual(t, "", resp.String(), "expected empty response body on bad request")

	logResponse(t, resp)
}

func TestSetContextCancel(t *testing.T) {
	ch := make(chan struct{})
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			ch <- struct{}{} // tell test request is finished
		}()
		t.Logf("Server: %v %v", r.Method, r.URL.Path)
		ch <- struct{}{}
		<-ch // wait for client to finish request
		select {
		case <-r.Context().Done():
			t.Log("Server: context cancelled, aborting write")
			return
		default:
		}
		n, err := w.Write([]byte("TestSetContextCancel: response"))
		t.Logf("Server: wrote %d bytes", n)
		t.Logf("Server: err is %v ", err)
	})
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-ch // wait for server to start request handling
		cancel()
	}()

	_, err := dcnl().R().
		SetContext(ctx).
		Get(ts.URL + "/")

	ch <- struct{}{} // tell server to continue request handling

	<-ch // wait for server to finish request handling

	t.Logf("Error: %v", err)
	if !errIsContextCanceled(err) {
		t.Errorf("Got unexpected error: %v", err)
	}
}

func TestSetContextCancelRetry(t *testing.T) {
	reqCount := 0
	ch := make(chan struct{})
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		defer func() {
			ch <- struct{}{} // tell test request is finished
		}()
		t.Logf("Server: %v %v", r.Method, r.URL.Path)
		ch <- struct{}{}
		<-ch // wait for client to finish request
		select {
		case <-r.Context().Done():
			t.Log("Server: context cancelled, aborting write")
			return
		default:
		}
		n, err := w.Write([]byte("TestSetContextCancel: response"))
		t.Logf("Server: wrote %d bytes", n)
		t.Logf("Server: err is %v ", err)
	})
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-ch // wait for server to start request handling
		cancel()
	}()

	c := dcnl().
		SetTimeout(time.Second * 3).
		SetRetryCount(3)

	_, err := c.R().
		SetContext(ctx).
		Get(ts.URL + "/")

	ch <- struct{}{} // tell server to continue request handling

	<-ch // wait for server to finish request handling

	t.Logf("Error: %v", err)
	if !errIsContextCanceled(err) {
		t.Errorf("Got unexpected error: %v", err)
	}

	if reqCount != 1 {
		t.Errorf("Request was retried %d times instead of 1", reqCount)
	}
}

func TestSetContextCancelWithError(t *testing.T) {
	ch := make(chan struct{})
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			ch <- struct{}{} // tell test request is finished
		}()
		t.Logf("Server: %v %v", r.Method, r.URL.Path)
		t.Log("Server: sending StatusBadRequest response")
		w.WriteHeader(http.StatusBadRequest)
		ch <- struct{}{}
		<-ch // wait for client to finish request
		select {
		case <-r.Context().Done():
			t.Log("Server: context cancelled, aborting write")
			return
		default:
		}
		n, err := w.Write([]byte("TestSetContextCancelWithError: response"))
		t.Logf("Server: wrote %d bytes", n)
		t.Logf("Server: err is %v ", err)
	})
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-ch // wait for server to start request handling
		cancel()
	}()

	_, err := dcnl().R().
		SetContext(ctx).
		Get(ts.URL + "/")

	ch <- struct{}{} // tell server to continue request handling

	<-ch // wait for server to finish request handling

	t.Logf("Error: %v", err)
	if !errIsContextCanceled(err) {
		t.Errorf("Got unexpected error: %v", err)
	}
}

func TestClientRetryWithSetContext(t *testing.T) {
	var attempt int32
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Method: %v", r.Method)
		t.Logf("Path: %v", r.URL.Path)
		if atomic.AddInt32(&attempt, 1) <= 4 {
			time.Sleep(100 * time.Millisecond)
		}
		_, _ = w.Write([]byte("TestClientRetry page"))
	})
	defer ts.Close()

	c := dcnl().
		SetTimeout(50 * time.Millisecond).
		SetRetryCount(3)

	_, err := c.R().
		SetContext(context.Background()).
		Get(ts.URL + "/")

	assertNotNil(t, ts)
	assertNotNil(t, err)
	assertErrorIs(t, context.DeadlineExceeded, err, "expected context deadline exceeded error")
}

func TestRequestContext(t *testing.T) {
	client := dcnl()
	r := client.NewRequest()
	assertNotNil(t, r.Context(), "expected default context to be non-nil")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.SetContext(ctx)
	assertEqual(t, ctx, r.Context(), "expected context to be set")
}

func TestSSESourceContext(t *testing.T) {
	es := NewSSESource()
	assertNotNil(t, es.Context(), "expected default context to be non-nil")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	es.SetContext(ctx)
	assertEqual(t, ctx, es.Context(), "expected context to be set")
}

func TestSSESourceSetContextCancelBeforeConnect(t *testing.T) {
	var count int32
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := NewSSESource().
		SetURL(ts.URL).
		SetContext(ctx).
		OnMessage(func(any) {}, nil).
		Get()

	assertErrorIs(t, context.Canceled, err, "expected canceled context to stop before connect")
	assertEqual(t, int32(0), atomic.LoadInt32(&count), "expected no request to be sent")
}

func TestSSESourceSetContextCancel(t *testing.T) {
	canceled := make(chan struct{}, 1)
	var count int32

	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		_, err := w.Write([]byte("id: 1\ndata: test\n\n"))
		assertNil(t, err)
		assertNil(t, http.NewResponseController(w).Flush())

		<-r.Context().Done()
		canceled <- struct{}{}
	})
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	received := 0

	err := NewSSESource().
		SetURL(ts.URL).
		SetRetryCount(0).
		SetContext(ctx).
		OnMessage(func(any) {
			received++
			cancel()
		}, nil).
		Get()

	assertErrorIs(t, context.Canceled, err, "expected canceled context while listening to stream")
	assertEqual(t, 1, received, "expected one event before cancellation")
	assertEqual(t, int32(1), atomic.LoadInt32(&count), "expected a single request")

	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("expected request context to be canceled on the server")
	}
}

func errIsContextCanceled(err error) bool {
	return errors.Is(err, context.Canceled)
}
