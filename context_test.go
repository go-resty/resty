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
	assertEqual(t, http.StatusBadRequest, resp.StatusCode())
	assertEqual(t, "", resp.String())

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
		n, err := w.Write([]byte("TestSetContextCancel: response"))
		// FIXME? test server doesn't handle request cancellation
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
		n, err := w.Write([]byte("TestSetContextCancel: response"))
		// FIXME? test server doesn't handle request cancellation
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
		n, err := w.Write([]byte("TestSetContextCancelWithError: response"))
		// FIXME? test server doesn't handle request cancellation
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
	assertEqual(t, true, errors.Is(err, context.DeadlineExceeded))
}

func TestRequestContext(t *testing.T) {
	client := dcnl()
	r := client.NewRequest()
	assertNotNil(t, r.Context())

	r.SetContext(context.Background())
	assertNotNil(t, r.Context())
}

func errIsContextCanceled(err error) bool {
	return errors.Is(err, context.Canceled)
}
