// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	resty "resty.dev/v3"
)

func TestRequestCloneIsolatesRetryConditions(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := resty.New()
	defer client.Close()
	parent := client.R().SetRetryCount(1).SetRetryWaitTime(time.Microsecond)
	neverRetry := func(*resty.Response, error) bool { return false }
	for i := 0; i < 3; i++ {
		parent.AddRetryConditions(neverRetry)
	}
	clone := parent.Clone(context.Background())
	clone.AddRetryConditions(func(response *resty.Response, err error) bool {
		return err == nil && response.StatusCode() == http.StatusServiceUnavailable
	})
	parent.AddRetryConditions(neverRetry)

	response, err := clone.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || response.StatusCode() != http.StatusOK {
		t.Fatalf("cloned request: attempts=%d, status=%d; want 2 attempts and 200", attempts, response.StatusCode())
	}
}

func TestRequestCloneIsolatesRetryHooks(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := resty.New()
	defer client.Close()
	parent := client.R().SetRetryCount(1).SetRetryWaitTime(time.Microsecond).
		AddRetryConditions(func(response *resty.Response, err error) bool {
			return err == nil && response.StatusCode() == http.StatusServiceUnavailable
		})
	for i := 0; i < 3; i++ {
		parent.AddRetryHooks(func(*resty.Response, error) {})
	}
	clone := parent.Clone(context.Background())
	parentCalls, cloneCalls := 0, 0
	clone.AddRetryHooks(func(*resty.Response, error) { cloneCalls++ })
	parent.AddRetryHooks(func(*resty.Response, error) { parentCalls++ })

	if _, err := clone.Get(server.URL); err != nil {
		t.Fatal(err)
	}
	if cloneCalls != 1 || parentCalls != 0 {
		t.Fatalf("clone hook calls=%d, parent hook calls=%d; want 1 and 0", cloneCalls, parentCalls)
	}
}
