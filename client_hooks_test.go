// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"errors"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestClientHookGetterWithPendingWriter(t *testing.T) {
	for _, tc := range []struct {
		name     string
		register func(*Client, func())
		invoke   func(*Client)
	}{
		{"success", func(c *Client, h func()) { c.OnSuccess(func(*Client, *Response) { h() }) }, func(c *Client) { c.onErrorHooks(nil, &Response{}, nil) }},
		{"error", func(c *Client, h func()) { c.OnError(func(*Request, error) { h() }) }, func(c *Client) { c.onErrorHooks(nil, nil, errors.New("request error")) }},
		{"invalid", func(c *Client, h func()) { c.OnInvalid(func(*Request, error) { h() }) }, func(c *Client) { c.onInvalidHooks(nil, errors.New("invalid request")) }},
		{"panic", func(c *Client, h func()) { c.OnPanic(func(*Request, error) { h() }) }, func(c *Client) { c.onPanicHooks(nil, errors.New("request panic")) }},
		{"close", func(c *Client, h func()) { c.OnClose(h) }, func(c *Client) { c.onCloseHooks() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New().SetBaseURL("https://example.test")
			entered := make(chan struct{})
			read := make(chan struct{})
			done := make(chan struct{})
			tc.register(c, func() {
				close(entered)
				<-read
				_ = c.BaseURL()
			})
			go func() { tc.invoke(c); close(done) }()
			<-entered
			writerDone := make(chan struct{})
			go func() { c.SetHeader("X-Config", "updated"); close(writerDone) }()
		waitForWriter:
			for {
				if !c.lock.TryRLock() {
					break
				}
				c.lock.RUnlock()
				select {
				case <-writerDone:
					break waitForWriter
				default:
					runtime.Gosched()
				}
			}
			close(read)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("read-only client getter deadlocked in callback while another goroutine waited to update the client")
			}
			<-writerDone
		})
	}
}

func TestClientCloseHookCanRepeatClose(t *testing.T) {
	c := New()
	done := make(chan struct{})
	c.OnClose(func() { _ = c.Close() })
	go func() { _ = c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idempotent Close deadlocked when called from a close hook")
	}
}

func TestClientHookRegistrationDuringDispatch(t *testing.T) {
	c := New()
	var calls []int
	added := false
	c.OnSuccess(func(c *Client, _ *Response) {
		calls = append(calls, 1)
		if !added {
			added = true
			c.OnSuccess(func(*Client, *Response) { calls = append(calls, 3) })
		}
	}, func(*Client, *Response) { calls = append(calls, 2) })
	c.onErrorHooks(nil, &Response{}, nil)
	if !reflect.DeepEqual(calls, []int{1, 2}) {
		t.Fatalf("first dispatch called hooks %v, want [1 2]", calls)
	}
	c.onErrorHooks(nil, &Response{}, nil)
	if !reflect.DeepEqual(calls, []int{1, 2, 1, 2, 3}) {
		t.Fatalf("second dispatch called hooks %v, want [1 2 1 2 3]", calls)
	}
}
