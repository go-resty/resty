// +build go1.8

// Copyright (c) 2015-2019 Jeevanandam M (jeeva@myjeeva.com)
// 2016 Andrew Grigorev (https://github.com/ei-grad)
// All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestRequestContext(t *testing.T) {
	r := NewRequest()
	assertNotNil(t, r.Context())

	r.SetContext(context.Background())
	assertNotNil(t, r.Context())
}

func TestContextWithPreRequestHook(t *testing.T) {
	ts := createGetServer(t)
	defer ts.Close()

	c := dc()
	c.SetPreRequestHook(func(cl *Client, r *Request) error {
		type ctxKey int
		var key ctxKey
		val := "test-value"
		ctx := context.WithValue(r.Context(), key, val)
		r.SetContext(ctx)
		ctxValue := r.RawRequest.Context().Value(key).(string)
		assertEqual(t, val, ctxValue)
		return nil
	})

	resp, err := c.R().Get(ts.URL)

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func errIsContextCanceled(err error) bool {
	ue, ok := err.(*url.Error)
	if !ok {
		return false
	}
	return ue.Err == context.Canceled
}
