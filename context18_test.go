// +build go1.8

// Copyright (c) 2015-2019 Jeevanandam M (jeeva@myjeeva.com)
// 2016 Andrew Grigorev (https://github.com/ei-grad)
// All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"context"
	"net/url"
	"testing"
)

func TestRequestContext(t *testing.T) {
	r := NewRequest()
	assertNotNil(t, r.Context())

	r.SetContext(context.Background())
	assertNotNil(t, r.Context())
}

func errIsContextCanceled(err error) bool {
	ue, ok := err.(*url.Error)
	if !ok {
		return false
	}
	return ue.Err == context.Canceled
}
