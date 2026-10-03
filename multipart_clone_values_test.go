// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	resty "resty.dev/v3"
)

func TestMultipartFieldCloneValuesHTTP(t *testing.T) {
	for _, requestClone := range []bool{false, true} {
		name := "field"
		if requestClone {
			name = "request"
		}
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseMultipartForm(4096); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				defer r.MultipartForm.RemoveAll()
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(r.MultipartForm.Value["tag"]); err != nil {
					t.Error(err)
				}
			}))
			defer ts.Close()
			c := resty.New().SetTimeout(5 * time.Second)
			defer c.Close()
			source := &resty.MultipartField{Name: "tag", Values: []string{"first", "second"}}
			original := c.R().SetMultipartFields(source)
			var cloned *resty.Request
			if requestClone {
				cloned = original.Clone(context.Background())
			} else {
				copied := source.Clone()
				// Changing the clone must not change the source, either.
				copied.Values[1] = "clone-second"
				if source.Values[1] != "second" {
					t.Errorf("source changed through clone: %q", source.Values)
				}
				copied.Values[1] = "second"
				cloned = c.R().SetMultipartFields(copied)
			}
			source.Values[0] = "source-first"
			for _, tt := range []struct {
				name string
				req  *resty.Request
				want []string
			}{
				{"clone", cloned, []string{"first", "second"}},
				{"source", original, []string{"source-first", "second"}},
			} {
				t.Run(tt.name, func(t *testing.T) {
					var got []string
					res, err := tt.req.SetResult(&got).Post(ts.URL)
					if err != nil {
						t.Fatal(err)
					}
					if res.StatusCode() != http.StatusOK {
						t.Fatalf("status: %d", res.StatusCode())
					}
					if !reflect.DeepEqual(got, tt.want) {
						t.Fatalf("multipart values = %q; want %q", got, tt.want)
					}
				})
			}
		})
	}
}

func TestMultipartFieldClonePreservesReaderAndEmptyValues(t *testing.T) {
	reader := strings.NewReader("payload")
	for _, values := range [][]string{nil, {}, {"one", "two"}} {
		source := &resty.MultipartField{Name: "tag", Reader: reader, Values: values}
		copied := source.Clone()
		if copied == source || copied.Reader != reader || !reflect.DeepEqual(copied.Values, values) {
			t.Fatalf("clone does not preserve field metadata and shared reader: %#v", copied)
		}
	}
}
