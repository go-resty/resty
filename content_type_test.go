// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestContentTypeParametersDoNotOverrideResponseDecoder(t *testing.T) {
	type result struct {
		Message string `json:"message" xml:"message"`
	}
	for _, tc := range []struct {
		name        string
		contentType string
		body        string
		want        string
		statusCode  int
		globalError bool
	}{
		{"XML with JSON parameter", "application/xml; profile=json", "<result><message>hello</message></result>", "hello", http.StatusOK, false},
		{"XML with mixed case and quoted parameter", "Application/XML; profile=\"https://example.com/JSON;v=1\"", "<result><message>hello</message></result>", "hello", http.StatusOK, false},
		{"JSON with XML parameter", "application/json; profile=xml", `{"message":"hello"}`, "hello", http.StatusOK, false},
		{"request error with JSON parameter", "application/xml; profile=json", "<result><message>hello</message></result>", "hello", http.StatusBadRequest, false},
		{"client error with JSON parameter", "application/xml; profile=json", "<result><message>hello</message></result>", "hello", http.StatusInternalServerError, true},
		{"plain text with JSON parameter", "text/plain; format=json", "plain text", "", http.StatusOK, false},
		{"plain text with XML parameter", "text/plain; format=xml", "plain text", "", http.StatusOK, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(hdrContentTypeKey, tc.contentType)
				w.WriteHeader(tc.statusCode)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer ts.Close()
			c := dcnl()
			defer c.Close()
			var got result
			req := c.R()
			if tc.globalError {
				c.SetResultError(result{})
			} else if tc.statusCode >= http.StatusBadRequest {
				req.SetResultError(&got)
			} else {
				req.SetResult(&got)
			}
			res, err := req.Get(ts.URL)
			if err != nil {
				t.Fatal(err)
			}
			if tc.globalError {
				got = *res.ResultError().(*result)
			}
			assertEqual(t, tc.want, got.Message)
			if tc.want == "" {
				assertEqual(t, tc.body, res.String())
			}
		})
	}
}

func TestContentTypeParametersDoNotOverrideRequestEncoder(t *testing.T) {
	type payload struct {
		Message string `json:"message" xml:"message"`
	}
	bodies := make(chan []byte, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- body
		_, _ = io.WriteString(w, "ok")
	}))
	defer ts.Close()
	c := dcnl()
	defer c.Close()
	_, err := c.R().SetHeader(hdrContentTypeKey, "application/xml; profile=json").
		SetBody(payload{Message: "hello"}).Post(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	var got payload
	err = xml.Unmarshal(<-bodies, &got)
	assertError(t, err)
	assertEqual(t, "hello", got.Message)
}

func TestContentTypeParametersPreserveRegisteredDecoder(t *testing.T) {
	const contentType = "application/xml; profile=json"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(hdrContentTypeKey, contentType)
		_, _ = io.WriteString(w, "custom body")
	}))
	defer ts.Close()
	c := dcnl().AddContentTypeDecoder(contentType, func(r io.Reader, v any) error {
		body, err := io.ReadAll(r)
		*v.(*string) = string(body)
		return err
	})
	defer c.Close()
	var got string
	_, err := c.R().SetResult(&got).Get(ts.URL)
	assertError(t, err)
	assertEqual(t, "custom body", got)
}
