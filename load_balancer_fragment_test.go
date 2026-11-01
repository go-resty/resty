// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// SPDX-License-Identifier: MIT

package resty

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoadBalancerDiscardsBaseURLFragment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.RequestURI))
	}))
	defer server.Close()
	for _, suffix := range []string{"/ignored?old=value#section", "/ignored#encoded%2Fsection", "/ignored?", "/ignored?old=value"} {
		t.Run(suffix, func(t *testing.T) {
			lb, err := NewRoundRobin(server.URL + suffix)
			if err != nil {
				t.Fatal(err)
			}
			client := New().SetLoadBalancer(lb)
			defer client.Close()
			response, err := client.R().Get("/requested?new=value")
			if err != nil {
				t.Fatal(err)
			}
			if got := response.String(); got != "/requested?new=value" {
				t.Fatalf("server received %q; want requested path and query", got)
			}
		})
	}
}
