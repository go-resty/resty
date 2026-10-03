// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"net/http"
	"net/url"
	"testing"
)

func mustReq(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	assertNil(t, err)
	return req
}

func TestSameOrigin(t *testing.T) {
	for _, tc := range []struct {
		name   string
		a, b   string
		expect bool
	}{
		{"identical", "https://a.com/x", "https://a.com/y", true},
		{"case-insensitive host", "https://A.com/x", "https://a.com/y", true},
		{"scheme downgrade", "http://a.com/x", "https://a.com/y", false},
		{"different host", "https://a.com/x", "https://b.com/y", false},
		{"explicit port differs", "https://a.com:8443/x", "https://a.com/y", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			au, _ := url.Parse(tc.a)
			bu, _ := url.Parse(tc.b)
			assertEqual(t, tc.expect, sameOrigin(au, bu))
		})
	}
}

// An https -> http redirect keeps the same URL.Host, because the default port is
// elided, so a host-only comparison treated the downgrade as same-origin and put
// the caller's credentials on the wire in cleartext.
func TestCheckHostAndAddHeadersSchemeDowngrade(t *testing.T) {
	orig := mustReq(t, http.MethodGet, "https://example.com/api")
	orig.Header.Set("Authorization", "Bearer secret")
	orig.Header.Set("Cookie", "sid=secret")

	cur := mustReq(t, http.MethodGet, "http://example.com/api")
	checkHostAndAddHeaders(cur, []*http.Request{orig})

	assertEqual(t, "", cur.Header.Get("Authorization"))
	assertEqual(t, "", cur.Header.Get("Cookie"))
}

// net/http sets its strip flag once and never clears it, so a credential dropped
// at a foreign hop must stay dropped even when the chain returns to the original
// host. Resty compared only against via[0] and copied the originals back.
func TestCheckHostAndAddHeadersDoesNotResurrectCredentials(t *testing.T) {
	orig := mustReq(t, http.MethodGet, "https://example.com/api")
	orig.Header.Set("Authorization", "Bearer secret")
	orig.Header.Set("X-Api-Key", "key")
	orig.Header.Set("X-Safe", "safe")

	attacker := mustReq(t, http.MethodGet, "https://evil.example.net/x")
	cur := mustReq(t, http.MethodGet, "https://example.com/back")

	checkHostAndAddHeaders(cur, []*http.Request{orig, attacker})

	assertEqual(t, "", cur.Header.Get("Authorization"))
	assertEqual(t, "", cur.Header.Get("X-Api-Key"))
	// non-sensitive headers are still restored
	assertEqual(t, "safe", cur.Header.Get("X-Safe"))
}

// A chain that never leaves the origin still gets its headers restored.
func TestCheckHostAndAddHeadersSameOriginChain(t *testing.T) {
	orig := mustReq(t, http.MethodGet, "https://example.com/api")
	orig.Header.Set("Authorization", "Bearer secret")

	hop := mustReq(t, http.MethodGet, "https://example.com/hop")
	cur := mustReq(t, http.MethodGet, "https://example.com/final")

	checkHostAndAddHeaders(cur, []*http.Request{orig, hop})
	assertEqual(t, "Bearer secret", cur.Header.Get("Authorization"))
}

// RFC 9110 section 8.3: Content-Type describes the enclosed representation, and
// a 301/302/303 that rewrites POST to GET drops the body. net/http withholds the
// body headers accordingly; Resty copied them back.
func TestCheckHostAndAddHeadersDropsBodyHeadersOnMethodChange(t *testing.T) {
	orig := mustReq(t, http.MethodPost, "https://example.com/api")
	orig.Header.Set("Content-Type", "application/json")
	orig.Header.Set("Content-Language", "en")
	orig.Header.Set("X-Trace", "abc")

	cur := mustReq(t, http.MethodGet, "https://example.com/api")
	checkHostAndAddHeaders(cur, []*http.Request{orig})

	assertEqual(t, "", cur.Header.Get("Content-Type"))
	assertEqual(t, "", cur.Header.Get("Content-Language"))
	assertEqual(t, "abc", cur.Header.Get("X-Trace"))

	// same method keeps them
	cur2 := mustReq(t, http.MethodPost, "https://example.com/api")
	checkHostAndAddHeaders(cur2, []*http.Request{orig})
	assertEqual(t, "application/json", cur2.Header.Get("Content-Type"))
}

// RFC 6265 section 5.3: a cookie received with the redirect supersedes the one
// the caller sent. maps.Copy overwrote the corrected header with the stale one,
// so the request carried "sid=old; sid=new" and servers took the first match.
func TestCheckHostAndAddHeadersDoesNotClobberExistingHeaders(t *testing.T) {
	orig := mustReq(t, http.MethodGet, "https://example.com/api")
	orig.Header.Set("Cookie", "sid=old")
	orig.Header.Set("X-Only-On-Original", "yes")

	cur := mustReq(t, http.MethodGet, "https://example.com/next")
	cur.Header.Set("Cookie", "sid=new")

	checkHostAndAddHeaders(cur, []*http.Request{orig})

	assertEqual(t, "sid=new", cur.Header.Get("Cookie"))
	assertEqual(t, 1, len(cur.Header["Cookie"]))
	assertEqual(t, "yes", cur.Header.Get("X-Only-On-Original"))
}
