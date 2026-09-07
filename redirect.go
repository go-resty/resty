// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type (
	// RedirectPolicy controls redirect behaviour in the Resty client.
	// Implementations can be registered via [Client.SetRedirectPolicy].
	//
	// Apply should return nil to allow the redirect to proceed, or a non-nil
	// error to stop it.
	RedirectPolicy interface {
		Apply(*http.Request, []*http.Request) error
	}

	// RedirectPolicyFunc is an adapter that allows an ordinary function with the
	// appropriate signature to be used as a [RedirectPolicy].
	RedirectPolicyFunc func(*http.Request, []*http.Request) error

	// RedirectInfo records the URL and HTTP status code of a single redirect hop,
	// used to build the redirect history on a [Response].
	RedirectInfo struct {
		// URL is the redirect target URL.
		URL string
		// StatusCode is the HTTP status code that triggered the redirect.
		StatusCode int
	}
)

// Apply calls f(req, via).
func (f RedirectPolicyFunc) Apply(req *http.Request, via []*http.Request) error {
	return f(req, via)
}

// RedirectNoPolicy disables all redirects in the Resty client.
//
//	client.SetRedirectPolicy(resty.RedirectNoPolicy())
func RedirectNoPolicy() RedirectPolicy {
	return RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	})
}

// RedirectFlexiblePolicy creates a [RedirectPolicy] that allows up to noOfRedirect
// redirects. Once the limit is reached, the redirect is stopped with an error.
//
//	client.SetRedirectPolicy(resty.RedirectFlexiblePolicy(20))
func RedirectFlexiblePolicy(noOfRedirect int) RedirectPolicy {
	return RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		if len(via) >= noOfRedirect {
			return fmt.Errorf("resty: stopped after %d redirects", noOfRedirect)
		}
		checkHostAndAddHeaders(req, via)
		return nil
	})
}

// RedirectDomainCheckPolicy creates a [RedirectPolicy] that only allows redirects
// to the specified hostnames. Redirects to any other host are stopped with an error.
//
//	client.SetRedirectPolicy(resty.RedirectDomainCheckPolicy("host1.com", "host2.org", "host3.net"))
func RedirectDomainCheckPolicy(hostnames ...string) RedirectPolicy {
	hosts := make(map[string]bool)
	for _, h := range hostnames {
		hosts[strings.ToLower(h)] = true
	}

	return RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		if ok := hosts[strings.ToLower(req.URL.Host)]; !ok {
			return errors.New("resty: redirect is not allowed as per DomainCheckRedirectPolicy")
		}
		checkHostAndAddHeaders(req, via)
		return nil
	})
}

// RedirectHeaderStripSensitivePolicy creates a [RedirectPolicy] that removes
// selected headers from redirected requests.
//
// If applyDefault is true, it also removes headers that match Resty's
// built-in sensitive-header filter (for example Authorization, auth, token, etc.).
// Any headers passed via headers are removed as well.
//
//	client.SetRedirectPolicy(resty.RedirectHeaderStripSensitivePolicy(
//		true,
//		"X-Internal-Header",
//		"X-Another-Header",
//	))
//
// NOTE:
//   - Use this policy with caution as stripping headers may cause some redirects to fail
//     if the server relies on those headers.
//   - The default sensitive header filter is based on common patterns and may not cover all cases.
//     Always review which headers are being stripped to avoid unintended consequences.
//   - If combined with policies that copy headers from previous requests (for example,
//     [RedirectFlexiblePolicy] and [RedirectDomainCheckPolicy]), register this policy
//     last in [Client.SetRedirectPolicy] so stripped headers are not reintroduced later.
func RedirectHeaderStripSensitivePolicy(applyDefault bool, headers ...string) RedirectPolicy {
	return RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		// Apply default behavior to strip sensitive headers if applyDefault is true
		if applyDefault {
			for key := range req.Header {
				if isSanitizeHeader(key) {
					req.Header.Del(key)
				}
			}
		}
		// Strip sensitive headers provided by the user
		for _, header := range headers {
			req.Header.Del(header)
		}
		return nil
	})
}

// redirectBodyHeaders describe the enclosed representation. RFC 9110 section 8.3
// ties them to a request body, and net/http deliberately withholds them when a
// 301, 302 or 303 turns a request with a body into a body-less GET, so they must
// not be restored on a method change either.
var redirectBodyHeaders = []string{
	"Content-Type",
	"Content-Encoding",
	"Content-Language",
	"Content-Location",
}

// sameOrigin reports whether two URLs share a scheme and a host. Host alone is
// not enough: the default port is elided, so an https to http downgrade of the
// same hostname compares equal on Host and would look like a same-origin hop.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// leftOrigin reports whether any hop so far targeted an origin other than the
// one the chain started at.
func leftOrigin(via []*http.Request) bool {
	for _, r := range via[1:] {
		if !sameOrigin(r.URL, via[0].URL) {
			return true
		}
	}
	return false
}

// By default, Golang will not redirect request headers.
// After reading through the various discussion comments from the thread -
// https://github.com/golang/go/issues/4800
// Resty will add all the headers during a redirect for the same host and
// adds library user-agent if the Host is different.
//
// For cross-origin redirects, sensitive headers (matching [isSanitizeHeader])
// are stripped from the redirected request. Go's net/http only strips standard
// headers such as Authorization and Cookie; custom authentication headers
// (e.g. those set via [Client.SetHeaderAuthorizationKey]) are forwarded
// verbatim unless explicitly removed. See https://github.com/go-resty/resty/issues/1128.
//
// Headers already present on the redirected request are never overwritten, and
// three kinds are never restored from the original request:
//
//   - anything sensitive, once any hop in the chain has left the original
//     origin. net/http sets its own strip flag once and never clears it, so a
//     credential dropped at a foreign hop must stay dropped even if the chain
//     returns to the original host.
//   - [redirectBodyHeaders], when the redirect changed the method and therefore
//     dropped the body.
//   - anything on a hop whose scheme or host differs from the original.
func checkHostAndAddHeaders(cur *http.Request, via []*http.Request) {
	orig := via[0]

	if !sameOrigin(cur.URL, orig.URL) {
		// Cross-origin redirect: strip sensitive headers that Go's
		// net/http does not know about (custom auth, token, api-key, etc.).
		for key := range cur.Header {
			if isSanitizeHeader(key) {
				cur.Header.Del(key)
			}
		}
		return
	}

	credentialsSpent := leftOrigin(via)
	methodChanged := cur.Method != orig.Method

	for key, value := range orig.Header {
		// Never clobber what net/http or an earlier hop already set; that is how
		// a Set-Cookie delivered with the redirect supersedes the original
		// Cookie header (RFC 6265 section 5.3).
		if _, ok := cur.Header[key]; ok {
			continue
		}
		if credentialsSpent && isSanitizeHeader(key) {
			continue
		}
		if methodChanged && slices.ContainsFunc(redirectBodyHeaders, func(h string) bool {
			return strings.EqualFold(h, key)
		}) {
			continue
		}
		cur.Header[key] = slices.Clone(value)
	}
}
