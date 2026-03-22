// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"errors"
	"fmt"
	"net"
	"net/http"
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
		checkHostAndAddHeaders(req, via[0])
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
		if ok := hosts[getHostname(req.URL.Host)]; !ok {
			return errors.New("redirect is not allowed as per DomainCheckRedirectPolicy")
		}
		checkHostAndAddHeaders(req, via[0])
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

func getHostname(host string) (hostname string) {
	if strings.Index(host, ":") > 0 {
		host, _, _ = net.SplitHostPort(host)
	}
	hostname = strings.ToLower(host)
	return
}

// By default, Golang will not redirect request headers.
// After reading through the various discussion comments from the thread -
// https://github.com/golang/go/issues/4800
// Resty will add all the headers during a redirect for the same host and
// adds library user-agent if the Host is different.
func checkHostAndAddHeaders(cur *http.Request, pre *http.Request) {
	curHostname := getHostname(cur.URL.Host)
	preHostname := getHostname(pre.URL.Host)
	if strings.EqualFold(curHostname, preHostname) {
		for key, val := range pre.Header {
			cur.Header[key] = val
		}
	}
}
