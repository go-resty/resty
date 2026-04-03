// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"slices"

	"net/url"
	"strings"
)

const unexecutedRequestURL = "http://unexecuted-request"

// buildCurlCmd returns an equivalent curl command for the given request.
func buildCurlCmd(req *Request) string {
	// generate curl raw headers
	var curl = "curl -X " + req.Method + " "
	headers := dumpCurlHeaders(req.RawRequest)
	for _, kv := range *headers {
		value := kv[1]

		// Check if header should be redacted
		if isSanitizeHeader(kv[0]) {
			value = "*****REDACTED*****"
		}

		curl += "-H " + cmdQuote(kv[0]+": "+value) + " "
	}

	// generate curl cookies
	if cookieJar := req.client.CookieJar(); cookieJar != nil {
		if cookies := cookieJar.Cookies(req.RawRequest.URL); len(cookies) > 0 {
			curl += "-H " + cmdQuote(dumpCurlCookies(cookies)) + " "
		}
	}

	// generate curl body except for io.Reader and multipart request flow
	// Check content type
	contentType := req.RawRequest.Header.Get(hdrContentTypeKey)
	if strings.HasPrefix(contentType, "multipart/form-data") {
		// Multipart: show placeholder
		curl += "-F '<fields omitted, see original request>'"
	} else if req.RawRequest.GetBody != nil {
		// Handle normal body
		body, err := req.RawRequest.GetBody()
		if err == nil {
			buf, _ := io.ReadAll(body)
			curl += "-d " + cmdQuote(string(bytes.TrimRight(buf, "\r\n"))) + " "
		} else {
			req.log.Errorf("curl: %v", err)
			curl += "-d ''"
		}
	}

	url := req.RawRequest.URL.String()
	if isStringEmpty(url) {
		url = unexecutedRequestURL
	}
	urlString := cmdQuote(url)

	curl += urlString
	return curl
}

// dumpCurlCookies returns a Cookie header string formatted for curl.
func dumpCurlCookies(cookies []*http.Cookie) string {
	sb := strings.Builder{}
	sb.WriteString("Cookie: ")
	for i, cookie := range cookies {
		if i > 0 {
			sb.WriteString("; ") // Pairs are delimited by "; " per RFC 6265.
		}
		sb.WriteString(cookie.Name + "=" + url.QueryEscape(cookie.Value))
	}
	return sb.String()
}

// dumpCurlHeaders returns request headers as sorted key/value pairs for curl generation.
func dumpCurlHeaders(req *http.Request) *[][2]string {
	headers := [][2]string{}
	for k, vs := range req.Header {
		for _, v := range vs {
			headers = append(headers, [2]string{k, v})
		}
	}

	slices.SortFunc(headers, func(a, b [2]string) int {
		return strings.Compare(a[0], b[0])
	})

	return &headers
}

var regexCmdQuote = regexp.MustCompile(`[^\w@%+=:,./-]`)

// cmdQuote escapes arbitrary strings for safe use as command-line arguments
// in common POSIX shells.
//
// The original Python package which this work was inspired by can be found
// at https://pypi.python.org/pypi/shellescape.
func cmdQuote(s string) string {
	if len(s) == 0 {
		return "''"
	}

	if regexCmdQuote.MatchString(s) {
		return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
	}

	return s
}
