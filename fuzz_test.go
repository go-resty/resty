// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"path/filepath"
	"strings"
	"testing"
)

// FuzzDigestParseChallenge exercises the hand-written WWW-Authenticate parser with
// server-controlled input. It must always either return a challenge or an error.
func FuzzDigestParseChallenge(f *testing.F) {
	seeds := []string{
		`Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"`,
		`Digest realm="r", nonce="n", algorithm=SHA-256, charset=UTF-8, userhash=true`,
		`Digest realm="r", nonce="n", qop=" auth , auth-int ", nc=0000000f`,
		`Digest realm="hello", domain`,
		`Digest realm="hello, qop=auth`,
		`Digest unknown_param=true`,
		`Digest `,
		`Bad Challenge`,
		``,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	dt := &digestTransport{credentials: &credentials{"user", "pass"}}

	f.Fuzz(func(t *testing.T, in string) {
		cha, err := dt.parseChallenge(in)
		if err != nil {
			if cha != nil {
				t.Fatalf("parseChallenge returned both a challenge and an error for %q", in)
			}
			return
		}
		if cha == nil {
			t.Fatalf("parseChallenge returned neither a challenge nor an error for %q", in)
		}
		// a returned challenge must be usable: nonce present, qop tokens trimmed
		if isStringEmpty(cha.nonce) {
			t.Fatalf("accepted a challenge with no nonce: %q", in)
		}
		for _, q := range cha.qop {
			if q != strings.TrimSpace(q) {
				t.Fatalf("qop token %q was not trimmed, from %q", q, in)
			}
		}
		// building credentials from it must not panic either
		cred := &digestCredentials{algorithm: cha.algorithm}
		_ = cred.parseQop(cha)
	})
}

// FuzzSSEParseEvent exercises the SSE field parser with server-controlled bytes.
func FuzzSSEParseEvent(f *testing.F) {
	seeds := []string{
		"id: 1\nevent: message\ndata: hello",
		"data: one\ndata: two",
		"data",
		"retry: 100\ndata: x",
		"id:\ndata:\nevent:\nretry:",
		":comment only",
		"\n\n\n",
		"data: \xff\xfe invalid utf8",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		// trimHeader must never grow its input nor read out of range
		for _, size := range []int{0, 1, 3, 5, 6, len(in), len(in) + 1} {
			if got := trimHeader(size, in); len(got) > len(in) {
				t.Fatalf("trimHeader(%d) grew the input: %d > %d", size, len(got), len(in))
			}
		}

		ev, err := parseEvent(in)
		if err != nil {
			return
		}
		defer putRawEvent(ev)

		// Data must not alias the caller's buffer: mutating the input afterwards
		// must not change what was parsed.
		data := string(ev.Data)
		for i := range in {
			in[i] = 'Z'
		}
		if string(ev.Data) != data {
			t.Fatalf("parsed data aliases the input buffer")
		}
	})
}

// FuzzSanitizeResponseSaveFileName exercises the Content-Disposition filename
// sanitizer, which turns server-controlled text into a local path.
func FuzzSanitizeResponseSaveFileName(f *testing.F) {
	seeds := []string{
		"report.pdf",
		"../../etc/passwd",
		`..\..\windows\system32\config`,
		"/absolute/path",
		"C:/Windows/System32/x",
		"c:/x",
		"dir/sub/file.txt",
		"...",
		".",
		"..",
		"",
		"   ",
		"a\x00b",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		got, err := sanitizeResponseSaveFileNameFromHeader(in)
		if err != nil {
			return
		}
		if got == "" {
			return // empty input is reported as no filename
		}
		// whatever comes back must be a single bare filename
		if filepath.IsAbs(got) || strings.HasPrefix(got, "/") {
			t.Fatalf("returned an absolute path %q for input %q", got, in)
		}
		if strings.ContainsAny(got, `/\`) {
			t.Fatalf("returned a path separator in %q for input %q", got, in)
		}
		if got == "." || got == ".." || strings.HasPrefix(got, "../") {
			t.Fatalf("returned a traversal component %q for input %q", got, in)
		}
	})
}
