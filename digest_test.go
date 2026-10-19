// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type digestServerConfig struct {
	realm, qop, nonce, opaque, algo, uri, charset, username, password, nc string
	userhash                                                              bool
}

func defaultDigestServerConf() *digestServerConfig {
	return &digestServerConfig{
		realm:    "testrealm@host.com",
		qop:      "auth",
		nonce:    "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		opaque:   "5ccc069c403ebaf9f0171e9517f40e41",
		algo:     "MD5",
		uri:      "/dir/index.html",
		charset:  "utf-8",
		username: "Mufasa",
		password: "Circle Of Life",
		nc:       "00000001",
		userhash: true,
	}
}

func TestClientDigestAuth(t *testing.T) {
	conf := *defaultDigestServerConf()
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().
		SetBaseURL(ts.URL+"/").
		SetDigestAuth(conf.username, conf.password)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		Get(conf.uri)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestClientDigestAuthSession(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.algo = "MD5-sess"
	conf.qop = "auth, auth-int"
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().
		SetBaseURL(ts.URL+"/").
		SetDigestAuth(conf.username, conf.password)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		Get(conf.uri)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestClientDigestAuthErrors(t *testing.T) {
	type test struct {
		mutateConf func(*digestServerConfig)
		expect     error
	}
	tests := []test{
		{mutateConf: func(c *digestServerConfig) { c.algo = "BAD_ALGO" }, expect: ErrDigestAlgNotSupported},
		{mutateConf: func(c *digestServerConfig) { c.qop = "bad-qop" }, expect: ErrDigestQopNotSupported},
		{mutateConf: func(c *digestServerConfig) { c.charset = "utf-16" }, expect: ErrDigestInvalidCharset},
		{mutateConf: func(c *digestServerConfig) { c.uri = "/bad" }, expect: ErrDigestBadChallenge},
		{mutateConf: func(c *digestServerConfig) { c.uri = "/unknown_param" }, expect: ErrDigestBadChallenge},
		{mutateConf: func(c *digestServerConfig) { c.uri = "/missing_value" }, expect: ErrDigestBadChallenge},
		{mutateConf: func(c *digestServerConfig) { c.uri = "/unclosed_quote" }, expect: ErrDigestBadChallenge},
		{mutateConf: func(c *digestServerConfig) { c.uri = "/no_challenge" }, expect: ErrDigestBadChallenge},
		{mutateConf: func(c *digestServerConfig) { c.uri = "/status_500" }, expect: nil},
	}

	for _, tc := range tests {
		conf := *defaultDigestServerConf()
		tc.mutateConf(&conf)
		ts := createDigestServer(t, &conf)

		c := dcnl().
			SetBaseURL(ts.URL+"/").
			SetDigestAuth(conf.username, conf.password)

		_, err := c.R().Get(conf.uri)
		assertErrorIs(t, tc.expect, err)
		ts.Close()
	}
}

func TestClientDigestAuthWithBody(t *testing.T) {
	conf := *defaultDigestServerConf()
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetDigestAuth(conf.username, conf.password)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(map[string]any{"zip_code": "00000", "city": "Los Angeles"}).
		Post(ts.URL + conf.uri)

	resObj := resp.Result().(*AuthSuccess)

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, resObj.ID, "success")
	assertEqual(t, resObj.Message, "login successful")
}

func TestClientDigestAuthWithBodyQopAuthInt(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.qop = "auth-int"
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetDigestAuth(conf.username, conf.password)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(map[string]any{"zip_code": "00000", "city": "Los Angeles"}).
		Post(ts.URL + conf.uri)

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestClientDigestAuthWithBodyQopAuthIntIoCopyError(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.qop = "auth-int"
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetDigestAuth(conf.username, conf.password)

	errCopyMsg := "test copy error"
	ioCopy = func(dst io.Writer, src io.Reader) (written int64, err error) {
		return 0, errors.New(errCopyMsg)
	}
	t.Cleanup(func() {
		ioCopy = io.Copy
	})

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(map[string]any{"zip_code": "00000", "city": "Los Angeles"}).
		Post(ts.URL + conf.uri)

	assertNotNil(t, err)
	assertTrue(t, strings.Contains(err.Error(), errCopyMsg), "expected io copy error")
	assertEqual(t, 0, resp.StatusCode(), "expected response status code to be zero on error")
}

func TestClientDigestAuthRoundTripError(t *testing.T) {
	conf := *defaultDigestServerConf()
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetTransport(&CustomRoundTripper2{returnErr: true})
	c.SetDigestAuth(conf.username, conf.password)

	_, err := c.R().
		SetResult(&AuthSuccess{}).
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(map[string]any{"zip_code": "00000", "city": "Los Angeles"}).
		Post(ts.URL + conf.uri)

	assertNotNil(t, err)
	assertTrue(t, strings.Contains(err.Error(), "test req mock error"), "expected round trip error")
}

func TestClientDigestAuthWithBodyQopAuthIntGetBodyNil(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.qop = "auth-int"
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetDigestAuth(conf.username, conf.password)
	c.SetRequestMiddlewares(
		MiddlewareRequestCreate,
		func(c *Client, r *Request) error {
			r.RawRequest.GetBody = nil
			return nil
		},
	)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(map[string]any{"zip_code": "00000", "city": "Los Angeles"}).
		Post(ts.URL + conf.uri)

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestClientDigestAuthWithGetBodyError(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.qop = "auth-int"
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetDigestAuth(conf.username, conf.password)
	c.SetRequestMiddlewares(
		MiddlewareRequestCreate,
		func(c *Client, r *Request) error {
			r.RawRequest.GetBody = func() (_ io.ReadCloser, _ error) {
				return nil, errors.New("get body test error")
			}
			return nil
		},
	)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(map[string]any{"zip_code": "00000", "city": "Los Angeles"}).
		Post(ts.URL + conf.uri)

	assertNotNil(t, err)
	assertTrue(t, strings.Contains(err.Error(), "resty: digest: failed to get body for auth-int: get body test error"),
		"expected get body error")
	assertEqual(t, 0, resp.StatusCode(), "expected response status code to be zero on error")
}

func TestClientDigestAuthPrefersAuthWithoutGetBody(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.qop = "auth, auth-int"
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetDigestAuth(conf.username, conf.password)
	c.SetRequestMiddlewares(
		MiddlewareRequestCreate,
		func(c *Client, r *Request) error {
			r.RawRequest.GetBody = func() (_ io.ReadCloser, _ error) {
				return nil, errors.New("get body test error")
			}
			return nil
		},
	)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(map[string]any{"zip_code": "00000", "city": "Los Angeles"}).
		Post(ts.URL + conf.uri)

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestClientDigestAuthWithGetBodyNilReadError(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.qop = "auth-int"
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetDigestAuth(conf.username, conf.password)
	c.SetRequestMiddlewares(
		MiddlewareRequestCreate,
		func(c *Client, r *Request) error {
			r.RawRequest.GetBody = nil
			return nil
		},
	)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(&brokenReadCloser{}).
		Post(ts.URL + conf.uri)

	assertNotNil(t, err)
	assertTrue(t, strings.Contains(err.Error(), "resty: digest: failed to prepare body for auth-int: resty: digest: failed to read request body: read error"),
		"expected read error")
	assertEqual(t, 0, resp.StatusCode(), "expected response status code to be zero on error")
}

func TestClientDigestAuthWithNoBodyQopAuthInt(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.qop = "auth-int"
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetDigestAuth(conf.username, conf.password)

	resp, err := c.R().Get(ts.URL + conf.uri)

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

func TestClientDigestAuthNoQop(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.qop = ""

	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetDigestAuth(conf.username, conf.password)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(map[string]any{"zip_code": "00000", "city": "Los Angeles"}).
		Post(ts.URL + conf.uri)

	assertNil(t, err)
	assertEqual(t, "200 OK", resp.Status())
}

func TestClientDigestAuthWithIncorrectNcValue(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.nc = "1234567890"

	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetDigestAuth(conf.username, conf.password)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(map[string]any{"zip_code": "00000", "city": "Los Angeles"}).
		Post(ts.URL + conf.uri)

	assertNotNil(t, err)
	assertTrue(t, strings.Contains(err.Error(), `parsing "1234567890": value out of range`),
		"expected nc value out of range error")
	assertEqual(t, "", resp.Status(), "expected empty response status on error")
}

func TestDigestCredentialsDigestParseQopError(t *testing.T) {
	dc := &digestCredentials{
		username:  "Mufasa",
		password:  "Circle Of Life",
		method:    http.MethodGet,
		uri:       "/dir/index.html",
		realm:     "testrealm@host.com",
		nonce:     "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		algorithm: "MD5",
		userHash:  "true",
	}

	cha := &digestChallenge{qop: []string{"bad-qop"}}
	_, err := dc.digest(cha)

	assertErrorIs(t, ErrDigestQopNotSupported, err)
}

func TestClientDigestAuthNoUserhash(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.userhash = false
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().
		SetBaseURL(ts.URL+"/").
		SetDigestAuth(conf.username, conf.password)

	resp, err := c.R().
		SetResult(&AuthSuccess{}).
		Get(conf.uri)
	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
}

// qop is a comma-separated list whose tokens may carry space, and unrecognized
// challenge directives must be ignored rather than rejected (RFC 7616 3.3).
func TestDigestChallengeParsing(t *testing.T) {
	dt := &digestTransport{credentials: &credentials{"u", "p"}}

	t.Run("qop tokens are trimmed", func(t *testing.T) {
		cha, err := dt.parseChallenge(`Digest realm="r", nonce="n", qop="foo, auth"`)
		assertNil(t, err)
		assertTrue(t, cha.isQopSupported(qopAuth))

		cred := &digestCredentials{}
		assertNil(t, cred.parseQop(cha))
		assertEqual(t, qopAuth, cred.qop)
	})

	t.Run("unknown directives are ignored", func(t *testing.T) {
		cha, err := dt.parseChallenge(`Digest realm="r", nonce="n", extension="x", userhash=false`)
		assertNil(t, err)
		assertEqual(t, "r", cha.realm)
		assertEqual(t, "n", cha.nonce)
	})

	t.Run("a challenge without nonce is rejected", func(t *testing.T) {
		_, err := dt.parseChallenge(`Digest extension="x"`)
		assertErrorIs(t, ErrDigestBadChallenge, err)
	})
}

func TestDigestChallengeQuotedPairs(t *testing.T) {
	for _, tc := range []struct {
		name, challenge, realm string
		invalid                bool
	}{
		{"escaped quote", `Digest realm="a\"b", nonce="n"`, `a"b`, false},
		{"escaped backslash", `Digest realm="a\\b", nonce="n"`, `a\b`, false},
		{"escaped delimiters", `Digest realm="a\,b\=c", nonce="n"`, `a,b=c`, false},
		{"trailing escape", `Digest nonce="n\`, "", true},
		{"escaped closing quote", `Digest nonce="n\"`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cha, err := (&digestTransport{}).parseChallenge(tc.challenge)
			if tc.invalid {
				assertErrorIs(t, ErrDigestBadChallenge, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertEqual(t, tc.realm, cha.realm)
			assertEqual(t, "n", cha.nonce)
		})
	}
}

func TestClientDigestAuthQuotedPairs(t *testing.T) {
	for _, tc := range []struct {
		name, username, challenge, realm, nonce, opaque string
	}{
		{
			"quoted username", `u"ser\name`,
			`Digest realm="realm", nonce="nonce", opaque="opaque", algorithm=SHA-256, qop="auth"`,
			"realm", "nonce", "opaque",
		},
		{
			"quoted challenge", "user",
			`Digest realm="r\"e\\alm,=", nonce="n\"o\\nce", opaque="o\"p\\aque", algorithm=SHA-256, qop="auth"`,
			`r"e\alm,=`, `n"o\nce`, `o"p\aque`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth == "" {
					w.Header().Set("WWW-Authenticate", tc.challenge)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				// Use an independent quoted-string parser with MIME parameter separators.
				authParams := strings.ReplaceAll(strings.TrimPrefix(auth, "Digest "), ", ", "; ")
				_, params, err := mime.ParseMediaType("Digest; " + authParams)
				if err != nil {
					t.Errorf("invalid Authorization %q: %v", auth, err)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				for key, want := range map[string]string{
					"username": tc.username, "realm": tc.realm, "nonce": tc.nonce, "opaque": tc.opaque,
					"uri": "/protected", "algorithm": "SHA-256", "qop": "auth", "nc": "00000001",
				} {
					if params[key] != want {
						t.Errorf("%s = %q, want %q", key, params[key], want)
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
				}
				h := func(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }
				ha1 := h(tc.username + ":" + tc.realm + ":pass")
				ha2 := h("GET:/protected")
				want := h(ha1 + ":" + tc.nonce + ":00000001:" + params["cnonce"] + ":auth:" + ha2)
				if params["response"] != want {
					t.Errorf("response = %q, want %q", params["response"], want)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusOK)
			})
			defer ts.Close()

			c := dcnl().SetDigestAuth(tc.username, "pass")
			defer c.Close()
			res, err := c.R().Get(ts.URL + "/protected")
			if err != nil {
				t.Fatal(err)
			}
			assertEqual(t, http.StatusOK, res.StatusCode())
		})
	}
}

// A server offering an unsupported qop alongside a supported one must still
// authenticate rather than fail with ErrDigestQopNotSupported.
func TestClientDigestAuthQopListWithSpaces(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.qop = "some-future-qop, auth"
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().
		SetBaseURL(ts.URL+"/").
		SetDigestAuth(conf.username, conf.password)
	defer c.Close()

	res, err := c.R().SetResult(&AuthSuccess{}).Get(conf.uri)
	assertNil(t, err)
	assertEqual(t, http.StatusOK, res.StatusCode())
}

// An unsupported algorithm combined with qop=auth-int reached newHashFunc before
// the algorithm was validated, and the nil map entry panicked.
func TestDigestUnsupportedAlgorithmWithAuthInt(t *testing.T) {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate",
			`Digest realm="test", nonce="abc123", qop="auth-int", algorithm=NOT-A-HASH`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer ts.Close()

	c := dcnl().SetDigestAuth("user", "pass")
	defer c.Close()

	_, err := c.R().SetBody(`{"a":1}`).Post(ts.URL)
	assertErrorIs(t, ErrDigestAlgNotSupported, err)
}

// digestTransport runs on every redirect hop, so a redirect to a host the caller
// never addressed used to be answered with the configured credentials: the
// username in cleartext plus a digest over a realm and nonce that host chose.
// Compare curl CVE-2022-27774.
func TestDigestDoesNotAuthenticateToRedirectTarget(t *testing.T) {
	var attackerGotAuth string
	var attackerHits int
	attacker := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		attackerHits++
		attackerGotAuth = r.Header.Get("Authorization")
		w.Header().Set("WWW-Authenticate",
			`Digest realm="attacker-realm", nonce="attacker-nonce", qop="auth"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer attacker.Close()

	origin := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/x", http.StatusFound)
	})
	defer origin.Close()

	c := dcnl().SetDigestAuth("victim-user", "victim-pass")
	defer c.Close()

	res, err := c.R().Get(origin.URL + "/start")
	assertError(t, err)

	// the attacker sees the unauthenticated probe only, and gets no credentials
	assertEqual(t, 1, attackerHits)
	assertEqual(t, "", attackerGotAuth)
	assertEqual(t, http.StatusUnauthorized, res.StatusCode())
}

// A same-origin challenge must still be answered.
func TestDigestAuthenticatesOnSameOriginRedirect(t *testing.T) {
	var authed bool
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/protected", http.StatusFound)
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate",
				`Digest realm="test", nonce="abc", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authed = true
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	c := dcnl().SetDigestAuth("user", "pass")
	defer c.Close()

	res, err := c.R().Get(ts.URL + "/start")
	assertError(t, err)
	assertEqual(t, true, authed)
	assertEqual(t, http.StatusOK, res.StatusCode())
}

func TestOriginatingURL(t *testing.T) {
	first, _ := http.NewRequest(http.MethodGet, "https://origin.example/start", nil)
	second, _ := http.NewRequest(http.MethodGet, "https://evil.example/x", nil)
	second.Response = &http.Response{Request: first}

	assertEqual(t, "https://origin.example/start", originatingURL(second).String())
	assertEqual(t, "https://origin.example/start", originatingURL(first).String())
}

func TestDigestChallengeCaseInsensitiveNames(t *testing.T) {
	for _, tc := range []struct {
		name, scheme, params string
	}{
		{"lowercase scheme", "digest", `realm="CaseSensitiveRealm", domain="/MixedPath", nonce="AbCd123", opaque="OpAqUe", algorithm=SHA-256, qop="auth", stale=FALSE, nc=0000000A, userhash=false, charset=UTF-8, extension="MiXeD"`},
		{"mixed scheme", "DiGeSt", `realm="CaseSensitiveRealm", domain="/MixedPath", nonce="AbCd123", opaque="OpAqUe", algorithm=SHA-256, qop="auth", stale=FALSE, nc=0000000A, userhash=false, charset=UTF-8, extension="MiXeD"`},
		{"algorithm name only", "Digest", `realm="CaseSensitiveRealm", domain="/MixedPath", nonce="AbCd123", opaque="OpAqUe", AlGoRiThM=SHA-256, qop="auth", stale=FALSE, nc=0000000A, userhash=false, charset=UTF-8, extension="MiXeD"`},
		{"parameter names", "Digest", `ReAlM="CaseSensitiveRealm", DoMaIn="/MixedPath", NoNcE="AbCd123", OpAqUe="OpAqUe", AlGoRiThM=SHA-256, QoP="auth", StAlE=FALSE, Nc=0000000A, UsErHaSh=false, ChArSeT=UTF-8, ExTeNsIoN="MiXeD"`},
		{"scheme and parameter names", "DiGeSt", `ReAlM="CaseSensitiveRealm", DoMaIn="/MixedPath", NoNcE="AbCd123", OpAqUe="OpAqUe", AlGoRiThM=SHA-256, QoP="auth", StAlE=FALSE, Nc=0000000A, UsErHaSh=false, ChArSeT=UTF-8, ExTeNsIoN="MiXeD"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cha, err := (&digestTransport{}).parseChallenge(tc.scheme + " " + tc.params)
			if err != nil {
				t.Fatal(err)
			}
			assertEqual(t, "CaseSensitiveRealm", cha.realm)
			assertEqual(t, "/MixedPath", cha.domain)
			assertEqual(t, "AbCd123", cha.nonce)
			assertEqual(t, "OpAqUe", cha.opaque)
			assertEqual(t, "SHA-256", cha.algorithm)
			assertEqual(t, "FALSE", cha.stale)
			assertEqual(t, "false", cha.userHash)
			assertEqual(t, 10, cha.nc)
			assertEqual(t, 1, len(cha.qop))
			assertEqual(t, "auth", cha.qop[0])
		})
	}
}

func TestDigestChallengeCaseInsensitiveNamesErrors(t *testing.T) {
	for _, tc := range []struct {
		name, challenge string
		want            error
	}{
		{"empty", "", ErrDigestBadChallenge},
		{"short scheme", "DiGe", ErrDigestBadChallenge},
		{"scheme only", "DiGeSt", ErrDigestBadChallenge},
		{"unknown scheme", `Basic nonce="n"`, ErrDigestBadChallenge},
		{"longer scheme", `DigestX nonce="n"`, ErrDigestBadChallenge},
		{"no space", `Digestnonce="n"`, ErrDigestBadChallenge},
		{"missing nonce", `DiGeSt ReAlM="r", ExTeNsIoN="x"`, ErrDigestBadChallenge},
		{"unclosed quote", `DiGeSt NoNcE="n`, ErrDigestBadChallenge},
		{"charset", `Digest nonce="n", ChArSeT=UTF-16`, ErrDigestInvalidCharset},
		{"algorithm value", `Digest nonce="n", AlGoRiThM=sha-256`, ErrDigestAlgNotSupported},
		{"qop value", `Digest nonce="n", QoP="AUTH"`, ErrDigestQopNotSupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dt := &digestTransport{credentials: &credentials{"user", "pass"}}
			cha, err := dt.parseChallenge(tc.challenge)
			if err == nil {
				_, err = dt.createCredentials(cha, mustReq(t, http.MethodGet, "http://example.com/"))
			}
			assertErrorIs(t, tc.want, err)
		})
	}
}

func TestClientDigestAuthCaseInsensitiveNames(t *testing.T) {
	for _, tc := range []struct{ name, challenge string }{
		{"lowercase scheme", `digest realm="CaseSensitiveRealm", nonce="AbCd123", opaque="OpAqUe", algorithm=SHA-256, qop="auth"`},
		{"mixed scheme", `DiGeSt realm="CaseSensitiveRealm", nonce="AbCd123", opaque="OpAqUe", algorithm=SHA-256, qop="auth"`},
		{"parameter names", `Digest ReAlM="CaseSensitiveRealm", NoNcE="AbCd123", OpAqUe="OpAqUe", AlGoRiThM=SHA-256, QoP="auth"`},
		{"scheme and parameter names", `DiGeSt ReAlM="CaseSensitiveRealm", NoNcE="AbCd123", OpAqUe="OpAqUe", AlGoRiThM=SHA-256, QoP="auth"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var requests []string
			ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				mu.Lock()
				requests = append(requests, auth)
				mu.Unlock()
				if auth == "" {
					w.Header().Set("WWW-Authenticate", tc.challenge)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				// Verify the response independently using SHA-256 and the original values.
				params := make(map[string]string)
				for _, param := range strings.Split(strings.TrimPrefix(auth, "Digest "), ", ") {
					key, value, ok := strings.Cut(param, "=")
					if !ok {
						t.Errorf("malformed Authorization parameter: %q", param)
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					params[key] = strings.Trim(value, `"`)
				}
				for key, want := range map[string]string{
					"username": "user", "realm": "CaseSensitiveRealm", "nonce": "AbCd123",
					"opaque": "OpAqUe", "algorithm": "SHA-256", "qop": "auth", "uri": "/MixedPath", "nc": "00000001",
				} {
					if params[key] != want {
						t.Errorf("%s = %q, want %q", key, params[key], want)
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
				}
				if !strings.HasPrefix(auth, "Digest ") || params["cnonce"] == "" {
					t.Errorf("invalid Authorization: %q", auth)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				h := func(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }
				ha1 := h("user:CaseSensitiveRealm:pass")
				ha2 := h("GET:/MixedPath")
				want := h(ha1 + ":AbCd123:00000001:" + params["cnonce"] + ":auth:" + ha2)
				if params["response"] != want {
					t.Errorf("response = %q, want %q", params["response"], want)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusOK)
			})
			defer ts.Close()
			c := dcnl().SetDigestAuth("user", "pass")
			defer c.Close()
			res, err := c.R().Get(ts.URL + "/MixedPath")
			if err != nil {
				t.Fatal(err)
			}
			assertEqual(t, http.StatusOK, res.StatusCode())
			mu.Lock()
			defer mu.Unlock()
			if len(requests) != 2 {
				t.Fatalf("got %d requests, want 2", len(requests))
			}
			assertEqual(t, "", requests[0])
			assertTrue(t, strings.HasPrefix(requests[1], "Digest "))
		})
	}
}
