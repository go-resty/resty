// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type digestServerConfig struct {
	realm, qop, nonce, opaque, algo, uri, charset, username, password, nc string
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

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
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
	assertEqual(t, true, strings.Contains(err.Error(), errCopyMsg))
	assertEqual(t, 0, resp.StatusCode())
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
	assertEqual(t, true, strings.Contains(err.Error(), "test req mock error"))
}

func TestClientDigestAuthWithBodyQopAuthIntGetBodyNil(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.qop = "auth-int"
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetDigestAuth(conf.username, conf.password)
	c.SetRequestMiddlewares(
		PrepareRequestMiddleware,
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
		PrepareRequestMiddleware,
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
	assertEqual(t, true, strings.Contains(err.Error(), "resty: digest: failed to get body for auth-int: get body test error"))
	assertEqual(t, 0, resp.StatusCode())
}

func TestClientDigestAuthWithGetBodyNilReadError(t *testing.T) {
	conf := *defaultDigestServerConf()
	conf.qop = "auth-int"
	ts := createDigestServer(t, &conf)
	defer ts.Close()

	c := dcnl().SetDigestAuth(conf.username, conf.password)
	c.SetRequestMiddlewares(
		PrepareRequestMiddleware,
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
	assertEqual(t, true, strings.Contains(err.Error(), "resty: digest: failed to prepare body for auth-int: read error"))
	assertEqual(t, 0, resp.StatusCode())
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
	assertEqual(t, true, strings.Contains(err.Error(), `parsing "1234567890": value out of range`))
	assertEqual(t, "", resp.Status())
}
