// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// 2023 Segev Dagan (https://github.com/segevda)
// 2024 Philipp Wolfer (https://github.com/phw)
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
)

var (
	ErrDigestBadChallenge    = errors.New("resty: digest: challenge is bad")
	ErrDigestInvalidCharset  = errors.New("resty: digest: invalid charset")
	ErrDigestAlgNotSupported = errors.New("resty: digest: algorithm is not supported")
	ErrDigestQopNotSupported = errors.New("resty: digest: qop is not supported")
)

// Reference: https://datatracker.ietf.org/doc/html/rfc7616#section-6.1
var digestHashFuncs = map[string]func() hash.Hash{
	"":                 md5.New,
	"MD5":              md5.New,
	"MD5-sess":         md5.New,
	"SHA-256":          sha256.New,
	"SHA-256-sess":     sha256.New,
	"SHA-512":          sha512.New,
	"SHA-512-sess":     sha512.New,
	"SHA-512-256":      sha512.New512_256,
	"SHA-512-256-sess": sha512.New512_256,
}

const (
	qopAuth    = "auth"
	qopAuthInt = "auth-int"
)

type digestTransport struct {
	*credentials
	transport http.RoundTripper
}

func (dt *digestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// first request without body for all HTTP verbs
	req1 := dt.cloneReq(req, true)

	// make a request to get the 401 that contains the challenge.
	res, err := dt.transport.RoundTrip(req1)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusUnauthorized {
		return res, nil
	}
	_, _ = ioCopy(io.Discard, res.Body)
	closeq(res.Body)

	chaHdrValue := strings.TrimSpace(res.Header.Get(hdrWwwAuthenticateKey))
	if chaHdrValue == "" {
		return nil, ErrDigestBadChallenge
	}

	cha, err := dt.parseChallenge(chaHdrValue)
	if err != nil {
		return nil, err
	}

	// prepare second request
	req2 := dt.cloneReq(req, false)
	cred, err := dt.createCredentials(cha, req2)
	if err != nil {
		return nil, err
	}

	auth, err := cred.digest(cha)
	if err != nil {
		return nil, err
	}

	req2.Header.Set(hdrAuthorizationKey, auth)
	return dt.transport.RoundTrip(req2)
}

func (dt *digestTransport) cloneReq(r *http.Request, first bool) *http.Request {
	r1 := r.Clone(r.Context())
	if first {
		r1.Body = http.NoBody
		r1.ContentLength = 0
		r1.GetBody = nil
	}
	return r1
}

func (dt *digestTransport) parseChallenge(input string) (*digestChallenge, error) {
	const ws = " \n\r\t"
	s := strings.Trim(input, ws)
	if !strings.HasPrefix(s, "Digest ") {
		return nil, ErrDigestBadChallenge
	}

	s = strings.Trim(s[7:], ws)
	c := &digestChallenge{}
	b := strings.Builder{}
	key := ""
	quoted := false
	for _, r := range s {
		switch r {
		case '"':
			quoted = !quoted
		case ',':
			if quoted {
				b.WriteRune(r)
			} else {
				val := strings.Trim(b.String(), ws)
				b.Reset()
				if err := c.setValue(key, val); err != nil {
					return nil, err
				}
				key = ""
			}
		case '=':
			if quoted {
				b.WriteRune(r)
			} else {
				key = strings.Trim(b.String(), ws)
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}

	key = strings.TrimSpace(key)
	if quoted || (key == "" && b.Len() > 0) {
		return nil, ErrDigestBadChallenge
	}

	if key != "" {
		val := strings.Trim(b.String(), ws)
		if err := c.setValue(key, val); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (dt *digestTransport) createCredentials(cha *digestChallenge, req *http.Request) (*digestCredentials, error) {
	cred := &digestCredentials{
		username:      dt.Username,
		password:      dt.Password,
		uri:           req.URL.RequestURI(),
		method:        req.Method,
		realm:         cha.realm,
		nonce:         cha.nonce,
		nc:            cha.nc,
		algorithm:     cha.algorithm,
		sessAlgorithm: strings.HasSuffix(cha.algorithm, "-sess"),
		opaque:        cha.opaque,
		userHash:      cha.userHash,
	}

	if cha.isQopSupported(qopAuthInt) {
		if err := dt.prepareBody(req); err != nil {
			return nil, fmt.Errorf("resty: digest: failed to prepare body for auth-int: %w", err)
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("resty: digest: failed to get body for auth-int: %w", err)
		}
		if body != http.NoBody {
			defer closeq(body)
			h := newHashFunc(cha.algorithm)
			if _, err := ioCopy(h, body); err != nil {
				return nil, err
			}
			cred.bodyHash = hex.EncodeToString(h.Sum(nil))
		}
	}

	return cred, nil
}

func (dt *digestTransport) prepareBody(req *http.Request) error {
	if req.GetBody != nil {
		return nil
	}

	if req.Body == nil || req.Body == http.NoBody {
		req.GetBody = func() (io.ReadCloser, error) {
			return http.NoBody, nil
		}
		return nil
	}

	b, err := ioReadAll(req.Body)
	if err != nil {
		return err
	}
	closeq(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(b))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	}

	return nil
}

type digestChallenge struct {
	realm     string
	domain    string
	nonce     string
	opaque    string
	stale     string
	algorithm string
	qop       []string
	nc        int
	userHash  string
}

func (dc *digestChallenge) isQopSupported(qop string) bool {
	for _, v := range dc.qop {
		if v == qop {
			return true
		}
	}
	return false
}

func (dc *digestChallenge) setValue(k, v string) error {
	switch k {
	case "realm":
		dc.realm = v
	case "domain":
		dc.domain = v
	case "nonce":
		dc.nonce = v
	case "opaque":
		dc.opaque = v
	case "stale":
		dc.stale = v
	case "algorithm":
		dc.algorithm = v
	case "qop":
		if !isStringEmpty(v) {
			dc.qop = strings.Split(v, ",")
		}
	case "charset":
		if strings.ToUpper(v) != "UTF-8" {
			return ErrDigestInvalidCharset
		}
	case "nc":
		nc, err := strconv.ParseInt(v, 16, 32)
		if err != nil {
			return fmt.Errorf("resty: digest: invalid nc: %w", err)
		}
		dc.nc = int(nc)
	case "userhash":
		dc.userHash = v
	default:
		return ErrDigestBadChallenge
	}
	return nil
}

type digestCredentials struct {
	username      string
	password      string
	userHash      string
	method        string
	uri           string
	realm         string
	nonce         string
	algorithm     string
	sessAlgorithm bool
	cnonce        string
	opaque        string
	qop           string
	nc            int
	response      string
	bodyHash      string
}

func (dc *digestCredentials) parseQop(cha *digestChallenge) error {
	if len(cha.qop) == 0 {
		return nil
	}

	if cha.isQopSupported(qopAuth) {
		dc.qop = qopAuth
		return nil
	}

	if cha.isQopSupported(qopAuthInt) {
		dc.qop = qopAuthInt
		return nil
	}

	return ErrDigestQopNotSupported
}

func (dc *digestCredentials) h(data string) string {
	h := newHashFunc(dc.algorithm)
	_, _ = h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func (dc *digestCredentials) digest(cha *digestChallenge) (string, error) {
	if _, ok := digestHashFuncs[dc.algorithm]; !ok {
		return "", ErrDigestAlgNotSupported
	}

	if err := dc.parseQop(cha); err != nil {
		return "", err
	}

	dc.nc++

	b := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, b)
	dc.cnonce = hex.EncodeToString(b)

	ha1 := dc.ha1()
	ha2 := dc.ha2()

	var resp string
	switch dc.qop {
	case "":
		resp = fmt.Sprintf("%s:%s:%s", ha1, dc.nonce, ha2)
	case qopAuth, qopAuthInt:
		resp = fmt.Sprintf("%s:%s:%08x:%s:%s:%s",
			ha1, dc.nonce, dc.nc, dc.cnonce, dc.qop, ha2)
	}
	dc.response = dc.h(resp)

	return "Digest " + dc.String(), nil
}

// https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.2
func (dc *digestCredentials) ha1() string {
	a1 := dc.h(fmt.Sprintf("%s:%s:%s", dc.username, dc.realm, dc.password))
	if dc.sessAlgorithm {
		return dc.h(fmt.Sprintf("%s:%s:%s", a1, dc.nonce, dc.cnonce))
	}
	return a1
}

// https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.3
func (dc *digestCredentials) ha2() string {
	if dc.qop == qopAuthInt {
		return dc.h(fmt.Sprintf("%s:%s:%s", dc.method, dc.uri, dc.bodyHash))
	}
	return dc.h(fmt.Sprintf("%s:%s", dc.method, dc.uri))
}

func (dc *digestCredentials) String() string {
	sl := make([]string, 0, 10)
	// https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.4
	if dc.userHash == "true" {
		dc.username = dc.h(fmt.Sprintf("%s:%s", dc.username, dc.realm))
	}
	sl = append(sl, fmt.Sprintf(`username="%s"`, dc.username))
	sl = append(sl, fmt.Sprintf(`realm="%s"`, dc.realm))
	sl = append(sl, fmt.Sprintf(`nonce="%s"`, dc.nonce))
	sl = append(sl, fmt.Sprintf(`uri="%s"`, dc.uri))
	if dc.algorithm != "" {
		sl = append(sl, fmt.Sprintf(`algorithm=%s`, dc.algorithm))
	}
	if dc.opaque != "" {
		sl = append(sl, fmt.Sprintf(`opaque="%s"`, dc.opaque))
	}
	if dc.qop != "" {
		sl = append(sl, fmt.Sprintf("qop=%s", dc.qop))
		sl = append(sl, fmt.Sprintf("nc=%08x", dc.nc))
		sl = append(sl, fmt.Sprintf(`cnonce="%s"`, dc.cnonce))
	}
	sl = append(sl, fmt.Sprintf(`userhash=%s`, dc.userHash))
	sl = append(sl, fmt.Sprintf(`response="%s"`, dc.response))

	return strings.Join(sl, ", ")
}

func newHashFunc(algorithm string) hash.Hash {
	hf := digestHashFuncs[algorithm]
	h := hf()
	h.Reset()
	return h
}
