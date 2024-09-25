// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
)

type (
	// ContentTypeEncoder type is for encoding the request body based on header Content-Type
	ContentTypeEncoder func(w io.Writer, v any) error

	// ContentTypeDecoder type is for decoding the response body based on header Content-Type
	ContentTypeDecoder func(r io.Reader, v any) error
)

func encodeJSON(w io.Writer, v any) error {
	return encodeJSONEscapeHTML(w, v, true)
}

func encodeJSONEscapeHTML(w io.Writer, v any, esc bool) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(esc)
	return enc.Encode(v)
}

func encodeJSONEscapeHTMLIndent(w io.Writer, v any, esc bool, indent string) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(esc)
	enc.SetIndent("", indent)
	return enc.Encode(v)
}

func decodeJSON(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	for {
		if err := dec.Decode(v); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}
	return nil
}

func encodeXML(w io.Writer, v any) error {
	return xml.NewEncoder(w).Encode(v)
}

func decodeXML(r io.Reader, v any) error {
	dec := xml.NewDecoder(r)
	for {
		if err := dec.Decode(v); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}
	return nil
}

var ErrReadExceedsThresholdLimit = errors.New("resty: read exceeds the threshold limit")

var _ io.ReadCloser = (*limitReadCloser)(nil)

type limitReadCloser struct {
	r io.Reader
	l int64
	t int64
	f func(s int64)
}

func (l *limitReadCloser) Read(p []byte) (n int, err error) {
	if l.l == 0 {
		n, err = l.r.Read(p)
		l.t += int64(n)
		l.f(l.t)
		return n, err
	}
	if l.t > l.l {
		return 0, ErrReadExceedsThresholdLimit
	}
	n, err = l.r.Read(p)
	l.t += int64(n)
	l.f(l.t)
	return n, err
}

func (l *limitReadCloser) Close() error {
	if c, ok := l.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

var _ io.ReadCloser = (*readCopier)(nil)

type readCopier struct {
	s io.Reader
	t *bytes.Buffer
	c bool
	f func(*bytes.Buffer)
}

func (r *readCopier) Read(p []byte) (int, error) {
	n, err := r.s.Read(p)
	if n > 0 {
		_, _ = r.t.Write(p[:n])
	}
	if err == io.EOF || err == ErrReadExceedsThresholdLimit {
		if !r.c {
			r.f(r.t)
			r.c = true
		}
	}
	return n, err
}

func (r *readCopier) Close() error {
	if c, ok := r.s.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

var _ io.ReadCloser = (*readNoOpCloser)(nil)

type readNoOpCloser struct {
	r *bytes.Reader
}

func (r *readNoOpCloser) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err == io.EOF {
		r.r.Seek(0, 0)
	}
	return n, err
}

func (r *readNoOpCloser) Close() error { return nil }
