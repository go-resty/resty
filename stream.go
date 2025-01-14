// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"sync"
)

var (
	ErrContentDecompresserNotFound = errors.New("resty: content decoder not found")
)

type (
	// ContentTypeEncoder type is for encoding the request body based on header Content-Type
	ContentTypeEncoder func(io.Writer, any) error

	// ContentTypeDecoder type is for decoding the response body based on header Content-Type
	ContentTypeDecoder func(io.Reader, any) error

	// ContentDecompresser type is for decompressing response body based on header Content-Encoding
	// ([RFC 9110])
	//
	// For example, gzip, deflate, etc.
	//
	// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
	ContentDecompresser func(io.ReadCloser) (io.ReadCloser, error)
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

var gzipPool = sync.Pool{New: func() any { return new(gzip.Reader) }}

func decompressGzip(r io.ReadCloser) (io.ReadCloser, error) {
	gr := gzipPool.Get().(*gzip.Reader)
	err := gr.Reset(r)
	return &gzipReader{s: r, r: gr}, err
}

type gzipReader struct {
	s io.ReadCloser
	r *gzip.Reader
}

func (gz *gzipReader) Read(p []byte) (n int, err error) {
	return gz.r.Read(p)
}

func (gz *gzipReader) Close() error {
	gz.r.Reset(nopReader{})
	gzipPool.Put(gz.r)
	closeq(gz.s)
	return nil
}

var flatePool = sync.Pool{New: func() any { return flate.NewReader(nopReader{}) }}

func decompressDeflate(r io.ReadCloser) (io.ReadCloser, error) {
	fr := flatePool.Get().(io.ReadCloser)
	err := fr.(flate.Resetter).Reset(r, nil)
	return &deflateReader{s: r, r: fr}, err
}

type deflateReader struct {
	s io.ReadCloser
	r io.ReadCloser
}

func (d *deflateReader) Read(p []byte) (n int, err error) {
	return d.r.Read(p)
}

func (d *deflateReader) Close() error {
	d.r.(flate.Resetter).Reset(nopReader{}, nil)
	flatePool.Put(d.r)
	closeq(d.s)
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

var _ io.ReadCloser = (*copyReadCloser)(nil)

type copyReadCloser struct {
	s io.Reader
	t *bytes.Buffer
	c bool
	f func(*bytes.Buffer)
}

func (r *copyReadCloser) Read(p []byte) (int, error) {
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

func (r *copyReadCloser) Close() error {
	if c, ok := r.s.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

var _ io.ReadCloser = (*nopReadCloser)(nil)

type nopReadCloser struct {
	r *bytes.Reader
}

func (r *nopReadCloser) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err == io.EOF {
		r.r.Seek(0, io.SeekStart)
	}
	return n, err
}

func (r *nopReadCloser) Close() error { return nil }

var _ flate.Reader = (*nopReader)(nil)

type nopReader struct{}

func (nopReader) Read([]byte) (int, error) { return 0, io.EOF }
func (nopReader) ReadByte() (byte, error)  { return 0, io.EOF }
