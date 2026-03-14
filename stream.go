// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
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

	// Handle nopReadCloser specially to support multiple JSON objects
	// while preventing infinite loops
	if nrc, ok := r.(*nopReadCloser); ok {
		// Temporarily disable auto-reset to prevent infinite loops
		originalReset := nrc.resetOnEOF
		nrc.resetOnEOF = false
		defer func() { nrc.resetOnEOF = originalReset }()

		if err := doDecodeJSON(dec, v); err != nil {
			return err
		}

		// After decoding, reset for future reads
		nrc.Reset()
		return nil
	}

	// For other readers, decode multiple JSON objects as intended
	return doDecodeJSON(dec, v)
}

func doDecodeJSON(dec *json.Decoder, v any) error {
	// Decode all JSON objects in the data
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

// gzipReaderPool pools actual *gzip.Reader objects for reuse via Reset().
// This avoids the allocation cost of gzip.NewReader for each decompression.
// Thread-safety is ensured by the gzipReaderWrapper's mutex which guards access.
var gzipReaderPool = sync.Pool{
	New: func() any {
		// Return nil; let's create reader on first use or get them from pool
		return nil
	},
}

// gzipReaderWrapper wraps a pooled gzip.Reader with a mutex for safe concurrent access.
// The mutex ensures exclusive access to the reader during Read() and state transitions.
type gzipReaderWrapper struct {
	mu *sync.Mutex
	r  io.ReadCloser
	gr *gzip.Reader
}

// acquireGzipReader gets a gzip.Reader from the pool or creates one.
// It resets the reader for the new stream using the provided io.ReadCloser.
func acquireGzipReader(r io.ReadCloser) (*gzipReaderWrapper, error) {
	w := &gzipReaderWrapper{
		mu: new(sync.Mutex),
		r:  r,
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Try to get a cached reader from the pool
	if cached := gzipReaderPool.Get(); cached != nil {
		w.gr = cached.(*gzip.Reader)
		// Reset the pooled reader for the new stream
		if err := w.gr.Reset(r); err != nil {
			gzipReaderPool.Put(w.gr) // Return to pool on reset error
			return nil, err
		}
	} else {
		// Pool is empty, create a new reader
		gr, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		w.gr = gr
	}

	return w, nil
}

// releaseGzipReader returns the gzip reader to the pool for reuse,
// and closes the underlying source.
func releaseGzipReader(w *gzipReaderWrapper) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.gr != nil {
		gzipReaderPool.Put(w.gr)
		w.gr = nil
	}
	if w.r != nil {
		closeq(w.r)
		w.r = nil
	}
}

func decompressGzip(r io.ReadCloser) (io.ReadCloser, error) {
	return acquireGzipReader(r)
}

// Implement io.ReadCloser for gzipReaderWrapper
func (w *gzipReaderWrapper) Read(p []byte) (n int, err error) {
	// Hold the lock during Read to ensure exclusive access to the gzip reader
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.gr == nil {
		return 0, io.EOF
	}
	return w.gr.Read(p)
}

func (w *gzipReaderWrapper) Close() error {
	releaseGzipReader(w)
	return nil
}

// flateReaderPool pools io.ReadCloser (flate.Reader) objects for reuse via Reset().
// This avoids the allocation cost of flate.NewReader for each decompression.
// Thread-safety is ensured by the deflateReaderWrapper's mutex which guards access.
var flateReaderPool = sync.Pool{
	New: func() any {
		// Return nil; let's create reader on first use or get them from pool
		return nil
	},
}

// deflateReaderWrapper wraps a pooled flate.Reader with a mutex for safe concurrent access.
// The mutex ensures exclusive access to the reader during Read() and state transitions.
type deflateReaderWrapper struct {
	mu *sync.Mutex
	r  io.ReadCloser
	fr io.ReadCloser
}

// acquireDeflateReader gets a flate.Reader from the pool or creates one.
// It resets the reader for the new stream using the provided io.ReadCloser.
func acquireDeflateReader(r io.ReadCloser) (*deflateReaderWrapper, error) {
	w := &deflateReaderWrapper{
		mu: new(sync.Mutex),
		r:  r,
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Try to get a cached reader from the pool
	if cached := flateReaderPool.Get(); cached != nil {
		w.fr = cached.(io.ReadCloser)
		// Reset the pooled reader for the new stream; flate.Resetter.Reset never errors
		w.fr.(flate.Resetter).Reset(r, nil)
	} else {
		// Pool is empty, create a new reader
		w.fr = flate.NewReader(r)
	}

	return w, nil
}

// releaseDeflateReader returns the flate reader to the pool for reuse,
// and closes the underlying source.
func releaseDeflateReader(w *deflateReaderWrapper) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.fr != nil {
		w.fr.(flate.Resetter).Reset(nopReader{}, nil)
		flateReaderPool.Put(w.fr)
		w.fr = nil
	}
	if w.r != nil {
		closeq(w.r)
		w.r = nil
	}
}

func decompressDeflate(r io.ReadCloser) (io.ReadCloser, error) {
	return acquireDeflateReader(r)
}

// Implement io.ReadCloser for deflateReaderWrapper
func (w *deflateReaderWrapper) Read(p []byte) (n int, err error) {
	// Hold the lock during Read to ensure exclusive access to the flate reader
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.fr == nil {
		return 0, io.EOF
	}
	return w.fr.Read(p)
}

func (w *deflateReaderWrapper) Close() error {
	releaseDeflateReader(w)
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
	r          *bytes.Reader
	resetOnEOF bool // Whether to reset on EOF
}

func (r *nopReadCloser) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err == io.EOF && r.resetOnEOF {
		r.r.Seek(0, io.SeekStart)
	}
	return n, err
}

func (r *nopReadCloser) Close() error { return nil }

// Reset allows manual reset of the reader position
func (r *nopReadCloser) Reset() {
	r.r.Seek(0, io.SeekStart)
}

var _ flate.Reader = (*nopReader)(nil)

type nopReader struct{}

func (nopReader) Read([]byte) (int, error) { return 0, io.EOF }
func (nopReader) ReadByte() (byte, error)  { return 0, io.EOF }

type gracefulStopReader struct {
	ctx context.Context
	r   io.Reader
}

func (gsr *gracefulStopReader) Read(p []byte) (n int, err error) {
	if err := gsr.ctx.Err(); err != nil {
		// Return io.EOF to stop io.Copy gracefully without an error.
		return 0, io.EOF
	}
	return gsr.r.Read(p)
}
