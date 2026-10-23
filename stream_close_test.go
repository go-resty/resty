package resty

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockedCompressedBody struct {
	prefix     *bytes.Reader
	reading    chan struct{}
	closed     chan struct{}
	readOnce   sync.Once
	closeOnce  sync.Once
	closeCalls atomic.Int32
}

func (r *blockedCompressedBody) Read(p []byte) (int, error) {
	if r.prefix.Len() > 0 {
		return r.prefix.Read(p)
	}
	r.readOnce.Do(func() { close(r.reading) })
	<-r.closed
	return 0, io.ErrClosedPipe
}
func (r *blockedCompressedBody) Close() error {
	r.closeCalls.Add(1)
	r.closeOnce.Do(func() { close(r.closed) })
	return nil
}

func TestCompressedBodyCloseUnblocksRead(t *testing.T) {
	for _, encoding := range []string{"gzip", "zlib", "raw deflate"} {
		t.Run(encoding, func(t *testing.T) {
			var prefix bytes.Buffer
			var writer interface {
				io.WriteCloser
				Flush() error
			}
			var decode ContentDecompresser
			switch encoding {
			case "gzip":
				writer = gzip.NewWriter(&prefix)
				decode = decompressGzip
			case "zlib":
				writer = zlib.NewWriter(&prefix)
				decode = decompressDeflate
			default:
				writer, _ = flate.NewWriter(&prefix, flate.DefaultCompression)
				decode = decompressDeflate
			}
			_, err := writer.Write([]byte("partial response"))
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Flush(); err != nil {
				t.Fatal(err)
			}
			source := &blockedCompressedBody{prefix: bytes.NewReader(bytes.Clone(prefix.Bytes())), reading: make(chan struct{}), closed: make(chan struct{})}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			body, err := decode(source)
			if err != nil {
				t.Fatal(err)
			}
			readDone := make(chan struct{})
			go func() { _, _ = io.Copy(io.Discard, body); close(readDone) }()
			<-source.reading
			closeDone := make(chan struct{})
			go func() { _ = body.Close(); close(closeDone) }()
			select {
			case <-closeDone:
			case <-time.After(time.Second):
				source.Close()
				<-closeDone
				<-readDone
				t.Fatal("Close blocked behind Read instead of closing the source")
			}
			select {
			case <-readDone:
			case <-time.After(time.Second):
				t.Fatal("Read remained blocked after Close")
			}
			var closes sync.WaitGroup
			for range 8 {
				closes.Add(1)
				go func() { defer closes.Done(); _ = body.Close() }()
			}
			closes.Wait()
			if got := source.closeCalls.Load(); got != 1 {
				t.Fatalf("source closed %d times, want once", got)
			}
		})
	}
}

func TestStreamingCompressedResponseCanBeClosed(t *testing.T) {
	for _, encoding := range []string{"gzip", "zlib", "raw deflate"} {
		t.Run(encoding, func(t *testing.T) {
			released := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				contentEncoding := "deflate"
				if encoding == "gzip" {
					contentEncoding = "gzip"
				}
				w.Header().Set("Content-Encoding", contentEncoding)
				var compressor interface {
					io.WriteCloser
					Flush() error
				}
				if encoding == "gzip" {
					compressor = gzip.NewWriter(w)
				} else if encoding == "zlib" {
					compressor = zlib.NewWriter(w)
				} else {
					compressor, _ = flate.NewWriter(w, flate.DefaultCompression)
				}
				_, _ = io.WriteString(compressor, "partial response")
				_ = compressor.Flush()
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
				case <-released:
				}
				_ = compressor.Close()
			}))
			defer server.Close()
			defer close(released)
			var bodyRead *observedHTTPBody
			transport := http.DefaultTransport.(*http.Transport).Clone()
			defer transport.CloseIdleConnections()
			c := dcnl().SetResponseDoNotParse(true).SetHeader("Accept-Encoding", "gzip, deflate").
				SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
					res, err := transport.RoundTrip(req)
					if err == nil {
						bodyRead = &observedHTTPBody{ReadCloser: res.Body, reading: make(chan struct{})}
						res.Body = bodyRead
					}
					return res, err
				}))
			defer c.Close()
			response, err := c.R().Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			prefix := make([]byte, len("partial response"))
			if _, err := io.ReadFull(response.Body, prefix); err != nil {
				t.Fatal(err)
			}
			assertEqual(t, "partial response", string(prefix))
			bodyRead.armed.Store(true)
			readDone := make(chan struct{})
			go func() { _, _ = io.Copy(io.Discard, response.Body); close(readDone) }()
			select {
			case <-bodyRead.reading:
			case <-time.After(time.Second):
				t.Fatal("Read did not reach the HTTP body")
			}
			closeDone := make(chan struct{})
			go func() { _ = response.Body.Close(); close(closeDone) }()
			select {
			case <-closeDone:
			case <-time.After(time.Second):
				t.Fatal("streaming response Close blocked")
			}
			select {
			case <-readDone:
			case <-time.After(time.Second):
				t.Fatal("streaming response Read remained blocked")
			}
		})
	}
}

// Signals only after the decoder has entered its locked Read path.
type observedHTTPBody struct {
	io.ReadCloser
	armed   atomic.Bool
	once    sync.Once
	reading chan struct{}
}

func (r *observedHTTPBody) Read(p []byte) (int, error) {
	if r.armed.Load() {
		r.once.Do(func() { close(r.reading) })
	}
	return r.ReadCloser.Read(p)
}
