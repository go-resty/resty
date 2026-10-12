package resty

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
)

type bodyLimitReaderFunc func([]byte) (int, error)

func (f bodyLimitReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestLimitReadCloserProbe(t *testing.T) {
	readErr := errors.New("body read failed")
	for _, limit := range []int64{5, math.MaxInt64} {
		for _, tc := range []struct {
			name string
			n    int
			err  error
		}{
			{"no progress", 0, nil},
			{"EOF", 0, io.EOF},
			{"read error", 0, readErr},
			{"extra byte", 1, nil},
			{"extra byte with EOF", 1, io.EOF},
			{"extra byte with error", 1, readErr},
		} {
			t.Run(tc.name+"/"+strconv.FormatInt(limit, 10), func(t *testing.T) {
				calls := 0
				lc := &limitReadCloser{
					l: limit, t: limit,
					r: bodyLimitReaderFunc(func(p []byte) (int, error) {
						calls++
						assertEqual(t, 1, len(p))
						p[0] = '!'
						return tc.n, tc.err
					}),
					f: func(int64) { t.Error("probe changed the reported size") },
				}
				n, err := lc.Read(nil)
				assertEqual(t, 0, n)
				assertNil(t, err)
				assertEqual(t, 0, calls)

				buf := []byte("unchanged")
				n, err = lc.Read(buf)
				assertEqual(t, 0, n)
				assertEqual(t, "unchanged", string(buf))
				assertEqual(t, limit, lc.t)
				assertEqual(t, 1, calls)
				if tc.n == 0 {
					assertEqual(t, tc.err, err)
					// A zero-byte, nil-error read must not be mistaken for EOF.
					lc.r = strings.NewReader("")
					n, err = lc.Read(buf)
					assertEqual(t, 0, n)
					assertEqual(t, io.EOF, err)
				} else {
					assertEqual(t, ErrReadExceedsThresholdLimit, err)
					for range 2 {
						n, err = lc.Read(buf)
						assertEqual(t, 0, n)
						assertEqual(t, ErrReadExceedsThresholdLimit, err)
					}
					assertEqual(t, 1, calls)
					n, err = lc.Read(nil)
					assertEqual(t, 0, n)
					assertNil(t, err)
					assertEqual(t, 1, calls)
				}
			})
		}
	}
}

func TestLimitReadCloserResetAfterOverflow(t *testing.T) {
	r := strings.NewReader("hello!")
	var size int64
	lc := &limitReadCloser{r: r, l: 5, f: func(n int64) { size = n }}
	n, err := lc.Read(nil)
	assertEqual(t, 0, n)
	assertNil(t, err)
	assertEqual(t, 6, r.Len())
	body, err := io.ReadAll(lc)
	assertEqual(t, "hello", string(body))
	assertEqual(t, ErrReadExceedsThresholdLimit, err)
	assertEqual(t, int64(5), size)

	r.Reset("hello")
	assertNil(t, lc.Reset())
	assertEqual(t, int64(0), lc.t)
	body, err = io.ReadAll(lc)
	assertNil(t, err)
	assertEqual(t, "hello", string(body))
	assertEqual(t, int64(5), size)
}

func TestLimitReadCloserBoundary(t *testing.T) {
	readErr := errors.New("body read failed")
	for _, tc := range []struct {
		name  string
		body  io.Reader
		limit int64
		want  string
		err   error
	}{
		{"empty", strings.NewReader(""), 5, "", nil},
		{"below limit", strings.NewReader("hell"), 5, "hell", nil},
		{"exact limit", strings.NewReader("hello"), 5, "hello", nil},
		{"over limit", strings.NewReader("hello!"), 5, "hello", ErrReadExceedsThresholdLimit},
		{"exact limit with EOF", iotest.DataErrReader(strings.NewReader("hello")), 5, "hello", nil},
		{"over limit with EOF", iotest.DataErrReader(strings.NewReader("hello!")), 5, "hello", ErrReadExceedsThresholdLimit},
		{"one byte reads", iotest.OneByteReader(strings.NewReader("hello")), 5, "hello", nil},
		{"error after limit", io.MultiReader(strings.NewReader("hello"), iotest.ErrReader(readErr)), 5, "hello", readErr},
		{"zero limit", strings.NewReader("hello!"), 0, "hello!", nil},
		{"negative limit", strings.NewReader("hello!"), -1, "hello!", nil},
		{"maximum limit", strings.NewReader("hello"), math.MaxInt64, "hello", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var size int64
			lc := &limitReadCloser{r: tc.body, l: tc.limit, f: func(n int64) { size = n }}
			body, err := io.ReadAll(lc)
			assertEqual(t, tc.err, err)
			assertEqual(t, tc.want, string(body))
			assertEqual(t, int64(len(tc.want)), size)
			assertEqual(t, size, lc.t)
		})
	}
}

func TestResponseBodyLimitBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
		err  error
	}{
		{"below limit", "hell", "hell", nil},
		{"exact limit", "hello", "hello", nil},
		{"over limit", "hello!", "hello", ErrReadExceedsThresholdLimit},
	} {
		for _, requestLimit := range []bool{false, true} {
			for _, unlimitedReads := range []bool{false, true} {
				t.Run(tc.name+"/requestLimit="+strconv.FormatBool(requestLimit)+"/unlimitedReads="+strconv.FormatBool(unlimitedReads), func(t *testing.T) {
					c := New().SetResponseBodyLimit(5).SetResponseBodyUnlimitedReads(unlimitedReads)
					t.Cleanup(func() { c.Close() })
					c.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode:    http.StatusOK,
							Header:        http.Header{"Content-Type": {"text/plain"}},
							Body:          io.NopCloser(strings.NewReader(tc.body)),
							ContentLength: int64(len(tc.body)),
							Request:       r,
						}, nil
					}))
					if requestLimit {
						c.SetResponseBodyLimit(3)
					}
					r := c.R()
					if requestLimit {
						r.SetResponseBodyLimit(5)
					}
					resp, err := r.Get("http://example.test/")
					assertEqual(t, tc.err, err)
					assertEqual(t, tc.want, string(resp.Bytes()))
					assertEqual(t, int64(len(tc.want)), resp.Size())
				})
			}
		}
	}
}

func TestResponseBodyLimitJSON(t *testing.T) {
	const body = `{"name":"resty"}`
	for _, compressed := range []bool{false, true} {
		for _, unlimitedReads := range []bool{false, true} {
			for _, extra := range []string{"", " "} {
				t.Run("gzip="+strconv.FormatBool(compressed)+"/unlimitedReads="+strconv.FormatBool(unlimitedReads)+"/extra="+strconv.Itoa(len(extra)), func(t *testing.T) {
					c := New().SetResponseBodyLimit(int64(len(body))).SetResponseBodyUnlimitedReads(unlimitedReads)
					t.Cleanup(func() { c.Close() })
					c.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
						var data io.Reader = strings.NewReader(body + extra)
						header := http.Header{"Content-Type": {"application/json"}}
						if compressed {
							var buf bytes.Buffer
							w := gzip.NewWriter(&buf)
							_, err := io.WriteString(w, body+extra)
							assertNil(t, err)
							assertNil(t, w.Close())
							data = &buf
							header.Set("Content-Encoding", "gzip")
						}
						return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(data), Request: r}, nil
					}))
					var result struct{ Name string }
					resp, err := c.R().SetResult(&result).Get("http://example.test/")
					if extra == "" {
						assertNil(t, err)
						assertEqual(t, "resty", result.Name)
					} else {
						assertEqual(t, ErrReadExceedsThresholdLimit, err)
					}
					assertEqual(t, int64(len(body)), resp.Size())
					if unlimitedReads {
						assertEqual(t, body, string(resp.Bytes()))
						for range 2 {
							data, err := io.ReadAll(resp.Body)
							assertNil(t, err)
							assertEqual(t, body, string(data))
						}
					}
				})
			}
		}
	}
}

func TestLimitReadCloserMaxInt64Boundary(t *testing.T) {
	var size int64
	lc := &limitReadCloser{r: strings.NewReader("xy"), l: math.MaxInt64, t: math.MaxInt64 - 1, f: func(n int64) { size = n }}
	body, err := io.ReadAll(lc)
	assertEqual(t, "x", string(body))
	assertEqual(t, ErrReadExceedsThresholdLimit, err)
	assertEqual(t, int64(math.MaxInt64), size)
	assertEqual(t, size, lc.t)
}
