package resty

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestDecodeJSONWhenResponseBodyIsNull(t *testing.T) {
	r := &Response{
		Body: io.NopCloser(bytes.NewReader([]byte("null"))),
	}
	r.wrapCopyReadCloser()
	err := r.readAll()
	assertNil(t, err)

	var result map[int]int
	err = decodeJSON(r.Body, &result)
	assertNil(t, err)
	assertNil(t, result, "expected result to be nil map when JSON is null")
}

func TestGetMethodWhenResponseIsNull(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("null"))
	}))

	client := New().SetRetryCount(3).SetCurlCmdGenerate(true)

	var x any
	resp, err := client.R().SetBody("{}").
		SetHeader("Content-Type", "application/json; charset=utf-8").
		SetResponseForceContentType("application/json").
		SetMethodGetAllowPayload(true).
		SetResponseBodyUnlimitedReads(true).
		SetResult(&x).
		Get(server.URL + "/test")

	assertNil(t, err)
	assertEqual(t, "null", resp.String())
	assertNil(t, x, "expected result to be nil when response body is null")
}

func TestDecodeJSON(t *testing.T) {
	t.Run("single object", func(t *testing.T) {
		jsonData := `{"name": "John", "age": 30}`
		reader := bytes.NewReader([]byte(jsonData))
		var result map[string]any
		err := decodeJSON(reader, &result)
		assertNil(t, err)
		assertEqual(t, "John", result["name"])
		assertEqual(t, float64(30), result["age"])
	})

	t.Run("multiple objects", func(t *testing.T) {
		multipleJSON := `{"id": 1}
{"id": 2}
{"id": 3}`
		reader2 := bytes.NewReader([]byte(multipleJSON))
		var result2 map[string]any
		err := decodeJSON(reader2, &result2)
		assertNil(t, err)
		assertEqual(t, float64(3), result2["id"])
	})

	t.Run("list of objects", func(t *testing.T) {
		multipleJSON := `[{"id": 1},
{"id": 2},
{"id": 3}]`
		reader2 := bytes.NewReader([]byte(multipleJSON))
		var result2 []map[string]any
		err := decodeJSON(reader2, &result2)
		assertNil(t, err)
		assertEqual(t, float64(3), result2[2]["id"])
	})

	t.Run("malformed JSON", func(t *testing.T) {
		malformedJSON := `{"name": "John", "age":}`
		reader3 := bytes.NewReader([]byte(malformedJSON))
		var result3 map[string]any
		err := decodeJSON(reader3, &result3)
		assertNotNil(t, err)
	})

	t.Run("empty body", func(t *testing.T) {
		emptyJSON := ``
		reader4 := bytes.NewReader([]byte(emptyJSON))
		var result4 map[string]any
		err := decodeJSON(reader4, &result4)
		assertNil(t, err)
	})

	t.Run("exceeds maxDecodeObjects limit", func(t *testing.T) {
		preMaxDecodeObjects := maxDecodeObjects
		maxDecodeObjects = 51 // Set a lower limit for testing
		t.Cleanup(func() {
			maxDecodeObjects = preMaxDecodeObjects // Reset to original value after test
		})

		// Build a reader that returns maxDecodeObjects+1 objects without EOF
		// by using a custom reader that signals no EOF until asked enough times.
		// Simplest approach: patch the limit via the loop by creating a reader
		// backed by a sufficient number of elements. We instead test the boundary
		// by constructing exactly that many elements with a streaming reader
		// built from io.MultiReader.
		elem := []byte(`{"key": "value"}`)
		readers := make([]io.Reader, maxDecodeObjects+1)
		for i := range readers {
			readers[i] = bytes.NewReader(elem)
		}
		r := io.MultiReader(readers...)

		var v map[string]any
		err := decodeJSON(r, &v)
		assertNotNil(t, err)
		assertEqual(t, "resty: JSON decode exceeded 51 objects without EOF", err.Error())
	})
}

func TestWrapCopyReadCloser(t *testing.T) {
	testData := "Hello, World!"
	r := &Response{
		Body: io.NopCloser(bytes.NewReader([]byte(testData))),
	}

	// Before wrapping, bodyBytes should be empty
	assertEqual(t, 0, len(r.bodyBytes))

	r.wrapCopyReadCloser()

	// Read data - should trigger copy mechanism and transform to nopReadCloser
	data, err := io.ReadAll(r.Body)
	assertNil(t, err)
	assertEqual(t, testData, string(data))
	assertEqual(t, testData, string(r.bodyBytes))

	// Should now be nopReadCloser for unlimited reads
	_, ok := r.Body.(*nopReadCloser)
	assertTrue(t, ok, "expected Body to be of type *nopReadCloser")

	// Test unlimited reads
	data2, err := io.ReadAll(r.Body)
	assertNil(t, err)
	assertEqual(t, testData, string(data2))
}

func TestMultipleJSONObjectsSupport(t *testing.T) {
	// Test multiple JSON objects with wrapCopyReadCloser
	jsonData := `{"first": 1}
{"second": 2}
{"third": 3}`

	r := &Response{
		Body: io.NopCloser(bytes.NewReader([]byte(jsonData))),
	}
	r.wrapCopyReadCloser()

	// Should process all objects and get the last one
	var result map[string]any
	err := decodeJSON(r.Body, &result)
	assertNil(t, err)
	assertEqual(t, float64(3), result["third"])

	// Should support unlimited reads and decoding
	var result2 map[string]any
	err = decodeJSON(r.Body, &result2)
	assertNil(t, err)
	assertEqual(t, float64(3), result2["third"])

	// Test direct nopReadCloser usage
	nopReader := &nopReadCloser{
		r:          bytes.NewReader([]byte(jsonData)),
		resetOnEOF: true,
	}

	var result3 map[string]any
	err = decodeJSON(nopReader, &result3)
	assertNil(t, err)
	assertEqual(t, float64(3), result3["third"])
}

// Test case from GH-#1087 to ensure no panic occurs
// with gzip.Reader on corrupted gzip data when multiple
// concurrent requests are made.
func TestGzipReaderPanicOnConcurrentCorruptedBody(t *testing.T) {
	writeHeaders := func(w http.ResponseWriter) {
		w.Header().Set(hdrContentEncodingKey, "gzip")
		w.Header().Set(hdrContentTypeKey, "application/json")
		w.WriteHeader(http.StatusOK)
	}

	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		writeHeaders(w)

		// We want the Client to think it's reading Gzip, but fail immediately
		// upon processing these bytes.
		w.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01})
	})
	defer ts.Close()

	client := NewWithTransportSettings(&TransportSettings{MaxIdleConns: 1000, MaxIdleConnsPerHost: 1000}).
		SetRetryCount(2).
		AddRetryConditions(func(r *Response, err error) bool {
			return err != nil
		})

	totalRequests := 100
	concurrencyLimit := 100
	sem := make(chan struct{}, concurrencyLimit)

	panicChan := make(chan any, 1)
	doneChan := make(chan struct{})

	go func() {
		var wg sync.WaitGroup
		defer close(doneChan)

		for range totalRequests {
			select {
			case <-panicChan:
				return
			default:
			}

			wg.Add(1)
			sem <- struct{}{}

			go func() {
				defer wg.Done()
				defer func() { <-sem }()

				defer func() {
					if r := recover(); r != nil {
						select {
						case panicChan <- r:
						default:
						}
					}
				}()

				var out map[string]any
				client.R().
					SetRetryAllowNonIdempotent(true).
					SetResult(&out).
					Post(ts.URL)
			}()
		}
		wg.Wait()
	}()

	select {
	case r := <-panicChan:
		t.Errorf("Test Failed Immediately: Panic detected: %v", r)
	case <-doneChan:
		select {
		case r := <-panicChan:
			t.Errorf("Test Failed: Panic detected at end of run: %v", r)
		default:
			// If we get here, no panic occurred.
		}
	}

	// at the end the client should still be functional
	// and can make valid requests
	goodServer := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		writeHeaders(w)

		gz := gzip.NewWriter(w)
		defer gz.Close()
		gz.Write([]byte(`{"status": "ok"}`))
	})
	defer goodServer.Close()

	var result map[string]string
	res, err := client.R().
		SetResult(&result).
		Post(goodServer.URL)

	assertError(t, err)
	assertEqual(t, http.StatusOK, res.StatusCode())
	assertEqual(t, "ok", result["status"], "expected to successfully decode valid gzip response")
}

func TestGzipReaderAcquireAndResetError(t *testing.T) {
	t.Run("invalid data", func(t *testing.T) {
		// Test the scenario where gzip.NewReader fails (pool empty path)
		invalidData := io.NopCloser(bytes.NewReader([]byte("not gzip data")))

		// This should trigger the gzip.NewReader error path
		wrapper, err := acquireGzipReader(invalidData)
		assertNotNil(t, err)
		assertNil(t, wrapper)
		assertTrue(t, strings.Contains(err.Error(), "gzip") ||
			strings.Contains(err.Error(), "header") ||
			strings.Contains(err.Error(), "invalid"),
			"expected gzip-related error, got: "+err.Error())
	})

	t.Run("reset error", func(t *testing.T) {
		// Test the scenario where Reset fails (pool hit path)
		validData := io.NopCloser(bytes.NewReader(createGzipValidData()))

		// First acquire to populate the pool
		wrapper, err := acquireGzipReader(validData)
		assertNil(t, err)
		assertNotNil(t, wrapper)
		releaseGzipReader(wrapper)

		errorReader := &brokenReadCloser{}

		// Now acquire again with a broken reader to trigger Reset error on pool-hit path
		wrapper2, err := acquireGzipReader(errorReader)
		assertNotNil(t, err)
		assertNil(t, wrapper2)
		assertTrue(t, strings.Contains(err.Error(), "read error"))
	})
}

func TestGzipReaderPoolConcurrentAccess(t *testing.T) {
	// Test concurrent pool access to ensure thread safety

	const numGoroutines = 10
	const numOperations = 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for range numGoroutines {
		go func() {
			defer wg.Done()

			for range numOperations {
				// Create fresh data for each operation
				validData := io.NopCloser(bytes.NewReader(createGzipValidData()))
				wrapper, err := acquireGzipReader(validData)
				assertNil(t, err)
				assertNotNil(t, wrapper)

				// Use the reader briefly
				_, err = wrapper.gr.Read(make([]byte, 5))
				assertNil(t, err)

				// Release back to pool
				releaseGzipReader(wrapper)
			}
		}()
	}

	wg.Wait()
}

// Helper functions for testing

func createGzipValidData() []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("test data"))
	zw.Close()
	return buf.Bytes()
}

func createDeflateValidData() []byte {
	var buf bytes.Buffer
	zw, _ := flate.NewWriter(&buf, flate.BestSpeed)
	zw.Write([]byte("test data"))
	zw.Close()
	return buf.Bytes()
}

// Test case to ensure no panic occurs with flate.Reader on corrupted deflate data
// when multiple concurrent requests are made.
func TestDeflateReaderPanicOnConcurrentCorruptedBody(t *testing.T) {
	writeHeaders := func(w http.ResponseWriter) {
		w.Header().Set(hdrContentEncodingKey, "deflate")
		w.Header().Set(hdrContentTypeKey, "application/json")
		w.WriteHeader(http.StatusOK)
	}

	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		writeHeaders(w)
		// Send bytes that are not valid deflate data to force a read error.
		w.Write([]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03})
	})
	defer ts.Close()

	client := NewWithTransportSettings(&TransportSettings{MaxIdleConns: 1000, MaxIdleConnsPerHost: 1000}).
		SetRetryCount(2).
		AddRetryConditions(func(r *Response, err error) bool {
			return err != nil
		})

	totalRequests := 100
	concurrencyLimit := 100
	sem := make(chan struct{}, concurrencyLimit)

	panicChan := make(chan any, 1)
	doneChan := make(chan struct{})

	go func() {
		var wg sync.WaitGroup
		defer close(doneChan)

		for range totalRequests {
			select {
			case <-panicChan:
				return
			default:
			}

			wg.Add(1)
			sem <- struct{}{}

			go func() {
				defer wg.Done()
				defer func() { <-sem }()

				defer func() {
					if r := recover(); r != nil {
						select {
						case panicChan <- r:
						default:
						}
					}
				}()

				var out map[string]any
				client.R().
					SetRetryAllowNonIdempotent(true).
					SetResult(&out).
					Post(ts.URL)
			}()
		}
		wg.Wait()
	}()

	select {
	case r := <-panicChan:
		t.Errorf("Test Failed Immediately: Panic detected: %v", r)
	case <-doneChan:
		select {
		case r := <-panicChan:
			t.Errorf("Test Failed: Panic detected at end of run: %v", r)
		default:
			// If we get here, no panic occurred.
		}
	}

	// at the end the client should still be functional
	// and can make valid requests
	goodServer := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		writeHeaders(w)
		zw, _ := flate.NewWriter(w, flate.BestSpeed)
		defer zw.Close()
		zw.Write([]byte(`{"status": "ok"}`))
	})
	defer goodServer.Close()

	var result map[string]string
	res, err := client.R().
		SetResult(&result).
		Post(goodServer.URL)

	assertError(t, err)
	assertEqual(t, http.StatusOK, res.StatusCode())
	assertEqual(t, "ok", result["status"], "expected to successfully decode valid deflate response")
}

func TestDeflateReaderPoolAcquireAndRead(t *testing.T) {
	// Test successful creation and read with valid deflate data
	validData := io.NopCloser(bytes.NewReader(createDeflateValidData()))
	wrapper, err := acquireDeflateReader(validData)
	assertNil(t, err)
	assertNotNil(t, wrapper)

	buf := make([]byte, 128)
	// flate.Reader may return (n, io.EOF) in the same call on the final read; ignore it.
	n, _ := wrapper.Read(buf)
	assertTrue(t, n > 0, "expected to read some bytes from valid deflate data")
	assertEqual(t, "test data", strings.TrimRight(string(buf[:n]), "\x00"))

	wrapper.Close()

	// Test that Read on a closed wrapper returns io.EOF
	_, err = wrapper.Read(buf)
	assertEqual(t, io.EOF, err)
}

func TestDeflateReaderPoolConcurrentAccess(t *testing.T) {
	// Test concurrent pool access to ensure thread safety
	const numGoroutines = 10
	const numOperations = 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for range numGoroutines {
		go func() {
			defer wg.Done()

			for range numOperations {
				// Create fresh data for each operation
				validData := io.NopCloser(bytes.NewReader(createDeflateValidData()))
				wrapper, err := acquireDeflateReader(validData)
				assertNil(t, err)
				assertNotNil(t, wrapper)

				// Use the reader briefly
				_, err = wrapper.fr.Read(make([]byte, 5))
				assertNil(t, err)

				// Release back to pool
				releaseDeflateReader(wrapper)
			}
		}()
	}

	wg.Wait()
}

func TestLimitCloserResetterInterface(t *testing.T) {
	testStr := "This is limit reset test"
	testStrLen := int64(len(testStr))
	r := bytes.NewReader([]byte(testStr))
	lc := &limitReadCloser{
		r: r,
		l: testStrLen,
		f: func(total int64) {},
	}
	assertEqual(t, testStrLen, lc.l)

	rc := nopReadCloser{r: lc, resetOnEOF: true}
	rc.Read(make([]byte, 25)) // read to reach total size
	assertEqual(t, testStrLen, lc.l)
	assertEqual(t, testStrLen, lc.t)

	rc.Reset() // reset should change the total to 0
	assertEqual(t, int64(0), lc.t)
}

func TestDecodeXML(t *testing.T) {
	type Item struct {
		Name string `xml:"name"`
	}

	t.Run("single object", func(t *testing.T) {
		data := `<Item><name>foo</name></Item>`
		var v Item
		err := decodeXML(bytes.NewReader([]byte(data)), &v)
		assertNil(t, err)
		assertEqual(t, "foo", v.Name)
	})

	t.Run("multiple objects - last one wins", func(t *testing.T) {
		data := `<Item><name>first</name></Item><Item><name>last</name></Item>`
		var v Item
		err := decodeXML(bytes.NewReader([]byte(data)), &v)
		assertNil(t, err)
		assertEqual(t, "last", v.Name)
	})

	t.Run("malformed XML returns error", func(t *testing.T) {
		data := `<Item><name>broken</name>`
		var v Item
		err := decodeXML(bytes.NewReader([]byte(data)), &v)
		assertNotNil(t, err)
	})

	t.Run("exceeds maxDecodeObjects limit", func(t *testing.T) {
		preMaxDecodeObjects := maxDecodeObjects
		maxDecodeObjects = 51 // Set a lower limit for testing
		t.Cleanup(func() {
			maxDecodeObjects = preMaxDecodeObjects // Reset to original value after test
		})

		// Build a reader that returns maxDecodeObjects+1 objects without EOF
		// by using a custom reader that signals no EOF until asked enough times.
		// Simplest approach: patch the limit via the loop by creating a reader
		// backed by a sufficient number of elements. We instead test the boundary
		// by constructing exactly that many elements with a streaming reader
		// built from io.MultiReader.
		elem := []byte(`<Item><name>x</name></Item>`)
		readers := make([]io.Reader, maxDecodeObjects+1)
		for i := range readers {
			readers[i] = bytes.NewReader(elem)
		}
		r := io.MultiReader(readers...)

		var v Item
		err := decodeXML(r, &v)
		assertNotNil(t, err)
		assertEqual(t, "resty: XML decode exceeded 51 objects without EOF", err.Error())
	})
}

func TestCancelReadCloser(t *testing.T) {
	t.Run("read delegates to inner reader", func(t *testing.T) {
		data := []byte("hello resty")
		rc := &cancelReadCloser{
			r:      io.NopCloser(bytes.NewReader(data)),
			cancel: func() {},
		}
		buf := make([]byte, len(data))
		n, err := rc.Read(buf)
		assertNil(t, err)
		assertEqual(t, len(data), n)
		assertEqual(t, string(data), string(buf))
	})

	t.Run("close calls cancel", func(t *testing.T) {
		canceled := false
		rc := &cancelReadCloser{
			r:      io.NopCloser(strings.NewReader("")),
			cancel: func() { canceled = true },
		}
		err := rc.Close()
		assertNil(t, err)
		assertTrue(t, canceled, "expected cancel to be called on Close")
	})

	t.Run("close returns inner error", func(t *testing.T) {
		closeErr := errors.New("inner close error")
		canceled := false
		rc := &cancelReadCloser{
			r:      &errReadCloser{closeErr: closeErr},
			cancel: func() { canceled = true },
		}
		err := rc.Close()
		assertEqual(t, closeErr, err)
		assertTrue(t, canceled, "expected cancel to be called even when inner Close errors")
	})
}

// errReadCloser is a ReadCloser whose Close returns a fixed error.
type errReadCloser struct {
	closeErr error
}

func (e *errReadCloser) Read(p []byte) (int, error) { return 0, io.EOF }
func (e *errReadCloser) Close() error               { return e.closeErr }

func TestStreamMisc(t *testing.T) {
	t.Run("wrapper gzip reader is nil", func(t *testing.T) {
		// Simulate a scenario where gzip.NewReader returns a wrapper with nil gr
		// due to an error, and ensure that Read on the wrapper does not panic
		// and returns an appropriate error instead.
		gzipReader := &gzipReaderWrapper{mu: new(sync.Mutex)}
		n, err := gzipReader.Read(make([]byte, 5))
		assertNotNil(t, err)
		assertErrorIs(t, io.EOF, err)
		assertEqual(t, 0, n)

	})
}
