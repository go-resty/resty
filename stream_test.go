package resty

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
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
	// Test single object
	jsonData := `{"name": "John", "age": 30}`
	reader := bytes.NewReader([]byte(jsonData))
	var result map[string]any
	err := decodeJSON(reader, &result)
	assertNil(t, err)
	assertEqual(t, "John", result["name"])
	assertEqual(t, float64(30), result["age"])

	// Test multiple objects - should get the last one
	multipleJSON := `{"id": 1}
{"id": 2}
{"id": 3}`
	reader2 := bytes.NewReader([]byte(multipleJSON))
	var result2 map[string]any
	err = decodeJSON(reader2, &result2)
	assertNil(t, err)
	assertEqual(t, float64(3), result2["id"])

	// Test malformed JSON
	malformedJSON := `{"name": "John", "age":}`
	reader3 := bytes.NewReader([]byte(malformedJSON))
	var result3 map[string]any
	err = decodeJSON(reader3, &result3)
	assertNotNil(t, err)
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
			"expected gzip-related error, got: %v", err.Error())
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

		// Now acquire again with invalid data to trigger Reset error
		// invalidData := io.NopCloser(bytes.NewReader([]byte("not gzip data")))
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
