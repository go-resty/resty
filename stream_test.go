package resty

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
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
	assertNil(t, result)
}

func TestGetMethodWhenResponseIsNull(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("null"))
	}))

	client := New().SetRetryCount(3).EnableGenerateCurlCmd()

	var x any
	resp, err := client.R().SetBody("{}").
		SetHeader("Content-Type", "application/json; charset=utf-8").
		SetForceResponseContentType("application/json").
		SetAllowMethodGetPayload(true).
		SetResponseBodyUnlimitedReads(true).
		SetResult(&x).
		Get(server.URL + "/test")

	assertNil(t, err)
	assertEqual(t, "null", resp.String())
	assertEqual(t, nil, x)
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
	assertEqual(t, true, ok)

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
