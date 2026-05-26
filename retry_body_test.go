package resty

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestRetryReusesEncodedRequestBody(t *testing.T) {
	var encodes atomic.Int32
	attempts := atomic.Int32{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := dcnl().
		SetRetryCount(2).
		SetRetryDefaultConditions(false).
		SetRetryAllowNonIdempotent(true).
		AddRetryConditions(func(r *Response, err error) bool {
			return err != nil || (r != nil && r.StatusCode() >= 500)
		})
	c.AddContentTypeEncoder("application/json", func(w io.Writer, body any) error {
		encodes.Add(1)
		return encodeJSON(w, body)
	})

	type payload struct {
		Value string `json:"value"`
	}

	resp, err := c.R().
		SetHeader(hdrContentTypeKey, "application/json").
		SetBody(payload{Value: "test"}).
		Post(srv.URL)

	assertNil(t, err)
	assertEqual(t, 3, resp.Request.Attempt)
	assertEqual(t, int32(1), encodes.Load())
}
