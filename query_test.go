package resty

import (
	"io"
	"net/http"
	"testing"
)

func TestQuery(t *testing.T) {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != MethodQuery {
			t.Errorf("expected method %q, got %q", MethodQuery, r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	defer ts.Close()

	resp, err := dcnl().R().
		SetHeader("Content-Type", "application/sql").
		SetBody("select * from users limit 10").
		Query(ts.URL + "/")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "select * from users limit 10", resp.String())

	logResponse(t, resp)
}

func TestQueryMethodClassification(t *testing.T) {
	// QUERY is safe and idempotent per RFC 10008, so it must be treated as
	// read-only (hedging) and idempotent (automatic retries).
	assertEqual(t, true, isReadOnlyMethod(MethodQuery))

	r := dcnl().R()
	r.Method = MethodQuery
	assertEqual(t, true, r.isIdempotent())
}
