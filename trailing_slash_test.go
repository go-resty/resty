package resty

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBaseURLTrailingSlashRegression(t *testing.T) {
	var gotURI string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.RequestURI
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tests := []struct {
		baseURL string
		reqPath string
		wantURI string
	}{
		{ts.URL + "/api/", "", "/api/"},
		{ts.URL + "/api/", "/resource", "/api/resource"},
		{ts.URL + "/api", "/resource", "/api/resource"},
		{ts.URL + "/", "", "/"},
		{ts.URL, "/resource", "/resource"},
	}
	for _, tt := range tests {
		c := New().SetBaseURL(tt.baseURL)
		_, err := c.R().Get(tt.reqPath)
		if err != nil {
			t.Fatalf("baseURL=%q path=%q: %v", tt.baseURL, tt.reqPath, err)
		}
		if gotURI != tt.wantURI {
			t.Errorf("baseURL=%q path=%q: got URI %q, want %q", tt.baseURL, tt.reqPath, gotURI, tt.wantURI)
		}
	}
}
