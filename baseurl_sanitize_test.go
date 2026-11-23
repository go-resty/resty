package resty

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSetBaseURLStripsFragmentAndEmptyQuery is the regression test for
// Client.SetBaseURL keeping a fragment or an empty query in the stored
// base URL. Request URLs are composed by string concatenation, so
// "https://host/api#frag" + "/users" sent the request to "/api" with
// "/users" swallowed into the fragment, and "https://host/api?" +
// "/users" turned the path into the query string. Load balancer base
// URLs already strip these (extractBaseURL); the client base URL did not.
func TestSetBaseURLStripsFragmentAndEmptyQuery(t *testing.T) {
	var gotPath, gotQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	for _, suffix := range []string{"/api#frag", "/api?", "/api#", "/api"} {
		gotPath, gotQuery = "", ""
		c := New().SetBaseURL(ts.URL + suffix)
		if _, err := c.R().Get("/users"); err != nil {
			t.Fatalf("base %q: request error: %v", suffix, err)
		}
		if gotPath != "/api/users" {
			t.Fatalf("base %q: expected path /api/users, got %q (query %q)", suffix, gotPath, gotQuery)
		}
		if gotQuery != "" {
			t.Fatalf("base %q: expected empty query, got %q", suffix, gotQuery)
		}
	}
}

// TestSetBaseURLPreservesValidURLs guards the sanitization against
// changing well-formed base URLs, including the trailing slash that
// request composition relies on.
func TestSetBaseURLPreservesValidURLs(t *testing.T) {
	for _, u := range []string{
		"https://example.com",
		"https://example.com/",
		"https://example.com/api/",
		"https://example.com/api",
		"http://127.0.0.1:8080/v1",
	} {
		if got := New().SetBaseURL(u).BaseURL(); got != u {
			t.Fatalf("SetBaseURL(%q): stored base URL changed to %q", u, got)
		}
	}

	if got := New().SetBaseURL("https://example.com/api#frag").BaseURL(); got != "https://example.com/api" {
		t.Fatalf("fragment not stripped from stored base URL: %q", got)
	}
	if got := New().SetBaseURL("https://example.com/api?").BaseURL(); got != "https://example.com/api" {
		t.Fatalf("empty query not stripped from stored base URL: %q", got)
	}
	// An unparseable base URL is stored unchanged; its error surfaces at
	// request time, as before.
	if got := New().SetBaseURL("://bad").BaseURL(); got != "://bad" {
		t.Fatalf("unparseable base URL changed: %q", got)
	}
}
