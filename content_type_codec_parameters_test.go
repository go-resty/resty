package resty

import (
	"encoding/csv"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func encodeCSV(w io.Writer, v any) error {
	return csv.NewWriter(w).WriteAll(v.([][]string))
}

func decodeCSV(r io.Reader, v any) error {
	rows, err := csv.NewReader(r).ReadAll()
	if err == nil {
		*v.(*[][]string) = rows
	}
	return err
}

func TestRegisteredEncoderHandlesMediaTypeParameters(t *testing.T) {
	for _, contentType := range []string{"text/csv; charset=utf-8", "text/csv; charset=UTF-8; header=present"} {
		t.Run(contentType, func(t *testing.T) {
			gotBody := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if r.Header.Get("Content-Type") != contentType {
					t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
				}
				gotBody <- string(body)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			client := New().AddContentTypeEncoder("text/csv", encodeCSV)
			defer client.Close()
			_, err := client.R().SetContentType(contentType).SetBody([][]string{{"name", "city"}, {"Alice", "Paris"}}).Post(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			if body := <-gotBody; body != "name,city\nAlice,Paris\n" {
				t.Fatalf("body = %q", body)
			}
		})
	}
}

func TestRegisteredDecoderHandlesMediaTypeParameters(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/csv; charset=utf-8")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "name,city\nAlice,Paris\n")
			}))
			defer server.Close()
			client := New().AddContentTypeDecoder("text/csv", decodeCSV)
			defer client.Close()
			var rows [][]string
			request := client.R()
			if status == http.StatusOK {
				request.SetResult(&rows)
			} else {
				request.SetResultError(&rows)
			}
			_, err := request.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(rows, [][]string{{"name", "city"}, {"Alice", "Paris"}}) {
				t.Fatalf("rows = %#v", rows)
			}
		})
	}
}

func TestExactContentTypeCodecsKeepPriority(t *testing.T) {
	const contentType = "text/csv; charset=utf-8"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != "specific" {
			t.Errorf("body = %q", body)
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = io.WriteString(w, "response")
	}))
	defer server.Close()
	client := New().
		AddContentTypeEncoder("text/csv", func(w io.Writer, v any) error { t.Error("base encoder used"); return nil }).
		AddContentTypeEncoder(contentType, func(w io.Writer, v any) error { _, err := io.WriteString(w, "specific"); return err }).
		AddContentTypeDecoder("text/csv", func(r io.Reader, v any) error { t.Error("base decoder used"); return nil }).
		AddContentTypeDecoder(contentType, func(r io.Reader, v any) error {
			b, err := io.ReadAll(r)
			*v.(*string) = strings.ToUpper(string(b))
			return err
		})
	defer client.Close()
	var result string
	_, err := client.R().SetContentType(contentType).SetBody(struct{}{}).SetResult(&result).Post(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if result != "RESPONSE" {
		t.Fatalf("result = %q", result)
	}
}
