package resty

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRequestReaderRetryPreservesStartingOffset(t *testing.T) {
	factories := map[string]func(*testing.T) io.ReadSeeker{
		"string": func(t *testing.T) io.ReadSeeker { return strings.NewReader("prefix-payload") },
		"bytes":  func(t *testing.T) io.ReadSeeker { return bytes.NewReader([]byte("prefix-payload")) },
		"file section": func(t *testing.T) io.ReadSeeker {
			f, err := os.CreateTemp(t.TempDir(), "request-body")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.Close() })
			if _, err := f.WriteString("prefix-payload"); err != nil {
				t.Fatal(err)
			}
			return io.NewSectionReader(f, 0, 14)
		},
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			var bodies []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				bodies = append(bodies, string(b))
				if len(bodies) == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			reader := factory(t)
			if _, err := reader.Seek(7, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			client := New().SetRetryCount(1).SetRetryWaitTime(time.Millisecond).AddRetryConditions(RetryConditionStatus5XX)
			defer client.Close()
			response, err := client.R().SetBody(reader).Put(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode() != http.StatusOK {
				t.Fatalf("status = %d", response.StatusCode())
			}
			if !reflect.DeepEqual(bodies, []string{"payload", "payload"}) {
				t.Fatalf("attempt bodies = %#v", bodies)
			}
		})
	}
}

func TestRequestReaderOffsetQueryErrorDoesNotPreventFirstAttempt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(body) != "payload" {
			t.Errorf("body = %q", body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := New().SetRetryCount(1)
	defer client.Close()
	_, err := client.R().SetBody(&seekErrorReader{r: strings.NewReader("payload"), err: io.ErrUnexpectedEOF}).Put(server.URL)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRequestReaderOffsetIsResetWhenRetryHookReplacesBody(t *testing.T) {
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		bodies = append(bodies, string(body))
		if len(bodies) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	reader := strings.NewReader("prefix-payload")
	if _, err := reader.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	client := New().SetRetryCount(1).SetRetryWaitTime(time.Millisecond).
		AddRetryConditions(RetryConditionStatus5XX).
		AddRetryHooks(func(res *Response, _ error) { res.Request.SetBody(strings.NewReader("replacement")) })
	defer client.Close()
	_, err := client.R().SetBody(reader).Put(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bodies, []string{"payload", "replacement"}) {
		t.Fatalf("bodies = %#v", bodies)
	}
}
