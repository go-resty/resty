package examples

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"context"

	"github.com/go-resty/resty/v2"
)

// Example about error handling
func TestErrorConnnect(t *testing.T) {
	_, err := resty.New().R().Get("http://127.0.0.1:12346/connect-refused")
	var err2 *url.Error
	if !errors.As(err, &err2) {
		t.Fatalf("not expected url error:%+v", err)
	}
	if !strings.Contains(err2.Error(), "connection refused") {
		t.Fatalf("not expected connnect error:%+v", err2)
	}
}

func TestErrorTimeout(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	// resp, err := resty.New().Get("https://httpbin.org/json")
	_, err := resty.New().SetTimeout(1).R().Get(ts.URL + "/sleep/10")

	var err2 *url.Error
	if !errors.As(err, &err2) {
		t.Fatalf("not expected url error:%+v", err)
	}

	if !strings.Contains(err2.Error(), "context deadline exceeded") {
		t.Fatalf("unexpected error:%+v", err2)
	}

}

func TestErrorURL(t *testing.T) {
	_, err := resty.New().R().Get("xxxx")

	var err2 *url.Error
	if !errors.As(err, &err2) {
		t.Fatalf("not expected url error:%+v", err)
	}

	if err2.Op != "Get" {
		t.Fatalf("unexpected error(op=%s,err=%+v)", err2.Op,err2)
	}
}

func errIsContextCancel(err error) bool {
	var ue *url.Error
	ok := errors.As(err, &ue)
	if !ok {
		return false
	}
	return ue.Err == context.Canceled
}
