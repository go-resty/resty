package examples

import (
	"testing"

	"github.com/go-resty/resty/v2"
)

// Example about using proxy
func TestProxy(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	var json map[string]interface{}
	client := resty.New().SetProxy("http://proxy:8888")
	client.RemoveProxy() // remove proxy. TODO: mock proxy server in future
	_, err := client.R().SetResult(&json).Get(ts.URL + "/get")
	if err != nil {
		t.Fatal(err)
	}else {
		t.Logf("response json:%#v\n", json)
	}
}
