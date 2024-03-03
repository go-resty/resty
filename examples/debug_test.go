package examples

import (
	"testing"

	"github.com/go-resty/resty/v3"
)

// Example about debuging/showing request and response
func TestDebugRequestAndResponse(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	client := resty.New().SetDebug(true)
	req := client.R().SetBody(MapString{ "name": "Alex", })
	_, err := req.Post(ts.URL+"/post",)
	if err != nil {
		t.Fatal(err)
	}
}
