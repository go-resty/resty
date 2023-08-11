package examples

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-resty/resty/v3"
)

// Example about generating curl command
func TestDebugCurl(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	req := resty.New().R().SetBody(MapString{
		"name": "Alex",
	}).SetCookies(
		[]*http.Cookie{
			{ Name:  "count", Value: "1", }, 
		},
	)

	// 1. Generate curl for request(not executed)
	curlCmdUnexecuted := req.GetCurlCmd()
	if !strings.Contains(curlCmdUnexecuted, "Cookie: count=1") || !strings.Contains(curlCmdUnexecuted, "curl -X GET") {
		t.Fatal("bad curl:", curlCmdUnexecuted)
	}

	// 2. Generate curl for request(executed)
	var curlCmdExecuted string
	req.SetResultCurlCmd(&curlCmdExecuted)
	if _, err := req.Post(ts.URL+"/post"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(curlCmdExecuted, "Cookie: count=1") || !strings.Contains(curlCmdExecuted, "curl -X POST") {
		t.Fatal("bad curl:", curlCmdExecuted)
	}
}