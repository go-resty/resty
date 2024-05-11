package examples

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-resty/resty/v2"
)

// Example about generating curl command
func TestDebugCurl(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	req := resty.New().R().SetBody(map[string]string{
		"name": "Alex",
	}).SetCookies(
		[]*http.Cookie{
			{ Name:  "count", Value: "1", }, 
		},
	)

	// 1. Generate curl for request(dry-run: request isn't executed)
	curlCmdUnexecuted := req.GetCurlCmd()
	if !strings.Contains(curlCmdUnexecuted, "Cookie: count=1") || !strings.Contains(curlCmdUnexecuted, "curl -X GET") {
		t.Fatal("bad curl:", curlCmdUnexecuted)
	}else{
		t.Log("curlCmdUnexecuted: \n",curlCmdUnexecuted)
	}

	// 2. Generate curl for request(request is executed)
	var curlCmdExecuted string
	req.SetResultCurlCmd(&curlCmdExecuted)
	if _, err := req.Post(ts.URL+"/post"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(curlCmdExecuted, "Cookie: count=1") || !strings.Contains(curlCmdExecuted, "curl -X POST") {
		t.Fatal("bad curl:", curlCmdExecuted)
	}else{
		t.Log("curlCmdExecuted: \n",curlCmdExecuted)
	}
}