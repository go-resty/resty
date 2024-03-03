package examples

import (
	"strings"
	"testing"

	"github.com/go-resty/resty/v3"
)

// Example about sending Authentication header
func TestAuth(t *testing.T) {
	var curlCmdExecuted string
	ts := createEchoServer()
	defer ts.Close()
	// Test authentication usernae and password
	client := resty.New()
	resp, err := client.R().
	SetBasicAuth("USER", "PASSWORD").
	SetResultCurlCmd(&curlCmdExecuted).
	Get( ts.URL+"/echo",)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(curlCmdExecuted, "Authorization: Basic ") {
		t.Fatal("bad curl:", curlCmdExecuted)
	}
	if !strings.Contains(string(resp.Body()), "Authorization: Basic ") {
		t.Fatal("bad auth body:\n" + resp.String())
	}
	t.Log(curlCmdExecuted)
}
