package examples

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/go-resty/resty/v2"
)

// 1. Generate curl for unexecuted request(dry-run)
func TestGenerateUnexcutedCurl(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	req := resty.New().R().SetBody(map[string]string{
		"name": "Alex",
	}).SetCookies(
		[]*http.Cookie{
			{Name: "count", Value: "1"},
		},
	)

	curlCmdUnexecuted := req.GenerateCurlCommand()

	if !strings.Contains(curlCmdUnexecuted, "Cookie: count=1") ||
		!strings.Contains(curlCmdUnexecuted, "curl -X GET") ||
		!strings.Contains(curlCmdUnexecuted, `-d '{"name":"Alex"}'`) {
		t.Fatal("Incomplete curl:", curlCmdUnexecuted)
	} else {
		t.Log("curlCmdUnexecuted: \n", curlCmdUnexecuted)
	}

}

// 2. Generate curl for executed request
func TestGenerateExecutedCurl(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	data := map[string]string{
		"name": "Alex",
	}
	req := resty.New().R().SetBody(data).SetCookies(
		[]*http.Cookie{
			{Name: "count", Value: "1"},
		},
	)

	url := ts.URL + "/post"
	resp, err := req.
		EnableTrace().
		Post(url)
	if err != nil {
		t.Fatal(err)
	}
	curlCmdExecuted := resp.Request.GenerateCurlCommand()
	if !strings.Contains(curlCmdExecuted, "Cookie: count=1") ||
		!strings.Contains(curlCmdExecuted, "curl -X POST") ||
		!strings.Contains(curlCmdExecuted, `-d '{"name":"Alex"}'`) ||
		!strings.Contains(curlCmdExecuted, url) {
		t.Fatal("Incomplete curl:", curlCmdExecuted)
	} else {
		t.Log("curlCmdExecuted: \n", curlCmdExecuted)
	}
}

// 3. Generate curl in debug mode
func TestDebugModeCurl(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	// 1. Capture stderr
	getOutput, restore := captureStderr()
	defer restore()

	// 2. Build request
	req := resty.New().R().SetBody(map[string]string{
		"name": "Alex",
	}).SetCookies(
		[]*http.Cookie{
			{Name: "count", Value: "1"},
		},
	)

	// 3. Execute request: set debug mode
	url := ts.URL + "/post"
	_, err := req.SetDebug(true).Post(url)
	if err != nil {
		t.Fatal(err)
	}

	// 4. test output curl
	output := getOutput()
	if !strings.Contains(output, "Cookie: count=1") ||
		!strings.Contains(output, `-d '{"name":"Alex"}'`) {
		t.Fatal("Incomplete debug curl info:", output)
	} else {
		t.Log("Normal debug curl info: \n", output)
	}
}

func captureStderr() (getOutput func() string, restore func()) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	os.Stderr = w
	getOutput = func() string {
		w.Close()
		buf := make([]byte, 2048)
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		return string(buf[:n])
	}
	restore = func() {
		os.Stderr = old
		w.Close()
	}
	return getOutput, restore
}
