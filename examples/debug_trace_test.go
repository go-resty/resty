package examples

import (
	"testing"

	"github.com/go-resty/resty/v3"
)

// Example about getting trace info
func TestTrace(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	client := resty.New().EnableTrace()
	req := client.R().SetBody(MapString{ "name": "Alex", })
	resp, err := req.Post(ts.URL+"/post",)
	if err != nil {
		t.Fatal(err)
	}
	traceInfo := resp.Request.TraceInfo()
	if traceInfo.TotalTime <= 0 {
		t.Fatalf("invalid traceInfo: %+v\n body:%s", traceInfo, resp.String())
	}
}
