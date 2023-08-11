package examples

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-resty/resty/v3"
)

// Example about retrying request
func TestRetryCondition(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	// retry 3 times
	maxRetries := 2
	r := resty.New().
	SetRetryCount(maxRetries).
	SetRetryWaitTime(time.Microsecond).
	SetRetryMaxWaitTime(time.Microsecond).
	AddRetryCondition(
		func(r *resty.Response, _ error) bool {
			var data map[string]interface{}
			err:=json.Unmarshal(r.Body(), &data)
			if err != nil {
				return true
			}
			return data["headers"] != "a"
		},
	) .R()

	var data struct{
		Body string
		Method string
	}
	resp, err := r.SetBody([]byte("alex")).SetResult(&data).Post(ts.URL+"/post", )
	if err != nil {
		t.Fatal(err, resp.String())
	}

	if resp.Request.Attempt != maxRetries+1 {
		t.Fatalf("Attempt %d, expected: %d", resp.Request.Attempt, maxRetries+1)
	}

	if data.Body != "alex" {
		t.Fatalf("Bad response body:%s", resp.String())
	}
	if data.Method != "POST" {
		t.Fatalf("Bad request method:%s", resp.String())
	}
}

// func TestRetryConditionFalse(t *testing.T) {
// 	ts := createHttpbinServer(0)
// 	defer ts.Close()

// 	// retry 3 times
// 	r := requests.R().
// 		SetRetryCount(3).
// 		SetRetryCondition(func(resp *requests.Response, err error) bool {
// 			return false
// 		})

// 	resp, err := r.Get(ts.URL + "/get")
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	if resp.Attempt != 0 {
// 		t.Fatalf("Attemp %d not equal to %d", resp.Attempt, 0)
// 	}

// 	var json map[string]interface{}
// 	resp.Json(&json)
// 	t.Logf("response json:%#v\n", json["headers"])
// }
