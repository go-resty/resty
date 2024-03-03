package examples

import (
	"testing"

	"github.com/go-resty/resty/v3"
)

// Example about sending headers
func TestSendHeader(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	json := struct{
		Args struct{
			Name string 
			Age string `json:"age"`
		}
	}{}
	_, err := resty.New().
	SetDebug(true).
	R().
	SetHeader("Content-Type", "application/x-www-form-urlencoded").
	SetQueryString("name=Alex&age=29").
	SetResult(&json).
	Get(ts.URL + "/get")
	if err != nil {
		t.Fatal(err)
	}
	if json.Args.Age != "29" {
		t.Fatalf("invalid json:%v\n", json)
	}
}
