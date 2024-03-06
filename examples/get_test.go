package examples

import (
	"net/url"
	"testing"

	"github.com/go-resty/resty/v2"
)

var client = resty.New()

// Example about sending GET request

// Get example: fetch json response
func TestGetJson(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	var json map[string]interface{}
	_, err := resty.New().R().SetResult(&json).Get(ts.URL + "/get")
	if err != nil {
		t.Fatal(err)
	}else {
		t.Logf("response json:%#v\n", json)
	}
}

// Get example: fetch string response
func TestGetBody(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	resp, err := resty.New().R().Get(ts.URL + "/get")
	if err != nil {
		t.Fatal(err)
	}else {
		t.Logf("response body:%#v\n", string(resp.Body()))
	}
}

// Get with params
func TestGetParams(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	type HbResponse struct {
		Args map[string]string `json:"args"`
	}
	json := &HbResponse{}
	params := map[string]string{"name": "Alex", "page": "1"}
	resp, err := client.R().SetQueryParams(params).SetResult(&json).Get(ts.URL + "/get")

	if err != nil {
		t.Fatal(err)
	}
	if err == nil {
		if json.Args["name"] != "Alex" {
			t.Fatalf("bad json:%s", string(resp.Body()))
		}
	}
}

type MapString= map[string]string


// Support array args like: ids=id1&ids=id2&ids=id3
func TestGetParamArray(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	paramsArray := url.Values{
		"ids": []string{"id1", "id2"},
	}

	type HbResponse struct {
		Args map[string]string `json:"args"`
	}
	json := &HbResponse{}
	resp, err := client.R().SetQueryParamsFromValues(paramsArray).SetResult(&json).Get(ts.URL + "/get")

	if err != nil {
		t.Fatal(err)
	}
	if err == nil {
		if json.Args["ids"] != "id1,id2" {
			t.Fatal("Invalid response: " + string(resp.Body()))
		}
	}
}

func TestGetWithHeader(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

		type HbResponse struct {
			Args map[string]string `json:"args"`
		}
		json := &HbResponse{}
	params := MapString{"name": "Alex"}
	resp, err := client.R().SetResult(&json).SetQueryParams(params).Get(ts.URL+"/get",)

	if err != nil {
		t.Fatal(err)
	}
	if err == nil {
		t.Log(string(resp.Body()))
	}
}
