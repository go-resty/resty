package examples

import (
	"fmt"
	"testing"

	"github.com/go-resty/resty/v3"
)

// Example about using response
func TestResponse(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	request := resty.New().R()
	resp, _ := request.Get(ts.URL + "/get")
	fmt.Println("Status Code:", resp.StatusCode())
	fmt.Println("Time:", resp.Time())
	fmt.Println("Size:", resp.Size())
	fmt.Println("Headers:")
	for key, value := range resp.Header() {
		fmt.Println(key, "=", value)
	}
	fmt.Println("Cookies:")
	for i, cookie := range resp.Cookies() {
		fmt.Printf("cookie%d: name:%s value:%s\n", i, cookie.Name, cookie.Value)
	}

}

// Test response headers
func TestResponseHeader(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	request := resty.New().R()
	resp, _ := request.Get(ts.URL + "/get")

	if resp.Header().Get("content-type") != "application/json" {
		t.Fatal("bad response header")
	}

	println("content-type:", resp.Header().Get("content-type"))
}

// Test response body
func TestResponseBody(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	request := resty.New().R()
	resp, _ := request.Get(ts.URL + "/get")
	println(resp.Body())
	println(resp.String())
}
