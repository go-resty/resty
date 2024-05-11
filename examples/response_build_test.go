package examples

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/go-resty/resty/v3"
)

// Example about building response
func TestResponseBuilder(t *testing.T) {
	var err error
	var data = 1
	responseBytes, _ := json.Marshal(data)

	respRecorder := httptest.NewRecorder()
	respRecorder.Write(responseBytes)

	request := resty.New().R()
	// build response
	resp := resty.Response{
		Request: request,
		RawResponse :respRecorder.Result(),
		// body: []byte("abc"),
	}
	// if resp.body, err = io.ReadAll(resp.RawResponse.Body); err != nil {
	// 	t.Fatalf("err:%v", err)
	// }
	ndata, err := io.ReadAll(resp.RawResponse.Body) 
	if err != nil {
		t.Fatalf("err:%v", err)
	}

	if !bytes.Equal(ndata , responseBytes) {
		t.Fatalf("expect response:%v", data)
	}

}
