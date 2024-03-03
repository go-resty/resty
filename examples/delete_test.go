package examples

import (
	"fmt"
	"testing"

	"github.com/go-resty/resty/v3"
)

// Example about DELETE method with Form Request
func TestDeleteForm(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	json := MapString{
		"name": "Alex",
	}
	data := struct {
		Body string
	}{}

	r:=resty.New().R().SetBody(&json).SetResult(&data)
	resp, err := r.Delete(ts.URL+"/delete")
	if err == nil {
		fmt.Println(resp.String())
	}

}
