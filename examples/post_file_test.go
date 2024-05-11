package examples

import (
	"path/filepath"
	"testing"

	"github.com/go-resty/resty/v3"
)

/*
An example about post `file` with `form data`:
curl "https://www.httpbin.org/post" -F 'file1=@./test-file.txt'  -F 'name=alex'
*/
func TestPostFile(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	var data = struct {
		Body string
		Files struct {
			File1 string
		}
		Form struct {
			Name string
		}
	}{}
	r:=resty.New().R().SetFormData(MapString{
			"name": "Alex",
	}).
	SetFile("file1", filepath.Join(getTestDataPath(),"text-file.txt")).
	SetResult(&data)

	// 2. Post file
	resp, err := r.Post( ts.URL+"/post",)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Check response
	if data.Files.File1 == "" {
		t.Error("invalid response files:", resp.String())
	}
	if data.Form.Name == "" {
		t.Error("invalid response forms:", resp.String())
	}

}
