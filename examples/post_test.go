package examples

import (
	ejson "encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-resty/resty/v2"
)

// Example about sending POST request

// Post Params: use <QueryString> with content-type: none
// curl -X POST "https://www.httpbin.org/post?name=Alex"
func TestPostParams(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	var data = struct {
		Args struct {
			Name string
		}
	}{}
	resp, err := resty.New().R().SetResult(&data).SetQueryParams(MapString{"name":"Alex"}).Post(
		ts.URL+"/post",
	)
	if err != nil {
		t.Fatal(err)
	}
	if data.Args.Name != "Alex" {
		t.Fatal("invalid response body:", resp.String())
	}
}

// Post Datas: use <Form UrlEncoded data> with application/x-www-form-urlencoded
// curl -H 'Content-Type: application/x-www-form-urlencoded' https://www.httpbin.org/post -d 'name=Alex'
func TestPostFormUrlEncode(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	var data = struct {
		Body string
	}{}
	r:=resty.New().R().SetFormDataFromValues(url.Values{
			"name": []string{"Alex"},
	}).SetResult(&data)
	resp, err := r.Post( ts.URL+"/post",)
	if err != nil {
		t.Fatal(err)
	}
	if data.Body != "name=Alex" {
		t.Fatal("invalid response body:", resp.String())
	}
}

// POST FormData: multipart/form-data; boundary=....
// curl https://www.httpbin.org/post -F 'name=Alex' -F "file1=@./testdata/text-file.txt"
func TestPostFormData(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	var data = struct {
		Body string
	}{}
	r:=resty.New().R().SetFormData(MapString{
			"name": "Alex",
	}).SetFile("file1", filepath.Join(getTestDataPath(),"text-file.txt")).
	SetResult(&data)
	resp, err := r.Post( ts.URL+"/post",)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(data.Body, "form-data; name=\"name\"\r\n\r\nAlex\r\n") {
		t.Error("invalid response body:", resp.String())
	}
}

// POST Json: application/json
// curl -H "Content-Type: application/json" https://www.httpbin.org/post -d '{"name":"Alex"}'
func TestPostJson(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	json := MapString{
		"name": "Alex",
	}
	data := struct {
		Body string
	}{}
	r:=resty.New().R().SetBody(json).SetResult(&data)
	resp, err := r.Post(ts.URL+"/post")
	if err != nil {
		t.Fatal(err)
	}


	// is expected results
	jsonData, _ := ejson.Marshal(json) // if data.Data!= "{\"name\":\"Alex\"}"{
	if data.Body != string(jsonData) {
		t.Error("invalid response body:", resp.String())
	}
}

// Post Raw Bypes: text/plain(default)
// curl -H "Content-Type: text/plain" https://www.httpbin.org/post -d 'raw data: Hi, Jack!'
func TestRawBytes(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	rawText := "raw data: Hi, Jack!"
	var data = struct {
		Body string
	}{}
	r:=resty.New().R().SetBody([]byte(rawText)).SetResult(&data)
	resp, err := r.Post(ts.URL+"/post")
	if err != nil {
		t.Fatal(err)
	}
	if data.Body != rawText {
		t.Error("invalid response body:", resp.String())
	}
}

// Post Raw String: text/plain
// curl -H "Content-Type: text/plain" http://0:4500/post -d 'raw data: Hi, Jack!'
func TestRawString(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	var data interface{}
	rawText := "raw data: Hi, Jack!"
	r:=resty.New().R().SetHeader("Content-Type", "text/plain").SetBody([]byte(rawText)).SetResult(&data)
	resp, err := r.Post(ts.URL+"/post", )
	if err != nil {
		t.Fatal(err)
	}
	if data.(map[string]interface{})["body"].(string) != rawText {
		t.Error("invalid response body:", resp.String())
	}
}


// TestPostEncodedString: application/x-www-form-urlencoded
// curl -H 'Content-Type: application/x-www-form-urlencoded' http://0:4500/post -d 'name=Alex&age=29'
func TestPostEncodedString(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	var data = struct {
		Body string
	}{}
	r:=resty.New().
	SetDebug(true).
	R().
	SetHeader("Content-Type", "application/x-www-form-urlencoded").
	SetBody("name=Alex&age=29").
	SetResult(&data)
	resp, err := r.Post(ts.URL+"/post")
	if err != nil {
		t.Fatal(err)
	}
	if data.Body != "name=Alex\u0026age=29" {
		t.Error("invalid response body:", resp.String())
	}
}
