package examples

import (
	"bytes"
	"encoding/json"
	"fmt"
	ioutil "io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
)

const maxMultipartMemory = 4 << 30 // 4MB

// tlsCert:
//
//	0 No certificate
//	1 With self-signed certificate
//	2 With custom certificate from CA(todo)
func createHttpbinServer(tlsCert int) (ts *httptest.Server) {
	ts = createTestServer(func(w http.ResponseWriter, r *http.Request) {
		httpbinHandler(w, r)
	}, tlsCert)

	return ts
}

func httpbinHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	body, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body)) // important!!
	m := map[string]interface{}{
		"args":    parseRequestArgs(r),
		"headers": dumpRequestHeader(r),
		"data":    string(body),
		"json": nil,
		"form":   map[string]string{},
		"files":   map[string]string{},
		"method":  r.Method,
		"origin":  r.RemoteAddr,
		"url":     r.URL.String(),
	}

	// 1. parse text/plain
	if strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") {
		m["data"] = string(body)
	}

	// 2. parse application/json
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var data interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			m["err"] = err.Error()
		} else {
			m["json"] = data
		}
	}

	// 3. parse application/x-www-form-urlencoded
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		m["form"] = parseQueryString(string(body))
	}

	// 4. parse multipart/form-data
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		form, files := readMultipartForm(r)
		m["form"] = form
		m["files"] = files
	}
	buf, _ := json.Marshal(m)
	_, _ = w.Write(buf)
}

func readMultipartForm(r *http.Request) (map[string]string, map[string]string) {
	if err := r.ParseMultipartForm(maxMultipartMemory); err != nil {
		if err != http.ErrNotMultipart {
			panic(fmt.Sprintf("error on parse multipart form array: %v", err))
		}
	}
	// parse form data
	formData := make(map[string]string)
	for k, vs := range r.PostForm {
		for _, v := range vs {
			formData[k] = v
		}
	}
	// parse files
	files := make(map[string]string)
	if r.MultipartForm != nil && r.MultipartForm.File != nil {
		for key, fhs := range r.MultipartForm.File {
			// if len(fhs)>0
			// f, err := fhs[0].Open()
			files[key] = fhs[0].Filename
		}
	}
	return formData, files
}

func dumpRequestHeader(req *http.Request) string {
	var res strings.Builder
	headers := sortHeaders(req)
	for _, kv := range headers {
		res.WriteString(kv[0] + ": " + kv[1] + "\n")
	}
	return res.String()
}

// sortHeaders
func sortHeaders(request *http.Request) [][2]string {
	headers := [][2]string{}
	for k, vs := range request.Header {
		for _, v := range vs {
			headers = append(headers, [2]string{k, v})
		}
	}
	n := len(headers)
	for i := 0; i < n; i++ {
		for j := n - 1; j > i; j-- {
			jj := j - 1
			h1, h2 := headers[j], headers[jj]
			if h1[0] < h2[0] {
				headers[jj], headers[j] = headers[j], headers[jj]
			}
		}
	}
	return headers
}

func parseRequestArgs(request *http.Request) map[string]string {
	query := request.URL.RawQuery
	return parseQueryString(query)
}

func parseQueryString(query string) map[string]string {
	params := map[string]string{}
	paramsList, _ := url.ParseQuery(query)
	for key, vals := range paramsList {
		// params[key] = vals[len(vals)-1]
		params[key] = strings.Join(vals, ",")
	}
	return params
}

/*
*
  - tlsCert:
    0 no certificate
    1 with self-signed certificate
    2 with custom certificate from CA(todo)
*/
func createTestServer(fn func(w http.ResponseWriter, r *http.Request), tlsCert int) (ts *httptest.Server) {
	if tlsCert == 0 {
		// 1. http test server
		ts = httptest.NewServer(http.HandlerFunc(fn))
	} else if tlsCert == 1{
		// 2. https test server: https://stackoverflow.com/questions/54899550/create-https-test-server-for-any-client
		ts = httptest.NewUnstartedServer(http.HandlerFunc(fn))
		ts.StartTLS()
	}
	return ts
}
