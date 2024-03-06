package examples

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	ioutil "io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxMultipartMemory = 4 << 30 // 4MB


// tlsCert:
//
//	0 no certificate
//	1 with self-signed certificate
//	2 with custom certificate from CA
func createHttpbinServer(tlsCert int) (ts *httptest.Server) {
	ts = createTestServer(func(w http.ResponseWriter, r *http.Request) {
		const pathPattern = "^/(get|post|put|patch|delete)$"
		isMethodPath, _:= regexp.MatchString(pathPattern, r.URL.Path)
		switch path := r.URL.Path; {
		case isMethodPath:
			httpbinHandler(w, r)
		case strings.HasPrefix(path, "/sleep/"): //sleep/3
			sleepHandler(w, r)
		case path == "/cookie/count":
			cookieHandler(w, r)
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte("404 " + path))
		}
	}, tlsCert)

	return ts
}

func httpbinHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	body, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body)) // important!!
	m := map[string]interface{}{
		"headers": dumpRequestHeader(r),
		"args":    parseRequestArgs(r),
		"body":    string(body),
		"method":  r.Method,
	}

	// 1. parse text/plain
	if strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") {
		m["data"] = string(body)
	}

	// 2. parse application/json
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var data interface{}
		if err := json.Unmarshal(body, &data); err!=nil{
			m["err"] = err.Error()
		}else{
			m["json"] = data
		}
	}

	// 3. parse application/x-www-form-urlencoded
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		m["form"] = parseQueryString(string(body))
	}

	// 4. parse multipart/form-data
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		form, files:= readMultipartForm(r)
		m["form"] = form
		m["files"] = files
	}
	buf, _ := json.Marshal(m)
	_, _ = w.Write(buf)
}


func readMultipartForm(r *http.Request) (map[string]string, map[string]string){
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

func sleepHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	regx := regexp.MustCompile(`^/sleep/(\d+)`)
	res := regx.FindStringSubmatch(r.URL.Path) // res may be: []string(nil)
	miliseconds := 0
	if res != nil {
		miliseconds, _ = strconv.Atoi(res[1])
	}
	time.Sleep(time.Duration(miliseconds) * time.Microsecond)
	out := fmt.Sprintf("sleep %d ms", miliseconds)
	_, _ = w.Write([]byte(out))
}

func cookieHandler(w http.ResponseWriter, r *http.Request) {

	switch r.URL.Path {
	case "/cookie/count":
		reqCookies := map[string]string{}
		for _, c := range r.Cookies() {
			reqCookies[c.Name] = c.Value
		}

		count := "1"
		cookie, err := r.Cookie("count")
		if err == nil {
			i, _ := strconv.Atoi(cookie.Value)
			count = strconv.Itoa(i + 1)
		}
		http.SetCookie(w, &http.Cookie{Name: "count", Value: url.QueryEscape(count)})
		w.Header().Set("Content-Type", "application/json")

		body, _ := ioutil.ReadAll(r.Body)
		m := map[string]interface{}{
			"args":    parseRequestArgs(r),
			"body":    string(body),
			"count":   count,
			"cookies": reqCookies,
			"headers": dumpRequestHeader(r),
		}
		buf, _ := json.Marshal(m)
		_, _ = w.Write(buf)
	default:
		w.WriteHeader(404)
		_, _ = w.Write([]byte("404 " + r.URL.Path))
	}
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

func createEchoServer() (ts *httptest.Server) {
	ts = createTestServer(func(w http.ResponseWriter, r *http.Request) {
		res := dumpRequest(r)
		_, _ = w.Write([]byte(res))
	}, 0)

	return ts
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

func dumpRequest(request *http.Request) string {
	var r strings.Builder
	// dump header
	res := request.Method + " " + //request.URL.String() +" "+
		request.Host +
		request.URL.Path + "?" + request.URL.RawQuery + " " + request.Proto + " " +
		"\n"
	r.WriteString(res)
	r.WriteString(dumpRequestHeader(request))
	r.WriteString("\n")

	// dump body
	buf, _ := ioutil.ReadAll(request.Body)
	request.Body = ioutil.NopCloser(bytes.NewBuffer(buf)) // important!!
	r.WriteString(string(buf))
	return r.String()
}

/*
*
  - tlsCert:
    0 no certificate
    1 with self-signed certificate
    2 with custom certificate from CA
*/
func createTestServer(fn func(w http.ResponseWriter, r *http.Request), tlsCert int) (ts *httptest.Server) {
	if tlsCert == 0 {
		// 1. http test server
		ts = httptest.NewServer(http.HandlerFunc(fn))
	} else {
		// 2. https test server: https://stackoverflow.com/questions/54899550/create-https-test-server-for-any-client
		ts = httptest.NewUnstartedServer(http.HandlerFunc(fn))

		// 3. use own cert
		if tlsCert == 2 {
			cert, err := tls.LoadX509KeyPair("../conf/nginx.crt", "../conf/nginx.key")
			if err != nil {
				panic(err)
			}
			_ = cert
			ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		}
		ts.StartTLS()
	}
	return ts
}
