package resty

import (
	"bytes"
	"io"
	"net/http"

	"net/url"
	"strings"

	"github.com/go-resty/resty/v3/shellescape"
)

func buildCurlRequest(req *Request) (curl string) {
	// 1. Generate curl raw headers
	curl = "curl -X " + req.Method + " "
	// req.Host + req.URL.Path + "?" + req.URL.RawQuery + " " + req.Proto + " "
	headers := dumpCurlHeaders(req.RawRequest)
	for _, kv := range *headers {
		curl += `-H ` + shellescape.Quote(kv[0]+": "+kv[1]) + ` `
	}

	// 2. Generate curl cookies
	// TODO validate this block of code, I think its not required since cookie captured via Headers
	if cookieJar := req.client.CookieJar(); cookieJar != nil {
		if cookies := cookieJar.Cookies(req.RawRequest.URL); len(cookies) > 0 {
			curl += ` -H ` + shellescape.Quote(dumpCurlCookies(cookies)) + " "
		}
	}

	// 3. Generate curl body
	if req.RawRequest.GetBody != nil {
		body, err := req.RawRequest.GetBody()
		if err != nil {
			return ""
		}
		buf, _ := io.ReadAll(body)
		curl += `-d ` + shellescape.Quote(string(bytes.TrimRight(buf, "\n")))
	}

	urlString := shellescape.Quote(req.RawRequest.URL.String())
	if urlString == "''" {
		urlString = "'http://unexecuted-request'"
	}
	curl += " " + urlString
	return curl
}

// dumpCurlCookies dumps cookies to curl format
func dumpCurlCookies(cookies []*http.Cookie) string {
	sb := strings.Builder{}
	sb.WriteString("Cookie: ")
	for _, cookie := range cookies {
		sb.WriteString(cookie.Name + "=" + url.QueryEscape(cookie.Value) + "&")
	}
	return strings.TrimRight(sb.String(), "&")
}

// dumpCurlHeaders dumps headers to curl format
func dumpCurlHeaders(req *http.Request) *[][2]string {
	headers := [][2]string{}
	for k, vs := range req.Header {
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
	return &headers
}
