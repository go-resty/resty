package examples

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-resty/resty/v3"
)

// Example about sending cookie
func TestSendCookie(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	data := struct {
		Cookies struct{ Token string }
	}{}

	resp, err := resty.New().R().SetResult(&data).SetHeader("Cookie", "token=1234").Get(ts.URL + "/cookie/count")
	if err != nil {
		panic(err)
	}
	if data.Cookies.Token != "1234" {
		t.Errorf("Can not read cookie from response:%s", resp.String())
	}

}

// Test session Cookie
func TestSessionCookie(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	result := struct {
		Cookies struct {
			Count string
			Name1 string
			Name2 string
		}
	}{}
	cookie1 := &http.Cookie{
		Name:  "name1",
		Value: "value1",
		Path:  "/",
	}
	cookie2 := &http.Cookie{
		Name:  "name2",
		Value: "value2",
	}
	session := resty.New().SetDebug(true).R()

	// 1. set cookie1
	session.SetCookie(cookie1).Get(ts.URL + "/cookie/count")

	// 2. set cookie2 and get all cookies
	resp, err := session.SetCookie(cookie2).SetResult(&result).Get(ts.URL + "/cookie/count")
	if err != nil {
		t.Fatal(err)
	}
	cookies := map[string]string{}
	// cookies's type is `[]*http.Cookies`
	for _, c := range resp.Cookies() {
		if _, exists := cookies[c.Name]; exists {
			t.Fatal("duplicated cookie:", c.Name, c.Value)
		}
		cookies[c.Name] = c.Value
	}
	if cookies["count"] != "2" {
		t.Fatalf("cookie count is not 2(%+v)", resp.Cookies())
	}

	if result.Cookies.Name1 != "value1" || result.Cookies.Name2 != "value2" {
		t.Fatalf("Failed to send valid cookie(%+v)", resp.Cookies())
	}

}

// Test session Cookie
func TestSessionCookieWithClone(t *testing.T) {
	ts := createHttpbinServer(0)
	url := ts.URL + "/cookie/count"
	defer ts.Close()

	client := resty.New()
	req := client.R()

	// 0. Prepare cookie1 and cookie2
	cookie1 := &http.Cookie{
		Name:  "name1",
		Value: "value1",
		Path:  "/",
	}
	cookie2 := &http.Cookie{
		Name:  "name2",
		Value: "value2",
	}

	// 1. Set cookie1
	client.SetCookie(cookie1)
	req.SetCookie(cookie1).Get(url)

	// 2. Set cookie2 and get all cookies
	resp, err := req.SetCookie(cookie2).Get(url)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Check cookies: client and response
	respCookies := map[string]string{}
	clientCookies := map[string]string{}
	// cookies's type is `[]*http.Cookies`
	// 3.1 Check response cookies
	for _, c := range resp.Cookies() {
		if _, exists := respCookies[c.Name]; exists {
			t.Fatal("duplicated cookie:", c.Name, c.Value)
		}
		respCookies[c.Name] = c.Value
	}
	// 3.2 Check client cookies
	for _, c := range client.Cookies {
		if _, exists := clientCookies[c.Name]; exists {
			t.Fatal("duplicated cookie:", c.Name, c.Value)
		}
		clientCookies[c.Name] = c.Value
	}
	if clientCookies["name1"] != "value1" || respCookies["count"] == "" {
		t.Fatalf("bad cookie, respCookies=%+v, clientCookies=%+v", resp.Cookies(), client.Cookies)
	}

	// 4. Check response body
	body := resp.String()
	if (!strings.Contains(body, `"name1"`) ||
		!strings.Contains(body, `"name2"`) || 
		!strings.Contains(body, `"count"`) ){
		t.Fatalf("invalid response: %s", body)
	}

}

// Test Set-Cookie
func TestResponseCookie(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	session := resty.New().R()
	resp, err := session.Get(ts.URL + "/cookie/count")
	if err != nil {
		t.Fatal(err)
	}

	cs := resp.Cookies()
	if len(cs) == 0 {
		t.Fatalf("require cookies, body=%s", resp.Body())
	}
}

func TestResponseBuildCookie(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	session := resty.New().R()
	resp, err := session.Get(ts.URL + "/cookie/count")
	if err != nil {
		t.Fatal(err)
	}

	// build new resposne
	cs := resp.Cookies()
	if len(cs) == 0 {
		t.Fatalf("require cookies, headers=%#v, body=%s", resp.Header(), resp.Body())
	}
	findCount := false
	for _, c := range cs {
		if c.Name == "count" && c.Value == "1" {
			findCount = true
		}
	}
	if !findCount {
		t.Fatalf("could not find cookie, headers=%#v", resp.Header())
	}
}
