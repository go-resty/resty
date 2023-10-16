/**
 * refer to: git@github.com:go-resty/resty.git
 */
package examples

import (
	"net/http"
	"testing"

	"github.com/go-resty/resty/v2"
)

// Example about using custom transport
func TestTransportSet(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	session := resty.New()

	// tsp:= otelhttp.NewTransport(http.DefaultTransport)
	tsp := http.DefaultTransport.(*http.Transport).Clone()
	tsp.MaxIdleConnsPerHost = 1
	tsp.MaxIdleConns = 1
	tsp.MaxConnsPerHost = 1
	session.SetTransport(tsp)

	resp, err := session.R().Get(ts.URL + "/sleep/11")
	if err != nil {
		t.Fatal(err)
	}
	body :=  string(resp.Body())
	if body== "" {
		t.Fatal("emptay body")
	}
}
