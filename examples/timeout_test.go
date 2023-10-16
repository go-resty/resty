package examples

import (
	"strings"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
)

// Example about setting timeout
func TestTimeout(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	req := resty.New().SetTimeout(1*time.Microsecond).R()
	_, err:= req.Get(ts.URL+"/sleep/2")
	assertNotEqual(t, nil, err)
	assertEqual(t, true, strings.Contains(err.Error(), "Client.Timeout exceeded"))

}
