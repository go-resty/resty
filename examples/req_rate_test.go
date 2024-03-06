package examples

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"golang.org/x/time/rate"
)

func TestRateLimiter(t *testing.T) {
	ts := createHttpbinServer(0)
	defer ts.Close()

	// Test a burst with a valid capacity and then a consecutive request that must fail.

	// Allow a rate of 1 every 100 ms but also allow bursts of 10 requests.
	client := resty.New().SetRateLimiter(rate.NewLimiter(rate.Every(100*time.Millisecond), 10))

	// Execute a burst of 10 requests.
	for i := 0; i < 10; i++ {
		resp, err := client.R().
			SetQueryParam("request_no", strconv.Itoa(i)).Get(ts.URL + "/get")
		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
	}
	// Next request issued directly should fail because burst of 10 has been consumed.
	{
		_, err := client.R().
			SetQueryParam("request_no", strconv.Itoa(11)).Get(ts.URL + "/get")
		assertErrorIs(t, resty.ErrRateLimitExceeded, err)
	}

	// Test continues request at a valid rate

	// Allow a rate of 1 every ms with no burst.
	client = resty.New().SetRateLimiter(rate.NewLimiter(rate.Every(1*time.Millisecond), 1))

	// Sending requests every ms+tiny delta must succeed.
	for i := 0; i < 100; i++ {
		resp, err := client.R().
			SetQueryParam("request_no", strconv.Itoa(i)).Get(ts.URL + "/get")
		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		time.Sleep(1*time.Millisecond + 100*time.Microsecond)
	}
}
