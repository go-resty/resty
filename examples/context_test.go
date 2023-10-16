package examples

import (
	"context"
	"net/http"
	"net/http/httptrace"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
)

// Example about cancel request with context
func TestSetContextCancelMulti(t *testing.T) {
	// 0. Init test server
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Microsecond)
		n, err := w.Write([]byte("TestSetContextCancel: response"))
		t.Logf("%s Server: wrote %d bytes", time.Now(), n)
		t.Logf("%s Server: err is %v ", time.Now(), err)
	}, 0)
	defer ts.Close()

	// 1. Create client
	ctx, cancel := context.WithCancel(context.Background())
	client := resty.New().R().SetContext(ctx)
	go func() {
		time.Sleep(1 * time.Microsecond)
		cancel()
	}()

	// 2. First request
	_, err := client.Get(ts.URL + "/get")
	if !errIsContextCancel(err) {
		t.Fatalf("Got unexpected error: %v", err)
	}

	// 3. Second request
	_, err = client.Get(ts.URL + "/get")
	if !errIsContextCancel(err) {
		t.Fatalf("Got unexpected error: %v", err)
	}
}

// Test context: cancel with chan
func TestSetContextCancelWithChan(t *testing.T) {
	ch := make(chan struct{})
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			ch <- struct{}{} // tell test request is finished
		}()
		t.Logf("%s Server: %v %v", time.Now(), r.Method, r.URL.Path)
		ch <- struct{}{} // tell test request is canceld
		t.Logf("%s Server: call canceld", time.Now())

		<-ch // wait for client to finish request
		n, err := w.Write([]byte("TestSetContextCancel: response"))
		// FIXME? test server doesn't handle request cancellation
		t.Logf("%s Server: wrote %d bytes", time.Now(), n)
		t.Logf("%s Server: err is %v ", time.Now(), err)

	}, 0)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-ch // wait for server to start request handling
		cancel()
	}()

	_, err := resty.New().R().SetContext(ctx).Get(ts.URL + "/get")
	t.Logf("%s:client:is canceled", time.Now())

	ch <- struct{}{} // tell server to continue request handling
	t.Logf("%s:client:tell server to continue", time.Now())

	<-ch // wait for server to finish request handling

	if !errIsContextCancel(err) {
		t.Fatalf("Got unexpected error: %v", err)
	}
}

// test with trace context
func TestContextWithTrace(t *testing.T) {
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("TestSetContextWithTrace: response"))
	}, 0)
	defer ts.Close()

	//1. Create Trace context
	traceInfo := struct {
		dnsDone     time.Time
		connectDone time.Time
	}{}

	trace := &httptrace.ClientTrace{
		ConnectStart: func(network, addr string) {
			traceInfo.dnsDone = time.Now()
			t.Log(time.Now(), "ConnectStart:", "network=", network, ",addr=", addr)
		},
		ConnectDone: func(network, addr string, err error) {
			traceInfo.connectDone = time.Now()
			t.Log(time.Now(), "ConnectDone:", "network=", network, ",addr=", addr)
		},
	}
	ctx := httptrace.WithClientTrace(context.Background(), trace)

	//2. Send request with Trace context
	session := resty.New().R().SetContext(ctx)
	params := MapString{"name": "ahuigo", "page": "1"}
	_, err := session.SetQueryParams(params).Get(ts.URL+"/get")
	if err != nil {
		t.Fatal(err)
	}
	if traceInfo.connectDone.Sub(traceInfo.dnsDone) <= 0 {
		t.Fatal("Bad trace info")
	}

}
