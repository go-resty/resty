// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEventSourceSimpleFlow(t *testing.T) {
	es := createEventSource(t, "", nil, nil)

	messageCounter := 0
	messageFunc := func(e any) {
		event := e.(*SSE)
		assertEqual(t, strconv.Itoa(messageCounter), event.ID)
		assertTrue(t, strings.HasPrefix(event.Data, "The time is"))
		messageCounter++
		if messageCounter == 100 {
			es.Close()
		}
	}
	es.OnMessage(messageFunc, nil)

	counter := 0
	ts := createSSETestServer(
		t,
		10*time.Millisecond,
		func(w io.Writer) error {
			if counter == 100 {
				return fmt.Errorf("stop sending events")
			}
			_, err := fmt.Fprintf(w, "id: %v\ndata: The time is %s\n\n", counter, time.Now().Format(time.UnixDate))
			counter++
			return err
		},
	)
	defer ts.Close()

	es.SetURL(ts.URL)
	es.SetMethod(MethodPost)
	err := es.Get()
	assertNil(t, err)
	assertEqual(t, counter, messageCounter)
}

func TestEventSourceMultipleEventTypes(t *testing.T) {
	type userEvent struct {
		UserName string    `json:"username"`
		Message  string    `json:"msg"`
		Time     time.Time `json:"time"`
	}

	tm := time.Now().Add(-1 * time.Minute)
	userConnectCounter := 0
	userConnectFunc := func(e any) {
		data := e.(*userEvent)
		assertEqual(t, "username"+strconv.Itoa(userConnectCounter), data.UserName)
		assertTrue(t, data.Time.After(tm))
		userConnectCounter++
	}

	userMessageCounter := 0
	userMessageFunc := func(e any) {
		data := e.(*userEvent)
		assertEqual(t, "username"+strconv.Itoa(userConnectCounter), data.UserName)
		assertEqual(t, "Hello, how are you?", data.Message)
		assertTrue(t, data.Time.After(tm))
		userMessageCounter++
	}

	counter := 0
	es := createEventSource(t, "", func(any) {}, nil)
	ts := createSSETestServer(
		t,
		10*time.Millisecond,
		func(w io.Writer) error {
			if counter == 100 {
				es.Close()
				return fmt.Errorf("stop sending events")
			}

			id := counter / 2
			if counter%2 == 0 {
				event := fmt.Sprintf("id: %v\n"+
					"event: user_message\n"+
					`data: {"username": "%v", "time": "%v", "msg": "Hello, how are you?"}`+"\n\n",
					id,
					"username"+strconv.Itoa(id),
					time.Now().Format(time.RFC3339),
				)
				fmt.Fprint(w, event)
			} else {
				event := fmt.Sprintf("id: %v\n"+
					"event: user_connect\n"+
					`data: {"username": "%v", "time": "%v"}`+"\n\n",
					int(id),
					"username"+strconv.Itoa(int(id)),
					time.Now().Format(time.RFC3339),
				)
				fmt.Fprint(w, event)
			}

			counter++
			return nil
		},
	)
	defer ts.Close()

	es.SetURL(ts.URL).
		SetMethod(MethodPost).
		AddEventListener("user_connect", userConnectFunc, userEvent{}).
		AddEventListener("user_message", userMessageFunc, userEvent{})

	err := es.Get()
	assertNil(t, err)
	assertEqual(t, userConnectCounter, userMessageCounter)
}

func TestEventSourceOverwriteFuncs(t *testing.T) {
	messageFunc1 := func(e any) {
		assertNotNil(t, e)
	}
	es := createEventSource(t, "", messageFunc1, nil)

	message2Counter := 0
	messageFunc2 := func(e any) {
		event := e.(*SSE)
		assertEqual(t, strconv.Itoa(message2Counter), event.ID)
		assertTrue(t, strings.HasPrefix(event.Data, "The time is"))
		message2Counter++
		if message2Counter == 50 {
			es.Close()
		}
	}

	counter := 0
	ts := createSSETestServer(
		t,
		10*time.Millisecond,
		func(w io.Writer) error {
			if counter == 50 {
				return fmt.Errorf("stop sending events")
			}
			_, err := fmt.Fprintf(w, "id: %v\ndata: The time is %s\n\n", counter, time.Now().Format(time.UnixDate))
			counter++
			return err
		},
	)
	defer ts.Close()

	lb := new(bytes.Buffer)
	es.outputLogTo(lb)

	es.SetURL(ts.URL).
		OnMessage(messageFunc2, nil).
		OnOpen(func(url string, respHdr http.Header) {
			t.Log("from overwrite func", url, respHdr)
		}).
		OnError(func(err error) {
			t.Log("from overwrite func", err)
		})

	err := es.Get()
	assertNil(t, err)
	assertEqual(t, counter, message2Counter)

	logLines := lb.String()
	assertTrue(t, strings.Contains(logLines, "Overwriting an existing OnEvent callback"))
	assertTrue(t, strings.Contains(logLines, "Overwriting an existing OnOpen callback"))
	assertTrue(t, strings.Contains(logLines, "Overwriting an existing OnError callback"))
}

func TestEventSourceRetry(t *testing.T) {
	es := createEventSource(t, "", nil, nil)

	messageCounter := 2 // 0 & 1 connection failure
	messageFunc := func(e any) {
		event := e.(*SSE)
		assertEqual(t, strconv.Itoa(messageCounter), event.ID)
		assertTrue(t, strings.HasPrefix(event.Data, "The time is"))
		messageCounter++
		if messageCounter == 15 {
			es.Close()
		}
	}
	es.OnMessage(messageFunc, nil)

	counter := 0
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		if counter == 1 && r.URL.Query().Get("reconnect") == "1" {
			w.WriteHeader(http.StatusTooManyRequests)
			counter++
			return
		}
		if counter < 2 || counter == 7 {
			w.WriteHeader(http.StatusTooManyRequests)
			counter++
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		// for local testing allow it
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// Create a channel for client disconnection
		clientGone := r.Context().Done()

		rc := http.NewResponseController(w)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-clientGone:
				t.Log("Client disconnected")
				return
			case <-tick.C:
				if counter == 5 {
					fmt.Fprintf(w, "id: %v\nretry: abc\ndata: The time is %s\n\n", counter, time.Now().Format(time.UnixDate))
					counter++
					return
				}
				if counter == 15 {
					es.Close()
					return // stop sending events
				}
				fmt.Fprintf(w, "id: %v\nretry: 1\ndata: The time is %s\ndata\n\n", counter, time.Now().Format(time.UnixDate))
				counter++
				if err := rc.Flush(); err != nil {
					t.Log(err)
					return
				}
			}
		}
	})
	defer ts.Close()

	// first round
	es.SetURL(ts.URL)
	err1 := es.Get()
	assertNotNil(t, err1)

	// second round
	counter = 0
	messageCounter = 2
	es.SetRetryCount(1).
		SetURL(ts.URL + "?reconnect=1")
	err2 := es.Get()
	assertNotNil(t, err2)
}

func TestEventSourceTLSConfigerInterface(t *testing.T) {

	t.Run("set and get tls config", func(t *testing.T) {
		es := createEventSource(t, "", func(any) {}, nil)

		tc, err := es.tlsConfig()
		assertNil(t, err)
		assertNotNil(t, tc)

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		es.SetTLSClientConfig(tlsConfig)
		assertEqual(t, tlsConfig, es.TLSClientConfig())
	})

	t.Run("get tls config error", func(t *testing.T) {
		es := createEventSource(t, "", func(any) {}, nil)

		ct := &CustomRoundTripper1{}
		es.httpClient.Transport = ct
		assertNil(t, es.TLSClientConfig())
	})

	t.Run("set tls config", func(t *testing.T) {
		es := createEventSource(t, "", func(any) {}, nil)

		ct := &CustomRoundTripper2{}
		es.httpClient.Transport = ct

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		es.SetTLSClientConfig(tlsConfig)
		assertNotNil(t, es.TLSClientConfig())
	})

	t.Run("set tls config error", func(t *testing.T) {
		es := createEventSource(t, "", func(any) {}, nil)

		ct := &CustomRoundTripper2{returnErr: true}
		es.httpClient.Transport = ct

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		es.SetTLSClientConfig(tlsConfig)
		assertNil(t, es.TLSClientConfig())
	})
}

func TestEventSourceNoRetryRequired(t *testing.T) {
	es := createEventSource(t, "", func(any) {}, nil)
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	defer ts.Close()

	es.SetURL(ts.URL)
	err := es.Get()
	fmt.Println(err)
	assertTrue(t, strings.Contains(err.Error(), "400 Bad Request"))
}

func TestGH1044TrimHeader(t *testing.T) {
	t.Run("data is nil", func(t *testing.T) {
		result := trimHeader(0, nil)
		assertNil(t, result)
	})

	t.Run("data has double whitespace", func(t *testing.T) {
		data := []byte("data:  double whitespace message")
		result := trimHeader(5, data)
		assertTrue(t, result[0] == ' ')
	})

	t.Run("data has newline", func(t *testing.T) {
		data := []byte("data: newline message\n")
		result := trimHeader(5, data)
		assertTrue(t, result[len(result)-1] != '\n')
	})
}

func TestGH1041RequestFailureWithResponseBody(t *testing.T) {
	es := createEventSource(t, "", func(any) {}, nil)
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(hdrContentTypeKey, jsonContentType)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{ "id": "bad_request", "message": "Unable to establish connection" }`))
	})
	defer ts.Close()

	rfFunc := func(err error, res *http.Response) {
		defer res.Body.Close()
		resBytes, _ := io.ReadAll(res.Body)

		assertNotNil(t, err)
		assertEqual(t, "resty:sse: 400 Bad Request", err.Error())
		assertEqual(t, `{ "id": "bad_request", "message": "Unable to establish connection" }`, string(resBytes))
	}

	es.SetURL(ts.URL).OnRequestFailure(rfFunc)
	es.OnRequestFailure(rfFunc)
	err := es.Get()
	assertNotNil(t, err)
	assertEqual(t, "resty:sse: 400 Bad Request", err.Error())
}

func TestEventSourceHTTPError(t *testing.T) {
	es := createEventSource(t, "", func(any) {}, nil)
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://local host", http.StatusTemporaryRedirect)
	})
	defer ts.Close()

	es.SetURL(ts.URL)
	err := es.Get()
	assertTrue(t, strings.Contains(err.Error(), `invalid character " " in host name`))
}

func TestEventSourceParseAndReadError(t *testing.T) {
	type data struct{}
	counter := 0
	es := createEventSource(t, "", func(any) {}, data{})
	ts := createSSETestServer(
		t,
		5*time.Millisecond,
		func(w io.Writer) error {
			if counter == 5 {
				es.Close()
				return fmt.Errorf("stop sending events")
			}
			_, err := fmt.Fprintf(w, "id: %v\n"+
				`data: The time is %s\n\n`+"\n\n", counter, time.Now().Format(time.UnixDate))
			counter++
			return err
		},
	)
	defer ts.Close()

	es.SetURL(ts.URL)
	err := es.Get()
	assertNil(t, err)

	// parse error
	parseEvent = func(_ []byte) (*rawSSE, error) {
		return nil, errors.New("test error")
	}
	counter = 0
	err = es.Get()
	assertNil(t, err)
	t.Cleanup(func() {
		parseEvent = parseEventFunc
	})
}

func TestEventSourceReadError(t *testing.T) {
	es := createEventSource(t, "", func(any) {}, nil)
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	// read error
	readEvent = func(_ *bufio.Scanner) ([]byte, error) {
		return nil, errors.New("read event test error")
	}
	t.Cleanup(func() {
		readEvent = readEventFunc
	})

	es.SetURL(ts.URL)
	err := es.Get()
	assertNotNil(t, err)
	assertTrue(t, strings.Contains(err.Error(), "read event test error"))
}

func TestEventSourceWithDifferentMethods(t *testing.T) {
	testCases := []struct {
		name   string
		method string
		body   []byte
	}{
		{
			name:   "GET Method",
			method: MethodGet,
			body:   nil,
		},
		{
			name:   "POST Method",
			method: MethodPost,
			body:   []byte(`{"test":"post_data"}`),
		},
		{
			name:   "PUT Method",
			method: MethodPut,
			body:   []byte(`{"test":"put_data"}`),
		},
		{
			name:   "DELETE Method",
			method: MethodDelete,
			body:   nil,
		},
		{
			name:   "PATCH Method",
			method: MethodPatch,
			body:   []byte(`{"test":"patch_data"}`),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			es := createEventSource(t, "", nil, nil)

			messageCounter := 0
			messageFunc := func(e any) {
				event := e.(*SSE)
				assertEqual(t, strconv.Itoa(messageCounter), event.ID)
				assertTrue(t, strings.HasPrefix(event.Data, fmt.Sprintf("%s method test:", tc.method)))
				messageCounter++
				if messageCounter == 20 {
					es.Close()
				}
			}
			es.OnMessage(messageFunc, nil)

			counter := 0
			methodVerified := false
			bodyVerified := false

			ts := createMethodVerifyingSSETestServer(
				t,
				10*time.Millisecond,
				tc.method,
				tc.body,
				&methodVerified,
				&bodyVerified,
				func(w io.Writer) error {
					if counter == 20 {
						return fmt.Errorf("stop sending events")
					}
					_, err := fmt.Fprintf(w, "id: %v\ndata: %s method test: %s\n\n", counter, tc.method, time.Now().Format(time.RFC3339))
					counter++
					return err
				},
			)
			defer ts.Close()

			es.SetURL(ts.URL)
			es.SetMethod(tc.method)

			// set body
			if tc.body != nil {
				es.SetBody(bytes.NewBuffer(tc.body))
			}

			err := es.Get()
			assertNil(t, err)

			// check the message count
			assertEqual(t, counter, messageCounter)

			// check if server receive correct method and body
			assertTrue(t, methodVerified)
			if tc.body != nil {
				assertTrue(t, bodyVerified)
			}
		})
	}
}

func TestEventSource_readEventFunc(t *testing.T) {
	t.Run("successful scan", func(t *testing.T) {
		input := "event: test\ndata: test data\n\n"
		scanner := bufio.NewScanner(strings.NewReader(input))

		event, err := readEventFunc(scanner)

		assertNil(t, err)
		assertNotNil(t, event)
		assertEqual(t, "event: test", string(event))
	})

	t.Run("scanner error", func(t *testing.T) {
		// Create a custom reader that returns an error
		scanner := bufio.NewScanner(&errorReader{})

		event, err := readEventFunc(scanner)

		assertNotNil(t, err)
		assertNil(t, event)
		assertEqual(t, "fake", err.Error())
	})

	t.Run("EOF error", func(t *testing.T) {
		// Empty reader will immediately return EOF
		scanner := bufio.NewScanner(strings.NewReader(""))

		event, err := readEventFunc(scanner)

		assertEqual(t, io.EOF, err)
		assertNil(t, event)
	})

	t.Run("multiple lines", func(t *testing.T) {
		input := "line1\nline2\nline3\n"
		scanner := bufio.NewScanner(strings.NewReader(input))

		// First call should return the first line
		event1, err1 := readEventFunc(scanner)
		assertNil(t, err1)
		assertEqual(t, "line1", string(event1))

		// Second call should return the second line
		event2, err2 := readEventFunc(scanner)
		assertNil(t, err2)
		assertEqual(t, "line2", string(event2))

		// Third call should return the third line
		event3, err3 := readEventFunc(scanner)
		assertNil(t, err3)
		assertEqual(t, "line3", string(event3))

		// Fourth call should return EOF
		event4, err4 := readEventFunc(scanner)
		assertEqual(t, io.EOF, err4)
		assertNil(t, event4)
	})
}

func TestEventSourceCoverage(t *testing.T) {
	es := NewSSESource()
	err1 := es.Get()
	assertEqual(t, "resty:sse: event source URL is required", err1.Error())

	es.SetURL("https://sse.dev/test")
	err2 := es.Get()
	assertEqual(t, "resty:sse: At least one OnMessage/AddEventListener func is required", err2.Error())

	es.OnMessage(func(a any) {}, nil)
	es.SetURL("//res%20ty.dev")
	err3 := es.Get()
	assertTrue(t, strings.Contains(err3.Error(), `invalid URL escape "%20"`))

	wrapResponse(nil, nil)
	trimHeader(2, nil)
	parseEvent([]byte{})
}

func createEventSource(t *testing.T, url string, fn SSEMessageFunc, rt any) *SSESource {
	es := NewSSESource().
		SetURL(url).
		SetMethod(MethodGet).
		AddHeader("X-Test-Header-1", "test header 1").
		SetHeader("X-Test-Header-2", "test header 2").
		SetRetryCount(2).
		SetRetryWaitTime(200 * time.Millisecond).
		SetRetryMaxWaitTime(1000 * time.Millisecond).
		SetSizeMaxBuffer(1 << 14). // 16kb
		SetLogger(createLogger()).
		OnOpen(func(url string, respHdr http.Header) {
			t.Log("I'm connected:", url, respHdr)
		}).
		OnError(func(err error) {
			t.Log("Error occurred:", err)
		})
	if fn != nil {
		es.OnMessage(fn, rt)
	}
	return es
}

func createSSETestServer(t *testing.T, ticker time.Duration, fn func(io.Writer) error) *httptest.Server {
	return createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		// for local testing allow it
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// Create a channel for client disconnection
		clientGone := r.Context().Done()

		rc := http.NewResponseController(w)
		tick := time.NewTicker(ticker)
		defer tick.Stop()
		for {
			select {
			case <-clientGone:
				t.Log("Client disconnected")
				return
			case <-tick.C:
				if err := fn(w); err != nil {
					t.Log(err)
					return
				}
				if err := rc.Flush(); err != nil {
					t.Log(err)
					return
				}
			}
		}
	})
}

// almost like create server before but add verifying method and body
func createMethodVerifyingSSETestServer(
	t *testing.T,
	ticker time.Duration,
	expectedMethod string,
	expectedBody []byte,
	methodVerified *bool,
	bodyVerified *bool,
	fn func(io.Writer) error,
) *httptest.Server {
	return createTestServer(func(w http.ResponseWriter, r *http.Request) {
		// validate method
		if r.Method == expectedMethod {
			*methodVerified = true
		} else {
			t.Errorf("Expected method %s, got %s", expectedMethod, r.Method)
		}

		// validate body
		if expectedBody != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("Failed to read request body: %v", err)
			} else if string(body) == string(expectedBody) {
				*bodyVerified = true
			} else {
				t.Errorf("Expected body %s, got %s", string(expectedBody), string(body))
			}
		}

		// same as createSSETestServer
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		clientGone := r.Context().Done()

		rc := http.NewResponseController(w)
		tick := time.NewTicker(ticker)
		defer tick.Stop()

		for {
			select {
			case <-clientGone:
				t.Log("Client disconnected")
				return
			case <-tick.C:
				if err := fn(w); err != nil {
					t.Log(err)
					return
				}
				if err := rc.Flush(); err != nil {
					t.Log(err)
					return
				}
			}
		}
	})
}
