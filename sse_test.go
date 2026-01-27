// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bufio"
	"bytes"
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
	messageCounter := 0
	messageFunc := func(e any) {
		event := e.(*Event)
		assertEqual(t, strconv.Itoa(messageCounter), event.ID)
		assertEqual(t, true, strings.HasPrefix(event.Data, "The time is"))
		messageCounter++
	}

	counter := 0
	es := createEventSource(t, "", messageFunc, nil)
	ts := createSSETestServer(
		t,
		10*time.Millisecond,
		func(w io.Writer) error {
			if counter == 100 {
				es.Close()
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
		assertEqual(t, true, data.Time.After(tm))
		userConnectCounter++
	}

	userMessageCounter := 0
	userMessageFunc := func(e any) {
		data := e.(*userEvent)
		assertEqual(t, "username"+strconv.Itoa(userConnectCounter), data.UserName)
		assertEqual(t, "Hello, how are you?", data.Message)
		assertEqual(t, true, data.Time.After(tm))
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
	message2Counter := 0
	messageFunc2 := func(e any) {
		event := e.(*Event)
		assertEqual(t, strconv.Itoa(message2Counter), event.ID)
		assertEqual(t, true, strings.HasPrefix(event.Data, "The time is"))
		message2Counter++
	}

	counter := 0
	es := createEventSource(t, "", messageFunc1, nil)
	ts := createSSETestServer(
		t,
		10*time.Millisecond,
		func(w io.Writer) error {
			if counter == 50 {
				es.Close()
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
		OnOpen(func(url string) {
			t.Log("from overwrite func", url)
		}).
		OnError(func(err error) {
			t.Log("from overwrite func", err)
		})

	err := es.Get()
	assertNil(t, err)
	assertEqual(t, counter, message2Counter)

	logLines := lb.String()
	assertEqual(t, true, strings.Contains(logLines, "Overwriting an existing OnEvent callback"))
	assertEqual(t, true, strings.Contains(logLines, "Overwriting an existing OnOpen callback"))
	assertEqual(t, true, strings.Contains(logLines, "Overwriting an existing OnError callback"))
}

func TestEventSourceRetry(t *testing.T) {
	messageCounter := 2 // 0 & 1 connection failure
	messageFunc := func(e any) {
		event := e.(*Event)
		assertEqual(t, strconv.Itoa(messageCounter), event.ID)
		assertEqual(t, true, strings.HasPrefix(event.Data, "The time is"))
		messageCounter++
	}

	counter := 0
	es := createEventSource(t, "", messageFunc, nil)
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

func TestEventSourceNoRetryRequired(t *testing.T) {
	es := createEventSource(t, "", func(any) {}, nil)
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	defer ts.Close()

	es.SetURL(ts.URL)
	err := es.Get()
	fmt.Println(err)
	assertEqual(t, true, strings.Contains(err.Error(), "400 Bad Request"))
}

func TestEventSourceHTTPError(t *testing.T) {
	es := createEventSource(t, "", func(any) {}, nil)
	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://local host", http.StatusTemporaryRedirect)
	})
	defer ts.Close()

	es.SetURL(ts.URL)
	err := es.Get()
	assertEqual(t, true, strings.Contains(err.Error(), `invalid character " " in host name`))
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
	parseEvent = func(_ []byte) (*rawEvent, error) {
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
	assertEqual(t, true, strings.Contains(err.Error(), "read event test error"))
}

func TestEventSourceCoverage(t *testing.T) {
	es := NewEventSource()
	err1 := es.Get()
	assertEqual(t, "resty:sse: event source URL is required", err1.Error())

	es.SetURL("https://sse.dev/test")
	err2 := es.Get()
	assertEqual(t, "resty:sse: At least one OnMessage/AddEventListener func is required", err2.Error())

	es.OnMessage(func(a any) {}, nil)
	es.SetURL("//res%20ty.dev")
	err3 := es.Get()
	assertEqual(t, true, strings.Contains(err3.Error(), `invalid URL escape "%20"`))

	wrapResponse(nil)
	trimHeader(2, nil)
	parseEvent([]byte{})
}

func createEventSource(t *testing.T, url string, fn EventMessageFunc, rt any) *EventSource {
	es := NewEventSource().
		SetURL(url).
		SetMethod(MethodGet).
		AddHeader("X-Test-Header-1", "test header 1").
		SetHeader("X-Test-Header-2", "test header 2").
		SetRetryCount(2).
		SetRetryWaitTime(200 * time.Millisecond).
		SetRetryMaxWaitTime(1000 * time.Millisecond).
		SetMaxBufSize(1 << 14). // 16kb
		SetLogger(createLogger()).
		OnOpen(func(url string) {
			t.Log("I'm connected:", url)
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
			messageCounter := 0
			messageFunc := func(e any) {
				event := e.(*Event)
				assertEqual(t, strconv.Itoa(messageCounter), event.ID)
				assertEqual(t, true, strings.HasPrefix(event.Data, fmt.Sprintf("%s method test:", tc.method)))
				messageCounter++
			}

			counter := 0
			methodVerified := false
			bodyVerified := false

			es := createEventSource(t, "", messageFunc, nil)
			ts := createMethodVerifyingSSETestServer(
				t,
				10*time.Millisecond,
				tc.method,
				tc.body,
				&methodVerified,
				&bodyVerified,
				func(w io.Writer) error {
					if counter == 20 {
						es.Close()
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
			assertEqual(t, true, methodVerified)
			if tc.body != nil {
				assertEqual(t, true, bodyVerified)
			}
		})
	}
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
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
}
