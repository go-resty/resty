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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Spec: https://html.spec.whatwg.org/multipage/server-sent-events.html

var (
	defaultSseMaxBufSize = 1 << 15 // 32kb
	defaultEventName     = "message"

	headerID    = []byte("id:")
	headerData  = []byte("data:")
	headerEvent = []byte("event:")
	headerRetry = []byte("retry:")

	hdrCacheControlKey = http.CanonicalHeaderKey("Cache-Control")
	hdrConnectionKey   = http.CanonicalHeaderKey("Connection")
	hdrLastEvevntID    = http.CanonicalHeaderKey("Last-Event-ID")
)

type (
	// EventOpenFunc is a callback function type used to receive notification
	// when Resty establishes a connection with the server for the
	// Server-Sent Events(SSE)
	EventOpenFunc func(url string)

	// EventMessageFunc is a callback function type used to receive event details
	// from the Server-Sent Events(SSE) stream
	EventMessageFunc func(any)

	// EventErrorFunc is a callback function type used to receive notification
	// when an error occurs with [EventSource] processing
	EventErrorFunc func(error)

	// Event struct represents the event details from the Server-Sent Events(SSE) stream
	Event struct {
		ID   string
		Name string
		Data string
	}

	// EventSource struct implements the Server-Sent Events(SSE) [specification] to receive
	// stream from the server
	//
	// [specification]: https://html.spec.whatwg.org/multipage/server-sent-events.html
	EventSource struct {
		lock             *sync.RWMutex
		url              string
		header           http.Header
		lastEventID      string
		retryCount       int
		retryWaitTime    time.Duration
		retryMaxWaitTime time.Duration
		serverSentRetry  time.Duration
		maxBufSize       int
		onOpen           EventOpenFunc
		onError          EventErrorFunc
		onEvent          map[string]*callback
		log              Logger
		closed           bool
		httpClient       *http.Client
	}

	callback struct {
		Func   EventMessageFunc
		Result any
	}
)

// NewEventSource method creates a new instance of [EventSource]
// with default values for Server-Sent Events(SSE)
//
//	es := NewEventSource().
//		SetURL("https://sse.dev/test").
//		OnMessage(
//			func(e any) {
//				e = e.(*Event)
//				fmt.Println(e)
//			},
//			nil, // see method godoc
//		)
//
//	err := es.Connect()
//	fmt.Println(err)
//
// See [EventSource.OnMessage], [EventSource.AddEventListener]
func NewEventSource() *EventSource {
	es := &EventSource{
		lock:             new(sync.RWMutex),
		header:           make(http.Header),
		retryCount:       3,
		retryWaitTime:    defaultWaitTime,
		retryMaxWaitTime: defaultMaxWaitTime,
		maxBufSize:       defaultSseMaxBufSize,
		onEvent:          make(map[string]*callback),
		httpClient: &http.Client{
			Jar:       createCookieJar(),
			Transport: createTransport(nil, nil),
		},
	}
	return es
}

// SetURL method sets a [EventSource] connection URL in the instance
//
//	es.SetURL("https://sse.dev/test")
func (es *EventSource) SetURL(url string) *EventSource {
	es.url = url
	return es
}

// SetHeader method sets a header and its value to the [EventSource] instance.
// It overwrites the header value if the key already exists. These headers will be sent in
// the request while establishing a connection to the event source
//
//	es.SetHeader("Authorization", "token here").
//		SetHeader("X-Header", "value")
func (es *EventSource) SetHeader(header, value string) *EventSource {
	es.lock.Lock()
	defer es.lock.Unlock()
	es.header.Set(header, value)
	return es
}

// AddHeader method adds a header and its value to the [EventSource] instance.
// If the header key already exists, it appends. These headers will be sent in
// the request while establishing a connection to the event source
//
//	es.AddHeader("Authorization", "token here").
//		AddHeader("X-Header", "value")
func (es *EventSource) AddHeader(header, value string) *EventSource {
	es.lock.Lock()
	defer es.lock.Unlock()
	es.header.Add(header, value)
	return es
}

// SetRetryCount method enables retry attempts on the SSE client while establishing
// connection with the server
//
//	first attempt + retry count = total attempts
//
// Default is 3
//
//	es.SetRetryCount(10)
func (es *EventSource) SetRetryCount(count int) *EventSource {
	es.lock.Lock()
	defer es.lock.Unlock()
	es.retryCount = count
	return es
}

// SetRetryWaitTime method sets the default wait time for sleep before retrying
// the request
//
// Default is 100 milliseconds.
//
// NOTE: The server-sent retry value takes precedence if present.
//
//	es.SetRetryWaitTime(1 * time.Second)
func (es *EventSource) SetRetryWaitTime(waitTime time.Duration) *EventSource {
	es.lock.Lock()
	defer es.lock.Unlock()
	es.retryWaitTime = waitTime
	return es
}

// SetRetryMaxWaitTime method sets the max wait time for sleep before retrying
// the request
//
// Default is 2 seconds.
//
// NOTE: The server-sent retry value takes precedence if present.
//
//	es.SetRetryMaxWaitTime(3 * time.Second)
func (es *EventSource) SetRetryMaxWaitTime(maxWaitTime time.Duration) *EventSource {
	es.lock.Lock()
	defer es.lock.Unlock()
	es.retryMaxWaitTime = maxWaitTime
	return es
}

// SetMaxBufSize method sets the given buffer size into the SSE client
//
// Default is 32kb
//
//	es.SetMaxBufSize(64 * 1024) // 64kb
func (es *EventSource) SetMaxBufSize(bufSize int) *EventSource {
	es.lock.Lock()
	defer es.lock.Unlock()
	es.maxBufSize = bufSize
	return es
}

// SetLogger method sets given writer for logging
//
// Compliant to interface [resty.Logger]
func (es *EventSource) SetLogger(l Logger) *EventSource {
	es.lock.Lock()
	defer es.lock.Unlock()
	es.log = l
	return es
}

// just an internal helper method for test case
func (es *EventSource) outputLogTo(w io.Writer) *EventSource {
	es.lock.Lock()
	defer es.lock.Unlock()
	es.log.(*logger).l.SetOutput(w)
	return es
}

// OnOpen registered callback gets triggered when the connection is
// established with the server
//
//	es.OnOpen(func(url string) {
//		fmt.Println("I'm connected:", url)
//	})
func (es *EventSource) OnOpen(ef EventOpenFunc) *EventSource {
	es.lock.Lock()
	defer es.lock.Unlock()
	if es.onOpen != nil {
		es.log.Warnf("Overwriting an existing OnOpen callback from=%s to=%s",
			functionName(es.onOpen), functionName(ef))
	}
	es.onOpen = ef
	return es
}

// OnError registered callback gets triggered when the error occurred
// in the process
//
//	es.OnError(func(err error) {
//		fmt.Println("Error occurred:", err)
//	})
func (es *EventSource) OnError(ef EventErrorFunc) *EventSource {
	es.lock.Lock()
	defer es.lock.Unlock()
	if es.onError != nil {
		es.log.Warnf("Overwriting an existing OnError callback from=%s to=%s",
			functionName(es.OnError), functionName(ef))
	}
	es.onError = ef
	return es
}

// OnMessage method registers a callback to emit every SSE event message
// from the server. The second result argument is optional; it can be used
// to register the data type for JSON data.
//
//	es.OnMessage(
//		func(e any) {
//			e = e.(*Event)
//			fmt.Println("Event message", e)
//		},
//		nil,
//	)
//
//	// Receiving JSON data from the server, you can set result type
//	// to do auto-unmarshal
//	es.OnMessage(
//		func(e any) {
//			e = e.(*MyData)
//			fmt.Println(e)
//		},
//		MyData{},
//	)
func (es *EventSource) OnMessage(ef EventMessageFunc, result any) *EventSource {
	return es.AddEventListener(defaultEventName, ef, result)
}

// AddEventListener method registers a callback to consume a specific event type
// messages from the server. The second result argument is optional; it can be used
// to register the data type for JSON data.
//
//	es.AddEventListener(
//		"friend_logged_in",
//		func(e any) {
//			e = e.(*Event)
//			fmt.Println(e)
//		},
//		nil,
//	)
//
//	// Receiving JSON data from the server, you can set result type
//	// to do auto-unmarshal
//	es.AddEventListener(
//		"friend_logged_in",
//		func(e any) {
//			e = e.(*UserLoggedIn)
//			fmt.Println(e)
//		},
//		UserLoggedIn{},
//	)
func (es *EventSource) AddEventListener(eventName string, ef EventMessageFunc, result any) *EventSource {
	es.lock.Lock()
	defer es.lock.Unlock()
	if e, found := es.onEvent[eventName]; found {
		es.log.Warnf("Overwriting an existing OnEvent callback from=%s to=%s",
			functionName(e), functionName(ef))
	}
	cb := &callback{Func: ef, Result: nil}
	if result != nil {
		cb.Result = getPointer(result)
	}
	es.onEvent[eventName] = cb
	return es
}

// Get method establishes the connection with the server.
//
//	es := NewEventSource().
//		SetURL("https://sse.dev/test").
//		OnMessage(
//			func(e any) {
//				e = e.(*Event)
//				fmt.Println(e)
//			},
//			nil, // see method godoc
//		)
//
//	err := es.Get()
//	fmt.Println(err)
func (es *EventSource) Get() error {
	// Validate required values
	if isStringEmpty(es.url) {
		return fmt.Errorf("resty:sse: event source URL is required")
	}
	if _, found := es.onEvent[defaultEventName]; !found {
		return fmt.Errorf("resty:sse: OnMessage function is required")
	}

	// reset to begin
	es.enableConnect()

	for {
		if es.isClosed() {
			return nil
		}
		res, err := es.connect()
		if err != nil {
			return err
		}
		es.triggerOnOpen()
		if err := es.listenStream(res); err != nil {
			return err
		}
	}
}

// Close method used to close SSE connection explicitly
func (es *EventSource) Close() {
	es.lock.Lock()
	defer es.lock.Unlock()
	es.closed = true
}

func (es *EventSource) enableConnect() {
	es.lock.Lock()
	defer es.lock.Unlock()
	es.closed = false
}

func (es *EventSource) isClosed() bool {
	es.lock.RLock()
	defer es.lock.RUnlock()
	return es.closed
}

func (es *EventSource) triggerOnOpen() {
	es.lock.RLock()
	defer es.lock.RUnlock()
	if es.onOpen != nil {
		es.onOpen(strings.Clone(es.url))
	}
}

func (es *EventSource) triggerOnError(err error) {
	es.lock.RLock()
	defer es.lock.RUnlock()
	if es.onError != nil {
		es.onError(err)
	}
}

func (es *EventSource) createRequest() (*http.Request, error) {
	req, err := http.NewRequest(MethodGet, es.url, nil)
	if err != nil {
		return nil, err
	}

	req.Header = es.header.Clone()
	req.Header.Set(hdrAcceptKey, "text/event-stream")
	req.Header.Set(hdrCacheControlKey, "no-cache")
	req.Header.Set(hdrConnectionKey, "keep-alive")
	if len(es.lastEventID) > 0 {
		req.Header.Set(hdrLastEvevntID, es.lastEventID)
	}

	return req, nil
}

func (es *EventSource) connect() (*http.Response, error) {
	es.lock.RLock()
	defer es.lock.RUnlock()

	var backoff *backoffWithJitter
	if es.serverSentRetry > 0 {
		backoff = newBackoffWithJitter(es.serverSentRetry, es.serverSentRetry)
	} else {
		backoff = newBackoffWithJitter(es.retryWaitTime, es.retryMaxWaitTime)
	}

	var (
		err     error
		attempt int
	)
	for i := 0; i <= es.retryCount; i++ {
		attempt++
		req, reqErr := es.createRequest()
		if reqErr != nil {
			err = reqErr
			break
		}

		resp, doErr := es.httpClient.Do(req)
		if resp != nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		// we have reached the maximum no. of requests
		// first attempt + retry count = total attempts
		if attempt-1 == es.retryCount {
			err = doErr
			break
		}

		rRes := wrapResponse(resp)
		needsRetry := applyRetryDefaultConditions(rRes, doErr)

		// retry not required stop here
		if !needsRetry {
			if rRes != nil {
				err = wrapErrors(fmt.Errorf("resty:sse: %v", rRes.Status()), doErr)
			} else {
				err = doErr
			}
			break
		}

		// let's drain the response body, before retry wait
		drainBody(rRes)

		waitDuration, _ := backoff.NextWaitDuration(nil, rRes, doErr, attempt)
		timer := time.NewTimer(waitDuration)
		<-timer.C
		timer.Stop()
	}

	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("resty:sse: unable to connect stream")
}

func (es *EventSource) listenStream(res *http.Response) error {
	defer closeq(res.Body)

	scanner := bufio.NewScanner(res.Body)
	scanner.Buffer(make([]byte, slices.Min([]int{4096, es.maxBufSize})), es.maxBufSize)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.Index(data, []byte{'\n', '\n'}); i >= 0 {
			// We have a full double newline-terminated line.
			return i + 1, data[0:i], nil
		}
		// If we're at EOF, we have a final, non-terminated line. Return it.
		if atEOF {
			return len(data), data, nil
		}
		// Request more data.
		return 0, nil, nil
	})

	for {
		if es.isClosed() {
			return nil
		}

		e, err := readEvent(scanner)
		if err != nil {
			if err == io.EOF {
				return err
			}
			es.triggerOnError(err)
			return err
		}

		ed, err := parseEvent(e)
		if err != nil {
			es.triggerOnError(err)
			continue // parsing errors, just continue
		}

		if len(ed.ID) > 0 {
			es.lock.Lock()
			es.lastEventID = string(ed.ID)
			es.lock.Unlock()
		}

		if len(ed.Retry) > 0 {
			if retry, err := strconv.Atoi(string(ed.Retry)); err == nil {
				es.lock.Lock()
				es.serverSentRetry = time.Second * time.Duration(retry)
				es.lock.Unlock()
			} else {
				es.triggerOnError(err)
			}
		}

		if len(ed.Data) > 0 {
			es.handleCallback(&Event{
				ID:   string(ed.ID),
				Name: string(ed.Event),
				Data: string(ed.Data),
			})
		}
	}
}

func (es *EventSource) handleCallback(e *Event) {
	es.lock.RLock()
	defer es.lock.RUnlock()

	eventName := e.Name
	if len(eventName) == 0 {
		eventName = defaultEventName
	}
	if cb, found := es.onEvent[eventName]; found {
		if cb.Result == nil {
			cb.Func(e)
			return
		}
		r := newInterface(cb.Result)
		if err := decodeJSON(strings.NewReader(e.Data), r); err != nil {
			es.triggerOnError(err)
			return
		}
		cb.Func(r)
	}
}

var readEvent = readEventFunc

func readEventFunc(scanner *bufio.Scanner) ([]byte, error) {
	if scanner.Scan() {
		event := scanner.Bytes()
		return event, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

func wrapResponse(res *http.Response) *Response {
	if res == nil {
		return nil
	}
	return &Response{RawResponse: res}
}

type rawEvent struct {
	ID    []byte
	Data  []byte
	Event []byte
	Retry []byte
}

var parseEvent = parseEventFunc

// event value parsing logic obtained and modified for Resty processing flow.
// https://github.com/r3labs/sse/blob/c6d5381ee3ca63828b321c16baa008fd6c0b4564/client.go#L322
func parseEventFunc(msg []byte) (*rawEvent, error) {
	if len(msg) < 1 {
		return nil, errors.New("resty:sse: event message was empty")
	}

	e := new(rawEvent)

	// Split the line by "\n"
	for _, line := range bytes.FieldsFunc(msg, func(r rune) bool { return r == '\n' }) {
		switch {
		case bytes.HasPrefix(line, headerID):
			e.ID = append([]byte(nil), trimHeader(len(headerID), line)...)
		case bytes.HasPrefix(line, headerData):
			// The spec allows for multiple data fields per event, concatenated them with "\n"
			e.Data = append(e.Data[:], append(trimHeader(len(headerData), line), byte('\n'))...)
		// The spec says that a line that simply contains the string "data" should be treated as a data field with an empty body.
		case bytes.Equal(line, bytes.TrimSuffix(headerData, []byte(":"))):
			e.Data = append(e.Data, byte('\n'))
		case bytes.HasPrefix(line, headerEvent):
			e.Event = append([]byte(nil), trimHeader(len(headerEvent), line)...)
		case bytes.HasPrefix(line, headerRetry):
			e.Retry = append([]byte(nil), trimHeader(len(headerRetry), line)...)
		default:
			// Ignore anything that doesn't match the header
		}
	}

	// Trim the last "\n" per the spec
	e.Data = bytes.TrimSuffix(e.Data, []byte("\n"))

	return e, nil
}

func trimHeader(size int, data []byte) []byte {
	if data == nil || len(data) < size {
		return data
	}
	data = data[size:]
	data = bytes.TrimSpace(data)
	data = bytes.TrimSuffix(data, []byte("\n"))
	return data
}
