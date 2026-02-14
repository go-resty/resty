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
	defaultHTTPMethod    = MethodGet

	headerID    = []byte("id:")
	headerData  = []byte("data:")
	headerEvent = []byte("event:")
	headerRetry = []byte("retry:")

	hdrCacheControlKey = http.CanonicalHeaderKey("Cache-Control")
	hdrConnectionKey   = http.CanonicalHeaderKey("Connection")
	hdrLastEvevntID    = http.CanonicalHeaderKey("Last-Event-ID")
)

type (
	// SSEOpenFunc is a callback function type used to receive notification
	// when Resty establishes a connection with the server for the
	// Server-Sent Events(SSE)
	SSEOpenFunc func(url string, respHdr http.Header)

	// SSEMessageFunc is a callback function type used to receive event details
	// from the Server-Sent Events(SSE) stream
	SSEMessageFunc func(any)

	// SSEErrorFunc is a callback function type used to receive notification
	// when an error occurs with [SSESource] processing
	SSEErrorFunc func(error)

	// SSERequestFailureFunc is a callback function type used to receive event
	// details from the Server-Sent Events(SSE) request failure
	SSERequestFailureFunc func(err error, res *http.Response)

	// SSE struct represents the event details from the Server-Sent Events(SSE) stream
	SSE struct {
		ID   string
		Name string
		Data string
	}

	// SSESource struct implements the Server-Sent Events(SSE) [specification] to receive
	// stream from the server
	//
	// [specification]: https://html.spec.whatwg.org/multipage/server-sent-events.html
	SSESource struct {
		lock             *sync.RWMutex
		url              string
		method           string
		header           http.Header
		body             io.Reader
		lastEventID      string
		retryCount       int
		retryWaitTime    time.Duration
		retryMaxWaitTime time.Duration
		serverSentRetry  time.Duration
		maxBufSize       int
		onOpen           SSEOpenFunc
		onError          SSEErrorFunc
		onRequestFailure SSERequestFailureFunc
		onEvent          map[string]*callback
		log              Logger
		closed           bool
		httpClient       *http.Client
	}

	callback struct {
		Func   SSEMessageFunc
		Result any
	}
)

// NewSSESource method creates a new instance of [SSESource]
// with default values for Server-Sent Events(SSE)
//
//	sse := NewSSESource().
//		SetURL("https://sse.dev/test").
//		OnMessage(
//			func(e any) {
//				event := e.(*resty.SSE)
//				fmt.Println(event)
//			},
//			nil, // see method godoc
//		)
//
//	err := sse.Connect()
//	fmt.Println(err)
//
// See [SSESource.OnMessage], [SSESource.AddEventListener]
func NewSSESource() *SSESource {
	sse := &SSESource{
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
	return sse
}

// SetURL method sets a [SSESource] connection URL in the instance
//
//	sse.SetURL("https://sse.dev/test")
func (sse *SSESource) SetURL(url string) *SSESource {
	sse.url = url
	return sse
}

// SetMethod method sets a [SSESource] connection HTTP method in the instance
//
//	sse.SetMethod("POST"), or sse.SetMethod(resty.MethodPost)
func (sse *SSESource) SetMethod(method string) *SSESource {
	sse.method = method
	return sse
}

// SetHeader method sets a header and its value to the [SSESource] instance.
// It overwrites the header value if the key already exists. These headers will be sent in
// the request while establishing a connection to the event source
//
//	sse.SetHeader("Authorization", "token here").
//		SetHeader("X-Header", "value")
func (sse *SSESource) SetHeader(header, value string) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.header.Set(header, value)
	return sse
}

// SetBody method sets body value to the [SSESource] instance
//
// Example:
// sse.SetBody(bytes.NewReader([]byte(`{"test":"put_data"}`)))
func (sse *SSESource) SetBody(body io.Reader) *SSESource {
	sse.body = body
	return sse
}

// TLSClientConfig method returns the [tls.Config] from underlying client transport
// otherwise returns nil
func (sse *SSESource) TLSClientConfig() *tls.Config {
	cfg, err := sse.tlsConfig()
	if err != nil {
		sse.Logger().Errorf("%v", err)
	}
	return cfg
}

// SetTLSClientConfig method sets TLSClientConfig for underlying client Transport.
//
// Values supported by https://pkg.go.dev/crypto/tls#Config can be configured.
//
//	// Disable SSL cert verification for local development
//	sse.SetTLSClientConfig(&tls.Config{
//		InsecureSkipVerify: true
//	})
//
// NOTE: This method overwrites existing [http.Transport.TLSClientConfig]
func (sse *SSESource) SetTLSClientConfig(tlsConfig *tls.Config) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()

	// TLSClientConfiger interface handling
	if tc, ok := sse.httpClient.Transport.(TLSClientConfiger); ok {
		if err := tc.SetTLSClientConfig(tlsConfig); err != nil {
			sse.log.Errorf("%v", err)
		}
		return sse
	}

	// default standard transport handling
	if transport, ok := sse.httpClient.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = tlsConfig
	}

	return sse
}

// getting TLS client config if not exists then create one
func (sse *SSESource) tlsConfig() (*tls.Config, error) {
	sse.lock.Lock()
	defer sse.lock.Unlock()

	if tc, ok := sse.httpClient.Transport.(TLSClientConfiger); ok {
		return tc.TLSClientConfig(), nil
	}

	transport, ok := sse.httpClient.Transport.(*http.Transport)
	if !ok {
		return nil, ErrNotHttpTransportType
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	return transport.TLSClientConfig, nil
}

// AddHeader method adds a header and its value to the [SSESource] instance.
// If the header key already exists, it appends. These headers will be sent in
// the request while establishing a connection to the event source
//
//	sse.AddHeader("Authorization", "token here").
//		AddHeader("X-Header", "value")
func (sse *SSESource) AddHeader(header, value string) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.header.Add(header, value)
	return sse
}

// SetRetryCount method enables retry attempts on the SSE client while establishing
// connection with the server
//
//	first attempt + retry count = total attempts
//
// Default is 3
//
//	sse.SetRetryCount(10)
func (sse *SSESource) SetRetryCount(count int) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.retryCount = count
	return sse
}

// SetRetryWaitTime method sets the default wait time for sleep before retrying
// the request
//
// Default is 100 milliseconds.
//
// NOTE: The server-sent retry value takes precedence if present.
//
//	sse.SetRetryWaitTime(1 * time.Second)
func (sse *SSESource) SetRetryWaitTime(waitTime time.Duration) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.retryWaitTime = waitTime
	return sse
}

// SetRetryMaxWaitTime method sets the max wait time for sleep before retrying
// the request
//
// Default is 2 seconds.
//
// NOTE: The server-sent retry value takes precedence if present.
//
//	sse.SetRetryMaxWaitTime(3 * time.Second)
func (sse *SSESource) SetRetryMaxWaitTime(maxWaitTime time.Duration) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.retryMaxWaitTime = maxWaitTime
	return sse
}

// SetSizeMaxBuffer method sets the given buffer size into the SSE client
//
// Default is 32kb
//
//	sse.SetSizeMaxBuffer(64 * 1024) // 64kb
func (sse *SSESource) SetSizeMaxBuffer(bufSize int) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.maxBufSize = bufSize
	return sse
}

// Logger method returns the logger instance used by the event source instance.
func (sse *SSESource) Logger() Logger {
	sse.lock.RLock()
	defer sse.lock.RUnlock()
	return sse.log
}

// SetLogger method sets given writer for logging
//
// Compliant to interface [resty.Logger]
func (sse *SSESource) SetLogger(l Logger) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.log = l
	return sse
}

// just an internal helper method for test case
func (sse *SSESource) outputLogTo(w io.Writer) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.log.(*logger).l.SetOutput(w)
	return sse
}

// OnOpen registered callback gets triggered when the connection is
// established with the server
//
//	sse.OnOpen(func(url string, resHdr http.Header) {
//		fmt.Println("I'm connected:", url, resHdr)
//	})
func (sse *SSESource) OnOpen(ef SSEOpenFunc) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	if sse.onOpen != nil {
		sse.log.Warnf("Overwriting an existing OnOpen callback from=%s to=%s",
			functionName(sse.onOpen), functionName(ef))
	}
	sse.onOpen = ef
	return sse
}

// OnError registered callback gets triggered when the error occurred
// in the process
//
//	sse.OnError(func(err error) {
//		fmt.Println("Error occurred:", err)
//	})
func (sse *SSESource) OnError(ef SSEErrorFunc) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	if sse.onError != nil {
		sse.log.Warnf("Overwriting an existing OnError callback from=%s to=%s",
			functionName(sse.onError), functionName(ef))
	}
	sse.onError = ef
	return sse
}

// OnRequestFailure registered callback gets triggered when the HTTP request
// failure while establishing a SSE connection.
//
//	sse.OnRequestFailure(func(err error, res *http.Response) {
//		fmt.Println("Error and response:", err, res)
//	})
//
// NOTE:
//   - Do not forget to close the HTTP response body.
//   - HTTP response may be nil.
func (sse *SSESource) OnRequestFailure(ef SSERequestFailureFunc) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	if sse.onRequestFailure != nil {
		sse.log.Warnf("Overwriting an existing OnRequestFailure callback from=%s to=%s",
			functionName(sse.onRequestFailure), functionName(ef))
	}
	sse.onRequestFailure = ef
	return sse
}

// OnMessage method registers a callback to emit every SSE event message
// from the server. The second result argument is optional; it can be used
// to register the data type for JSON data.
//
//	sse.OnMessage(
//		func(e any) {
//			event := e.(*resty.SSE)
//			fmt.Println("Event message", event)
//		},
//		nil,
//	)
//
//	// Receiving JSON data from the server, you can set result type
//	// to do auto-unmarshal
//	sse.OnMessage(
//		func(e any) {
//			event := e.(*MyData)
//			fmt.Println(event)
//		},
//		MyData{},
//	)
func (sse *SSESource) OnMessage(ef SSEMessageFunc, result any) *SSESource {
	return sse.AddEventListener(defaultEventName, ef, result)
}

// AddEventListener method registers a callback to consume a specific event type
// messages from the server. The second result argument is optional; it can be used
// to register the data type for JSON data.
//
//	sse.AddEventListener(
//		"friend_logged_in",
//		func(e any) {
//			event := e.(*resty.SSE)
//			fmt.Println(event)
//		},
//		nil,
//	)
//
//	// Receiving JSON data from the server, you can set result type
//	// to do auto-unmarshal
//	sse.AddEventListener(
//		"friend_logged_in",
//		func(e any) {
//			event := e.(*UserLoggedIn)
//			fmt.Println(event)
//		},
//		UserLoggedIn{},
//	)
func (sse *SSESource) AddEventListener(eventName string, ef SSEMessageFunc, result any) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	if e, found := sse.onEvent[eventName]; found {
		sse.log.Warnf("Overwriting an existing OnEvent callback from=%s to=%s",
			functionName(e), functionName(ef))
	}
	cb := &callback{Func: ef, Result: nil}
	if result != nil {
		cb.Result = getPointer(result)
	}
	sse.onEvent[eventName] = cb
	return sse
}

// Get method establishes the connection with the server.
//
//	sse := NewSSE().
//		SetURL("https://sse.dev/test").
//		OnMessage(
//			func(e any) {
//				event := e.(*resty.SSE)
//				fmt.Println(event)
//			},
//			nil, // see method godoc
//		)
//
//	err := sse.Get()
//	fmt.Println(err)
func (sse *SSESource) Get() error {
	// Validate required values
	if isStringEmpty(sse.url) {
		return fmt.Errorf("resty:sse: event source URL is required")
	}

	if isStringEmpty(sse.method) {
		// It is up to the user to choose which http method to use, depending on the specific code implementation. No restrictions are imposed here.
		// Ensure compatibility, use GET as default http method
		sse.method = defaultHTTPMethod
	}

	if len(sse.onEvent) == 0 {
		return fmt.Errorf("resty:sse: At least one OnMessage/AddEventListener func is required")
	}

	// reset to begin
	sse.enableConnect()

	for {
		if sse.isClosed() {
			return nil
		}
		res, err := sse.connect()
		if err != nil {
			return err
		}
		sse.triggerOnOpen(res.Header.Clone())
		if err := sse.listenStream(res); err != nil {
			return err
		}
	}
}

// Close method used to close SSE connection explicitly
func (sse *SSESource) Close() {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.closed = true
}

func (sse *SSESource) enableConnect() {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.closed = false
}

func (sse *SSESource) isClosed() bool {
	sse.lock.RLock()
	defer sse.lock.RUnlock()
	return sse.closed
}

func (sse *SSESource) triggerOnOpen(hdr http.Header) {
	sse.lock.RLock()
	defer sse.lock.RUnlock()
	if sse.onOpen != nil {
		sse.onOpen(strings.Clone(sse.url), hdr)
	}
}

func (sse *SSESource) triggerOnError(err error) {
	sse.lock.RLock()
	defer sse.lock.RUnlock()
	if sse.onError != nil {
		sse.onError(err)
	}
}

func (sse *SSESource) triggerOnRequestFailure(err error, res *http.Response) {
	sse.lock.RLock()
	defer sse.lock.RUnlock()
	if sse.onRequestFailure != nil {
		sse.onRequestFailure(err, res)
	}
}

func (sse *SSESource) createRequest() (*http.Request, error) {
	req, err := http.NewRequest(sse.method, sse.url, sse.body)
	if err != nil {
		return nil, err
	}

	req.Header = sse.header.Clone()
	req.Header.Set(hdrAcceptKey, "text/event-stream")
	req.Header.Set(hdrCacheControlKey, "no-cache")
	req.Header.Set(hdrConnectionKey, "keep-alive")
	if len(sse.lastEventID) > 0 {
		req.Header.Set(hdrLastEvevntID, sse.lastEventID)
	}

	return req, nil
}

func (sse *SSESource) connect() (*http.Response, error) {
	sse.lock.RLock()
	defer sse.lock.RUnlock()

	var backoff *backoffWithJitter
	if sse.serverSentRetry > 0 {
		backoff = newBackoffWithJitter(sse.serverSentRetry, sse.serverSentRetry)
	} else {
		backoff = newBackoffWithJitter(sse.retryWaitTime, sse.retryMaxWaitTime)
	}

	var (
		err     error
		attempt int
	)
	for i := 0; i <= sse.retryCount; i++ {
		attempt++
		req, reqErr := sse.createRequest()
		if reqErr != nil {
			err = reqErr
			break
		}

		resp, doErr := sse.httpClient.Do(req)
		if resp != nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		// we have reached the maximum no. of requests
		// first attempt + retry count = total attempts
		if attempt-1 == sse.retryCount {
			err = doErr
			break
		}

		rRes := wrapResponse(resp, req)
		needsRetry := applyRetryDefaultConditions(rRes, doErr)

		// retry not required stop here
		if !needsRetry {
			if rRes != nil {
				err = wrapErrors(fmt.Errorf("resty:sse: %v", rRes.Status()), doErr)
			} else {
				err = doErr
			}
			if err != nil {
				sse.triggerOnRequestFailure(err, resp)
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

func (sse *SSESource) listenStream(res *http.Response) error {
	defer closeq(res.Body)

	scanner := bufio.NewScanner(res.Body)
	scanner.Buffer(make([]byte, slices.Min([]int{4096, sse.maxBufSize})), sse.maxBufSize)
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
		if sse.isClosed() {
			return nil
		}

		if err := sse.processEvent(scanner); err != nil {
			return err
		}
	}
}

func (sse *SSESource) processEvent(scanner *bufio.Scanner) error {
	e, err := readEvent(scanner)
	if err != nil {
		if err == io.EOF {
			return err
		}
		sse.triggerOnError(err)
		return err
	}

	ed, err := parseEvent(e)
	if err != nil {
		sse.triggerOnError(err)
		return nil // parsing errors, will not return error.
	}
	defer putRawEvent(ed)

	if len(ed.ID) > 0 {
		sse.lock.Lock()
		sse.lastEventID = string(ed.ID)
		sse.lock.Unlock()
	}

	if len(ed.Retry) > 0 {
		if retry, err := strconv.Atoi(string(ed.Retry)); err == nil {
			sse.lock.Lock()
			sse.serverSentRetry = time.Millisecond * time.Duration(retry)
			sse.lock.Unlock()
		} else {
			sse.triggerOnError(err)
		}
	}

	if len(ed.Data) > 0 {
		sse.handleCallback(&SSE{
			ID:   string(ed.ID),
			Name: string(ed.Event),
			Data: string(ed.Data),
		})
	}

	return nil
}

func (sse *SSESource) handleCallback(e *SSE) {
	eventName := e.Name
	if len(eventName) == 0 {
		eventName = defaultEventName
	}

	sse.lock.RLock()
	cb, found := sse.onEvent[eventName]
	sse.lock.RUnlock()

	if found {
		if cb.Result == nil {
			cb.Func(e)
			return
		}
		r := newInterface(cb.Result)
		if err := decodeJSON(strings.NewReader(e.Data), r); err != nil {
			sse.triggerOnError(err)
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

func wrapResponse(res *http.Response, req *http.Request) *Response {
	if res == nil {
		return nil
	}
	return &Response{RawResponse: res, Request: &Request{RawRequest: req}}
}

type rawSSE struct {
	ID    []byte
	Data  []byte
	Event []byte
	Retry []byte
}

var parseEvent = parseEventFunc

// event value parsing logic obtained and modified for Resty processing flow.
// https://github.com/r3labs/sse/blob/c6d5381ee3ca63828b321c16baa008fd6c0b4564/client.go#L322
func parseEventFunc(msg []byte) (*rawSSE, error) {
	if len(msg) < 1 {
		return nil, errors.New("resty:sse: event message was empty")
	}

	e := newRawEvent()

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
	if len(data) > 0 && data[0] == ' ' {
		data = data[1:]
	}
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	return data
}

var rawEventPool = &sync.Pool{New: func() any { return new(rawSSE) }}

func newRawEvent() *rawSSE {
	e := rawEventPool.Get().(*rawSSE)
	e.ID = e.ID[:0]
	e.Data = e.Data[:0]
	e.Event = e.Event[:0]
	e.Retry = e.Retry[:0]
	return e
}

func putRawEvent(e *rawSSE) {
	rawEventPool.Put(e)
}
