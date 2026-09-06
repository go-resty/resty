// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bufio"
	"bytes"
	"context"
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

// SSE specification: https://html.spec.whatwg.org/multipage/server-sent-events.html

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
	// SSEOpenFunc is a callback type invoked when Resty establishes a
	// Server-Sent Events (SSE) connection.
	SSEOpenFunc func(url string, respHdr http.Header)

	// SSEMessageFunc is a callback type used to receive event values from the
	// Server-Sent Events (SSE) stream.
	SSEMessageFunc func(any)

	// SSEErrorFunc is a callback type invoked when an error occurs while
	// processing an [SSESource] stream.
	SSEErrorFunc func(error)

	// SSERequestFailureFunc is a callback function type invoked when the HTTP
	// request to the SSE endpoint fails to establish or maintain a connection.
	SSERequestFailureFunc func(err error, res *http.Response)

	// SSE represents one event from a Server-Sent Events (SSE) stream.
	SSE struct {
		ID   string
		Name string
		Data string
	}

	// SSESource implements the Server-Sent Events (SSE) [specification] client
	// and consumes a stream from a server endpoint.
	//
	// [specification]: https://html.spec.whatwg.org/multipage/server-sent-events.html
	SSESource struct {
		lock             *sync.RWMutex
		url              string
		method           string
		header           http.Header
		bodyBytes        []byte
		lastEventID      string
		retryCount       int
		retryWaitTime    time.Duration
		retryMaxWaitTime time.Duration
		retryConditions  []RetryConditionFunc
		serverSentRetry  time.Duration
		maxBufSize       int
		onOpen           SSEOpenFunc
		onError          SSEErrorFunc
		onRequestFailure SSERequestFailureFunc
		onEvent          map[string]*callback
		log              Logger
		ctx              context.Context
		closed           bool
		httpClient       *http.Client
	}

	callback struct {
		Func   SSEMessageFunc
		Result any
	}
)

// NewSSESource creates a new [SSESource] with default SSE settings.
//
//	sse := NewSSESource().
//		SetURL("https://example.com/events").
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
//
// See [SSESource.OnMessage], [SSESource.AddEventListener]
func NewSSESource() *SSESource {
	sse := &SSESource{
		lock:             new(sync.RWMutex),
		header:           make(http.Header),
		retryCount:       3,
		retryWaitTime:    defaultWaitTime,
		retryMaxWaitTime: defaultMaxWaitTime,
		retryConditions:  make([]RetryConditionFunc, 0),
		maxBufSize:       defaultSseMaxBufSize,
		onEvent:          make(map[string]*callback),
		log:              createLogger(),
		httpClient: &http.Client{
			Jar:       createCookieJar(),
			Transport: createTransport(nil, nil),
		},
	}
	sse.retryConditions = append(sse.retryConditions,
		RetryConditionStatusZero,
		RetryConditionStatusTooManyRequests,
		RetryConditionStatus5XX,
	)
	return sse
}

// SetURL method sets the event-source URL on the [SSESource] instance.
//
//	sse.SetURL("https://example.com/events")
func (sse *SSESource) SetURL(url string) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.url = url
	return sse
}

// SetMethod method sets the HTTP method used for the [SSESource] connection.
//
//	sse.SetMethod("POST"), or sse.SetMethod(resty.MethodPost)
func (sse *SSESource) SetMethod(method string) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.method = method
	return sse
}

// SetHeader method sets a header and its value on the [SSESource] instance.
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

// Context method returns the [context.Context] from the SSE source instance.
//
// The returned context is always non-nil; it defaults to the
// background context.
func (sse *SSESource) Context() context.Context {
	sse.lock.RLock()
	defer sse.lock.RUnlock()
	if sse.ctx == nil {
		return context.Background()
	}
	return sse.ctx
}

// SetContext method sets the [context.Context] for the current [SSESource].
// It overwrites the current context in the SSESource instance.
//
// If you want this method to take effect, use this method before invoking
// [SSESource.Get].
func (sse *SSESource) SetContext(ctx context.Context) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.ctx = ctx
	return sse
}

// SetBody method sets the request body for the [SSESource] connection.
//
// Example:
// sse.SetBody(bytes.NewReader([]byte(`{"test":"put_data"}`)))
func (sse *SSESource) SetBody(body io.Reader) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	if body == nil {
		sse.bodyBytes = nil
		return sse
	}

	sse.bodyBytes = nil
	bodyBytes, err := ioReadAll(body)
	if err != nil {
		sse.log.Errorf("resty:sse: unable to read body, error: %v", err)
		return sse
	}

	sse.bodyBytes = bodyBytes
	return sse
}

// TLSClientConfig method returns the [tls.Config] from the underlying client
// transport, or nil when unavailable.
func (sse *SSESource) TLSClientConfig() *tls.Config {
	cfg, err := sse.tlsConfig()
	if err != nil {
		sse.Logger().Errorf("%v", err)
	}
	return cfg
}

// SetTLSClientConfig method sets TLS configuration on the underlying client transport.
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
		return nil, ErrNotHTTPTransportType
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	return transport.TLSClientConfig, nil
}

// SetTransport method sets custom [http.Transport] or any [http.RoundTripper]
// on the underlying client transport.
//
//	transport := &http.Transport{
//		// something like Proxying to httptest.Server, etc...
//		Proxy: func(req *http.Request) (*url.URL, error) {
//			return url.Parse(server.URL)
//		},
//	}
//	sse.SetTransport(transport)
//
// NOTE:
//   - If transport is not the type of [http.Transport], you may lose the
//     ability to set a few Resty client settings. However, if you implement
//     [TLSClientConfiger] interface, then TLS client config is possible to set.
//   - It overwrites the Resty client transport instance and its configurations.
func (sse *SSESource) SetTransport(transport http.RoundTripper) *SSESource {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	if transport != nil {
		sse.httpClient.Transport = transport
	}
	return sse
}

// AddHeader method appends a header value on the [SSESource] instance.
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

// SetRetryCount method sets the retry count used while establishing an SSE
// connection with the server.
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

// SetRetryWaitTime method sets the default wait time before retrying the
// connection request.
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

// SetRetryMaxWaitTime method sets the maximum wait time before retrying the
// connection request.
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

// SetMaxBufferSize method sets the maximum scanner buffer size for the SSE client.
//
// Default is 32kb
//
//	sse.SetMaxBufferSize(64 * 1024) // 64kb
func (sse *SSESource) SetMaxBufferSize(bufSize int) *SSESource {
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

// SetLogger method sets the [Logger] used by the SSE client.
//
// Compliant to interface [Logger].
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

// OnOpen registers a callback that is triggered when a connection is
// established with the server.
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

// OnError registers a callback that is triggered when an error occurs.
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

// OnRequestFailure registers a callback that is triggered when the HTTP request
// fails while establishing an SSE connection.
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

// AddEventListener method registers a callback to consume messages for a specific
// event type from the server. The second result argument is optional; it can be used
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
//	sse := NewSSESource().
//		SetURL("https://example.com/events").
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
//
// Get blocks until the stream ends, the context is done, or [SSESource.Close] is
// called.
//
// NOTE: Get does not reconnect. The retry settings ([SSESource.SetRetryCount],
// [SSESource.SetRetryWaitTime], [SSESource.SetRetryMaxWaitTime]) apply only while
// establishing the initial connection. Once connected, a stream that ends returns
// [io.EOF] to the caller; call Get again to reconnect. Resty tracks the last event
// ID and any server-sent `retry:` value, and sends `Last-Event-ID` on the next
// connect, so calling Get again resumes where the stream left off.
//
// Get returns nil only when [SSESource.Close] was called.
func (sse *SSESource) Get() error {
	// Validate required values and reset to begin, all under one write lock
	sse.lock.Lock()
	if isStringEmpty(sse.url) {
		sse.lock.Unlock()
		return fmt.Errorf("resty:sse: event source URL is required")
	}

	if isStringEmpty(sse.method) {
		// It is up to the user to choose which http method to use, depending on the specific code implementation. No restrictions are imposed here.
		// Ensure compatibility, use GET as default http method
		sse.method = defaultHTTPMethod
	}

	if len(sse.onEvent) == 0 {
		sse.lock.Unlock()
		return fmt.Errorf("resty:sse: At least one OnMessage/AddEventListener func is required")
	}

	sse.closed = false
	sse.lock.Unlock()

	for {
		ctx := sse.Context()
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if sse.isClosed() {
				return nil
			}
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

// Close method closes the SSE connection explicitly.
func (sse *SSESource) Close() {
	sse.lock.Lock()
	defer sse.lock.Unlock()
	sse.closed = true
}

func (sse *SSESource) isClosed() bool {
	sse.lock.RLock()
	defer sse.lock.RUnlock()
	return sse.closed
}

// The three trigger methods below snapshot the callback under the read lock and
// invoke it after releasing. Calling user code while holding the lock deadlocks
// the moment the callback touches the source -- Close, SetURL and SetHeader all
// take the write lock, and sync.RWMutex is not reentrant. Stopping the stream
// from OnOpen and refreshing auth from OnError are both ordinary SSE patterns.

func (sse *SSESource) triggerOnOpen(hdr http.Header) {
	sse.lock.RLock()
	onOpen, url := sse.onOpen, strings.Clone(sse.url)
	sse.lock.RUnlock()
	if onOpen != nil {
		onOpen(url, hdr)
	}
}

func (sse *SSESource) triggerOnError(err error) {
	sse.lock.RLock()
	onError := sse.onError
	sse.lock.RUnlock()
	if onError != nil {
		onError(err)
	}
}

func (sse *SSESource) triggerOnRequestFailure(err error, res *http.Response) {
	sse.lock.RLock()
	onRequestFailure := sse.onRequestFailure
	sse.lock.RUnlock()
	if onRequestFailure != nil {
		onRequestFailure(err, res)
	}
}

func (sse *SSESource) createRequest() (*http.Request, error) {
	// Resolve the context before taking the read lock; Context also acquires it
	// and sync.RWMutex read locks are not reentrant.
	ctx := sse.Context()

	sse.lock.RLock()
	method, url := sse.method, sse.url
	hdr := sse.header.Clone()
	lastEventID := sse.lastEventID
	var reqBody io.Reader
	if sse.bodyBytes != nil {
		// create reader from bytes on each request
		reqBody = bytes.NewReader(sse.bodyBytes)
	}
	sse.lock.RUnlock()

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header = hdr
	req.Header.Set(hdrAcceptKey, "text/event-stream")
	req.Header.Set(hdrCacheControlKey, "no-cache")
	req.Header.Set(hdrConnectionKey, "keep-alive")
	if len(lastEventID) > 0 {
		req.Header.Set(hdrLastEvevntID, lastEventID)
	}

	return req, nil
}

// sseConnectError describes a non-OK connect response, or nil when no response
// was received.
func sseConnectError(res *Response) error {
	if res == nil {
		return nil
	}
	return fmt.Errorf("resty:sse: %v", res.Status())
}

func (sse *SSESource) connect() (*http.Response, error) {
	// Snapshot the settings this attempt needs, then release the lock. Holding
	// it across httpClient.Do, the retry wait, and the nested read locks taken
	// by createRequest and triggerOnRequestFailure would deadlock against any
	// concurrent Close or setter call, since read locks are not reentrant.
	sse.lock.RLock()
	serverSentRetry := sse.serverSentRetry
	retryWaitTime := sse.retryWaitTime
	retryMaxWaitTime := sse.retryMaxWaitTime
	retryCount := sse.retryCount
	retryConditions := slices.Clone(sse.retryConditions)
	httpClient := sse.httpClient
	sse.lock.RUnlock()

	var backoff *backoffWithJitter
	if serverSentRetry > 0 {
		backoff = newBackoffWithJitter(serverSentRetry, serverSentRetry)
	} else {
		backoff = newBackoffWithJitter(retryWaitTime, retryMaxWaitTime)
	}

	var (
		err     error
		attempt int
	)
	for i := 0; i <= retryCount; i++ {
		attempt++
		req, reqErr := sse.createRequest()
		if reqErr != nil {
			err = reqErr
			break
		}

		resp, doErr := httpClient.Do(req)
		if resp != nil && resp.StatusCode == http.StatusOK {
			// successful connection, return response to listenStream
			return resp, nil
		}

		rRes := wrapResponse(resp, req)

		// we have reached the maximum no. of requests
		// first attempt + retry count = total attempts
		if attempt-1 == retryCount {
			err = wrapErrors(sseConnectError(rRes), doErr)
			// nothing is returned to the caller, so this body is ours to release
			drainBody(rRes)
			break
		}

		needsRetry := isDoNotRetryError(doErr)
		if !needsRetry && rRes != nil {
			for _, retryCondition := range retryConditions {
				if needsRetry = retryCondition(rRes, doErr); needsRetry {
					break
				}
			}
		}

		// retry not required stop here
		if !needsRetry {
			err = wrapErrors(sseConnectError(rRes), doErr)
			if err != nil {
				// the callback is documented to own the body, so hand it over
				// first and only then release whatever is left of it
				sse.triggerOnRequestFailure(err, resp)
			}
			drainBody(rRes)
			break
		}

		// let's drain the response body, before retry wait
		drainBody(rRes)

		waitDuration, _ := backoff.NextWaitDuration(nil, nil, rRes, doErr, attempt)
		timer := time.NewTimer(waitDuration)
		select {
		case <-sse.Context().Done():
			timer.Stop()
			return nil, sse.Context().Err()
		case <-timer.C:
		}
		timer.Stop()
	}

	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("resty:sse: unable to connect stream")
}

// eventTerminators end an event. The WHATWG event stream grammar separates
// lines with CRLF, LF or CR, so a blank line -- and therefore the end of an
// event -- is any of those doubled. Recognising only "\n\n" left CRLF streams,
// which are common in .NET and Java servers, undispatched until EOF.
var eventTerminators = [][]byte{
	[]byte("\r\n\r\n"),
	[]byte("\n\n"),
	[]byte("\r\r"),
}

// indexEventTerminator returns the offset and length of the earliest event
// terminator in data, or -1 when there is none.
func indexEventTerminator(data []byte) (int, int) {
	best, width := -1, 0
	for _, t := range eventTerminators {
		i := bytes.Index(data, t)
		if i < 0 {
			continue
		}
		if best < 0 || i < best || (i == best && len(t) > width) {
			best, width = i, len(t)
		}
	}
	return best, width
}

// isEventLineBreak reports whether r ends a line in an event stream.
func isEventLineBreak(r rune) bool { return r == '\n' || r == '\r' }

func (sse *SSESource) listenStream(res *http.Response) error {
	defer closeq(res.Body)

	scanner := bufio.NewScanner(res.Body)
	scanner.Buffer(make([]byte, min(4096, sse.maxBufSize)), sse.maxBufSize)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i, width := indexEventTerminator(data); i >= 0 {
			// We have a full event, terminated by a blank line.
			return i + width, data[0:i], nil
		}
		// If we're at EOF, we have a final, non-terminated line. Return it.
		if atEOF {
			return len(data), data, nil
		}
		// Request more data.
		return 0, nil, nil
	})

	for {
		ctx := sse.Context()
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if sse.isClosed() {
				return nil
			}
		}

		if err := sse.processEvent(scanner); err != nil {
			// Close racing with the server ending the stream must report a clean
			// shutdown rather than the io.EOF the closed connection produced.
			if sse.isClosed() {
				return nil
			}
			return err
		}
	}
}

func (sse *SSESource) processEvent(scanner *bufio.Scanner) error {
	e, err := readEvent(scanner)
	if err != nil {
		if errors.Is(err, io.EOF) {
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

	// Split into lines. Per the WHATWG event stream grammar a line ends with
	// CRLF, LF or CR; FieldsFunc drops the empty field a CRLF pair produces.
	for _, line := range bytes.FieldsFunc(msg, isEventLineBreak) {
		switch {
		case bytes.HasPrefix(line, headerID):
			e.ID = append([]byte(nil), trimHeader(len(headerID), line)...)
		case bytes.HasPrefix(line, headerData):
			// The spec allows for multiple data fields per event, concatenated them with "\n".
			// Append into e.Data rather than onto the trimmed slice: that slice aliases
			// bufio.Scanner's buffer, so appending to it can write over bytes the
			// scanner has not handed out yet.
			e.Data = append(e.Data, trimHeader(len(headerData), line)...)
			e.Data = append(e.Data, '\n')
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
	for len(data) > 0 && isEventLineBreak(rune(data[len(data)-1])) {
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
