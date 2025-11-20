// Copyright (c) 2015-2024 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptrace"
	"sync"
	"time"
)

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// TraceInfo struct
//_______________________________________________________________________

// TraceInfo struct is used to provide request trace info such as DNS lookup
// duration, Connection obtain duration, Server processing duration, etc.
type TraceInfo struct {
	// DNSLookup is the duration that transport took to perform
	// DNS lookup.
	DNSLookup time.Duration

	// ConnTime is the duration it took to obtain a successful connection.
	ConnTime time.Duration

	// TCPConnTime is the duration it took to obtain the TCP connection.
	TCPConnTime time.Duration

	// TLSHandshake is the duration of the TLS handshake.
	TLSHandshake time.Duration

	// ServerTime is the server's duration for responding to the first byte.
	ServerTime time.Duration

	// ResponseTime is the duration since the first response byte from the server to
	// request completion.
	ResponseTime time.Duration

	// TotalTime is the duration of the total time request taken end-to-end.
	TotalTime time.Duration

	// IsConnReused is whether this connection has been previously
	// used for another HTTP request.
	IsConnReused bool

	// IsConnWasIdle is whether this connection was obtained from an
	// idle pool.
	IsConnWasIdle bool

	// ConnIdleTime is the duration how long the connection that was previously
	// idle, if IsConnWasIdle is true.
	ConnIdleTime time.Duration

	// RequestAttempt is to represent the request attempt made during a Resty
	// request execution flow, including retry count.
	RequestAttempt int

	// RemoteAddr returns the remote network address.
	RemoteAddr net.Addr
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// ClientTrace struct and its methods
//_______________________________________________________________________

// clientTrace struct maps the [httptrace.ClientTrace] hooks into Fields
// with the same naming for easy understanding. Plus additional insights
// [Request].
type clientTrace struct {
	lock                 sync.RWMutex
	getConn              time.Time
	dnsStart             time.Time
	dnsDone              time.Time
	connectDone          time.Time
	tlsHandshakeStart    time.Time
	tlsHandshakeDone     time.Time
	gotConn              time.Time
	gotFirstResponseByte time.Time
	endTime              time.Time
	gotConnInfo          httptrace.GotConnInfo
}

func (t *clientTrace) createContext(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(
		ctx,
		&httptrace.ClientTrace{
			DNSStart: func(_ httptrace.DNSStartInfo) {
				t.lock.Lock()
				t.dnsStart = time.Now()
				t.lock.Unlock()
			},
			DNSDone: func(_ httptrace.DNSDoneInfo) {
				t.lock.Lock()
				t.dnsDone = time.Now()
				t.lock.Unlock()
			},
			ConnectStart: func(_, _ string) {
				t.lock.Lock()
				if t.dnsDone.IsZero() {
					t.dnsDone = time.Now()
				}
				if t.dnsStart.IsZero() {
					t.dnsStart = t.dnsDone
				}
				t.lock.Unlock()
			},
			ConnectDone: func(net, addr string, err error) {
				t.lock.Lock()
				t.connectDone = time.Now()
				t.lock.Unlock()
			},
			GetConn: func(_ string) {
				t.lock.Lock()
				t.getConn = time.Now()
				t.lock.Unlock()
			},
			GotConn: func(ci httptrace.GotConnInfo) {
				t.lock.Lock()
				t.gotConn = time.Now()
				t.gotConnInfo = ci
				t.lock.Unlock()
			},
			GotFirstResponseByte: func() {
				t.lock.Lock()
				t.gotFirstResponseByte = time.Now()
				t.lock.Unlock()
			},
			TLSHandshakeStart: func() {
				t.lock.Lock()
				t.tlsHandshakeStart = time.Now()
				t.lock.Unlock()
			},
			TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
				t.lock.Lock()
				t.tlsHandshakeDone = time.Now()
				t.lock.Unlock()
			},
		},
	)
}
