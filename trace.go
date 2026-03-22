// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http/httptrace"
	"sync"
	"time"
)

// TraceInfo holds timing and connection details captured during a request via
// [httptrace.ClientTrace]. Fields cover DNS lookup, TCP connection, TLS handshake,
// server processing, and total end-to-end duration.
type TraceInfo struct {
	// DNSLookup is the duration that the transport took to perform the DNS lookup.
	DNSLookup time.Duration `json:"dns_lookup_time"`

	// ConnTime is the duration it took to obtain a successful connection.
	ConnTime time.Duration `json:"connection_time"`

	// TCPConnTime is the duration it took to establish the TCP connection.
	TCPConnTime time.Duration `json:"tcp_connection_time"`

	// TLSHandshake is the duration of the TLS handshake.
	TLSHandshake time.Duration `json:"tls_handshake_time"`

	// ServerTime is the duration from sending the request to receiving the first response byte.
	ServerTime time.Duration `json:"server_time"`

	// ResponseTime is the duration from the first response byte to the completion of reading the body.
	ResponseTime time.Duration `json:"response_time"`

	// TotalTime is the total end-to-end duration of the request.
	TotalTime time.Duration `json:"total_time"`

	// IsConnReused reports whether this connection was previously used for another HTTP request.
	IsConnReused bool `json:"is_connection_reused"`

	// IsConnWasIdle reports whether this connection was obtained from an idle pool.
	IsConnWasIdle bool `json:"is_connection_was_idle"`

	// ConnIdleTime is the duration that the connection had been idle before being reused,
	// valid only when IsConnWasIdle is true.
	ConnIdleTime time.Duration `json:"connection_idle_time"`

	// RequestAttempt is the number of the current attempt in the request execution flow,
	// where 1 is the initial attempt and values greater than 1 indicate retries.
	RequestAttempt int `json:"request_attempt"`

	// RemoteAddr is the remote network address of the server.
	RemoteAddr string `json:"remote_address"`
}

// String method returns a string representation of the request trace information.
func (ti TraceInfo) String() string {
	return fmt.Sprintf(`TRACE INFO:
  DNSLookupTime : %v
  ConnTime      : %v
  TCPConnTime   : %v
  TLSHandshake  : %v
  ServerTime    : %v
  ResponseTime  : %v
  TotalTime     : %v
  IsConnReused  : %v
  IsConnWasIdle : %v
  ConnIdleTime  : %v
  RequestAttempt: %v
  RemoteAddr    : %v`, ti.DNSLookup, ti.ConnTime, ti.TCPConnTime,
		ti.TLSHandshake, ti.ServerTime, ti.ResponseTime, ti.TotalTime,
		ti.IsConnReused, ti.IsConnWasIdle, ti.ConnIdleTime, ti.RequestAttempt,
		ti.RemoteAddr)
}

// JSON method returns the JSON representation of the request trace information.
func (ti TraceInfo) JSON() string {
	return toJSON(ti)
}

// Clone method returns a deep copy of the [TraceInfo].
func (ti TraceInfo) Clone() *TraceInfo {
	ti2 := new(TraceInfo)
	*ti2 = ti
	return ti2
}

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
