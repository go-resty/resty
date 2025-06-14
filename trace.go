// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"context"
	"crypto/tls"
	"fmt"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"net/http/httptrace"
	"time"
)

// TraceInfo struct is used to provide request trace info such as DNS lookup
// duration, Connection obtain duration, Server processing duration, etc.
type TraceInfo struct {
	// DNSLookup is the duration that transport took to perform
	// DNS lookup.
	DNSLookup time.Duration `json:"dns_lookup_time"`

	// ConnTime is the duration it took to obtain a successful connection.
	ConnTime time.Duration `json:"connection_time"`

	// TCPConnTime is the duration it took to obtain the TCP connection.
	TCPConnTime time.Duration `json:"tcp_connection_time"`

	// TLSHandshake is the duration of the TLS handshake.
	TLSHandshake time.Duration `json:"tls_handshake_time"`

	// ServerTime is the server's duration for responding to the first byte.
	ServerTime time.Duration `json:"server_time"`

	// ResponseTime is the duration since the first response byte from the server to
	// request completion.
	ResponseTime time.Duration `json:"response_time"`

	// TotalTime is the duration of the total time request taken end-to-end.
	TotalTime time.Duration `json:"total_time"`

	// IsConnReused is whether this connection has been previously
	// used for another HTTP request.
	IsConnReused bool `json:"is_connection_reused"`

	// IsConnWasIdle is whether this connection was obtained from an
	// idle pool.
	IsConnWasIdle bool `json:"is_connection_was_idle"`

	// ConnIdleTime is the duration how long the connection that was previously
	// idle, if IsConnWasIdle is true.
	ConnIdleTime time.Duration `json:"connection_idle_time"`

	// RequestAttempt is to represent the request attempt made during a Resty
	// request execution flow, including retry count.
	RequestAttempt int `json:"request_attempt"`

	// RemoteAddr returns the remote network address.
	RemoteAddr string `json:"remote_address"`
}

// String method returns string representation of request trace information.
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

// JSON method returns the JSON string of request trace information
func (ti TraceInfo) JSON() string {
	return toJSON(ti)
}

// Clone method returns the clone copy of [TraceInfo]
func (ti TraceInfo) Clone() *TraceInfo {
	ti2 := new(TraceInfo)
	*ti2 = ti
	return ti2
}

// clientTrace struct maps the [httptrace.ClientTrace] hooks into Fields
// with the same naming for easy understanding. Plus additional insights
// [Request].
type clientTrace struct {
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

type tracer struct {
	ctx  context.Context
	span trace.Span
}

type HttpJaegerTracers struct {
	RootTracer         tracer
	DNSTracer          tracer
	ConnectTracer      tracer
	GetConnectTracer   tracer
	TLSHandshakeTracer tracer
	WriteRequestTracer tracer
	WriteHeaderTracer  tracer
}

func (t *clientTrace) createContext(ctx context.Context) context.Context {

	trace := otel.Tracer("trace")
	tracers := HttpJaegerTracers{}
	return httptrace.WithClientTrace(
		ctx,
		&httptrace.ClientTrace{
			DNSStart: func(info httptrace.DNSStartInfo) {
				c, span := trace.Start(tracers.GetConnectTracer.ctx, "DNSTrace")
				tracers.DNSTracer = tracer{
					ctx:  c,
					span: span,
				}
				span.SetAttributes(
					attribute.String("host", info.Host),
				)
				t.dnsStart = time.Now()
			},
			DNSDone: func(info httptrace.DNSDoneInfo) {
				tracers.DNSTracer.span.SetAttributes(
					attribute.String("address", info.Addrs[0].String()),
				)
				if info.Err != nil {
					attribute.String("error", info.Err.Error())
				}
				t.dnsDone = time.Now()
				tracers.DNSTracer.span.End()
			},
			ConnectStart: func(network, address string) {
				c, span := trace.Start(tracers.GetConnectTracer.ctx, "ConnectTrace")
				tracers.ConnectTracer = tracer{
					ctx:  c,
					span: span,
				}
				if t.dnsDone.IsZero() {
					t.dnsDone = time.Now()
				}
				if t.dnsStart.IsZero() {
					t.dnsStart = t.dnsDone
				}
				span.SetAttributes(
					attribute.String("address", address),
					attribute.String("network", network),
				)
			},
			ConnectDone: func(net, addr string, err error) {
				t.connectDone = time.Now()
				if err != nil {
					tracers.ConnectTracer.span.SetAttributes(
						attribute.String("error", err.Error()),
					)
				}
				tracers.ConnectTracer.span.End()
			},
			GetConn: func(hostPort string) {
				c, span := trace.Start(ctx, "GetConnectTrace")
				tracers.GetConnectTracer = tracer{
					ctx:  c,
					span: span,
				}
				tracers.GetConnectTracer.span.SetAttributes(
					attribute.String(
						"hostPort", hostPort,
					),
				)
				t.getConn = time.Now()
			},
			GotConn: func(ci httptrace.GotConnInfo) {
				t.gotConn = time.Now()
				t.gotConnInfo = ci
				tracers.GetConnectTracer.span.End()
			},
			GotFirstResponseByte: func() {
				tracers.WriteRequestTracer.span.End()
				_, span := trace.Start(ctx, "GotResponse")
				defer span.End()
				t.gotFirstResponseByte = time.Now()
			},
			TLSHandshakeStart: func() {
				c, span := trace.Start(tracers.GetConnectTracer.ctx, "TLSHandshakeTrace")
				tracers.TLSHandshakeTracer = tracer{
					ctx:  c,
					span: span,
				}
				t.tlsHandshakeStart = time.Now()
			},
			TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
				t.tlsHandshakeDone = time.Now()
				tracers.TLSHandshakeTracer.span.End()
			},
			WroteRequest: func(info httptrace.WroteRequestInfo) {
				c, span := trace.Start(ctx, "WroteRequest")
				tracers.WriteRequestTracer = tracer{
					ctx:  c,
					span: span,
				}
			},
			WroteHeaderField: func(key string, value []string) {
				if tracers.WriteHeaderTracer.span == nil {
					c, span := trace.Start(ctx, "WriteHeader")
					tracers.WriteHeaderTracer = tracer{
						ctx:  c,
						span: span,
					}
				}
				tracers.WriteHeaderTracer.span.SetAttributes(
					attribute.StringSlice(fmt.Sprintf("headers.%s", key), value),
				)

			},
			WroteHeaders: func() {
				tracers.WriteHeaderTracer.span.End()
			},
		},
	)
}
