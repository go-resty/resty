// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// LoadBalancer is the interface that wraps the HTTP client load-balancing
// algorithm that returns the "Next" Base URL for the request to target
type LoadBalancer interface {
	Next() (string, error)
	Feedback(*RequestFeedback)
	Close() error
}

// RequestFeedback struct is used to send the request feedback to load balancing
// algorithm
type RequestFeedback struct {
	BaseURL string
	Success bool
	Attempt int
}

// NewRoundRobin method creates the new Round-Robin(RR) request load balancer
// instance with given base URLs
func NewRoundRobin(baseURLs ...string) (*RoundRobin, error) {
	rr := &RoundRobin{lock: new(sync.Mutex)}
	if err := rr.Refresh(baseURLs...); err != nil {
		return rr, err
	}
	return rr, nil
}

var _ LoadBalancer = (*RoundRobin)(nil)

// RoundRobin struct used to implement the Round-Robin(RR) request
// load balancer algorithm
type RoundRobin struct {
	lock     *sync.Mutex
	baseURLs []string
	current  int
}

// Next method returns the next Base URL based on the Round-Robin(RR) algorithm
func (rr *RoundRobin) Next() (string, error) {
	rr.lock.Lock()
	defer rr.lock.Unlock()

	baseURL := rr.baseURLs[rr.current]
	rr.current = (rr.current + 1) % len(rr.baseURLs)
	return baseURL, nil
}

// Feedback method does nothing in Round-Robin(RR) request load balancer
func (rr *RoundRobin) Feedback(_ *RequestFeedback) {}

// Close method does nothing in Round-Robin(RR) request load balancer
func (rr *RoundRobin) Close() error { return nil }

// Refresh method reset the existing Base URLs with the given Base URLs slice to refresh it
func (rr *RoundRobin) Refresh(baseURLs ...string) error {
	rr.lock.Lock()
	defer rr.lock.Unlock()
	result := make([]string, 0)
	for _, u := range baseURLs {
		baseURL, err := extractBaseURL(u)
		if err != nil {
			return err
		}
		result = append(result, baseURL)
	}

	// after processing, assign the updates
	rr.baseURLs = result
	return nil
}

// Host struct used to represent the host information and its weight
// to load balance the requests
type Host struct {
	// BaseURL represents the targeted host base URL
	//	https://resty.dev
	BaseURL string

	// Weight represents the host weight to determine
	// the percentage of requests to send
	Weight int

	// MaxFailures represents the value to mark the host as
	// not usable until it reaches the Recovery duration
	//	Default value is 5
	MaxFailures int

	state          HostState
	currentWeight  int
	failedRequests int
}

func (h *Host) addWeight() {
	h.currentWeight += h.Weight
}

func (h *Host) resetWeight(totalWeight int) {
	h.currentWeight -= totalWeight
}

type HostState int

// Host transition states
const (
	HostStateInActive HostState = iota
	HostStateActive
)

// HostStateChangeFunc type provides feedback on host state transitions
type HostStateChangeFunc func(baseURL string, from, to HostState)

// ErrNoActiveHost error returned when all hosts are inactive on the load balancer
var ErrNoActiveHost = errors.New("resty: no active host")

// NewWeightedRoundRobin method creates the new Weighted Round-Robin(WRR)
// request load balancer instance with given recovery duration and hosts slice
func NewWeightedRoundRobin(recovery time.Duration, hosts ...*Host) (*WeightedRoundRobin, error) {
	if recovery == 0 {
		recovery = 120 * time.Second // defaults to 120 seconds
	}
	wrr := &WeightedRoundRobin{
		lock:     new(sync.Mutex),
		hosts:    make([]*Host, 0),
		tick:     time.NewTicker(recovery),
		recovery: recovery,
	}

	err := wrr.Refresh(hosts...)

	go wrr.ticker()

	return wrr, err
}

var _ LoadBalancer = (*WeightedRoundRobin)(nil)

// WeightedRoundRobin struct used to represent the host details for
// Weighted Round-Robin(WRR) algorithm implementation
type WeightedRoundRobin struct {
	lock          *sync.Mutex
	hosts         []*Host
	totalWeight   int
	tick          *time.Ticker
	onStateChange HostStateChangeFunc

	// Recovery duration is used to set the timer to put
	// the host back in the pool for the next turn and
	// reset the failed request count for the segment
	recovery time.Duration
}

// Next method returns the next Base URL based on Weighted Round-Robin(WRR)
func (wrr *WeightedRoundRobin) Next() (string, error) {
	wrr.lock.Lock()
	defer wrr.lock.Unlock()

	var best *Host
	total := 0
	for _, h := range wrr.hosts {
		if h.state == HostStateInActive {
			continue
		}

		h.addWeight()
		total += h.Weight

		if best == nil || h.currentWeight > best.currentWeight {
			best = h
		}
	}

	if best == nil {
		return "", ErrNoActiveHost
	}

	best.resetWeight(total)
	return best.BaseURL, nil
}

// Feedback method process the request feedback for Weighted Round-Robin(WRR)
// request load balancer
func (wrr *WeightedRoundRobin) Feedback(f *RequestFeedback) {
	wrr.lock.Lock()
	defer wrr.lock.Unlock()

	for _, host := range wrr.hosts {
		if host.BaseURL == f.BaseURL {
			if !f.Success {
				host.failedRequests++
			}
			if host.failedRequests >= host.MaxFailures {
				host.state = HostStateInActive
				if wrr.onStateChange != nil {
					wrr.onStateChange(host.BaseURL, HostStateActive, HostStateInActive)
				}
			}
			break
		}
	}
}

// Close method does the cleanup by stopping the [time.Ticker] on
// Weighted Round-Robin(WRR) request load balancer
func (wrr *WeightedRoundRobin) Close() error {
	wrr.lock.Lock()
	defer wrr.lock.Unlock()
	wrr.tick.Stop()
	return nil
}

// Refresh method reset the existing values with the given [Host] slice to refresh it
func (wrr *WeightedRoundRobin) Refresh(hosts ...*Host) error {
	if hosts == nil {
		return nil
	}

	wrr.lock.Lock()
	defer wrr.lock.Unlock()
	newTotalWeight := 0
	for _, h := range hosts {
		baseURL, err := extractBaseURL(h.BaseURL)
		if err != nil {
			return err
		}

		h.BaseURL = baseURL
		h.state = HostStateActive
		newTotalWeight += h.Weight

		// assign defaults if not provided
		if h.MaxFailures == 0 {
			h.MaxFailures = 5 // default value is 5
		}
	}

	// after processing, assign the updates
	wrr.hosts = hosts
	wrr.totalWeight = newTotalWeight
	return nil
}

// SetOnStateChange method used to set a callback for the host transition state
func (wrr *WeightedRoundRobin) SetOnStateChange(fn HostStateChangeFunc) {
	wrr.lock.Lock()
	defer wrr.lock.Unlock()
	wrr.onStateChange = fn
}

// SetRecoveryDuration method is used to change the existing recovery duration for the host
func (wrr *WeightedRoundRobin) SetRecoveryDuration(d time.Duration) {
	wrr.lock.Lock()
	defer wrr.lock.Unlock()
	wrr.recovery = d
	wrr.tick.Reset(d)
}

func (wrr *WeightedRoundRobin) ticker() {
	for range wrr.tick.C {
		wrr.lock.Lock()
		for _, host := range wrr.hosts {
			if host.state == HostStateInActive {
				host.state = HostStateActive
				host.failedRequests = 0

				if wrr.onStateChange != nil {
					wrr.onStateChange(host.BaseURL, HostStateInActive, HostStateActive)
				}
			}
		}
		wrr.lock.Unlock()
	}
}

// NewSRVWeightedRoundRobin method creates a new Weighted Round-Robin(WRR) load balancer instance
// with given SRV values
func NewSRVWeightedRoundRobin(service, proto, domainName, httpScheme string) (*SRVWeightedRoundRobin, error) {
	if isStringEmpty(proto) {
		proto = "tcp"
	}
	if isStringEmpty(httpScheme) {
		httpScheme = "https"
	}

	wrr, _ := NewWeightedRoundRobin(0) // with this input error will not occur
	swrr := &SRVWeightedRoundRobin{
		Service:    service,
		Proto:      proto,
		DomainName: domainName,
		HttpScheme: httpScheme,
		wrr:        wrr,
		tick:       time.NewTicker(180 * time.Second), // default is 180 seconds
		lock:       new(sync.Mutex),
		lookupSRV: func() ([]*net.SRV, error) {
			_, addrs, err := net.LookupSRV(service, proto, domainName)
			return addrs, err
		},
	}

	err := swrr.Refresh()

	go swrr.ticker()

	return swrr, err
}

var _ LoadBalancer = (*SRVWeightedRoundRobin)(nil)

// SRVWeightedRoundRobin struct used to implement SRV Weighted Round-Robin(RR) algorithm
type SRVWeightedRoundRobin struct {
	Service    string
	Proto      string
	DomainName string
	HttpScheme string

	wrr       *WeightedRoundRobin
	tick      *time.Ticker
	lock      *sync.Mutex
	lookupSRV func() ([]*net.SRV, error)
}

// Next method returns the next SRV Base URL based on Weighted Round-Robin(RR)
func (swrr *SRVWeightedRoundRobin) Next() (string, error) {
	return swrr.wrr.Next()
}

// Feedback method does nothing in SRV Base URL based on Weighted Round-Robin(WRR)
// request load balancer
func (swrr *SRVWeightedRoundRobin) Feedback(f *RequestFeedback) {
	swrr.wrr.Feedback(f)
}

// Close method does the cleanup by stopping the [time.Ticker] SRV Base URL based
// on Weighted Round-Robin(WRR) request load balancer
func (swrr *SRVWeightedRoundRobin) Close() error {
	swrr.lock.Lock()
	defer swrr.lock.Unlock()
	swrr.wrr.Close()
	swrr.tick.Stop()
	return nil
}

// Refresh method reset the values based [net.LookupSRV] values to refresh it
func (swrr *SRVWeightedRoundRobin) Refresh() error {
	swrr.lock.Lock()
	defer swrr.lock.Unlock()
	addrs, err := swrr.lookupSRV()
	if err != nil {
		return err
	}

	hosts := make([]*Host, len(addrs))
	for idx, addr := range addrs {
		domain := strings.TrimRight(addr.Target, ".")
		baseURL := fmt.Sprintf("%s://%s:%d", swrr.HttpScheme, domain, addr.Port)
		hosts[idx] = &Host{BaseURL: baseURL, Weight: int(addr.Weight)}
	}

	return swrr.wrr.Refresh(hosts...)
}

// SetRefreshDuration method assists in changing the default (180 seconds) refresh duration
func (swrr *SRVWeightedRoundRobin) SetRefreshDuration(d time.Duration) {
	swrr.lock.Lock()
	defer swrr.lock.Unlock()
	swrr.tick.Reset(d)
}

// SetOnStateChange method used to set a callback for the host transition state
func (swrr *SRVWeightedRoundRobin) SetOnStateChange(fn HostStateChangeFunc) {
	swrr.wrr.SetOnStateChange(fn)
}

// SetRecoveryDuration method is used to change the existing recovery duration for the host
func (swrr *SRVWeightedRoundRobin) SetRecoveryDuration(d time.Duration) {
	swrr.wrr.SetRecoveryDuration(d)
}

func (swrr *SRVWeightedRoundRobin) ticker() {
	for range swrr.tick.C {
		swrr.Refresh()
	}
}

func extractBaseURL(u string) (string, error) {
	baseURL, err := url.Parse(u)
	if err != nil {
		return "", err
	}

	// we only require base URL LB
	baseURL.Path = ""
	baseURL.RawQuery = ""

	return strings.TrimRight(baseURL.String(), "/"), nil
}
