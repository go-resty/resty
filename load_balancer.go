// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrNoBaseURLs is returned when no base URLs are found.
var ErrNoBaseURLs = errors.New("resty: no base URLs found")

// LoadBalancer is the interface that abstracts a load-balancing algorithm.
// Implementations return the next target base URL for each request and accept
// feedback about request outcomes so the algorithm can adapt over time.
type LoadBalancer interface {
	NextWithContext(ctx context.Context) (string, error)
	Feedback(*RequestFeedback)
	Close() error
}

// RequestFeedback contains request outcome data reported back to a
// [LoadBalancer] implementation.
type RequestFeedback struct {
	BaseURL string
	Success bool
	Attempt int
}

// NewRoundRobin creates a Round-Robin (RR) load balancer with the given base URLs.
func NewRoundRobin(baseURLs ...string) (*RoundRobin, error) {
	if len(baseURLs) == 0 {
		return nil, ErrNoBaseURLs
	}

	rr := &RoundRobin{lock: new(sync.Mutex)}
	if err := rr.Refresh(baseURLs...); err != nil {
		return rr, err
	}
	return rr, nil
}

var _ LoadBalancer = (*RoundRobin)(nil)

// RoundRobin implements the Round-Robin (RR) load-balancing algorithm.
type RoundRobin struct {
	lock     *sync.Mutex
	baseURLs []string
	current  int
}

// NextWithContext returns the next base URL using the Round-Robin (RR)
// algorithm and supports context cancellation.
func (rr *RoundRobin) NextWithContext(ctx context.Context) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	rr.lock.Lock()
	defer rr.lock.Unlock()

	if len(rr.baseURLs) == 0 {
		return "", ErrNoBaseURLs
	}

	baseURL := rr.baseURLs[rr.current]
	rr.current = (rr.current + 1) % len(rr.baseURLs)
	return baseURL, nil
}

// Feedback is a no-op for the Round-Robin (RR) load balancer.
func (rr *RoundRobin) Feedback(_ *RequestFeedback) {}

// Close is a no-op for the Round-Robin (RR) load balancer.
func (rr *RoundRobin) Close() error { return nil }

// Refresh method replaces the existing base URL list with the given base URLs.
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

// Host represents a backend target and its load-balancing parameters.
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

// Host transition states.
const (
	HostStateInactive HostState = iota
	HostStateActive
)

// HostStateChangeFunc is a callback type invoked whenever a host transitions between states.
// baseURL identifies the host, from is the previous [HostState], and to is the new [HostState].
type HostStateChangeFunc func(baseURL string, from, to HostState)

// ErrNoActiveHost is returned when all hosts are inactive in the load balancer.
var ErrNoActiveHost = errors.New("resty: no active host")

// NewWeightedRoundRobin creates a Weighted Round-Robin (WRR) load balancer with
// the given recovery duration and hosts.
func NewWeightedRoundRobin(recovery time.Duration, hosts ...*Host) (*WeightedRoundRobin, error) {
	if recovery == 0 {
		recovery = 120 * time.Second // defaults to 120 seconds
	}
	wrr := &WeightedRoundRobin{
		lock:     new(sync.RWMutex),
		hosts:    make([]*Host, 0),
		tick:     time.NewTicker(recovery),
		recovery: recovery,
		done:     make(chan struct{}),
	}

	if err := wrr.Refresh(hosts...); err != nil {
		wrr.tick.Stop()
		return wrr, err
	}

	go wrr.ticker()

	return wrr, nil
}

var _ LoadBalancer = (*WeightedRoundRobin)(nil)

// WeightedRoundRobin implements the Weighted Round-Robin (WRR) load-balancing algorithm.
// Hosts with higher weights receive a proportionally larger share of requests.
type WeightedRoundRobin struct {
	lock          *sync.RWMutex
	hosts         []*Host
	tick          *time.Ticker
	onStateChange HostStateChangeFunc

	// done is closed by Close to stop the recovery ticker goroutine.
	// Ticker.Stop does not close its channel, so the goroutine needs
	// a separate shutdown signal.
	done      chan struct{}
	closeOnce sync.Once

	// Recovery duration is used to set the timer to put
	// the host back in the pool for the next turn and
	// reset the failed request count for the segment
	recovery time.Duration
}

// NextWithContext returns the next base URL using the Weighted Round-Robin (WRR)
// algorithm and supports context cancellation.
func (wrr *WeightedRoundRobin) NextWithContext(ctx context.Context) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	wrr.lock.Lock()
	defer wrr.lock.Unlock()

	var best *Host
	total := 0
	for _, h := range wrr.hosts {
		if h.state == HostStateInactive {
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

// Feedback method processes a request outcome report for the Weighted Round-Robin(WRR)
// load balancer.
func (wrr *WeightedRoundRobin) Feedback(f *RequestFeedback) {
	if f == nil {
		return
	}

	wrr.lock.Lock()
	deactivated := ""
	onStateChange := wrr.onStateChange
	for _, host := range wrr.hosts {
		if host.BaseURL != f.BaseURL {
			continue
		}
		if !f.Success {
			host.failedRequests++
		}
		// Report the transition only on the crossing from active to inactive.
		// Feedback for a host that is already inactive (in-flight requests that
		// were dispatched before it was taken out) must not re-fire the hook.
		if host.state == HostStateActive && host.failedRequests >= host.MaxFailures {
			host.state = HostStateInactive
			deactivated = host.BaseURL
		}
		break
	}
	wrr.lock.Unlock()

	if onStateChange != nil && deactivated != "" {
		onStateChange(deactivated, HostStateActive, HostStateInactive)
	}
}

// Close stops the internal recovery ticker used by the Weighted Round-Robin (WRR)
// load balancer. It is safe to call Close more than once.
func (wrr *WeightedRoundRobin) Close() error {
	wrr.closeOnce.Do(func() {
		close(wrr.done)
	})
	wrr.lock.Lock()
	defer wrr.lock.Unlock()
	wrr.tick.Stop()
	return nil
}

// Refresh method replaces the existing host list with the given [Host] slice.
//
// The [Host] values are copied, so the balancer does not observe later changes
// the caller makes to them and the caller does not observe the balancer's
// internal bookkeeping.
func (wrr *WeightedRoundRobin) Refresh(hosts ...*Host) error {
	if hosts == nil {
		return nil
	}

	updated := make([]*Host, 0, len(hosts))
	for _, h := range hosts {
		baseURL, err := extractBaseURL(h.BaseURL)
		if err != nil {
			return err
		}

		hc := new(Host)
		*hc = *h
		hc.BaseURL = baseURL
		hc.state = HostStateActive
		hc.currentWeight = 0
		hc.failedRequests = 0

		// assign defaults if not provided
		if hc.MaxFailures == 0 {
			hc.MaxFailures = 5 // default value is 5
		}
		if hc.Weight <= 0 {
			// A non-positive weight never raises currentWeight, so such a host
			// would only ever be picked as the fallback first entry.
			hc.Weight = 1
		}

		updated = append(updated, hc)
	}

	// after processing, assign the updates
	wrr.lock.Lock()
	defer wrr.lock.Unlock()
	wrr.hosts = updated
	return nil
}

// SetOnStateChange sets a callback for host state transitions.
func (wrr *WeightedRoundRobin) SetOnStateChange(fn HostStateChangeFunc) {
	wrr.lock.Lock()
	defer wrr.lock.Unlock()
	wrr.onStateChange = fn
}

// SetRecoveryDuration updates the host recovery interval used by the WRR ticker.
func (wrr *WeightedRoundRobin) SetRecoveryDuration(d time.Duration) {
	wrr.lock.Lock()
	defer wrr.lock.Unlock()
	wrr.recovery = d
	wrr.tick.Reset(d)
}

func (wrr *WeightedRoundRobin) ticker() {
	for {
		select {
		case <-wrr.done:
			return
		case <-wrr.tick.C:
			wrr.recoverHosts()
		}
	}
}

// recoverHosts returns inactive hosts to the pool and resets their failure
// counters. The [Host] values are shared with NextWithContext and Feedback, so
// they are mutated under the write lock; the state change hooks run after the
// lock is released so a hook is free to call back into the balancer.
func (wrr *WeightedRoundRobin) recoverHosts() {
	wrr.lock.Lock()
	recovered := make([]string, 0, len(wrr.hosts))
	for _, host := range wrr.hosts {
		if host.state == HostStateInactive {
			host.state = HostStateActive
			host.failedRequests = 0
			recovered = append(recovered, host.BaseURL)
		}
	}
	onStateChange := wrr.onStateChange
	wrr.lock.Unlock()

	if onStateChange == nil {
		return
	}
	for _, baseURL := range recovered {
		onStateChange(baseURL, HostStateInactive, HostStateActive)
	}
}

// NewSRVWeightedRoundRobin creates an SRV-backed Weighted Round-Robin (WRR)
// load balancer.
func NewSRVWeightedRoundRobin(service, proto, domainName, httpScheme string) (*SRVWeightedRoundRobin, error) {
	if isStringEmpty(proto) {
		proto = "tcp"
	}
	if isStringEmpty(httpScheme) {
		httpScheme = "https"
	}

	return newSRVWeightedRoundRobin(service, proto, domainName, httpScheme,
		func() ([]*net.SRV, error) {
			_, addrs, err := net.LookupSRV(service, proto, domainName)
			return addrs, err
		})
}

// newSRVWeightedRoundRobin builds the balancer around the given SRV resolver so
// it can be replaced in tests.
func newSRVWeightedRoundRobin(service, proto, domainName, httpScheme string,
	lookupSRV func() ([]*net.SRV, error)) (*SRVWeightedRoundRobin, error) {
	wrr, _ := NewWeightedRoundRobin(0) // with this input error will not occur
	swrr := &SRVWeightedRoundRobin{
		Service:    service,
		Proto:      proto,
		DomainName: domainName,
		HTTPScheme: httpScheme,
		wrr:        wrr,
		tick:       time.NewTicker(180 * time.Second), // default is 180 seconds
		lock:       new(sync.Mutex),
		done:       make(chan struct{}),
		log:        createLogger(),
		lookupSRV:  lookupSRV,
	}

	if err := swrr.Refresh(); err != nil {
		swrr.tick.Stop()
		silently(swrr.wrr.Close())
		return swrr, err
	}

	go swrr.ticker()

	return swrr, nil
}

var _ LoadBalancer = (*SRVWeightedRoundRobin)(nil)

// SRVWeightedRoundRobin implements an SRV-backed Weighted Round-Robin (WRR)
// load balancer.
type SRVWeightedRoundRobin struct {
	Service    string
	Proto      string
	DomainName string
	HTTPScheme string

	wrr       *WeightedRoundRobin
	tick      *time.Ticker
	lock      *sync.Mutex
	lookupSRV func() ([]*net.SRV, error)
	log       Logger

	// done is closed by Close to stop the SRV refresh goroutine; see the same
	// field on [WeightedRoundRobin].
	done      chan struct{}
	closeOnce sync.Once
}

// NextWithContext returns the next SRV-derived base URL using the underlying
// Weighted Round-Robin (WRR) algorithm.
func (swrr *SRVWeightedRoundRobin) NextWithContext(ctx context.Context) (string, error) {
	return swrr.wrr.NextWithContext(ctx)
}

// Feedback forwards request feedback to the underlying WRR load balancer.
func (swrr *SRVWeightedRoundRobin) Feedback(f *RequestFeedback) {
	swrr.wrr.Feedback(f)
}

// Close stops the SRV refresh ticker and closes the underlying WRR load balancer.
// It is safe to call Close more than once.
func (swrr *SRVWeightedRoundRobin) Close() error {
	swrr.closeOnce.Do(func() {
		close(swrr.done)
	})
	swrr.lock.Lock()
	defer swrr.lock.Unlock()
	silently(swrr.wrr.Close())
	swrr.tick.Stop()
	return nil
}

// Refresh resolves SRV records and replaces the underlying WRR host list.
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
		baseURL := fmt.Sprintf("%s://%s:%d", swrr.HTTPScheme, domain, addr.Port)
		hosts[idx] = &Host{BaseURL: baseURL, Weight: int(addr.Weight)}
	}

	return swrr.wrr.Refresh(hosts...)
}

// SetRefreshDuration changes the SRV refresh interval (default: 180 seconds).
func (swrr *SRVWeightedRoundRobin) SetRefreshDuration(d time.Duration) {
	swrr.lock.Lock()
	defer swrr.lock.Unlock()
	swrr.tick.Reset(d)
}

// SetOnStateChange sets a callback for host state transitions.
func (swrr *SRVWeightedRoundRobin) SetOnStateChange(fn HostStateChangeFunc) {
	swrr.wrr.SetOnStateChange(fn)
}

// SetRecoveryDuration updates the host recovery interval used by the underlying WRR balancer.
func (swrr *SRVWeightedRoundRobin) SetRecoveryDuration(d time.Duration) {
	swrr.wrr.SetRecoveryDuration(d)
}

func (swrr *SRVWeightedRoundRobin) ticker() {
	for {
		select {
		case <-swrr.done:
			return
		case <-swrr.tick.C:
			// A failed periodic refresh keeps the previous host list; surface it
			// rather than dropping it, otherwise a broken SRV record is silent.
			if err := swrr.Refresh(); err != nil {
				swrr.log.Errorf("resty: SRV load balancer refresh: %v", err)
			}
		}
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
