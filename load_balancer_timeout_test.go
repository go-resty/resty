package resty

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

type feedbackRecorder struct {
	LoadBalancer
	reports []RequestFeedback
}

func (r *feedbackRecorder) Feedback(f *RequestFeedback) {
	r.reports = append(r.reports, *f)
	r.LoadBalancer.Feedback(f)
}

type feedbackRoundTripper func(*http.Request) (*http.Response, error)

func (f feedbackRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLoadBalancerTimeoutIsFailure(t *testing.T) {
	rr, err := NewRoundRobin("http://bad.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	client := dcnl().SetLoadBalancer(lb).SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	}))
	defer client.Close()
	_, err = client.R().Get("/")
	if err == nil {
		t.Fatal("expected a transport timeout")
	}
	if len(lb.reports) != 1 || lb.reports[0].Success {
		t.Fatalf("timeout feedback = %+v, want one failed attempt", lb.reports)
	}
}

func TestLoadBalancerTimeoutFeedbackBeforeRetry(t *testing.T) {
	rr, err := NewRoundRobin("http://bad.invalid", "http://good.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	calls := 0
	client := dcnl().SetLoadBalancer(lb).SetRetryCount(1).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(time.Millisecond).
		SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
			}
			if len(lb.reports) != 1 || lb.reports[0].Success {
				t.Errorf("feedback before retry = %+v, want first attempt recorded as failed", lb.reports)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
		}))
	defer client.Close()
	res, err := client.R().Get("/")
	assertNil(t, err)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if len(lb.reports) != 2 {
		t.Fatalf("feedback = %+v, want one report per attempt", lb.reports)
	}
	if lb.reports[0].BaseURL != "http://bad.invalid" || lb.reports[0].Success || lb.reports[0].Attempt != 1 {
		t.Errorf("first attempt feedback = %+v", lb.reports[0])
	}
	if lb.reports[1].BaseURL != "http://good.invalid" || !lb.reports[1].Success || lb.reports[1].Attempt != 2 {
		t.Errorf("second attempt feedback = %+v", lb.reports[1])
	}
}

func TestLoadBalancerTimeoutWeightedFailover(t *testing.T) {
	bad := &Host{BaseURL: "http://bad.invalid", Weight: 100, MaxFailures: 1}
	good := &Host{BaseURL: "http://good.invalid", Weight: 1, MaxFailures: 1}
	wrr, err := NewWeightedRoundRobin(time.Hour, bad, good)
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: wrr}
	var hosts []string
	client := dcnl().SetLoadBalancer(lb).SetRetryCount(2).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(time.Millisecond).
		SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
			hosts = append(hosts, r.URL.Host)
			if r.URL.Host == "bad.invalid" {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
			}
			return feedbackResponse(r, http.StatusOK), nil
		}))
	defer client.Close()
	res, err := client.R().Get("/")
	assertNil(t, err)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if strings.Join(hosts, ",") != "bad.invalid,good.invalid" {
		t.Errorf("attempted hosts = %v, want immediate failover", hosts)
	}
	wrr.lock.RLock()
	states := make(map[string]HostState)
	for _, host := range wrr.hosts {
		states[host.BaseURL] = host.state
	}
	wrr.lock.RUnlock()
	if states[bad.BaseURL] != HostStateInActive || states[good.BaseURL] != HostStateActive {
		t.Errorf("host states: %v", states)
	}
	if len(lb.reports) != 2 {
		t.Errorf("feedback = %+v, want exactly two reports", lb.reports)
	}
}

func TestLoadBalancerTimeoutFinalAttemptReportedOnce(t *testing.T) {
	rr, err := NewRoundRobin("http://bad.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	client := dcnl().SetLoadBalancer(lb).SetRetryCount(2).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(time.Millisecond).
		SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
			return nil, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
		}))
	defer client.Close()
	_, err = client.R().Get("/")
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if len(lb.reports) != 3 {
		t.Fatalf("feedback = %+v, want exactly three attempts", lb.reports)
	}
	for i, report := range lb.reports {
		if report.Attempt != i+1 || report.Success {
			t.Errorf("attempt %d feedback = %+v", i+1, report)
		}
	}
}

func TestLoadBalancerFeedbackStatusCodes(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusNotImplemented, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			rr, err := NewRoundRobin("http://backend.invalid")
			assertNil(t, err)
			lb := &feedbackRecorder{LoadBalancer: rr}
			client := dcnl().SetLoadBalancer(lb).SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
				return feedbackResponse(r, status), nil
			}))
			defer client.Close()
			res, err := client.R().Get("/")
			assertNil(t, err)
			if res != nil && res.Body != nil {
				defer res.Body.Close()
			}
			wantSuccess := status < 500 || status == http.StatusNotImplemented
			if len(lb.reports) != 1 || lb.reports[0].Success != wantSuccess || lb.reports[0].Attempt != 1 {
				t.Errorf("status %d feedback = %+v, want success=%v", status, lb.reports, wantSuccess)
			}
		})
	}
}

func TestLoadBalancerFeedbackConnectionRefused(t *testing.T) {
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	client := dcnl().SetLoadBalancer(lb).SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	}))
	defer client.Close()
	_, err = client.R().Get("/")
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("got %v, want connection refused", err)
	}
	if len(lb.reports) != 1 || lb.reports[0].Success {
		t.Errorf("connection-refused feedback = %+v", lb.reports)
	}
}

func TestLoadBalancerFeedbackCallerCancellation(t *testing.T) {
	for _, when := range []string{"before_request", "during_transport", "deadline_cause"} {
		t.Run(when, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			cause := context.Canceled
			if when == "deadline_cause" {
				cause = context.DeadlineExceeded
			}
			if when == "before_request" {
				cancel(cause)
			}
			rr, err := NewRoundRobin("http://backend.invalid")
			assertNil(t, err)
			lb := &feedbackRecorder{LoadBalancer: rr}
			calls := 0
			client := dcnl().SetLoadBalancer(lb).SetRetryCount(2).
				SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
					calls++
					cancel(cause)
					return nil, cause
				}))
			defer client.Close()
			_, err = client.R().SetContext(ctx).Get("/")
			if !errors.Is(err, context.Canceled) {
				t.Errorf("got %v, want caller cancellation", err)
			}
			wantCalls := 1
			if when == "before_request" {
				wantCalls = 0
			}
			if calls != wantCalls || len(lb.reports) != 0 {
				t.Errorf("calls=%d feedback=%+v, want %d calls and no backend report", calls, lb.reports, wantCalls)
			}
		})
	}
}

func TestLoadBalancerFeedbackInvalidRequest(t *testing.T) {
	for _, tc := range []struct{ method, url string }{{MethodGet, "%"}, {"bad method", "/"}} {
		t.Run(tc.method+tc.url, func(t *testing.T) {
			rr, err := NewRoundRobin("http://backend.invalid")
			assertNil(t, err)
			lb := &feedbackRecorder{LoadBalancer: rr}
			client := dcnl().SetLoadBalancer(lb).SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
				t.Error("invalid request reached the transport")
				return nil, errors.New("unexpected transport call")
			}))
			defer client.Close()
			_, err = client.R().Execute(tc.method, tc.url)
			if err == nil || len(lb.reports) != 0 {
				t.Errorf("invalid request: error=%v feedback=%+v", err, lb.reports)
			}
		})
	}
}

func TestLoadBalancerFeedbackBeforeCanceledRetryWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	calls := 0
	client := dcnl().SetLoadBalancer(lb).SetRetryCount(1).
		SetRetryWaitTime(time.Hour).SetRetryMaxWaitTime(time.Hour).
		AddRetryConditions(func(res *Response, _ error) bool { return res.StatusCode() == http.StatusServiceUnavailable }).
		AddRetryHooks(func(*Response, error) {
			if len(lb.reports) != 1 || lb.reports[0].Success {
				t.Errorf("feedback before retry hook = %+v, want the failed HTTP attempt", lb.reports)
			}
			cancel()
		}).
		SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			return feedbackResponse(r, http.StatusServiceUnavailable), nil
		}))
	defer client.Close()
	res, err := client.R().SetContext(ctx).Get("/")
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if !errors.Is(err, context.Canceled) || calls != 1 || len(lb.reports) != 1 {
		t.Errorf("error=%v calls=%d feedback=%+v, want cancellation after one reported attempt", err, calls, lb.reports)
	}
}

func TestLoadBalancerFeedbackCompletedResponseAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	client := dcnl().SetLoadBalancer(lb).SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
		cancel()
		return feedbackResponse(r, http.StatusOK), nil
	}))
	defer client.Close()
	res, err := client.R().SetContext(ctx).Get("/")
	assertNil(t, err)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if len(lb.reports) != 1 || !lb.reports[0].Success {
		t.Errorf("completed-response feedback = %+v, want the successful response retained", lb.reports)
	}
}

func feedbackResponse(r *http.Request, status int) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader("ok")), Request: r}
}

func TestLoadBalancerFeedbackParentDeadline(t *testing.T) {
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	calls := 0
	client := dcnl().SetLoadBalancer(lb).SetRetryCount(2).
		SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			<-r.Context().Done()
			return nil, r.Context().Err()
		}))
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = client.R().SetContext(ctx).Get("/")
	if !errors.Is(err, context.DeadlineExceeded) || calls > 1 || len(lb.reports) != 0 {
		t.Errorf("parent deadline: error=%v calls=%d feedback=%+v", err, calls, lb.reports)
	}
}

func TestLoadBalancerFeedbackNonIdempotent(t *testing.T) {
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	calls := 0
	client := dcnl().SetLoadBalancer(lb).SetRetryCount(2).
		SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, &net.OpError{Op: "write", Net: "tcp", Err: os.ErrDeadlineExceeded}
		}))
	defer client.Close()
	_, err = client.R().Post("/")
	if err == nil || calls != 1 || len(lb.reports) != 1 || lb.reports[0].Success {
		t.Errorf("non-idempotent request: error=%v calls=%d feedback=%+v", err, calls, lb.reports)
	}
}

func TestLoadBalancerFeedbackResponseErrorAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	middlewareErr := errors.New("response processing failed")
	client := dcnl().SetLoadBalancer(lb).
		AddResponseMiddleware(func(*Client, *Response) error {
			cancel()
			return middlewareErr
		}).
		SetTransport(feedbackRoundTripper(func(r *http.Request) (*http.Response, error) {
			return feedbackResponse(r, http.StatusServiceUnavailable), nil
		}))
	defer client.Close()
	res, err := client.R().SetContext(ctx).Get("/")
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err == nil || len(lb.reports) != 1 || lb.reports[0].Success {
		t.Errorf("observed HTTP failure: error=%v feedback=%+v", err, lb.reports)
	}
}

func TestLoadBalancerFeedbackPreparationError(t *testing.T) {
	rr, err := NewRoundRobin("http://backend.invalid")
	assertNil(t, err)
	lb := &feedbackRecorder{LoadBalancer: rr}
	prepareErr := errors.New("request preparation failed")
	client := dcnl().SetLoadBalancer(lb).
		SetRequestMiddlewares(MiddlewareRequestCreate, func(*Client, *Request) error { return prepareErr }).
		SetTransport(feedbackRoundTripper(func(*http.Request) (*http.Response, error) {
			t.Error("request preparation error reached the transport")
			return nil, errors.New("unexpected transport call")
		}))
	defer client.Close()
	_, err = client.R().Get("/")
	if !errors.Is(err, prepareErr) || len(lb.reports) != 0 {
		t.Errorf("preparation error=%v feedback=%+v", err, lb.reports)
	}
}
