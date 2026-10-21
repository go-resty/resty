package resty

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCircuitBreakerTransportErrors(t *testing.T) {
	closedAddr := func() string {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := l.Addr().String()
		l.Close()
		return "http://" + addr
	}

	t.Run("count opens on connection refused", func(t *testing.T) {
		c := dcnl().SetBaseURL(closedAddr()).SetCircuitBreaker(NewCircuitBreakerCount(2, 1, time.Minute))
		for range 2 {
			_, err := c.R().Get("/")
			assertNotNil(t, err)
			assertFalse(t, errors.Is(err, ErrCircuitBreakerOpen), "should dial while closed")
		}
		_, err := c.R().Get("/")
		assertErrorIs(t, ErrCircuitBreakerOpen, err, "expected open after 2 transport errors")
	})

	t.Run("ratio opens on timeout", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { time.Sleep(200 * time.Millisecond) }))
		defer ts.Close()
		c := dcnl().SetBaseURL(ts.URL).SetTimeout(20 * time.Millisecond).
			SetCircuitBreaker(NewCircuitBreakerRatio(0.5, 2, time.Minute))
		for range 2 {
			_, err := c.R().Get("/")
			assertNotNil(t, err)
		}
		_, err := c.R().Get("/")
		assertErrorIs(t, ErrCircuitBreakerOpen, err, "expected open after timeouts")
	})

	t.Run("caller cancellation is not a failure", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { time.Sleep(200 * time.Millisecond) }))
		defer ts.Close()
		c := dcnl().SetBaseURL(ts.URL).SetCircuitBreaker(NewCircuitBreakerCount(1, 1, time.Minute))
		for range 3 {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := c.R().SetContext(ctx).Get("/")
			assertNotNil(t, err)
			assertFalse(t, errors.Is(err, ErrCircuitBreakerOpen), "cancellation must not open the breaker")
		}
	})

	t.Run("custom error policy ignores deadline exceeded", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { time.Sleep(200 * time.Millisecond) }))
		defer ts.Close()
		cb := NewCircuitBreakerCount(1, 1, time.Minute).SetErrorPolicy(func(err error) bool {
			return !errors.Is(err, context.DeadlineExceeded) && CircuitBreakerTransportErrorPolicy(err)
		})
		c := dcnl().SetBaseURL(ts.URL).SetTimeout(20 * time.Millisecond).SetCircuitBreaker(cb)
		for range 3 {
			_, err := c.R().Get("/")
			assertNotNil(t, err)
			assertFalse(t, errors.Is(err, ErrCircuitBreakerOpen), "timeouts ignored by the policy must not open the breaker")
		}
	})

	t.Run("nil error policy restores default", func(t *testing.T) {
		c := dcnl().SetBaseURL(closedAddr()).
			SetCircuitBreaker(NewCircuitBreakerCount(1, 1, time.Minute).SetErrorPolicy(func(error) bool { return false }).SetErrorPolicy(nil))
		_, _ = c.R().Get("/")
		_, err := c.R().Get("/")
		assertErrorIs(t, ErrCircuitBreakerOpen, err, "expected default policy after nil reset")
	})

	t.Run("ratio custom error policy is honored", func(t *testing.T) {
		cb := NewCircuitBreakerRatio(0.5, 2, time.Minute).SetErrorPolicy(func(error) bool { return false })
		c := dcnl().SetBaseURL(closedAddr()).SetCircuitBreaker(cb)
		for range 4 {
			_, err := c.R().Get("/")
			assertNotNil(t, err)
			assertFalse(t, errors.Is(err, ErrCircuitBreakerOpen), "errors ignored by the policy must not open the breaker")
		}
	})

	t.Run("ratio nil error policy restores default", func(t *testing.T) {
		cb := NewCircuitBreakerRatio(0.5, 2, time.Minute).SetErrorPolicy(func(error) bool { return false }).SetErrorPolicy(nil)
		c := dcnl().SetBaseURL(closedAddr()).SetCircuitBreaker(cb)
		for range 2 {
			_, err := c.R().Get("/")
			assertNotNil(t, err)
		}
		_, err := c.R().Get("/")
		assertErrorIs(t, ErrCircuitBreakerOpen, err, "expected default policy after nil reset")
	})
}
