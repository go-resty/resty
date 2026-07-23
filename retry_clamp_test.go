package resty

import (
	"testing"
	"time"
)

func TestClampNegativeRetrySettings(t *testing.T) {
	c := New()
	c.SetRetryCount(-3)
	if c.RetryCount() != 0 {
		t.Fatalf("RetryCount=%d want 0", c.RetryCount())
	}
	c.SetRetryWaitTime(-time.Second)
	if c.RetryWaitTime() != 0 {
		t.Fatalf("RetryWaitTime=%v want 0", c.RetryWaitTime())
	}
	c.SetRetryMaxWaitTime(-time.Second)
	if c.RetryMaxWaitTime() != 0 {
		t.Fatalf("RetryMaxWaitTime=%v want 0", c.RetryMaxWaitTime())
	}

	r := c.R()
	r.SetRetryCount(-1)
	if r.RetryCount != 0 {
		t.Fatalf("request RetryCount=%d want 0", r.RetryCount)
	}
	r.SetRetryWaitTime(-time.Millisecond)
	if r.RetryWaitTime != 0 {
		t.Fatalf("request RetryWaitTime=%v want 0", r.RetryWaitTime)
	}
	r.SetRetryMaxWaitTime(-time.Millisecond)
	if r.RetryMaxWaitTime != 0 {
		t.Fatalf("request RetryMaxWaitTime=%v want 0", r.RetryMaxWaitTime)
	}
}
