package resty

import (
	"crypto/tls"
	"net/http"
	"net/url"
)

// ITransport ...
type ITransport interface {
	http.RoundTripper
	SetTLSClientConfig(config *tls.Config)
	GetTLSClientConfig() *tls.Config
	SetProxy(proxyURL string) error
	GetProxy() func(*http.Request) (*url.URL, error)
	RemoveProxy()
	IsProxySet() bool
}

// Transport ...
type Transport struct {
	transport *http.Transport
	proxyURL  *url.URL
}

// SetTLSClientConfig ...
func (t *Transport) SetTLSClientConfig(config *tls.Config) {
	t.transport.TLSClientConfig = config
}

// GetTLSClientConfig ...
func (t *Transport) GetTLSClientConfig() *tls.Config {
	return t.transport.TLSClientConfig
}

// SetProxy ...
func (t *Transport) SetProxy(proxyURL string) (err error) {
	if pURL, err := url.Parse(proxyURL); err == nil {
		t.proxyURL = pURL
		t.transport.Proxy = http.ProxyURL(t.proxyURL)
	} else {
		t.RemoveProxy()
	}
	return
}

// GetProxy ...
func (t *Transport) GetProxy() func(*http.Request) (*url.URL, error) {
	return t.transport.Proxy
}

// RemoveProxy ...
func (t *Transport) RemoveProxy() {
	t.proxyURL = nil
	t.transport.Proxy = nil
}

// IsProxySet ...
func (t *Transport) IsProxySet() bool {
	return t.proxyURL != nil
}

// RoundTrip ...
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(req)
}
