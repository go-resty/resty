package resty

import (
	"github.com/jinzhu/copier"
	"net/http"
	"net/url"
)

// CopyOrCreateClient Implement session mode
func CopyOrCreateClient(c *Client) *Client {
	if c == nil {
		return New()
	}

	tr := c.httpClient.Transport.(*http.Transport)
	newTr := http.DefaultTransport
	if tr != nil {
		newTr = &http.Transport{
			Proxy:                  tr.Proxy,
			DialContext:            tr.DialContext,
			Dial:                   tr.Dial,
			DialTLSContext:         tr.DialTLSContext,
			DialTLS:                tr.DialTLS,
			TLSClientConfig:        tr.TLSClientConfig,
			TLSHandshakeTimeout:    tr.TLSHandshakeTimeout,
			DisableKeepAlives:      tr.DisableKeepAlives,
			DisableCompression:     tr.DisableCompression,
			MaxIdleConns:           tr.MaxIdleConns,
			MaxIdleConnsPerHost:    tr.MaxIdleConnsPerHost,
			MaxConnsPerHost:        tr.MaxConnsPerHost,
			IdleConnTimeout:        tr.IdleConnTimeout,
			ResponseHeaderTimeout:  tr.ResponseHeaderTimeout,
			ExpectContinueTimeout:  tr.ExpectContinueTimeout,
			TLSNextProto:           tr.TLSNextProto,
			ProxyConnectHeader:     tr.ProxyConnectHeader,
			GetProxyConnectHeader:  tr.GetProxyConnectHeader,
			MaxResponseHeaderBytes: tr.MaxResponseHeaderBytes,
			WriteBufferSize:        tr.WriteBufferSize,
			ReadBufferSize:         tr.ReadBufferSize,
			ForceAttemptHTTP2:      tr.ForceAttemptHTTP2,
		}
	}
	httpClient := &http.Client{
		Transport:     newTr,
		CheckRedirect: c.httpClient.CheckRedirect,
		Jar:           c.httpClient.Jar,
		Timeout:       c.httpClient.Timeout,
	}

	var userInfo *User
	if c.UserInfo != nil {
		userInfo = &User{
			Username: c.UserInfo.Username,
			Password: c.UserInfo.Password,
		}
	}

	var proxyURL *url.URL
	if c.proxyURL != nil {
		proxyURL = &url.URL{
			Scheme:      c.proxyURL.Scheme,
			Opaque:      c.proxyURL.Opaque,
			User:        c.proxyURL.User,
			Host:        c.proxyURL.Host,
			Path:        c.proxyURL.Path,
			RawPath:     c.proxyURL.RawPath,
			OmitHost:    c.proxyURL.OmitHost,
			ForceQuery:  c.proxyURL.ForceQuery,
			RawQuery:    c.proxyURL.RawQuery,
			Fragment:    c.proxyURL.Fragment,
			RawFragment: c.proxyURL.RawFragment,
		}
	}

	var newC Client
	copier.Copy(&newC, c)
	newC.httpClient = httpClient
	newC.UserInfo = userInfo
	newC.proxyURL = proxyURL

	return &newC
}
