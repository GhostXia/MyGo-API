package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
	
	"golang.org/x/net/proxy"
)

// ProxyTransport 创建一个支持HTTP/SOCKS5代理的http.Transport
func ProxyTransport(proxyURL string) (*http.Transport, error) {
	var transport *http.Transport

	if proxyURL == "" {
		// 不使用代理
		transport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
		return transport, nil
	}

	// 解析代理URL
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	// 根据代理类型创建不同的Transport
	switch proxy.Scheme {
	case "http", "https":
		// HTTP/HTTPS代理
		transport = &http.Transport{
			Proxy: http.ProxyURL(proxy),
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
	case "socks5":
		// SOCKS5代理
		dialer, err := proxy.SOCKS5("tcp", proxy.Host, nil, nil)
		if err != nil {
			return nil, err
		}
		transport = &http.Transport{
			DialContext:           dialer.(proxy.ContextDialer).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
	default:
		return nil, &url.Error{
			Op:  "proxy",
			URL: proxyURL,
			Err: err,
		}
	}

	return transport, nil
}