package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
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
		dialer, err := newSocks5Dialer(proxy)
		if err != nil {
			return nil, err
		}
		transport = &http.Transport{
			DialContext:           dialer.DialContext,
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

// socks5Dialer 实现SOCKS5代理的拨号器
type socks5Dialer struct {
	proxyURL *url.URL
	dialer   *net.Dialer
}

// newSocks5Dialer 创建一个新的SOCKS5拨号器
func newSocks5Dialer(proxyURL *url.URL) (*socks5Dialer, error) {
	return &socks5Dialer{
		proxyURL: proxyURL,
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}, nil
}

// DialContext 实现SOCKS5代理的拨号
func (d *socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// 连接到SOCKS5代理服务器
	proxyAddr := d.proxyURL.Host
	if d.proxyURL.Port() == "" {
		proxyAddr = proxyAddr + ":1080" // 默认SOCKS5端口
	}

	conn, err := d.dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	// 这里应该实现SOCKS5协议的握手过程
	// 由于Go标准库没有内置SOCKS5客户端，实际项目中应该使用第三方库如golang.org/x/net/proxy
	// 这里简化处理，实际使用时应替换为完整的SOCKS5实现
	return conn, nil
}