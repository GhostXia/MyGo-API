package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CookieJar 定义了一个Cookie管理器，用于存储和管理不同服务的Cookie
type CookieJar struct {
	Cookies     map[string][]*http.Cookie `json:"cookies"`     // 按服务名称存储Cookie
	FilePath    string                    `json:"file_path"`   // Cookie文件路径
	LastUpdated time.Time                 `json:"last_updated"` // 最后更新时间
	mutex       sync.RWMutex               `json:"-"`          // 用于并发安全
}

// NewCookieJar 创建一个新的CookieJar实例
func NewCookieJar(filePath string) (*CookieJar, error) {
	jar := &CookieJar{
		Cookies:  make(map[string][]*http.Cookie),
		FilePath: filePath,
	}

	// 如果文件存在，则从文件加载Cookie
	if _, err := os.Stat(filePath); err == nil {
		err := jar.Load()
		if err != nil {
			return nil, fmt.Errorf("加载Cookie文件失败: %v", err)
		}
	}

	return jar, nil
}

// Load 从文件加载Cookie
func (jar *CookieJar) Load() error {
	jar.mutex.Lock()
	defer jar.mutex.Unlock()

	data, err := ioutil.ReadFile(jar.FilePath)
	if err != nil {
		return err
	}

	// 创建一个临时结构体用于解析JSON
	type cookieJarFile struct {
		Cookies     map[string][]cookieJSON `json:"cookies"`
		LastUpdated time.Time              `json:"last_updated"`
	}

	type cookieJSON struct {
		Name       string    `json:"name"`
		Value      string    `json:"value"`
		Path       string    `json:"path"`
		Domain     string    `json:"domain"`
		Expires    time.Time `json:"expires"`
		RawExpires string    `json:"raw_expires"`
		MaxAge     int       `json:"max_age"`
		Secure     bool      `json:"secure"`
		HttpOnly   bool      `json:"http_only"`
		SameSite   int       `json:"same_site"`
		Raw        string    `json:"raw"`
		Unparsed   []string  `json:"unparsed"`
	}

	var jarFile cookieJarFile
	if err := json.Unmarshal(data, &jarFile); err != nil {
		return err
	}

	// 将解析的数据转换为http.Cookie
	jar.Cookies = make(map[string][]*http.Cookie)
	for service, cookies := range jarFile.Cookies {
		jar.Cookies[service] = make([]*http.Cookie, len(cookies))
		for i, c := range cookies {
			jar.Cookies[service][i] = &http.Cookie{
				Name:       c.Name,
				Value:      c.Value,
				Path:       c.Path,
				Domain:     c.Domain,
				Expires:    c.Expires,
				RawExpires: c.RawExpires,
				MaxAge:     c.MaxAge,
				Secure:     c.Secure,
				HttpOnly:   c.HttpOnly,
				SameSite:   http.SameSite(c.SameSite),
				Raw:        c.Raw,
				Unparsed:   c.Unparsed,
			}
		}
	}

	jar.LastUpdated = jarFile.LastUpdated
	return nil
}

// Save 将Cookie保存到文件
func (jar *CookieJar) Save() error {
	jar.mutex.RLock()
	defer jar.mutex.RUnlock()

	// 创建一个临时结构体用于序列化JSON
	type cookieJarFile struct {
		Cookies     map[string][]cookieJSON `json:"cookies"`
		LastUpdated time.Time              `json:"last_updated"`
	}

	type cookieJSON struct {
		Name       string    `json:"name"`
		Value      string    `json:"value"`
		Path       string    `json:"path"`
		Domain     string    `json:"domain"`
		Expires    time.Time `json:"expires"`
		RawExpires string    `json:"raw_expires"`
		MaxAge     int       `json:"max_age"`
		Secure     bool      `json:"secure"`
		HttpOnly   bool      `json:"http_only"`
		SameSite   int       `json:"same_site"`
		Raw        string    `json:"raw"`
		Unparsed   []string  `json:"unparsed"`
	}

	jarFile := cookieJarFile{
		Cookies:     make(map[string][]cookieJSON),
		LastUpdated: time.Now(),
	}

	// 将http.Cookie转换为可序列化的结构
	for service, cookies := range jar.Cookies {
		jarFile.Cookies[service] = make([]cookieJSON, len(cookies))
		for i, c := range cookies {
			jarFile.Cookies[service][i] = cookieJSON{
				Name:       c.Name,
				Value:      c.Value,
				Path:       c.Path,
				Domain:     c.Domain,
				Expires:    c.Expires,
				RawExpires: c.RawExpires,
				MaxAge:     c.MaxAge,
				Secure:     c.Secure,
				HttpOnly:   c.HttpOnly,
				SameSite:   int(c.SameSite),
				Raw:        c.Raw,
				Unparsed:   c.Unparsed,
			}
		}
	}

	// 确保目录存在
	dir := filepath.Dir(jar.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 序列化并保存到文件
	data, err := json.MarshalIndent(jarFile, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(jar.FilePath, data, 0644)
}

// SetCookies 设置指定服务的Cookie
func (jar *CookieJar) SetCookies(service string, cookies []*http.Cookie) {
	jar.mutex.Lock()
	defer jar.mutex.Unlock()

	// 过滤掉过期的Cookie
	validCookies := make([]*http.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie.MaxAge < 0 {
			continue // 跳过已删除的Cookie
		}
		if !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()) {
			continue // 跳过已过期的Cookie
		}
		validCookies = append(validCookies, cookie)
	}

	// 更新Cookie
	jar.Cookies[service] = validCookies
	// 保存到文件
	jar.LastUpdated = time.Now()
}

// GetCookies 获取指定服务的所有Cookie
func (jar *CookieJar) GetCookies(service string) []*http.Cookie {
	jar.mutex.RLock()
	defer jar.mutex.RUnlock()

	// 过滤掉过期的Cookie
	validCookies := make([]*http.Cookie, 0)
	for _, cookie := range jar.Cookies[service] {
		if cookie.MaxAge < 0 {
			continue // 跳过已删除的Cookie
		}
		if !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()) {
			continue // 跳过已过期的Cookie
		}
		validCookies = append(validCookies, cookie)
	}

	return validCookies
}

// AddCookie 添加单个Cookie到指定服务
func (jar *CookieJar) AddCookie(service string, cookie *http.Cookie) {
	jar.mutex.Lock()
	defer jar.mutex.Unlock()

	// 如果Cookie已过期，则不添加
	if cookie.MaxAge < 0 {
		return
	}
	if !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()) {
		return
	}

	// 检查是否已存在同名Cookie，如果存在则更新
	cookies := jar.Cookies[service]
	for i, c := range cookies {
		if c.Name == cookie.Name && c.Domain == cookie.Domain && c.Path == cookie.Path {
			cookies[i] = cookie
			jar.Cookies[service] = cookies
			jar.LastUpdated = time.Now()
			return
		}
	}

	// 不存在则添加
	jar.Cookies[service] = append(cookies, cookie)
	jar.LastUpdated = time.Now()
}

// RemoveCookie 从指定服务中删除Cookie
func (jar *CookieJar) RemoveCookie(service, name, domain, path string) {
	jar.mutex.Lock()
	defer jar.mutex.Unlock()

	cookies := jar.Cookies[service]
	for i, c := range cookies {
		if c.Name == name && (domain == "" || c.Domain == domain) && (path == "" || c.Path == path) {
			// 移除找到的Cookie
			cookies = append(cookies[:i], cookies[i+1:]...)
			jar.Cookies[service] = cookies
			jar.LastUpdated = time.Now()
			return
		}
	}
}

// ClearService 清除指定服务的所有Cookie
func (jar *CookieJar) ClearService(service string) {
	jar.mutex.Lock()
	defer jar.mutex.Unlock()

	delete(jar.Cookies, service)
	jar.LastUpdated = time.Now()
}

// Clear 清除所有Cookie
func (jar *CookieJar) Clear() {
	jar.mutex.Lock()
	defer jar.mutex.Unlock()

	jar.Cookies = make(map[string][]*http.Cookie)
	jar.LastUpdated = time.Now()
}

// ApplyToRequest 将指定服务的Cookie应用到HTTP请求
func (jar *CookieJar) ApplyToRequest(service string, req *http.Request) {
	cookies := jar.GetCookies(service)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
}

// ExtractFromResponse 从HTTP响应中提取Cookie并保存到指定服务
func (jar *CookieJar) ExtractFromResponse(service string, resp *http.Response) {
	if resp == nil {
		return
	}

	cookies := resp.Cookies()
	if len(cookies) > 0 {
		jar.SetCookies(service, cookies)
		// 自动保存到文件
		if err := jar.Save(); err != nil {
			fmt.Printf("保存Cookie失败: %v\n", err)
		}
	}
}

// CookieAuthMiddleware 创建一个基于Cookie的认证中间件
func CookieAuthMiddleware(cookieJar *CookieJar, service string, requiredCookies []string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 检查是否有必要的Cookie
			cookies := cookieJar.GetCookies(service)
			cookieMap := make(map[string]*http.Cookie)
			for _, cookie := range cookies {
				cookieMap[cookie.Name] = cookie
			}

			// 验证所有必需的Cookie是否存在且有效
			for _, name := range requiredCookies {
				if _, exists := cookieMap[name]; !exists {
					http.Error(w, "Unauthorized: Missing required cookies", http.StatusUnauthorized)
					return
				}
			}

			// 将Cookie应用到请求中
			cookieJar.ApplyToRequest(service, r)

			// 继续处理请求
			next.ServeHTTP(w, r)
		})
	}
}