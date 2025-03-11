package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// CookieResponse 定义Cookie API响应结构
type CookieResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// CookieInfo 定义Cookie信息结构，用于API响应
type CookieInfo struct {
	Name       string    `json:"name"`
	Value      string    `json:"value,omitempty"` // 出于安全考虑，可能不返回实际值
	Domain     string    `json:"domain,omitempty"`
	Path       string    `json:"path,omitempty"`
	Expires    time.Time `json:"expires,omitempty"`
	MaxAge     int       `json:"max_age,omitempty"`
	Secure     bool      `json:"secure,omitempty"`
	HttpOnly   bool      `json:"http_only,omitempty"`
	SameSite   string    `json:"same_site,omitempty"`
}

// AddCookieRequest 定义添加Cookie的请求结构
type AddCookieRequest struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	MaxAge   int    `json:"max_age,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HttpOnly bool   `json:"http_only,omitempty"`
	SameSite string `json:"same_site,omitempty"`
}

// DeleteCookieRequest 定义删除Cookie的请求结构
type DeleteCookieRequest struct {
	Name   string `json:"name"`
	Domain string `json:"domain,omitempty"`
	Path   string `json:"path,omitempty"`
}

// handleCookies 处理获取所有Cookie的请求
func handleCookies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 认证（仅当未启用Cookie认证时检查令牌）
	if !config.CookieAuth.Enabled && r.Header.Get("Authorization") != "Bearer "+config.AuthToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 获取服务名称，默认使用配置中的服务名称
	service := r.URL.Query().Get("service")
	if service == "" {
		service = config.CookieAuth.ServiceName
	}

	// 获取指定服务的所有Cookie
	cookies := cookieJar.GetCookies(service)

	// 转换为API响应格式
	cookieInfos := make([]CookieInfo, 0, len(cookies))
	for _, cookie := range cookies {
		sameSite := ""
		switch cookie.SameSite {
		case http.SameSiteDefaultMode:
			sameSite = "default"
		case http.SameSiteNoneMode:
			sameSite = "none"
		case http.SameSiteLaxMode:
			sameSite = "lax"
		case http.SameSiteStrictMode:
			sameSite = "strict"
		}

		cookieInfos = append(cookieInfos, CookieInfo{
			Name:     cookie.Name,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Expires:  cookie.Expires,
			MaxAge:   cookie.MaxAge,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: sameSite,
		})
	}

	// 构造响应
	response := CookieResponse{
		Success: true,
		Message: "Cookies retrieved successfully",
		Data:    cookieInfos,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAddCookie 处理添加Cookie的请求
func handleAddCookie(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 认证（仅当未启用Cookie认证时检查令牌）
	if !config.CookieAuth.Enabled && r.Header.Get("Authorization") != "Bearer "+config.AuthToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 解析请求体
	var req AddCookieRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request: Invalid JSON", http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if req.Name == "" || req.Value == "" {
		http.Error(w, "Bad Request: Name and Value are required", http.StatusBadRequest)
		return
	}

	// 获取服务名称，默认使用配置中的服务名称
	service := r.URL.Query().Get("service")
	if service == "" {
		service = config.CookieAuth.ServiceName
	}

	// 创建Cookie
	cookie := &http.Cookie{
		Name:     req.Name,
		Value:    req.Value,
		Domain:   req.Domain,
		Path:     req.Path,
		MaxAge:   req.MaxAge,
		Secure:   req.Secure,
		HttpOnly: req.HttpOnly,
	}

	// 设置SameSite
	switch req.SameSite {
	case "none":
		cookie.SameSite = http.SameSiteNoneMode
	case "lax":
		cookie.SameSite = http.SameSiteLaxMode
	case "strict":
		cookie.SameSite = http.SameSiteStrictMode
	}

	// 添加Cookie
	cookieJar.AddCookie(service, cookie)

	// 保存Cookie到文件
	if err := cookieJar.Save(); err != nil {
		http.Error(w, "Internal Server Error: Failed to save cookies", http.StatusInternalServerError)
		return
	}

	// 构造响应
	response := CookieResponse{
		Success: true,
		Message: "Cookie added successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleDeleteCookie 处理删除Cookie的请求
func handleDeleteCookie(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 认证（仅当未启用Cookie认证时检查令牌）
	if !config.CookieAuth.Enabled && r.Header.Get("Authorization") != "Bearer "+config.AuthToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 解析请求体
	var req DeleteCookieRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request: Invalid JSON", http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if req.Name == "" {
		http.Error(w, "Bad Request: Name is required", http.StatusBadRequest)
		return
	}

	// 获取服务名称，默认使用配置中的服务名称
	service := r.URL.Query().Get("service")
	if service == "" {
		service = config.CookieAuth.ServiceName
	}

	// 删除Cookie
	cookieJar.RemoveCookie(service, req.Name, req.Domain, req.Path)

	// 保存Cookie到文件
	if err := cookieJar.Save(); err != nil {
		http.Error(w, "Internal Server Error: Failed to save cookies", http.StatusInternalServerError)
		return
	}

	// 构造响应
	response := CookieResponse{
		Success: true,
		Message: "Cookie deleted successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}