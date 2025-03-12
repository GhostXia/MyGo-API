package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
)

// 全局变量
var (
	authToken        *string
	httpProxy        *string
	port             *uint
	configFile       *string
	longTxt          *bool
	longTxtThreshold int
	cookiesDir       *string
	httpClient       = &http.Client{Timeout: 30 * time.Minute}
	cookieJar        *CookieJar
	cacheStore       *cache.Cache
	config           *Config
)

// Config 定义应用配置结构
type Config struct {
	AuthToken   string           `json:"auth_token"`
	HttpProxy   string           `json:"http_proxy"`
	Port        uint             `json:"port"`
	BaseURL     string           `json:"base_url"`
	Timeout     time.Duration    `json:"timeout"`
	RetryCount  int              `json:"retry_count"`
	ConfigFlags map[string]bool  `json:"config_flags"`
	Models      []string         `json:"models"`
	RateLimit   int              `json:"rate_limit"`
	CacheSize   int              `json:"cache_size"`
	CookieAuth  CookieAuthConfig `json:"cookie_auth"`
	CORS        CORSConfig       `json:"cors"`
	Logging     LoggingConfig    `json:"logging"`
	TLS         TLSConfig        `json:"tls"`
}

// CookieAuthConfig 定义Cookie认证配置
type CookieAuthConfig struct {
	Enabled         bool     `json:"enabled"`          // 是否启用Cookie认证
	CookieFile      string   `json:"cookie_file"`      // Cookie文件路径
	ServiceName     string   `json:"service_name"`     // 服务名称
	RequiredCookies []string `json:"required_cookies"` // 必需的Cookie名称列表
}

// CORSConfig 定义CORS配置
type CORSConfig struct {
	AllowedOrigins []string `json:"allowed_origins"`
	AllowedMethods []string `json:"allowed_methods"`
	AllowedHeaders []string `json:"allowed_headers"`
	MaxAge         int      `json:"max_age"`
}

// LoggingConfig 定义日志配置
type LoggingConfig struct {
	Level  string `json:"level"`
	File   string `json:"file"`
	Format string `json:"format"`
}

// TLSConfig 定义TLS配置
type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// ConfigManager 配置管理器结构
type ConfigManager struct {
	configPath string
	config     *Config
	logger     *log.Logger
	mutex      sync.RWMutex
}

// NewConfigManager 创建配置管理器
func NewConfigManager(configPath string, logger *log.Logger) (*ConfigManager, error) {
	cm := &ConfigManager{
		configPath: configPath,
		logger:     logger,
		config: &Config{
			Port:        8080,
			Timeout:     30 * time.Second,
			RetryCount:  3,
			ConfigFlags: make(map[string]bool),
			Models:      []string{"model-base", "model-reasoning"},
			RateLimit:   60,
			CacheSize:   1000,
			CookieAuth: CookieAuthConfig{
				Enabled:     false,
				CookieFile:  "cookies.json",
				ServiceName: "default",
			},
			CORS: CORSConfig{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "OPTIONS"},
				AllowedHeaders: []string{"Content-Type", "Authorization"},
				MaxAge:         86400,
			},
		},
	}

	// 加载配置文件
	err := cm.loadConfig()
	if err != nil {
		return cm, err
	}

	return cm, nil
}

// loadConfig 加载配置文件
func (cm *ConfigManager) loadConfig() error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// 检查配置文件是否存在
	if _, err := os.Stat(cm.configPath); os.IsNotExist(err) {
		cm.logger.Printf("配置文件 %s 不存在，使用默认配置", cm.configPath)
		return fmt.Errorf("配置文件不存在")
	}

	// 读取配置文件
	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		cm.logger.Printf("读取配置文件失败: %v", err)
		return err
	}

	// 解析配置
	var newConfig Config
	if err := json.Unmarshal(data, &newConfig); err != nil {
		cm.logger.Printf("解析配置文件失败: %v", err)
		return err
	}

	// 更新配置
	cm.config = &newConfig
	cm.logger.Printf("配置已加载: %s", cm.configPath)

	return nil
}

// GetConfig 获取当前配置
func (cm *ConfigManager) GetConfig() *Config {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	return cm.config
}

// StartWatching 启动配置文件监控
func (cm *ConfigManager) StartWatching() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if err := cm.loadConfig(); err != nil {
				cm.logger.Printf("重新加载配置失败: %v", err)
			}
		}
	}()

	cm.logger.Printf("配置监控已启动: %s", cm.configPath)
}

// CookieJar 定义Cookie管理器
type CookieJar struct {
	cookies  map[string][]*http.Cookie
	filePath string
	mutex    sync.RWMutex
}

// NewCookieJar 创建Cookie管理器
func NewCookieJar(filePath string) (*CookieJar, error) {
	jar := &CookieJar{
		cookies:  make(map[string][]*http.Cookie),
		filePath: filePath,
	}

	// 如果文件存在，加载Cookie
	if _, err := os.Stat(filePath); err == nil {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("读取Cookie文件失败: %v", err)
		}

		var cookieData map[string][]*http.Cookie
		if err := json.Unmarshal(data, &cookieData); err != nil {
			return nil, fmt.Errorf("解析Cookie文件失败: %v", err)
		}

		jar.cookies = cookieData
	}

	return jar, nil
}

// AddCookie 添加Cookie
func (jar *CookieJar) AddCookie(serviceName string, cookie *http.Cookie) {
	jar.mutex.Lock()
	defer jar.mutex.Unlock()

	if _, ok := jar.cookies[serviceName]; !ok {
		jar.cookies[serviceName] = make([]*http.Cookie, 0)
	}

	// 检查是否已存在相同名称的Cookie
	for i, c := range jar.cookies[serviceName] {
		if c.Name == cookie.Name {
			// 更新现有Cookie
			jar.cookies[serviceName][i] = cookie
			return
		}
	}

	// 添加新Cookie
	jar.cookies[serviceName] = append(jar.cookies[serviceName], cookie)

	// 保存到文件
	jar.Save()
}

// GetCookies 获取指定服务的所有Cookie
func (jar *CookieJar) GetCookies(serviceName string) []*http.Cookie {
	jar.mutex.RLock()
	defer jar.mutex.RUnlock()

	if cookies, ok := jar.cookies[serviceName]; ok {
		return cookies
	}
	return nil
}

// ApplyToRequest 将Cookie应用到请求
func (jar *CookieJar) ApplyToRequest(serviceName string, req *http.Request) {
	cookies := jar.GetCookies(serviceName)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
}

// ExtractFromResponse 从响应中提取Cookie
func (jar *CookieJar) ExtractFromResponse(serviceName string, resp *http.Response) {
	for _, cookie := range resp.Cookies() {
		jar.AddCookie(serviceName, cookie)
	}
}

// Save 保存Cookie到文件
func (jar *CookieJar) Save() error {
	data, err := json.Marshal(jar.cookies)
	if err != nil {
		return err
	}

	return os.WriteFile(jar.filePath, data, 0644)
}

// Client 定义API客户端
type Client struct {
	baseUrl        string
	headers        map[string]string
	configFlags    map[string]bool
	timeout        time.Duration
	retryCount     int
	logger         *log.Logger
	cookieJar      *CookieJar
	serviceName    string
	isReasoning    bool
	enableSearch   bool
	uploadMessage  bool
	keepChat       bool
	ignoreThinking bool
	enableUpload   bool
}

// ClientOption 定义客户端配置选项
type ClientOption func(*Client)

// WithTimeout 设置超时时间
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = timeout
	}
}

// WithRetryCount 设置重试次数
func WithRetryCount(count int) ClientOption {
	return func(c *Client) {
		c.retryCount = count
	}
}

// WithBaseURL 设置基础URL
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseUrl = url
	}
}

// WithLogger 设置日志记录器
func WithLogger(logger *log.Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// WithCookieJar 设置Cookie管理器
func WithCookieJar(jar *CookieJar, serviceName string) ClientOption {
	return func(c *Client) {
		c.cookieJar = jar
		c.serviceName = serviceName
	}
}

// WithReasoning 设置是否使用推理模型
func WithReasoning(isReasoning bool) ClientOption {
	return func(c *Client) {
		c.isReasoning = isReasoning
	}
}

// WithSearch 设置是否启用搜索
func WithSearch(enableSearch bool) ClientOption {
	return func(c *Client) {
		c.enableSearch = enableSearch
	}
}

// WithUploadMessage 设置是否将消息上传为文件
func WithUploadMessage(uploadMessage bool) ClientOption {
	return func(c *Client) {
		c.uploadMessage = uploadMessage
	}
}

// WithKeepChat 设置是否保留聊天历史
func WithKeepChat(keepChat bool) ClientOption {
	return func(c *Client) {
		c.keepChat = keepChat
	}
}

// WithIgnoreThinking 设置是否忽略思考内容
func WithIgnoreThinking(ignoreThinking bool) ClientOption {
	return func(c *Client) {
		c.ignoreThinking = ignoreThinking
	}
}

// WithEnableUpload 设置是否启用文件上传
func WithEnableUpload(enableUpload bool) ClientOption {
	return func(c *Client) {
		c.enableUpload = enableUpload
	}
}

// getModelName 根据isReasoning标志返回模型名称
func (c *Client) getModelName() string {
	if c.isReasoning {
		return "model-reasoning"
	}
	return "model-base"
}

// NewClient 创建一个新的客户端实例
func NewClient(authToken string, configFlags map[string]bool, options ...ClientOption) *Client {
	client := &Client{
		baseUrl: "", // 将在应用选项时设置
		headers: map[string]string{
			"accept":        "*/*",
			"content-type":  "application/json",
			"authorization": "Bearer " + authToken,
			"user-agent":    "MyGo-API/1.0",
		},
		configFlags: configFlags,
		timeout:     30 * time.Second, // 默认值
		retryCount:  3, // 默认值
		logger:      log.New(os.Stdout, "[API Client] ", log.LstdFlags),
	}

	// 应用自定义选项
	for _, option := range options {
		option(client)
	}

	return client
}

// RequestBody 定义了符合OpenAI格式的请求体结构
type RequestBody struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Stream bool `json:"stream"`
}

// preparePayload 构造发送到目标API的请求负载
func (c *Client) preparePayload(message string, fileId string) map[string]any {
	var toolOverrides any = map[string]bool{
		"imageGen":     true,
		"webSearch":    c.enableSearch,
		"trendsSearch": c.enableSearch,
	}

	fileAttachments := []string{}
	if fileId != "" {
		fileAttachments = []string{fileId}
	}

	// 基本负载
	payload := map[string]any{
		"modelName":             c.getModelName(),
		"message":               message,
		"fileAttachments":       fileAttachments,
		"temporary":             !c.keepChat,
		"toolOverrides":         toolOverrides,
		"enableImageGeneration": true,
	}

	// 添加配置标志
	for key, value := range c.configFlags {
		payload[key] = value
	}

	return payload
}

// uploadMessageAsFile 将消息上传为文件并返回文件ID
func (c *Client) uploadMessageAsFile(message string) (string, error) {
	content := base64.StdEncoding.EncodeToString([]byte(message))
	payload := map[string]any{
		"content":      content,
		"fileMimeType": "text/plain",
		"fileName":     uuid.New().String() + ".txt",
	}

	c.logger.Println("正在将消息上传为文件")
	resp, err := c.doRequest(http.MethodPost, c.baseUrl+"/upload-file", payload)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("上传文件错误: %d %s", resp.StatusCode, resp.Status)
	}

	var response struct {
		FileMetadataId string `json:"fileMetadataId"`
	}

	err = json.Unmarshal(body, &response)
	if err != nil || response.FileMetadataId == "" {
		return "", fmt.Errorf("解析JSON错误或FileMetadataId为空: %s", string(body))
	}
	return response.FileMetadataId, nil
}

// doRequest 发送HTTP请求并返回响应
func (c *Client) doRequest(method, url string, payload any) (*http.Response, error) {
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化请求负载失败: %v", err)
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	// 如果启用了Cookie认证，应用Cookie到请求
	if c.cookieJar != nil {
		c.cookieJar.ApplyToRequest(c.serviceName, req)
		// 当使用Cookie认证时，可以选择不发送Authorization头
		if config.CookieAuth.Enabled {
			req.Header.Del("Authorization")
		}
	}

	// 创建带超时的HTTP客户端
	transport, err := ProxyTransport(config.HttpProxy)
	if err != nil {
		return nil, fmt.Errorf("创建代理传输层失败: %v", err)
	}

	client := &http.Client{
		Timeout:   c.timeout,
		Transport: transport,
	}

	// 实现重试机制
	var resp *http.Response
	var lastErr error
	for attempt := 0; attempt <= c.retryCount; attempt++ {
		if attempt > 0 {
			c.logger.Printf("重试请求 %d/%d，上次错误: %v", attempt, c.retryCount, lastErr)
			// 指数退避策略
			backoff := time.Duration(attempt*attempt) * 100 * time.Millisecond
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
			time.Sleep(backoff)
		}

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			// 如果启用了Cookie认证，从响应中提取Cookie
			if c.cookieJar != nil {
				c.cookieJar.ExtractFromResponse(c.serviceName, resp)
			}
			break // 成功或客户端错误不需要重试
		}

		lastErr = err
		if err == nil {
			resp.Body.Close() // 避免资源泄漏
			lastErr = fmt.Errorf("服务器错误: %s", resp.Status)
		}
	}

	if lastErr != nil && resp == nil {
		c.logger.Printf("所有重试尝试失败: %v", lastErr)
		return nil, fmt.Errorf("发送请求失败，已尝试 %d 次: %v", c.retryCount+1, lastErr)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API错误: %d %s", resp.StatusCode, resp.Status)
	}

	return resp, nil
}

// sendMessage 向API发送消息并返回响应体
func (c *Client) sendMessage(message string, stream bool) (io.ReadCloser, error) {
	// 检查是否需要上传长文本
	fileId := ""
	if (c.enableUpload || c.uploadMessage) && utf8.RuneCountInString(message) >= longTxtThreshold {
		c.logger.Printf("消息长度 %d 超过阈值 %d，正在上传文件", utf8.RuneCountInString(message), longTxtThreshold)
		uploadedFileId, err := c.uploadMessageAsFile(message)
		if err != nil {
			c.logger.Printf("文件上传失败: %v", err)
			return nil, err
		}
		fileId = uploadedFileId
		c.logger.Printf("文件上传成功，文件ID: %s", fileId)
		message = "请按照附件中的说明进行回复。"
	}

	// 准备请求负载
	payload := c.preparePayload(message, fileId)

	// 发送请求
	resp, err := c.doRequest(http.MethodPost, c.baseUrl+"/conversations/new", payload)
	if err != nil {
		return nil, err
	}

	if stream {
		return resp.Body, nil
	}

	// 非流式响应处理
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

// parseStreamingResponse 解析流式响应
func (c *Client) parseStreamingResponse(stream io.Reader, handler func(string, bool)) {
	isThinking := false
	decoder := json.NewDecoder(stream)
	for {
		var token struct {
			Result struct {
				Response struct {
					Token      string `json:"token"`
					IsThinking bool   `json:"isThinking"`
				} `json:"response"`
			} `json:"result"`
		}

		err := decoder.Decode(&token)
		if err != nil {
			if err != io.EOF {
				log.Printf("解析流式响应错误: %v", err)
			}
			break
		}

		// 如果配置为忽略思考内容且当前是思考内容，则跳过
		if c.ignoreThinking && token.Result.Response.IsThinking {
			continue
		}

		// 处理思考状态变化
		if isThinking != token.Result.Response.IsThinking {
			isThinking = token.Result.Response.IsThinking
		}

		// 调用处理函数
		handler(token.Result.Response.Token, isThinking)
	}
}

// OpenAIChatCompletionChunk 定义了OpenAI格式的流式响应块
type OpenAIChatCompletionChunk struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}

// OpenAIChatCompletion 定义了OpenAI格式的完整响应
type OpenAIChatCompletion struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// ModelData 表示模型元数据
type ModelData struct {
	Id       string `json:"id"`
	Object   string `json:"object"`
	Owned_by string `json:"owned_by"`
}

// ModelList 包含可用模型列表
type ModelList struct {
	Object string      `json:"object"`
	Data   []ModelData `json:"data"`
}

// ProxyTransport 创建代理传输层
func ProxyTransport(proxyURL string) (http.RoundTripper, error) {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("解析代理URL失败: %v", err)
		}
		transport.Proxy = http.ProxyURL(proxy)
	} else {
		// 使用系统代理
		transport.Proxy = http.ProxyFromEnvironment
	}

	return transport, nil
}

// 中间件函数

// LoggingMiddleware 日志中间件
func LoggingMiddleware(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			logger.Printf("%s %s %s", r.Method, r.URL.Path, r.RemoteAddr)
			next.ServeHTTP(w, r)
			logger.Printf("%s %s %s 完成，耗时: %v", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
		})
	}
}

// RecoveryMiddleware 恢复中间件
func RecoveryMiddleware(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Printf("恢复自: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware CORS中间件
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowed := false

			// 检查是否允许该来源
			for _, allowedOrigin := range allowedOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			// 处理预检请求
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AuthMiddleware 认证中间件
func AuthMiddleware(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			expected := "Bearer " + token

			if auth != expected {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// handleChatCompletion 处理聊天完成请求
func handleChatCompletion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析请求体
	var req RequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request: Invalid JSON", http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if len(req.Messages) == 0 {
		http.Error(w, "Bad Request: Messages are required", http.StatusBadRequest)
		return
	}

	// 提取用户消息
	userMessage := req.Messages[len(req.Messages)-1].Content

	// 创建客户端选项
	options := []ClientOption{
		WithTimeout(config.Timeout),
		WithRetryCount(config.RetryCount),
		WithBaseURL(config.BaseURL),
		WithLogger(log.New(os.Stdout, "[API Client] ", log.LstdFlags)),
	}

	// 添加Cookie管理器（如果启用）
	if config.CookieAuth.Enabled && cookieJar != nil {
		options = append(options, WithCookieJar(cookieJar, config.CookieAuth.ServiceName))
	}

	// 添加功能选项
	options = append(options, WithReasoning(req.Model == "model-reasoning"))
	options = append(options, WithEnableUpload(*longTxt))

	// 创建客户端
	client := NewClient(config.AuthToken, config.ConfigFlags, options...)

	// 检查缓存
	cacheKey := fmt.Sprintf("%s:%s:%v", req.Model, userMessage, req.Stream)
	if cachedResp, found := cacheStore.Get(cacheKey); found && !req.Stream {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Cache", "HIT")
		json.NewEncoder(w).Encode(cachedResp)
		return
	}

	// 发送请求
	resp, err := client.sendMessage(userMessage, req.Stream)
	if err != nil {
		http.Error(w, fmt.Sprintf("Internal Server Error: %v", err), http.StatusInternalServerError)
		return
	}

	// 处理流式响应
	if req.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		// 创建唯一ID
		completionID := "chatcmpl-" + uuid.New().String()
		model := req.Model
		if model == "" {
			model = "default-model"
		}

		// 发送初始块
		startChunk := OpenAIChatCompletionChunk{
			ID:      completionID,
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   model,
			Choices: []struct {
				Index int `json:"index"`
				Delta struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			}{
				{
					Index: 0,
					Delta: struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					}{
						Role: "assistant",
					},
					FinishReason: "",
				},
			},
		}

		data, _ := json.Marshal(startChunk)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()

		// 收集完整响应用于缓存
		var fullContent strings.Builder

		// 解析流式响应
		client.parseStreamingResponse(resp, func(token string, isThinking bool) {
			// 忽略思考内容
			if isThinking && client.ignoreThinking {
				return
			}

			// 构建响应块
			chunk := OpenAIChatCompletionChunk{
				ID:      completionID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   model,
				Choices: []struct {
					Index int `json:"index"`
					Delta struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"delta"`
					FinishReason string `json:"finish_reason"`
				}{
					{
						Index: 0,
						Delta: struct {
							Role    string `json:"role"`
							Content string `json:"content"`
						}{
							Content: token,
						},
						FinishReason: "",
					},
				},
			}

			// 收集完整内容
			fullContent.WriteString(token)

			// 发送响应块
			data, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		})

		// 发送结束块
		endChunk := OpenAIChatCompletionChunk{
			ID:      completionID,
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   model,
			Choices: []struct {
				Index int `json:"index"`
				Delta struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			}{
				{
					Index: 0,
					Delta: struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					}{},
					FinishReason: "stop",
				},
			},
		}

		data, _ = json.Marshal(endChunk)
		fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", data)
		flusher.Flush()

		// 缓存完整响应
		completeResponse := OpenAIChatCompletion{
			ID:      completionID,
			Object:  "chat.completion",
			Created: time.Now().Unix(),
			Model:   model,
			Choices: []struct {
				Index   int `json:"index"`
				Message struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			}{
				{
					Index: 0,
					Message: struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					}{
						Role:    "assistant",
						Content: fullContent.String(),
					},
					FinishReason: "stop",
				},
			},
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			}{
				PromptTokens:     len(userMessage) / 4, // 简单估算
				CompletionTokens: fullContent.Len() / 4,
				TotalTokens:      len(userMessage)/4 + fullContent.Len()/4,
			},
		}

		cacheStore.Set(cacheKey, completeResponse, cache.DefaultExpiration)
	} else {
		// 处理非流式响应
		defer resp.Close()
		body, err := io.ReadAll(resp)
		if err != nil {
			http.Error(w, fmt.Sprintf("Internal Server Error: %v", err), http.StatusInternalServerError)
			return
		}

		// 解析响应
		var content string
		var decoder = json.NewDecoder(bytes.NewReader(body))
		for {
			var token struct {
				Result struct {
					Response struct {
						Token      string `json:"token"`
						IsThinking bool   `json:"isThinking"`
					} `json:"response"`
				} `json:"result"`
			}

			err := decoder.Decode(&token)
			if err != nil {
				if err != io.EOF {
					log.Printf("解析响应错误: %v", err)
				}
				break
			}

			// 如果配置为忽略思考内容且当前是思考内容，则跳过
			if client.ignoreThinking && token.Result.Response.IsThinking {
				continue
			}

			content += token.Result.Response.Token
		}

		// 构造OpenAI格式的响应
		completionID := "chatcmpl-" + uuid.New().String()
		model := req.Model
		if model == "" {
			model = "default-model"
		}

		response := OpenAIChatCompletion{
			ID:      completionID,
			Object:  "chat.completion",
			Created: time.Now().Unix(),
			Model:   model,
			Choices: []struct {
				Index   int `json:"index"`
				Message struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			}{
				{
					Index: 0,
					Message: struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					}{
						Role:    "assistant",
						Content: content,
					},
					FinishReason: "stop",
				},
			},
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			}{
				PromptTokens:     len(userMessage) / 4,
				CompletionTokens: len(content) / 4,
				TotalTokens:      len(userMessage)/4 + len(content)/4,
			},
		}

		// 缓存响应
		cacheStore.Set(cacheKey, response, cache.DefaultExpiration)

		// 发送响应
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// listModels 处理模型列表请求
func listModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 构造模型列表
	models := ModelList{
		Object: "list",
		Data: []ModelData{
			{
				Id:       "model-base",
				Object:   "model",
				Owned_by: "generic",
			},
			{
				Id:       "model-reasoning",
				Object:   "model",
				Owned_by: "generic",
			},
		},
	}

	// 添加配置中的其他模型
	for _, model := range config.Models {
		if model != "model-base" && model != "model-reasoning" {
			models.Data = append(models.Data, ModelData{
				Id:       model,
				Object:   "model",
				Owned_by: "generic",
			})
		}
	}

	// 发送响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models)
}

// 加载Cookie文件
func loadCookiesFromDir(dir string) error {
	// 确保目录存在
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("目录不存在: %s", dir)
	}

	// 查找所有.txt文件
	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return err
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			log.Printf("读取Cookie文件失败: %s, %v", file, err)
			continue
		}

		cookieStr := strings.TrimSpace(string(data))
		if cookieStr != "" {
			cookieJar.AddCookie("default", &http.Cookie{
				Name:  "auth",
				Value: cookieStr,
			})
		}
	}

	return nil
}

// 创建缓存
func NewCache(size int) *cache.Cache {
	return cache.New(5*time.Minute, 10*time.Minute)
}

// 主函数
func main() {
	// 解析命令行参数
	authToken = flag.String("token", "", "API认证令牌")
	httpProxy = flag.String("proxy", "", "HTTP/SOCKS5代理URL")
	port = flag.Uint("port", 8080, "服务器端口")
	configFile = flag.String("config", "config.json", "配置文件路径")
	longTxt = flag.Bool("longtxt", false, "启用长文本处理，后面可接阈值（如 -longtxt 60000），默认 40000")
	cookiesDir = flag.String("cookiesDir", "cookies", "包含cookie.txt文件的目录")
	flag.Parse()

	// 创建日志记录器
	apiLogger := log.New(os.Stdout, "[MyGo-API] ", log.LstdFlags)
	apiLogger.Println("启动服务...")

	// 自定义解析 -longtxt 后面的阈值
	longTxtThreshold = 40000 // 默认阈值
	if *longTxt {
		// 检查命令行参数中 -longtxt 后的值
		for i, arg := range os.Args {
			if arg == "-longtxt" && i+1 < len(os.Args) {
				if threshold, err := strconv.Atoi(os.Args[i+1]); err == nil && threshold > 0 {
					longTxtThreshold = threshold
					break
				}
			}
		}
	}

	// 初始化配置管理器
	configManager, err := NewConfigManager(*configFile, apiLogger)
	if err != nil {
		apiLogger.Printf("警告: %v, 使用默认配置", err)
	}

	// 启动配置热重载
	configManager.StartWatching()

	// 获取当前配置
	config = configManager.GetConfig()

	// 命令行参数优先级高于配置文件
	if *authToken != "" {
		config.AuthToken = *authToken
	} else if config.AuthToken == "" {
		config.AuthToken = os.Getenv("API_TOKEN")
		if config.AuthToken == "" {
			apiLogger.Fatal("认证令牌未设置")
		}
	}

	if *httpProxy != "" {
		config.HttpProxy = *httpProxy
	}

	if *port != 8080 {
		config.Port = *port
	}

	// 初始化Cookie管理器（如果启用）
	if config.CookieAuth.Enabled {
		cookieJar, err = NewCookieJar(config.CookieAuth.CookieFile)
		if err != nil {
			apiLogger.Printf("初始化Cookie管理器失败: %v，将使用默认令牌认证", err)
		}

		// 如果指定了cookies目录，加载目录中的cookie文件
		if *cookiesDir != "" {
			err := loadCookiesFromDir(*cookiesDir)
			if err != nil {
				apiLogger.Printf("从目录加载Cookie失败: %v", err)
			}
		}
	}

	// 设置HTTP代理
	httpTransport, err := ProxyTransport(config.HttpProxy)
	if err != nil {
		apiLogger.Fatalf("创建代理传输层失败: %v", err)
	}
	httpClient.Transport = httpTransport

	// 初始化缓存
	cacheStore = NewCache(config.CacheSize)

	// 设置路由
	mux := http.NewServeMux()

	// 添加中间件
	handler := LoggingMiddleware(apiLogger)(mux)
	handler = RecoveryMiddleware(apiLogger)(handler)
	handler = CORSMiddleware(config.CORS.AllowedOrigins)(handler)

	// 如果启用了Cookie认证，使用Cookie认证中间件
	if config.CookieAuth.Enabled && cookieJar != nil {
		apiLogger.Printf("使用Cookie认证，服务名称: %s", config.CookieAuth.ServiceName)
	} else {
		// 否则使用令牌认证中间件
		handler = AuthMiddleware(config.AuthToken)(handler)
	}

	// 注册路由
	mux.HandleFunc("/v1/chat/completions", handleChatCompletion)
	mux.HandleFunc("/v1/models", listModels)

	// 启动服务器
	serverAddr := fmt.Sprintf(":%d", config.Port)
	apiLogger.Printf("服务器启动在 %s", serverAddr)

	// 如果启用了TLS，使用HTTPS
	if config.TLS.Enabled && config.TLS.CertFile != "" && config.TLS.KeyFile != "" {
		apiLogger.Printf("使用HTTPS")
		err = http.ListenAndServeTLS(serverAddr, config.TLS.CertFile, config.TLS.KeyFile, handler)
	} else {
		err = http.ListenAndServe(serverAddr, handler)
	}

	if err != nil {
		apiLogger.Fatalf("服务器启动失败: %v", err)
	}
}
