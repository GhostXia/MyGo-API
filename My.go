package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"golang.org/x/time/rate"
)

// Client 定义了一个通用的 API 客户端结构体，用于与目标服务交互
type Client struct {
	baseUrl     string            // API 的基础 URL
	headers     map[string]string // HTTP 请求头
	configFlags map[string]bool   // 通用配置标志
	timeout     time.Duration     // 请求超时时间
	retryCount  int               // 重试次数
	logger      *log.Logger       // 日志记录器
}

// ClientOption 定义客户端配置选项函数类型
type ClientOption func(*Client)

// WithTimeout 设置客户端超时时间
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = timeout
	}
}

// WithRetryCount 设置客户端重试次数
func WithRetryCount(count int) ClientOption {
	return func(c *Client) {
		c.retryCount = count
	}
}

// WithBaseURL 设置客户端基础URL
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseUrl = url
	}
}

// WithLogger 设置客户端日志记录器
func WithLogger(logger *log.Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// NewClient 创建一个新的客户端实例
func NewClient(authToken string, configFlags map[string]bool, options ...ClientOption) *Client {
	client := &Client{
		baseUrl: "https://api.example.com", // 替换为目标服务的实际 URL
		headers: map[string]string{
			"accept":        "*/*",
			"content-type":  "application/json",
			"authorization": "Bearer " + authToken, // 示例认证方式
			"user-agent":    "CustomAPIClient/1.0",
		},
		configFlags: configFlags,
		timeout:     30 * time.Second,
		retryCount:  3,
		logger:      log.New(os.Stdout, "[API Client] ", log.LstdFlags),
	}

	// 应用自定义选项
	for _, option := range options {
		option(client)
	}

	return client
}

// RequestBody 定义了符合 OpenAI 格式的请求体结构
type RequestBody struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Stream bool `json:"stream"`
	// 可根据需要添加其他字段
}

// ResponseChunk 定义了流式响应的单个数据块结构
type ResponseChunk struct {
	Token string `json:"token"`
	// 根据实际 API 响应结构调整字段
}

// preparePayload 构造发送到目标 API 的请求负载
func (c *Client) preparePayload(message string) map[string]any {
	payload := map[string]any{
		"message": message,
		// 根据目标 API 的要求添加其他字段
	}
	for key, value := range c.configFlags {
		payload[key] = value
	}
	return payload
}

// sendRequest 发送请求到目标 API，支持流式和非流式响应，并实现重试机制
func (c *Client) sendRequest(message string, stream bool) (io.ReadCloser, error) {
	payload := c.preparePayload(message)
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.logger.Printf("Error marshaling payload: %v", err)
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseUrl+"/endpoint", bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.logger.Printf("Error creating request: %v", err)
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	// 创建带超时的HTTP客户端
	transport, err := ProxyTransport(config.HttpProxy)
	if err != nil {
		c.logger.Printf("Error creating transport: %v", err)
		return nil, fmt.Errorf("failed to create transport: %v", err)
	}
	
	client := &http.Client{
		Timeout: c.timeout,
		Transport: transport,
	}

	// 实现重试机制
	var resp *http.Response
	var lastErr error
	for attempt := 0; attempt <= c.retryCount; attempt++ {
		if attempt > 0 {
			c.logger.Printf("Retry attempt %d/%d after error: %v", attempt, c.retryCount, lastErr)
			// 指数退避策略
			backoff := time.Duration(attempt*attempt) * 100 * time.Millisecond
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
			time.Sleep(backoff)
		}

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			break // 成功或客户端错误不需要重试
		}

		lastErr = err
		if err == nil {
			resp.Body.Close() // 避免资源泄漏
			lastErr = fmt.Errorf("server error: %s", resp.Status)
		}
	}

	if lastErr != nil && resp == nil {
		c.logger.Printf("All retry attempts failed: %v", lastErr)
		return nil, fmt.Errorf("failed to send request after %d attempts: %v", c.retryCount+1, lastErr)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		c.logger.Printf("API error: %d %s, body: %s", resp.StatusCode, resp.Status, string(body))
		return nil, fmt.Errorf("API error: %d %s, body: %s", resp.StatusCode, resp.Status, string(body))
	}

	if stream {
		return resp.Body, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Printf("Error reading response: %v", err)
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

// OpenAIChatCompletionChunk 定义了 OpenAI 格式的流式响应块
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

// OpenAIChatCompletion 定义了 OpenAI 格式的完整响应
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

// 定义流式响应解析器接口，便于支持不同的API格式
type StreamParser interface {
	Parse(data []byte) (string, error)
	IsFinished(data []byte) bool
}

// DefaultStreamParser 默认的流式响应解析器
type DefaultStreamParser struct{}

func (p *DefaultStreamParser) Parse(data []byte) (string, error) {
	// 这里实现对原始API响应的解析
	// 示例实现，实际应根据目标API的响应格式调整
	return string(data), nil
}

func (p *DefaultStreamParser) IsFinished(data []byte) bool {
	// 判断流是否结束的逻辑
	return false
}

// handleStreamingResponse 处理流式响应并转换为 OpenAI 格式
func (c *Client) handleStreamingResponse(reader io.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			c.logger.Println("Streaming unsupported by the client")
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		completionID := "chatcmpl-" + uuid.New().String()
		model := r.URL.Query().Get("model")
		if model == "" {
			model = "generic-model" // 默认模型名
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
			}{{Index: 0, Delta: struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			}{Role: "assistant"}, FinishReason: ""}},
		}
		fmt.Fprintf(w, "data: %s\n\n", mustMarshal(startChunk))
		flusher.Flush()

		// 使用解析器处理流式数据
		parser := &DefaultStreamParser{}
		scanner := bufio.NewScanner(reader)
		scanner.Split(bufio.ScanLines)

		for scanner.Scan() {
			data := scanner.Bytes()
			if len(data) == 0 {
				continue
			}

			// 解析响应数据
			content, err := parser.Parse(data)
			if err != nil {
				c.logger.Printf("Error parsing stream data: %v", err)
				continue
			}

			// 检查是否是结束标记
			if parser.IsFinished(data) {
				break
			}

			// 构造并发送OpenAI格式的响应块
			chunkData := OpenAIChatCompletionChunk{
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
				}{{Index: 0, Delta: struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				}{Content: content}, FinishReason: ""}},
			}
			fmt.Fprintf(w, "data: %s\n\n", mustMarshal(chunkData))
			flusher.Flush()
		}

		if err := scanner.Err(); err != nil {
			c.logger.Printf("Error reading stream: %v", err)
		}

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
			}{{Index: 0, Delta: struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			}{}, FinishReason: "stop"}},
		}
		fmt.Fprintf(w, "data: %s\n\n", mustMarshal(endChunk))
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()

// captureResponseWriter 是一个自定义的ResponseWriter，用于捕获响应内容以便缓存
type captureResponseWriter struct {
	http.ResponseWriter
	body       []byte
	statusCode int
}

func (w *captureResponseWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return w.ResponseWriter.Write(b)
}

func (w *captureResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// handleFullResponse 处理完整响应并转换为 OpenAI 格式
func (c *Client) handleFullResponse(reader io.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var fullResponse strings.Builder
		_, err := io.Copy(&fullResponse, reader)
		if err != nil {
			c.logger.Printf("Error reading response: %v", err)
			http.Error(w, fmt.Sprintf("Error reading response: %v", err), http.StatusInternalServerError)
			return
		}

		// 获取请求中的模型名称
		model := r.URL.Query().Get("model")
		if model == "" {
			var body RequestBody
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				model = body.Model
			}
		}
		if model == "" && len(config.Models) > 0 {
			model = config.Models[0]
		} else if model == "" {
			model = "generic-model"
		}

		response := OpenAIChatCompletion{
			ID:      "chatcmpl-" + uuid.New().String(),
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
			}{{Index: 0, Message: struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			}{Role: "assistant", Content: fullResponse.String()}, FinishReason: "stop"}},
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			}{PromptTokens: -1, CompletionTokens: -1, TotalTokens: -1},
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Cache", "MISS")
		json.NewEncoder(w).Encode(response)
	}
}

// mustMarshal 将数据序列化为 JSON 字符串
func mustMarshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Config 定义应用程序配置结构
type Config struct {
	AuthToken   string            `json:"auth_token"`
	HttpProxy   string            `json:"http_proxy"`
	Port        uint              `json:"port"`
	BaseURL     string            `json:"base_url"`
	Timeout     time.Duration     `json:"timeout"`
	RetryCount  int               `json:"retry_count"`
	ConfigFlags map[string]bool   `json:"config_flags"`
	Models      []string          `json:"models"`
	RateLimit   int               `json:"rate_limit"`
	CacheSize   int               `json:"cache_size"`
}

// 全局变量
var (
	authToken   *string
	httpProxy   *string
	port        *uint
	configFile  *string
	httpClient  = &http.Client{Timeout: 30 * time.Minute}
	configFlags = map[string]bool{} // 可通过命令行参数设置
	config      Config
	requestCache = cache.New(5*time.Minute, 10*time.Minute) // 简单的内存缓存
)

// handleChatCompletion 处理 /v1/chat/completions 端点的请求
func handleChatCompletion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 认证
	if r.Header.Get("Authorization") != "Bearer "+config.AuthToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	var body RequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Bad Request: Invalid JSON", http.StatusBadRequest)
		return
	}

	if len(body.Messages) == 0 {
		http.Error(w, "Bad Request: No messages", http.StatusBadRequest)
		return
	}
	
	// 检查模型是否支持
	modelSupported := false
	for _, model := range config.Models {
		if body.Model == model || body.Model == "" {
			modelSupported = true
			break
		}
	}
	
	if !modelSupported && len(config.Models) > 0 {
		body.Model = config.Models[0] // 使用默认模型
	}
	
	// 构造消息
	message := body.Messages[len(body.Messages)-1].Content
	
	// 计算请求的唯一标识，用于缓存
	requestKey := fmt.Sprintf("%s-%s-%v", body.Model, message, body.Stream)
	
	// 检查缓存
	if !body.Stream { // 只缓存非流式响应
		if cachedResp, found := requestCache.Get(requestKey); found {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Cache", "HIT")
			json.NewEncoder(w).Encode(cachedResp)
			return
		}
	}
	
	// 创建客户端并发送请求
	client := NewClient(config.AuthToken, configFlags, 
		WithBaseURL(config.BaseURL),
		WithTimeout(config.Timeout),
		WithRetryCount(config.RetryCount))
	
	resp, err := client.sendRequest(message, body.Stream)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Close()
	
	if body.Stream {
		client.handleStreamingResponse(resp)(w, r)
	} else {
		// 使用自定义ResponseWriter捕获响应
		crw := &captureResponseWriter{ResponseWriter: w}
		client.handleFullResponse(resp)(crw, r)
		
		// 缓存响应
		if crw.statusCode == http.StatusOK && len(crw.body) > 0 {
			var respObj OpenAIChatCompletion
			if err := json.Unmarshal(crw.body, &respObj); err == nil {
				requestCache.Set(requestKey, respObj, cache.DefaultExpiration)
			}
		}
	}
}

// loadConfig 从配置文件加载配置
func loadConfig(configPath string) (Config, error) {
	var config Config
	
	// 设置默认值
	config = Config{
		Port:       8080,
		BaseURL:    "https://api.example.com",
		Timeout:    30 * time.Second,
		RetryCount: 3,
		Models:     []string{"generic-model"},
		RateLimit:  60, // 每分钟请求数
		CacheSize:  1000,
	}
	
	// 如果配置文件存在，则从文件加载
	if configPath != "" {
		file, err := os.Open(configPath)
		if err != nil {
			if !os.IsNotExist(err) {
				return config, fmt.Errorf("failed to open config file: %v", err)
			}
			// 文件不存在时使用默认配置
		} else {
			defer file.Close()
			if err := json.NewDecoder(file).Decode(&config); err != nil {
				return config, fmt.Errorf("failed to parse config file: %v", err)
			}
		}
	}
	
	return config, nil
}

// listModels 处理 /v1/models 端点的请求
func listModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// 认证
	if r.Header.Get("Authorization") != "Bearer "+config.AuthToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// 构造模型列表响应
	response := struct {
		Object string `json:"object"`
		Data   []struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Created int64  `json:"created"`
		} `json:"data"`
	}{
		Object: "list",
		Data:   make([]struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Created int64  `json:"created"`
		}, len(config.Models)),
	}
	
	for i, model := range config.Models {
		response.Data[i] = struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Created int64  `json:"created"`
		}{
			ID:      model,
			Object:  "model",
			Created: time.Now().Add(-24 * time.Hour).Unix(), // 假设模型是昨天创建的
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// 添加更多OpenAI兼容的API端点

// handleCompletions 处理 /v1/completions 端点的请求
func handleCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// 认证
	if r.Header.Get("Authorization") != "Bearer "+config.AuthToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// 这里可以实现文本补全API的逻辑
	// 目前简单地重定向到聊天补全API
	handleChatCompletion(w, r)
}

// handleEmbeddings 处理 /v1/embeddings 端点的请求
func handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// 认证
	if r.Header.Get("Authorization") != "Bearer "+config.AuthToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// 这里应该实现嵌入API的逻辑
	// 目前返回一个模拟响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"object": "list",
		"data": []map[string]interface{}{
			{
				"object": "embedding",
				"embedding": []float64{0.1, 0.2, 0.3, 0.4, 0.5}, // 简化的嵌入向量
				"index": 0,
			},
		},
		"model": "text-embedding-ada-002",
		"usage": map[string]interface{}{
			"prompt_tokens": 8,
			"total_tokens": 8,
		},
	})
}

func main() {
	authToken = flag.String("token", "", "API authentication token")
	httpProxy = flag.String("proxy", "", "HTTP/SOCKS5 proxy URL")
	port = flag.Uint("port", 8080, "Server port")
	configFile = flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	// 加载配置文件
	var err error
	config, err = loadConfig(*configFile)
	if err != nil {
		log.Printf("Warning: %v, using default configuration", err)
	}

	// 命令行参数优先级高于配置文件
	if *authToken != "" {
		config.AuthToken = *authToken
	} else if config.AuthToken == "" {
		config.AuthToken = os.Getenv("API_TOKEN")
		if config.AuthToken == "" {
			log.Fatal("Authentication token is required")
		}
	}

	if *httpProxy != "" {
		config.HttpProxy = *httpProxy
	}

	if *port != 8080 {
		config.Port = *port
	}

	// 设置HTTP代理
	httpTransport, err := ProxyTransport(config.HttpProxy)
	if err != nil {
		log.Fatalf("Error creating proxy transport: %v", err)
	}
	httpClient.Transport = httpTransport

	// 设置路由
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", handleChatCompletion)
	mux.HandleFunc("/v1/models", listModels)
	mux.HandleFunc("/v1/completions", handleCompletions)
	mux.HandleFunc("/v1/embeddings", handleEmbeddings)
	
	// 创建日志记录器
	apiLogger := log.New(os.Stdout, "[API Server] ", log.LstdFlags)
	
	// 应用中间件链
	middlewares := []Middleware{
		LoggingMiddleware(apiLogger),
		RecoveryMiddleware(apiLogger),
		RateLimiterMiddleware(float64(config.RateLimit)/60.0, config.RateLimit),
		CORSMiddleware([]string{"*"}),
	}
	
	// 如果配置了认证令牌，添加认证中间件
	if config.AuthToken != "" {
		middlewares = append(middlewares, AuthMiddleware(config.AuthToken))
	}
	
	// 组合所有中间件
	handler := Chain(middlewares...)(mux)

	log.Printf("Starting server on :%d", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), handler))
}
