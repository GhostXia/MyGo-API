package main

import (
	"bytes"
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
	"sync"
	"time"

	"github.com/google/uuid"
)

// Client 定义了一个通用的 API 客户端结构体，用于与目标服务交互
type Client struct {
	baseUrl     string            // API 的基础 URL
	headers     map[string]string // HTTP 请求头
	configFlags map[string]bool   // 通用配置标志
}

// NewClient 创建一个新的客户端实例
func NewClient(authToken string, configFlags map[string]bool) *Client {
	return &Client{
		baseUrl: "https://api.example.com", // 替换为目标服务的实际 URL
		headers: map[string]string{
			"accept":          "*/*",
			"content-type":    "application/json",
			"authorization":   "Bearer " + authToken, // 示例认证方式
			"user-agent":      "CustomAPIClient/1.0",
		},
		configFlags: configFlags,
	}
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

// sendRequest 发送请求到目标 API，支持流式和非流式响应
func (c *Client) sendRequest(message string, stream bool) (io.ReadCloser, error) {
	payload := c.preparePayload(message)
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseUrl+"/endpoint", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %d %s, body: %s", resp.StatusCode, resp.Status, string(body))
	}

	if stream {
		return resp.Body, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
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
		Index        int    `json:"index"`
		Delta        struct {
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
		Index        int    `json:"index"`
		Message      struct {
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

// handleStreamingResponse 处理流式响应并转换为 OpenAI 格式
func (c *Client) handleStreamingResponse(reader io.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		completionID := "chatcmpl-" + uuid.New().String()
		model := "generic-model" // 替换为实际模型名

		// 发送初始块
		startChunk := OpenAIChatCompletionChunk{
			ID:      completionID,
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   model,
			Choices: []struct {
				Index        int    `json:"index"`
				Delta        struct {
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

		// 处理流式数据
		buf := make([]byte, 1024)
		for {
			n, err := reader.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Printf("Error reading stream: %v", err)
				return
			}

			chunk := string(buf[:n])
			// 此处需要根据实际 API 的响应格式解析数据
			token := ResponseChunk{Token: chunk} // 示例，需替换为实际解析逻辑

			chunkData := OpenAIChatCompletionChunk{
				ID:      completionID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   model,
				Choices: []struct {
					Index        int    `json:"index"`
					Delta        struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"delta"`
					FinishReason string `json:"finish_reason"`
				}{{Index: 0, Delta: struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				}{Role: "assistant", Content: token.Token}, FinishReason: ""}},
			}
			fmt.Fprintf(w, "data: %s\n\n", mustMarshal(chunkData))
			flusher.Flush()
		}

		// 发送结束块
		endChunk := OpenAIChatCompletionChunk{
			ID:      completionID,
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   model,
			Choices: []struct {
				Index        int    `json:"index"`
				Delta        struct {
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
	}
}

// handleFullResponse 处理完整响应并转换为 OpenAI 格式
func (c *Client) handleFullResponse(reader io.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var fullResponse strings.Builder
		_, err := io.Copy(&fullResponse, reader)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error reading response: %v", err), http.StatusInternalServerError)
			return
		}

		response := OpenAIChatCompletion{
			ID:      "chatcmpl-" + uuid.New().String(),
			Object:  "chat.completion",
			Created: time.Now().Unix(),
			Model:   "generic-model", // 替换为实际模型名
			Choices: []struct {
				Index        int    `json:"index"`
				Message      struct {
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

// 全局变量
var (
	authToken   *string
	httpProxy   *string
	httpClient  = &http.Client{Timeout: 30 * time.Minute}
	configFlags = map[string]bool{} // 可通过命令行参数设置
)

// handleChatCompletion 处理 /v1/chat/completions 端点的请求
func handleChatCompletion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 认证
	if r.Header.Get("Authorization") != "Bearer "+*authToken {
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

	// 构造消息（可根据需要调整逻辑）
	message := body.Messages[len(body.Messages)-1].Content
	client := NewClient(*authToken, configFlags)
	resp, err := client.sendRequest(message, body.Stream)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Close()

	if body.Stream {
		client.handleStreamingResponse(resp)(w, r)
	} else {
		client.handleFullResponse(resp)(w, r)
	}
}

func main() {
	authToken = flag.String("token", "", "API authentication token")
	httpProxy = flag.String("proxy", "", "HTTP/SOCKS5 proxy URL")
	port := flag.Uint("port", 8080, "Server port")
	flag.Parse()

	if *authToken == "" {
		*authToken = os.Getenv("API_TOKEN")
		if *authToken == "" {
			log.Fatal("Authentication token is required")
		}
	}

	if *httpProxy != "" {
		proxyURL, err := url.Parse(*httpProxy)
		if err != nil {
			log.Fatalf("Invalid proxy URL: %v", err)
		}
		httpClient.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        10,
			IdleConnTimeout:     600 * time.Second,
			TLSHandshakeTimeout: 20 * time.Second,
		}
	}

	http.HandleFunc("/v1/chat/completions", handleChatCompletion)
	// 可添加其他端点，如模型列表：http.HandleFunc("/v1/models", listModels)

	log.Printf("Starting server on :%d", *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
