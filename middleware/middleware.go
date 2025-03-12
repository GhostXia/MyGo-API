package middleware

import (
	"compress/gzip"
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Middleware 定义了HTTP中间件函数类型
type Middleware func(http.Handler) http.Handler

// Chain 将多个中间件组合成一个
func Chain(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// MiddlewareContext 定义中间件上下文，用于在中间件之间传递数据
type MiddlewareContext struct {
	Values map[string]interface{}
	mu     sync.RWMutex
}

// NewMiddlewareContext 创建一个新的中间件上下文
func NewMiddlewareContext() *MiddlewareContext {
	return &MiddlewareContext{
		Values: make(map[string]interface{}),
	}
}

// Set 设置上下文值
func (mc *MiddlewareContext) Set(key string, value interface{}) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.Values[key] = value
}

// Get 获取上下文值
func (mc *MiddlewareContext) Get(key string) (interface{}, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	val, ok := mc.Values[key]
	return val, ok
}

// contextKey 定义上下文键类型
type contextKey string

// 定义上下文键常量
const (
	middlewareContextKey contextKey = "middleware-context"
)

// ContextMiddleware 创建一个上下文中间件，用于在请求处理过程中共享数据
func ContextMiddleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 创建中间件上下文
			ctx := NewMiddlewareContext()
			
			// 将上下文添加到请求上下文中
			r = r.WithContext(context.WithValue(r.Context(), middlewareContextKey, ctx))
			
			// 继续处理请求
			next.ServeHTTP(w, r)
		})
	}
}

// GetMiddlewareContext 从请求上下文中获取中间件上下文
func GetMiddlewareContext(r *http.Request) (*MiddlewareContext, bool) {
	ctx := r.Context().Value(middlewareContextKey)
	if ctx == nil {
		return nil, false
	}
	
	middlewareCtx, ok := ctx.(*MiddlewareContext)
	return middlewareCtx, ok
}

// RateLimiterMiddleware 创建一个请求速率限制中间件
func RateLimiterMiddleware(rps float64, burst int) Middleware {
	limiter := rate.NewLimiter(rate.Limit(rps), burst)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// 注：IPBasedRateLimiterMiddleware已移除，使用全局RateLimiterMiddleware代替

// EnhancedLoggingMiddleware 创建一个增强的日志中间件，记录更详细的请求信息
func EnhancedLoggingMiddleware(logger *log.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			
			// 创建一个增强的响应记录器
			rw := &enhancedResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				contentLength:  0,
			}
			
			// 处理请求
			next.ServeHTTP(rw, r)
			
			// 计算处理时间
			duration := time.Since(start)
			
			// 获取用户代理
			userAgent := r.Header.Get("User-Agent")
			if userAgent == "" {
				userAgent = "unknown"
			}
			
			// 获取引荐来源
			referer := r.Header.Get("Referer")
			if referer == "" {
				referer = "-"
			}
			
			// 记录详细的请求信息
			logger.Printf("%s %s %s - %d %d %s - %s - %s",
				r.RemoteAddr,
				r.Method,
				r.URL.Path,
				rw.statusCode,
				rw.contentLength,
				duration,
				userAgent,
				referer,
			)
		})
	}
}

// enhancedResponseWriter 是一个增强的ResponseWriter，用于捕获状态码和响应大小
type enhancedResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	contentLength int64
}

func (rw *enhancedResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *enhancedResponseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.contentLength += int64(n)
	return n, err
}

// RecoveryMiddleware 创建一个恢复中间件，用于捕获panic
func RecoveryMiddleware(logger *log.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Printf("Panic recovered: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware 创建一个CORS中间件
func CORSMiddleware(allowedOrigins []string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 获取请求的Origin
			origin := r.Header.Get("Origin")

			// 检查Origin是否在允许列表中
			allowed := false
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
				w.Header().Set("Access-Control-Max-Age", "86400") // 24小时
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

// AuthMiddleware 创建一个认证中间件
func AuthMiddleware(authToken string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 检查认证头
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+authToken {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CompressionMiddleware 创建一个压缩中间件，支持gzip压缩
func CompressionMiddleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 检查客户端是否支持gzip
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}
			
			// 创建gzip响应写入器
			gw := gzip.NewWriter(w)
			defer gw.Close()
			
			// 设置响应头
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Vary", "Accept-Encoding")
			
			// 创建一个包装的响应写入器
			gzw := &gzipResponseWriter{
				ResponseWriter: w,
				Writer:         gw,
			}
			
			// 处理请求
			next.ServeHTTP(gzw, r)
		})
	}
}

// gzipResponseWriter 是一个支持gzip压缩的ResponseWriter
type gzipResponseWriter struct {
	http.ResponseWriter
	Writer io.Writer
}

func (gzw *gzipResponseWriter) Write(b []byte) (int, error) {
	return gzw.Writer.Write(b)
}

// TimeoutMiddleware 创建一个超时中间件，限制请求处理时间
func TimeoutMiddleware(timeout time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 创建一个带超时的上下文
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			
			// 使用新的上下文创建请求
			r = r.WithContext(ctx)
			
			// 创建一个通道用于通知请求完成
			done := make(chan struct{})
			
			// 在goroutine中处理请求
			go func() {
				next.ServeHTTP(w, r)
				close(done)
			}()
			
			// 等待请求完成或超时
			select {
			case <-done:
				// 请求正常完成
				return
			case <-ctx.Done():
				// 请求超时
				http.Error(w, "Request timeout", http.StatusGatewayTimeout)
				return
			}
		})
	}
}