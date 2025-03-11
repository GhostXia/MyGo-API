package main

import (
	"log"
	"net/http"
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

// IPBasedRateLimiterMiddleware 创建一个基于IP的请求速率限制中间件
func IPBasedRateLimiterMiddleware(rps float64, burst int) Middleware {
	limiters := make(map[string]*rate.Limiter)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 获取客户端IP
			ip := r.RemoteAddr
			if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
				ip = forwardedFor
			}

			// 为每个IP创建一个限流器
			limiter, exists := limiters[ip]
			if !exists {
				limiter = rate.NewLimiter(rate.Limit(rps), burst)
				limiters[ip] = limiter
			}

			if !limiter.Allow() {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// LoggingMiddleware 创建一个请求日志中间件
func LoggingMiddleware(logger *log.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// 创建一个响应记录器来捕获状态码
			rw := &responseWriter{w, http.StatusOK}

			// 处理请求
			next.ServeHTTP(rw, r)

			// 记录请求信息
			logger.Printf("%s %s %s - %d %s", r.RemoteAddr, r.Method, r.URL.Path, rw.statusCode, time.Since(start))
		})
	}
}

// responseWriter 是一个自定义的ResponseWriter，用于捕获状态码
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
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