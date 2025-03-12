package core

import (
	"net/http"
	"strings"
	"sync"
)

// Router 定义了一个高级路由器，支持路径参数和中间件
type Router struct {
	routes     map[string]map[string]http.Handler // 按HTTP方法和路径存储处理器
	middleware []Middleware                       // 全局中间件
	params     map[*http.Request]map[string]string // 请求参数
	mu         sync.RWMutex                        // 用于并发安全
}

// Middleware 定义了HTTP中间件函数类型
type Middleware func(http.Handler) http.Handler

// NewRouter 创建一个新的路由器实例
func NewRouter() *Router {
	return &Router{
		routes: make(map[string]map[string]http.Handler),
		params: make(map[*http.Request]map[string]string),
	}
}

// Use 添加全局中间件
func (r *Router) Use(middleware ...Middleware) {
	r.middleware = append(r.middleware, middleware...)
}

// Handle 注册一个处理器到指定的HTTP方法和路径
func (r *Router) Handle(method, path string, handler http.Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.routes[method] == nil {
		r.routes[method] = make(map[string]http.Handler)
	}

	r.routes[method][path] = handler
}

// HandleFunc 注册一个处理函数到指定的HTTP方法和路径
func (r *Router) HandleFunc(method, path string, handlerFunc http.HandlerFunc) {
	r.Handle(method, path, handlerFunc)
}

// GET 注册一个GET请求处理器
func (r *Router) GET(path string, handler http.Handler) {
	r.Handle(http.MethodGet, path, handler)
}

// POST 注册一个POST请求处理器
func (r *Router) POST(path string, handler http.Handler) {
	r.Handle(http.MethodPost, path, handler)
}

// PUT 注册一个PUT请求处理器
func (r *Router) PUT(path string, handler http.Handler) {
	r.Handle(http.MethodPut, path, handler)
}

// DELETE 注册一个DELETE请求处理器
func (r *Router) DELETE(path string, handler http.Handler) {
	r.Handle(http.MethodDelete, path, handler)
}

// OPTIONS 注册一个OPTIONS请求处理器
func (r *Router) OPTIONS(path string, handler http.Handler) {
	r.Handle(http.MethodOptions, path, handler)
}

// Group 创建一个路由组，共享前缀路径和中间件
func (r *Router) Group(prefix string, middleware ...Middleware) *RouterGroup {
	return &RouterGroup{
		router:     r,
		prefix:     prefix,
		middleware: middleware,
	}
}

// Param 获取URL参数值
func (r *Router) Param(req *http.Request, name string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if params, ok := r.params[req]; ok {
		return params[name]
	}
	return ""
}

// ServeHTTP 实现http.Handler接口
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	handlers, ok := r.routes[req.Method]
	r.mu.RUnlock()

	if !ok {
		http.NotFound(w, req)
		return
	}

	// 首先尝试精确匹配
	if handler, ok := handlers[req.URL.Path]; ok {
		// 应用全局中间件
		if len(r.middleware) > 0 {
			handler = Chain(r.middleware...)(handler)
		}
		handler.ServeHTTP(w, req)
		return
	}

	// 尝试路径参数匹配
	for pattern, handler := range handlers {
		if params, ok := r.matchPath(pattern, req.URL.Path); ok {
			r.mu.Lock()
			r.params[req] = params
			r.mu.Unlock()

			// 请求完成后清理参数
			defer func() {
				r.mu.Lock()
				delete(r.params, req)
				r.mu.Unlock()
			}()

			// 应用全局中间件
			if len(r.middleware) > 0 {
				handler = Chain(r.middleware...)(handler)
			}

			handler.ServeHTTP(w, req)
			return
		}
	}

	http.NotFound(w, req)
}

// matchPath 检查URL路径是否匹配模式，并提取参数
func (r *Router) matchPath(pattern, path string) (map[string]string, bool) {
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(path, "/"), "/")

	if len(patternParts) != len(pathParts) {
		return nil, false
	}

	params := make(map[string]string)
	for i, part := range patternParts {
		if strings.HasPrefix(part, ":") {
			// 这是一个参数
			paramName := strings.TrimPrefix(part, ":")
			params[paramName] = pathParts[i]
		} else if part != pathParts[i] {
			// 静态部分不匹配
			return nil, false
		}
	}

	return params, true
}

// RouterGroup 定义了一个路由组，共享前缀路径和中间件
type RouterGroup struct {
	router     *Router
	prefix     string
	middleware []Middleware
}

// Use 添加组级中间件
func (g *RouterGroup) Use(middleware ...Middleware) {
	g.middleware = append(g.middleware, middleware...)
}

// Handle 注册一个处理器到组
func (g *RouterGroup) Handle(method, path string, handler http.Handler) {
	// 应用组级中间件
	if len(g.middleware) > 0 {
		handler = Chain(g.middleware...)(handler)
	}

	// 注册到路由器
	g.router.Handle(method, g.prefix+path, handler)
}

// HandleFunc 注册一个处理函数到组
func (g *RouterGroup) HandleFunc(method, path string, handlerFunc http.HandlerFunc) {
	g.Handle(method, path, handlerFunc)
}

// GET 注册一个GET请求处理器到组
func (g *RouterGroup) GET(path string, handler http.Handler) {
	g.Handle(http.MethodGet, path, handler)
}

// POST 注册一个POST请求处理器到组
func (g *RouterGroup) POST(path string, handler http.Handler) {
	g.Handle(http.MethodPost, path, handler)
}

// PUT 注册一个PUT请求处理器到组
func (g *RouterGroup) PUT(path string, handler http.Handler) {
	g.Handle(http.MethodPut, path, handler)
}

// DELETE 注册一个DELETE请求处理器到组
func (g *RouterGroup) DELETE(path string, handler http.Handler) {
	g.Handle(http.MethodDelete, path, handler)
}

// OPTIONS 注册一个OPTIONS请求处理器到组
func (g *RouterGroup) OPTIONS(path string, handler http.Handler) {
	g.Handle(http.MethodOptions, path, handler)
}

// Group 创建一个嵌套路由组
func (g *RouterGroup) Group(prefix string, middleware ...Middleware) *RouterGroup {
	return &RouterGroup{
		router:     g.router,
		prefix:     g.prefix + prefix,
		middleware: append(g.middleware, middleware...),
	}
}