package main

import (
	"fmt"
	"log"
	"net/url"
	"sync"
	"time"
)

// ServiceEndpoint 定义了一个服务端点
type ServiceEndpoint struct {
	ID          string            // 端点唯一标识符
	Name        string            // 服务名称
	URL         string            // 服务URL
	HealthURL   string            // 健康检查URL
	Metadata    map[string]string // 元数据
	Weight      int               // 权重，用于负载均衡
	LastChecked time.Time         // 最后一次健康检查时间
	Healthy     bool              // 健康状态
}

// ServiceRegistry 定义了服务注册表
type ServiceRegistry struct {
	endpoints map[string]map[string]*ServiceEndpoint // 按服务名称和端点ID存储端点
	mu        sync.RWMutex                          // 用于并发安全
	logger    *log.Logger                           // 日志记录器
}

// NewServiceRegistry 创建一个新的服务注册表
func NewServiceRegistry(logger *log.Logger) *ServiceRegistry {
	if logger == nil {
		logger = log.New(log.Writer(), "[ServiceRegistry] ", log.LstdFlags)
	}

	return &ServiceRegistry{
		endpoints: make(map[string]map[string]*ServiceEndpoint),
		logger:    logger,
	}
}

// RegisterEndpoint 注册一个服务端点
func (sr *ServiceRegistry) RegisterEndpoint(endpoint *ServiceEndpoint) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	// 验证端点URL
	_, err := url.Parse(endpoint.URL)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %v", err)
	}

	// 确保服务名称存在
	if endpoint.Name == "" {
		return fmt.Errorf("service name cannot be empty")
	}

	// 确保端点ID存在
	if endpoint.ID == "" {
		return fmt.Errorf("endpoint ID cannot be empty")
	}

	// 初始化服务映射（如果不存在）
	if sr.endpoints[endpoint.Name] == nil {
		sr.endpoints[endpoint.Name] = make(map[string]*ServiceEndpoint)
	}

	// 添加或更新端点
	sr.endpoints[endpoint.Name][endpoint.ID] = endpoint
	sr.logger.Printf("Registered endpoint %s for service %s at %s", endpoint.ID, endpoint.Name, endpoint.URL)

	return nil
}

// DeregisterEndpoint 注销一个服务端点
func (sr *ServiceRegistry) DeregisterEndpoint(serviceName, endpointID string) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	// 检查服务是否存在
	serviceEndpoints, exists := sr.endpoints[serviceName]
	if !exists {
		return fmt.Errorf("service %s not found", serviceName)
	}

	// 检查端点是否存在
	_, exists = serviceEndpoints[endpointID]
	if !exists {
		return fmt.Errorf("endpoint %s not found for service %s", endpointID, serviceName)
	}

	// 删除端点
	delete(serviceEndpoints, endpointID)
	sr.logger.Printf("Deregistered endpoint %s for service %s", endpointID, serviceName)

	// 如果服务没有端点了，删除服务
	if len(serviceEndpoints) == 0 {
		delete(sr.endpoints, serviceName)
		sr.logger.Printf("Removed service %s with no endpoints", serviceName)
	}

	return nil
}

// GetEndpoint 获取一个服务的端点，支持简单的负载均衡策略
func (sr *ServiceRegistry) GetEndpoint(serviceName string, strategy string) (*ServiceEndpoint, error) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	// 检查服务是否存在
	serviceEndpoints, exists := sr.endpoints[serviceName]
	if !exists || len(serviceEndpoints) == 0 {
		return nil, fmt.Errorf("no endpoints available for service %s", serviceName)
	}

	// 筛选健康的端点
	healthyEndpoints := make([]*ServiceEndpoint, 0)
	for _, endpoint := range serviceEndpoints {
		if endpoint.Healthy {
			healthyEndpoints = append(healthyEndpoints, endpoint)
		}
	}

	// 如果没有健康的端点，返回错误
	if len(healthyEndpoints) == 0 {
		return nil, fmt.Errorf("no healthy endpoints available for service %s", serviceName)
	}

	// 简化的端点选择逻辑：仅支持随机选择或默认选择第一个
	if strategy == "random" && len(healthyEndpoints) > 1 {
		return healthyEndpoints[time.Now().UnixNano()%int64(len(healthyEndpoints))], nil
	}
	
	// 默认使用第一个端点
	return healthyEndpoints[0], nil
}

// GetAllEndpoints 获取一个服务的所有端点
func (sr *ServiceRegistry) GetAllEndpoints(serviceName string) ([]*ServiceEndpoint, error) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	// 检查服务是否存在
	serviceEndpoints, exists := sr.endpoints[serviceName]
	if !exists {
		return nil, fmt.Errorf("service %s not found", serviceName)
	}

	// 转换为切片
	endpoints := make([]*ServiceEndpoint, 0, len(serviceEndpoints))
	for _, endpoint := range serviceEndpoints {
		endpoints = append(endpoints, endpoint)
	}

	return endpoints, nil
}

// GetAllServices 获取所有服务名称
func (sr *ServiceRegistry) GetAllServices() []string {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	services := make([]string, 0, len(sr.endpoints))
	for service := range sr.endpoints {
		services = append(services, service)
	}

	return services
}

// UpdateEndpointHealth 更新端点的健康状态
func (sr *ServiceRegistry) UpdateEndpointHealth(serviceName, endpointID string, healthy bool) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	// 检查服务是否存在
	serviceEndpoints, exists := sr.endpoints[serviceName]
	if !exists {
		return fmt.Errorf("service %s not found", serviceName)
	}

	// 检查端点是否存在
	endpoint, exists := serviceEndpoints[endpointID]
	if !exists {
		return fmt.Errorf("endpoint %s not found for service %s", endpointID, serviceName)
	}

	// 更新健康状态
	endpoint.Healthy = healthy
	endpoint.LastChecked = time.Now()

	sr.logger.Printf("Updated health status for endpoint %s of service %s: %v", endpointID, serviceName, healthy)

	return nil
}

// StartHealthCheck 启动定期健康检查
func (sr *ServiceRegistry) StartHealthCheck(interval time.Duration, checkFunc func(*ServiceEndpoint) bool) {
	ticker := time.NewTicker(interval)

	go func() {
		for range ticker.C {
			sr.checkAllEndpoints(checkFunc)
		}
	}()
}

// checkAllEndpoints 检查所有端点的健康状态
func (sr *ServiceRegistry) checkAllEndpoints(checkFunc func(*ServiceEndpoint) bool) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	for serviceName, serviceEndpoints := range sr.endpoints {
		for endpointID, endpoint := range serviceEndpoints {
			prevHealth := endpoint.Healthy
			endpoint.Healthy = checkFunc(endpoint)
			endpoint.LastChecked = time.Now()

			if prevHealth != endpoint.Healthy {
				sr.logger.Printf("Health status changed for endpoint %s of service %s: %v -> %v",
					endpointID, serviceName, prevHealth, endpoint.Healthy)
			}
		}
	}
}