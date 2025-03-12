package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// ConfigManager 定义了配置管理器，支持配置热重载
type ConfigManager struct {
	configPath    string          // 配置文件路径
	currentConfig Config          // 当前配置
	mu            sync.RWMutex    // 用于并发安全
	listeners     []ConfigListener // 配置变更监听器
	lastModified  time.Time       // 配置文件最后修改时间
	logger        *log.Logger     // 日志记录器
	watchInterval time.Duration   // 文件监控间隔
}

// ConfigListener 定义了配置变更监听器接口
type ConfigListener interface {
	OnConfigChange(oldConfig, newConfig Config)
}

// ConfigListenerFunc 是ConfigListener接口的函数类型实现
type ConfigListenerFunc func(oldConfig, newConfig Config)

func (f ConfigListenerFunc) OnConfigChange(oldConfig, newConfig Config) {
	f(oldConfig, newConfig)
}

// ApplyFlags 应用命令行参数到配置
func (cm *ConfigManager) ApplyFlags(flags map[string]interface{}) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if v, ok := flags["token"].(string); ok && v != "" {
		cm.currentConfig.AuthToken = v
	}
	if v, ok := flags["port"].(int); ok && v != 0 {
		cm.currentConfig.Port = v
	}
	if v, ok := flags["proxy"].(string); ok && v != "" {
		cm.currentConfig.HTTPProxy = v
	}
}

// NewConfigManager 创建一个新的配置管理器
func NewConfigManager(configPath string, logger *log.Logger) (*ConfigManager, error) {
	if logger == nil {
		logger = log.New(os.Stdout, "[ConfigManager] ", log.LstdFlags)
	}

	cm := &ConfigManager{
		configPath:    configPath,
		listeners:     make([]ConfigListener, 0),
		logger:        logger,
		watchInterval: 10 * time.Second, // 默认10秒检查一次
	}

	// 加载初始配置
	if err := cm.loadConfig(); err != nil {
		return nil, err
	}

	return cm, nil
}

// loadConfig 从文件加载配置
func (cm *ConfigManager) loadConfig() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 检查文件是否存在
	fileInfo, err := os.Stat(cm.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在，使用默认配置
			cm.currentConfig = Config{
				Port:       8080,
				BaseURL:    "https://api.example.com",
				Timeout:    30 * time.Second,
				RetryCount: 3,
				Models:     []string{"generic-model"},
				RateLimit:  60,
				CacheSize:  1000,
			}
			cm.logger.Printf("配置文件 %s 不存在，使用默认配置", cm.configPath)
			return nil
		}
		return fmt.Errorf("无法读取配置文件: %v", err)
	}

	// 记录文件修改时间
	cm.lastModified = fileInfo.ModTime()

	// 打开并解析配置文件
	file, err := os.Open(cm.configPath)
	if err != nil {
		return fmt.Errorf("无法打开配置文件: %v", err)
	}
	defer file.Close()

	// 解析JSON配置
	var newConfig Config
	if err := json.NewDecoder(file).Decode(&newConfig); err != nil {
		return fmt.Errorf("无法解析配置文件: %v", err)
	}

	// 保存新配置
	oldConfig := cm.currentConfig
	cm.currentConfig = newConfig

	// 通知监听器（首次加载不通知）
	if oldConfig.BaseURL != "" {
		cm.notifyListeners(oldConfig, newConfig)
	}

	cm.logger.Printf("成功加载配置文件 %s", cm.configPath)
	return nil
}

// GetConfig 获取当前配置的副本
func (cm *ConfigManager) GetConfig() Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.currentConfig
}

// AddListener 添加配置变更监听器
func (cm *ConfigManager) AddListener(listener ConfigListener) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.listeners = append(cm.listeners, listener)
}

// AddListenerFunc 添加配置变更监听函数
func (cm *ConfigManager) AddListenerFunc(listenerFunc func(oldConfig, newConfig Config)) {
	cm.AddListener(ConfigListenerFunc(listenerFunc))
}

// notifyListeners 通知所有监听器配置已变更
func (cm *ConfigManager) notifyListeners(oldConfig, newConfig Config) {
	for _, listener := range cm.listeners {
		go listener.OnConfigChange(oldConfig, newConfig)
	}
}

// StartWatching 开始监控配置文件变更
func (cm *ConfigManager) StartWatching() {
	ticker := time.NewTicker(cm.watchInterval)

	go func() {
		for range ticker.C {
			cm.checkConfigFile()
		}
	}()

	cm.logger.Printf("开始监控配置文件 %s 的变更，间隔: %v", cm.configPath, cm.watchInterval)
}

// checkConfigFile 检查配置文件是否已更改
func (cm *ConfigManager) checkConfigFile() {
	// 获取文件信息
	fileInfo, err := os.Stat(cm.configPath)
	if err != nil {
		cm.logger.Printf("无法获取配置文件信息: %v", err)
		return
	}

	// 检查修改时间
	cm.mu.RLock()
	lastMod := cm.lastModified
	cm.mu.RUnlock()

	if fileInfo.ModTime().After(lastMod) {
		cm.logger.Printf("检测到配置文件变更，正在重新加载")
		if err := cm.loadConfig(); err != nil {
			cm.logger.Printf("重新加载配置文件失败: %v", err)
		}
	}
}

// SetWatchInterval 方法已移除，使用默认监控间隔

// SaveConfig 保存当前配置到文件
func (cm *ConfigManager) SaveConfig() error {
	cm.mu.RLock()
	config := cm.currentConfig
	cm.mu.RUnlock()

	// 创建临时文件
	tmpFile := cm.configPath + ".tmp"
	file, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("无法创建临时配置文件: %v", err)
	}

	// 将配置序列化为JSON并写入文件
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		file.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("无法写入配置: %v", err)
	}

	// 关闭文件
	if err := file.Close(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("无法关闭临时配置文件: %v", err)
	}

	// 重命名临时文件为正式配置文件
	if err := os.Rename(tmpFile, cm.configPath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("无法更新配置文件: %v", err)
	}

	cm.logger.Printf("成功保存配置到文件 %s", cm.configPath)
	return nil
}

// UpdateConfig 更新配置并保存到文件
func (cm *ConfigManager) UpdateConfig(updater func(*Config)) error {
	cm.mu.Lock()
	oldConfig := cm.currentConfig
	
	// 创建配置副本并应用更新
	newConfig := oldConfig
	updater(&newConfig)
	
	// 保存新配置
	cm.currentConfig = newConfig
	cm.mu.Unlock()

	// 保存到文件
	if err := cm.SaveConfig(); err != nil {
		// 保存失败，回滚配置
		cm.mu.Lock()
		cm.currentConfig = oldConfig
		cm.mu.Unlock()
		return err
	}

	// 通知监听器
	cm.notifyListeners(oldConfig, newConfig)
	return nil
}