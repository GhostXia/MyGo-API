# MyGo-API

## 项目简介

这是一个通用的API反向代理模板，专为兼容OpenAI API格式设计。它可以将请求转发到其他API服务，并将响应转换为OpenAI兼容格式返回给客户端。

## 主要特性

- 完全兼容OpenAI API格式的请求和响应
- 支持流式(Stream)和非流式响应
- 内置请求重试机制和错误处理
- 支持HTTP/SOCKS5代理
- 可配置的请求速率限制
- 响应缓存机制提高性能
- 支持配置文件和命令行参数
- 支持多种模型

## 安装与使用

### 前置条件

- Go 1.16+
- 以下依赖包:
  - github.com/google/uuid
  - github.com/patrickmn/go-cache
  - golang.org/x/time/rate

### 安装依赖

```bash
go get github.com/google/uuid
go get github.com/patrickmn/go-cache
go get golang.org/x/time/rate
```

### 配置

1. 复制配置文件示例并根据需要修改:

```bash
cp config.json.example config.json
```

2. 编辑`config.json`文件，设置你的API认证令牌和其他参数。

### 运行

```bash
go run My.go --config config.json
```

或者使用命令行参数:

```bash
go run My.go --token "your-token" --port 8080 --proxy "http://your-proxy-url"
```

## API端点

### 1. 聊天补全 - /v1/chat/completions

与OpenAI的聊天补全API兼容的端点。

**请求示例:**

```json
{
  "model": "generic-model",
  "messages": [
    {"role": "system", "content": "你是一个有用的助手。"},
    {"role": "user", "content": "你好！"}
  ],
  "stream": false
}
```

### 2. 模型列表 - /v1/models

返回可用模型列表。

## 自定义与扩展

- 修改`preparePayload`方法以适配目标API的请求格式
- 实现自定义的`StreamParser`接口以解析不同格式的流式响应
- 添加更多OpenAI兼容的API端点

## 许可证

MIT