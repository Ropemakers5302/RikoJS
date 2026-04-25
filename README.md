# RikoJS

一个高性能的 CLI 工具，用于快速侦察和 JS/API 攻击面分析。

## 功能特性

- **JS 分析 & HAE 引擎**：提取 JS 文件、发现敏感端点，并使用内置 HAE 正则规则检测硬编码密钥
- **指纹识别 & CVE 检测**：通过 HTTP 头/响应体识别 Web 技术并映射到已知 CVE
- **AI 驱动分析**：可选的 LLM 集成用于深度漏洞分析
- **API 模糊测试**：高并发目录/API 端点发现

## 安装

```bash
git clone https://github.com/Ropemakers5302/Rikojs.git
cd rikojs
go build -o rikojs ./cmd/rikojs
```

## 使用方法

```bash
./rikojs -u https://target.com [选项]
```

### 选项

| 标志 | 描述 | 默认值 |
|------|------|--------|
| `-u` | 目标 URL（必需） | - |
| `-t` | 并发线程数 | 25 |
| `-c` | 配置文件路径 | config.yaml |
| `--ai` | 启用 AI 分析 | false |
| `-o` | 输出文件路径 | auto |
| `-f` | 输出格式 | json |
| `--no-fuzz` | 跳过模糊测试 | false |

### 示例

```bash
# 基本扫描
./rikojs -u https://example.com

# 使用 AI 分析和自定义线程
./rikojs -u https://example.com -t 30 --ai

# 将结果保存到文件
./rikojs -u https://example.com -o results.json

# 跳过模糊测试以加快扫描
./rikojs -u https://example.com --no-fuzz
```

## 配置

创建 `config.yaml`：

```yaml
ai:
  enabled: false
  provider: "openai"
  api_key: ""
  api_base: "https://api.openai.com/v1"
  model: "gpt-4"

scan:
  threads: 25
  timeout: 10
  max_retries: 3

output:
  verbose: false
  save_results: true
  output_file: "results.json"
```

## 内置 HAE 规则

- AWS 访问密钥 / 密钥
- Google API 密钥 / OAuth
- GitHub / Slack / Stripe 令牌
- JWT 令牌
- 私钥
- 数据库连接字符串
- 通用密钥（password, api_key, token）

## 支持的技术

- Web 服务器：Nginx、Apache、IIS
- 应用服务器：Tomcat、WebLogic
- 框架：Spring、Django、Express、ThinkPHP
- CMS：WordPress、Drupal
- 安全：Shiro
- 等等...

## 项目结构

```
RikoJS/
├── cmd/rikojs/main.go
├── internal/
│   ├── ai/
│   ├── banner/
│   ├── config/
│   ├── fingerprint/
│   ├── fuzzer/
│   └── jsanalyser/
├── pkg/
│   ├── httpclient/
│   ├── output/
│   └── utils/
├── config.yaml
├── dicc.txt
└── go.mod
```

## 许可证

MIT 许可证
