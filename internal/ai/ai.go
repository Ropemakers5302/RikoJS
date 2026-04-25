package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rikojs/internal/config"
	"github.com/rikojs/internal/jsanalyser"
	"github.com/rikojs/pkg/utils"
)

type AIAnalyzer struct {
	cfg      *config.Config
	client   *http.Client
	provider Provider
}

type Provider interface {
	Analyze(ctx context.Context, code string, prompt string) (*AnalysisResult, error)
}

type AnalysisResult struct {
	Vulnerabilities []Vulnerability
	Summary         string
}

type Vulnerability struct {
	Type        string
	Severity    string
	Description string
	Location    string
	Code        string
}

type OpenAIProvider struct {
	apiKey  string
	apiBase string
	model   string
	client  *http.Client
}

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func NewAIAnalyzer(cfg *config.Config) *AIAnalyzer {
	analyzer := &AIAnalyzer{
		cfg: cfg,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}

	if cfg.AI.APIKey != "" {
		analyzer.provider = &OpenAIProvider{
			apiKey:  cfg.AI.APIKey,
			apiBase: cfg.AI.APIBase,
			model:   cfg.AI.Model,
			client:  analyzer.client,
		}
	}

	return analyzer
}

func (a *AIAnalyzer) Analyze(secrets []jsanalyser.Secret, jsContent string) (*AnalysisResult, error) {
	if a.provider == nil {
		return a.localAnalysis(secrets, jsContent)
	}

	utils.PrintInfo("正在发送代码片段至AI进行深度分析...")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var allResults []Vulnerability

	for _, secret := range secrets {
		prompt := a.buildSecretAnalysisPrompt(secret)
		result, err := a.provider.Analyze(ctx, secret.Value, prompt)
		if err != nil {
			utils.PrintWarn(fmt.Sprintf("AI分析失败 [%s]: %v", secret.Type, err))
			continue
		}
		if result != nil {
			allResults = append(allResults, result.Vulnerabilities...)
		}
	}

	if len(jsContent) > 0 && len(jsContent) < 8000 {
		prompt := a.buildCodeAnalysisPrompt(jsContent)
		result, err := a.provider.Analyze(ctx, jsContent, prompt)
		if err != nil {
			utils.PrintWarn(fmt.Sprintf("AI代码分析失败: %v", err))
		} else if result != nil {
			allResults = append(allResults, result.Vulnerabilities...)
		}
	}

	return &AnalysisResult{
		Vulnerabilities: allResults,
		Summary:         fmt.Sprintf("发现 %d 个潜在漏洞", len(allResults)),
	}, nil
}

func (a *AIAnalyzer) localAnalysis(secrets []jsanalyser.Secret, jsContent string) (*AnalysisResult, error) {
	utils.PrintInfo("使用本地分析 (未配置AI)")

	results := make([]Vulnerability, 0)

	highRiskPatterns := []struct {
		pattern  string
		vulnType string
		severity string
	}{
		{"password", "硬编码密码", "HIGH"},
		{"secret", "硬编码密钥", "MEDIUM"},
		{"apikey", "API密钥泄露", "HIGH"},
		{"token", "令牌泄露", "MEDIUM"},
		{"private_key", "私钥泄露", "CRITICAL"},
		{"authorization", "授权头泄露", "MEDIUM"},
	}

	jsLower := strings.ToLower(jsContent)
	for _, hp := range highRiskPatterns {
		if strings.Contains(jsLower, hp.pattern) {
			results = append(results, Vulnerability{
				Type:        hp.vulnType,
				Severity:    hp.severity,
				Description: fmt.Sprintf("JavaScript代码中发现潜在%s", hp.vulnType),
			})
		}
	}

	for _, secret := range secrets {
		results = append(results, Vulnerability{
			Type:        secret.Type,
			Severity:    secret.Severity,
			Description: fmt.Sprintf("HAE规则检测: %s", secret.Type),
			Location:    fmt.Sprintf("文件: %s, 行号: %d", secret.File, secret.Line),
			Code:        secret.Value,
		})
	}

	return &AnalysisResult{
		Vulnerabilities: results,
		Summary:         fmt.Sprintf("本地分析发现 %d 个潜在问题", len(results)),
	}, nil
}

func (a *AIAnalyzer) buildSecretAnalysisPrompt(secret jsanalyser.Secret) string {
	return fmt.Sprintf(`分析此潜在安全问题并给出简要评估:

类型: %s
值: %s
严重程度: %s

这是否为真实漏洞? 安全影响是什么? 请以JSON格式回复:
{"is_true_positive": true/false, "impact": "描述", "recommendation": "修复建议"}`,
		secret.Type, truncate(secret.Value, 200), secret.Severity)
}

func (a *AIAnalyzer) buildCodeAnalysisPrompt(code string) string {
	return fmt.Sprintf(`分析此JavaScript代码片段的安全漏洞。
重点关注: 硬编码凭证、不安全认证、XSS向量、SSRF、IDOR、SQL注入模式。

代码:
%s

请以JSON数组格式回复发现的漏洞:
[{"type": "漏洞类型", "severity": "HIGH/MEDIUM/LOW", "description": "描述", "location": "位置"}]

如未发现漏洞，回复: []`, truncate(code, 6000))
}

func (p *OpenAIProvider) Analyze(ctx context.Context, code string, prompt string) (*AnalysisResult, error) {
	req := openAIRequest{
		Model: p.model,
		Messages: []openAIMessage{
			{
				Role:    "system",
				Content: "你是一位安全专家，负责分析代码漏洞。请始终以有效的JSON格式回复。",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.apiBase+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var openAIResp openAIResponse
	if err := json.Unmarshal(respBody, &openAIResp); err != nil {
		return nil, err
	}

	if openAIResp.Error != nil {
		return nil, fmt.Errorf("API错误: %s", openAIResp.Error.Message)
	}

	if len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("API未返回响应")
	}

	return &AnalysisResult{
		Summary: openAIResp.Choices[0].Message.Content,
	}, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
