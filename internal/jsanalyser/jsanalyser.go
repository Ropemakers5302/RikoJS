package jsanalyser

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/rikojs/internal/config"
	"github.com/rikojs/pkg/httpclient"
	"github.com/rikojs/pkg/utils"
)

type JSFile struct {
	URL     string
	Content string
	Source  string
}

type JSAnalyser struct {
	client    *httpclient.HttpClient
	cfg       *config.Config
	jsFiles   []JSFile
	paths     []string
	secrets   []Secret
	mu        sync.Mutex
	hae       *HAEEngine
	extractor *Extractor
}

type Secret struct {
	Type     string
	Value    string
	File     string
	Line     int
	Severity string
}

func NewJSAnalyser(cfg *config.Config) *JSAnalyser {
	return &JSAnalyser{
		client:    httpclient.NewClient(cfg),
		cfg:       cfg,
		jsFiles:   make([]JSFile, 0),
		paths:     make([]string, 0),
		secrets:   make([]Secret, 0),
		hae:       NewHAEEngine(),
		extractor: NewExtractor(),
	}
}

func (ja *JSAnalyser) Analyse(targetURL string) ([]string, []Secret, error) {
	utils.PrintInfo("正在获取目标页面...")

	ctx := context.Background()
	html, _, err := ja.client.Get(ctx, targetURL)
	if err != nil {
		return nil, nil, err
	}

	jsURLs := ja.extractJSURLs(targetURL, string(html))
	utils.PrintInfo(fmt.Sprintf("发现 %d 个JS文件", len(jsURLs)))

	ja.fetchJSFiles(ctx, targetURL, jsURLs)

	ja.analyzeJSFiles()

	return ja.paths, ja.secrets, nil
}

func (ja *JSAnalyser) extractJSURLs(baseURL, html string) []string {
	jsURLs := make([]string, 0)
	seen := make(map[string]bool)

	srcPattern := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
	matches := srcPattern.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			resolved := httpclient.ResolveURL(baseURL, match[1])
			if resolved != "" && !seen[resolved] {
				seen[resolved] = true
				jsURLs = append(jsURLs, resolved)
			}
		}
	}

	inlinePattern := regexp.MustCompile(`(?i)<script[^>]*>([\s\S]*?)</script>`)
	inlineMatches := inlinePattern.FindAllStringSubmatch(html, -1)
	for _, match := range inlineMatches {
		if len(match) > 1 && len(match[1]) > 50 {
			ja.mu.Lock()
			ja.jsFiles = append(ja.jsFiles, JSFile{
				URL:     baseURL + " [内联]",
				Content: match[1],
				Source:  "inline",
			})
			ja.mu.Unlock()
		}
	}

	return jsURLs
}

func (ja *JSAnalyser) fetchJSFiles(ctx context.Context, baseURL string, jsURLs []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, ja.cfg.Scan.Threads)

	for _, jsURL := range jsURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			content, _, err := ja.client.Get(ctx, url)
			if err != nil {
				return
			}

			ja.mu.Lock()
			ja.jsFiles = append(ja.jsFiles, JSFile{
				URL:     url,
				Content: string(content),
				Source:  "external",
			})
			ja.mu.Unlock()
		}(jsURL)
	}
	wg.Wait()
}

func (ja *JSAnalyser) analyzeJSFiles() {
	utils.PrintInfo("正在分析JS文件，提取敏感信息...")

	var wg sync.WaitGroup

	for _, jsFile := range ja.jsFiles {
		wg.Add(1)
		go func(file JSFile) {
			defer wg.Done()

			secrets := ja.hae.Scan(file.Content)
			for i := range secrets {
				secrets[i].File = file.URL
			}

			if len(secrets) > 0 {
				ja.mu.Lock()
				ja.secrets = append(ja.secrets, secrets...)
				ja.mu.Unlock()
			}

			paths := ja.extractor.ExtractPaths(file.Content)
			if len(paths) > 0 {
				ja.mu.Lock()
				ja.paths = append(ja.paths, paths...)
				ja.mu.Unlock()
			}
		}(jsFile)
	}
	wg.Wait()

	ja.paths = uniquePaths(ja.paths)

	ja.printResults()
}

func (ja *JSAnalyser) printResults() {
	if len(ja.secrets) > 0 {
		utils.PrintWarn(fmt.Sprintf("发现 %d 个潜在敏感信息!", len(ja.secrets)))
		for _, secret := range ja.secrets {
			severity := secret.Severity
			if severity == "HIGH" || severity == "CRITICAL" {
				utils.PrintVuln(fmt.Sprintf("[%s] %s: %s", severity, secret.Type, truncate(secret.Value, 60)))
			} else {
				utils.PrintWarn(fmt.Sprintf("[%s] %s: %s", severity, secret.Type, truncate(secret.Value, 60)))
			}
		}
	}

	if len(ja.paths) > 0 {
		utils.PrintInfo(fmt.Sprintf("发现 %d 个路径/API", len(ja.paths)))
		for _, path := range ja.paths {
			utils.PrintData(path)
		}
	}
}

func uniquePaths(paths []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] && len(p) > 3 {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
