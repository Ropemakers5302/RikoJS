package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/rikojs/internal/config"
	"github.com/rikojs/pkg/httpclient"
	"github.com/rikojs/pkg/utils"
)

type Scanner struct {
	client       *httpclient.HttpClient
	cfg          *config.Config
	fingerprints []FingerprintRule
	results      []Fingerprint
	mu           sync.Mutex
}

func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{
		client:       httpclient.NewClient(cfg),
		cfg:          cfg,
		fingerprints: getDefaultFingerprints(),
		results:      make([]Fingerprint, 0),
	}
}

func (s *Scanner) Scan(targetURL string) ([]Fingerprint, error) {
	utils.PrintInfo("发送HTTP请求进行指纹识别...")

	ctx := context.Background()
	body, resp, err := s.client.Get(ctx, targetURL)
	if err != nil {
		return nil, err
	}

	s.analyzeResponse(targetURL, string(body), resp)

	s.printResults()

	return s.results, nil
}

func (s *Scanner) analyzeResponse(targetURL string, body string, resp *http.Response) {
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	for _, fp := range s.fingerprints {
		matched := false
		version := ""

		for _, hr := range fp.HeaderRules {
			headerName := hr.Header
			for h, v := range headers {
				if strings.EqualFold(h, headerName) || strings.Contains(strings.ToLower(h), strings.ToLower(headerName)) {
					if match, ver := hr.Match(v); match {
						matched = true
						if ver != "" {
							version = ver
						}
					}
				}
			}
		}

		for _, br := range fp.BodyRules {
			if match, ver := br.Match(body); match {
				matched = true
				if ver != "" {
					version = ver
				}
			}
		}

		if matched {
			result := Fingerprint{
				Name:     fp.Name,
				Version:  version,
				Category: fp.Category,
				CVEs:     fp.CVEs,
			}
			s.mu.Lock()
			s.results = append(s.results, result)
			s.mu.Unlock()
		}
	}

	s.detectAdditionalTech(body, headers)
}

func (s *Scanner) detectAdditionalTech(body string, headers map[string]string) {
	techPatterns := map[string]struct {
		Patterns []string
		Category string
	}{
		"jQuery": {
			Patterns: []string{"jquery", "jQuery"},
			Category: "Library",
		},
		"Bootstrap": {
			Patterns: []string{"bootstrap", "Bootstrap"},
			Category: "Framework",
		},
		"Laravel": {
			Patterns: []string{"laravel", "Laravel"},
			Category: "Framework",
		},
		"Ruby on Rails": {
			Patterns: []string{"ruby", "rails", "csrf-token"},
			Category: "Framework",
		},
	}

	for tech, info := range techPatterns {
		for _, pattern := range info.Patterns {
			if strings.Contains(body, pattern) {
				found := false
				for _, r := range s.results {
					if r.Name == tech {
						found = true
						break
					}
				}
				if !found {
					s.mu.Lock()
					s.results = append(s.results, Fingerprint{
						Name:     tech,
						Category: info.Category,
					})
					s.mu.Unlock()
				}
				break
			}
		}
	}
}

func (s *Scanner) printResults() {
	if len(s.results) == 0 {
		utils.PrintInfo("未识别到技术指纹")
		return
	}

	utils.PrintInfo(fmt.Sprintf("识别到 %d 项技术", len(s.results)))
	fmt.Println()

	for _, fp := range s.results {
		versionStr := ""
		if fp.Version != "" {
			versionStr = fmt.Sprintf(" (%s)", fp.Version)
		}
		utils.PrintData(fmt.Sprintf("[%-15s] %s%s", fp.Category, fp.Name, versionStr))

		if len(fp.CVEs) > 0 {
			for _, cve := range fp.CVEs {
				severityColor := utils.ColorYellow
				if cve.Severity == "CRITICAL" {
					severityColor = utils.ColorRed
				} else if cve.Severity == "HIGH" {
					severityColor = utils.ColorYellow
				}
				fmt.Printf("  %s[%s]%s %s - %s\n", severityColor, cve.Severity, utils.ColorReset, cve.ID, cve.Description)
			}
		}
	}
}

func (s *Scanner) AddCustomRule(name, category string, headerRules []HeaderRule, bodyRules []BodyRule, cves []CVEInfo) {
	s.fingerprints = append(s.fingerprints, FingerprintRule{
		Name:        name,
		Category:    category,
		HeaderRules: headerRules,
		BodyRules:   bodyRules,
		CVEs:        cves,
	})
}

func (s *Scanner) GetResults() []Fingerprint {
	return s.results
}
