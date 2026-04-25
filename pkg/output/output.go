package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rikojs/internal/fingerprint"
	"github.com/rikojs/internal/fuzzer"
	"github.com/rikojs/internal/jsanalyser"
	"github.com/rikojs/pkg/utils"
)

type ScanResult struct {
	Target       string                    `json:"target"`
	ScanTime     string                    `json:"scan_time"`
	Secrets      []jsanalyser.Secret       `json:"secrets,omitempty"`
	Paths        []string                  `json:"paths,omitempty"`
	Fingerprints []fingerprint.Fingerprint `json:"fingerprints,omitempty"`
	Endpoints    []fuzzer.Result           `json:"endpoints,omitempty"`
	Statistics   Statistics                `json:"statistics"`
}

type Statistics struct {
	JSSecrets      int `json:"js_secrets"`
	JSPaths        int `json:"js_paths"`
	Technologies   int `json:"technologies"`
	CVEs           int `json:"cves"`
	EndpointsFound int `json:"endpoints_found"`
}

type Exporter struct {
	outputPath string
	format     string
	targetURL  string
}

func NewExporter(outputPath, format, targetURL string) *Exporter {
	return &Exporter{
		outputPath: outputPath,
		format:     format,
		targetURL:  targetURL,
	}
}

func (e *Exporter) Export(target string, secrets []jsanalyser.Secret, paths []string,
	fps []fingerprint.Fingerprint, endpoints []fuzzer.Result) error {

	result := ScanResult{
		Target:       target,
		ScanTime:     time.Now().Format("2006-01-02 15:04:05"),
		Secrets:      secrets,
		Paths:        paths,
		Fingerprints: fps,
		Endpoints:    endpoints,
		Statistics: Statistics{
			JSSecrets:      len(secrets),
			JSPaths:        len(paths),
			Technologies:   len(fps),
			EndpointsFound: len(endpoints),
		},
	}

	cveCount := 0
	for _, fp := range fps {
		cveCount += len(fp.CVEs)
	}
	result.Statistics.CVEs = cveCount

	switch strings.ToLower(e.format) {
	case "json":
		return e.exportJSON(result)
	default:
		return e.exportJSON(result)
	}
}

func (e *Exporter) getDefaultOutputPath() string {
	target := e.targetURL
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimSuffix(target, "/")
	target = strings.ReplaceAll(target, "/", "_")
	target = strings.ReplaceAll(target, ":", "_")

	urlDir := "URL"
	if _, err := os.Stat(urlDir); os.IsNotExist(err) {
		os.MkdirAll(urlDir, 0755)
	}

	return filepath.Join(urlDir, target+".txt")
}

func (e *Exporter) exportJSON(result ScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	outputPath := e.outputPath
	if outputPath == "" {
		outputPath = e.getDefaultOutputPath()
	}

	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return err
	}

	utils.PrintInfo(fmt.Sprintf("结果已保存至: %s", outputPath))
	return nil
}

func (e *Exporter) PrintSummary(target string, secrets []jsanalyser.Secret, paths []string,
	fps []fingerprint.Fingerprint, endpoints []fuzzer.Result) {

	fmt.Println()
	utils.PrintInfo("扫描摘要")

	fmt.Printf("  目标地址:         %s\n", target)
	fmt.Printf("  JS敏感信息:       %d\n", len(secrets))
	fmt.Printf("  JS路径/API:       %d\n", len(paths))
	fmt.Printf("  识别技术栈:       %d\n", len(fps))

	cveCount := 0
	criticalCVEs := 0
	for _, fp := range fps {
		for _, cve := range fp.CVEs {
			cveCount++
			if cve.Severity == "CRITICAL" {
				criticalCVEs++
			}
		}
	}

	fmt.Printf("  可能存在的CVE:          %d (高危: %d)\n", cveCount, criticalCVEs)
	fmt.Printf("  有效端点:         %d\n", len(endpoints))

	if len(secrets) > 0 {
		utils.PrintWarn(fmt.Sprintf("! 发现 %d 个潜在敏感信息，请人工验证", len(secrets)))
	}

	if criticalCVEs > 0 {
		utils.PrintVuln(fmt.Sprintf("! 检测到可能存在 %d 个高危CVE", criticalCVEs))
	}
}
