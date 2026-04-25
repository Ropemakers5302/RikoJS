package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rikojs/internal/ai"
	"github.com/rikojs/internal/banner"
	"github.com/rikojs/internal/config"
	"github.com/rikojs/internal/fingerprint"
	"github.com/rikojs/internal/fuzzer"
	"github.com/rikojs/internal/jsanalyser"
	"github.com/rikojs/pkg/output"
	"github.com/rikojs/pkg/utils"
)

type Options struct {
	TargetURL  string
	ConfigPath string
	Threads    int
	EnableAI   bool
	Output     string
	Format     string
	NoFuzz     bool
}

func parseArgs() *Options {
	opts := &Options{}
	flag.StringVar(&opts.TargetURL, "u", "", "目标URL地址")
	flag.StringVar(&opts.ConfigPath, "c", "", "配置文件路径")
	flag.IntVar(&opts.Threads, "t", 25, "并发线程数 (默认: 25)")
	flag.BoolVar(&opts.EnableAI, "ai", false, "启用AI智能分析")
	flag.StringVar(&opts.Output, "o", "", "输出文件路径")
	flag.StringVar(&opts.Format, "f", "json", "输出格式 (json)")
	flag.BoolVar(&opts.NoFuzz, "no-fuzz", false, "跳过路径爆破")
	flag.Parse()
	return opts
}

func validateOptions(opts *Options) bool {
	if opts.TargetURL == "" {
		utils.PrintError("请指定目标URL，使用 -u <url>")
		flag.Usage()
		return false
	}
	return true
}

func runJSAnalyser(targetURL string, cfg *config.Config) ([]string, []jsanalyser.Secret) {
	utils.PrintInfo(fmt.Sprintf("[JS分析] 开始分析: %s", targetURL))

	analyser := jsanalyser.NewJSAnalyser(cfg)
	paths, secrets, err := analyser.Analyse(targetURL)
	if err != nil {
		utils.PrintError(fmt.Sprintf("JS分析失败: %v", err))
		return nil, nil
	}

	return paths, secrets
}

func runFingerprint(targetURL string, cfg *config.Config) []fingerprint.Fingerprint {
	utils.PrintInfo(fmt.Sprintf("[指纹识别] 开始扫描: %s", targetURL))

	scanner := fingerprint.NewScanner(cfg)
	fps, err := scanner.Scan(targetURL)
	if err != nil {
		utils.PrintError(fmt.Sprintf("指纹扫描失败: %v", err))
		return nil
	}

	return fps
}

func runAIAnalyser(cfg *config.Config, enableAI bool, secrets []jsanalyser.Secret, jsContent string) {
	if !enableAI && !cfg.AI.Enabled {
		utils.PrintInfo("[AI分析] 未启用AI分析，使用本地HAE规则")
		return
	}

	utils.PrintInfo("[AI分析] 启动AI智能漏洞分析...")

	analyzer := ai.NewAIAnalyzer(cfg)
	result, err := analyzer.Analyze(secrets, jsContent)
	if err != nil {
		utils.PrintError(fmt.Sprintf("AI分析失败: %v", err))
		return
	}

	if result != nil && len(result.Vulnerabilities) > 0 {
		utils.PrintWarn(fmt.Sprintf("[AI分析] 识别到可能存在 %d 个潜在漏洞", len(result.Vulnerabilities)))
		for _, vuln := range result.Vulnerabilities {
			severity := vuln.Severity
			if severity == "CRITICAL" || severity == "HIGH" {
				utils.PrintVuln(fmt.Sprintf("[%s] %s: %s", severity, vuln.Type, vuln.Description))
			} else {
				utils.PrintWarn(fmt.Sprintf("[%s] %s: %s", severity, vuln.Type, vuln.Description))
			}
		}
	} else {
		utils.PrintInfo("[AI分析] 分析完成，未发现额外漏洞")
	}
}

func runFuzzer(targetURL string, cfg *config.Config, threads int, discoveredPaths []string, skip bool) []fuzzer.Result {
	if skip {
		utils.PrintInfo("[路径爆破] 已跳过 (--no-fuzz)")
		return nil
	}

	utils.PrintInfo(fmt.Sprintf("[路径爆破] 启动扫描，线程数: %d", threads))

	f := fuzzer.NewFuzzer(cfg)
	results, err := f.Fuzz(targetURL, discoveredPaths)
	if err != nil {
		utils.PrintError(fmt.Sprintf("路径爆破失败: %v", err))
		return nil
	}

	return results
}

func main() {
	opts := parseArgs()

	if len(os.Args) == 1 {
		banner.PrintBanner()
		flag.Usage()
		os.Exit(1)
	}

	banner.PrintBanner()

	if !validateOptions(opts) {
		os.Exit(1)
	}

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		utils.PrintWarn(fmt.Sprintf("配置加载失败: %v，使用默认配置", err))
	}

	if opts.Threads != 25 {
		cfg.Scan.Threads = opts.Threads
	}

	utils.PrintInfo(fmt.Sprintf("目标地址: %s", opts.TargetURL))
	utils.PrintInfo(fmt.Sprintf("线程数量: %d", cfg.Scan.Threads))
	utils.PrintInfo(fmt.Sprintf("AI分析: %v", opts.EnableAI || cfg.AI.Enabled))
	fmt.Println()

	jsPaths, jsSecrets := runJSAnalyser(opts.TargetURL, cfg)
	fmt.Println()

	fps := runFingerprint(opts.TargetURL, cfg)
	fmt.Println()

	runAIAnalyser(cfg, opts.EnableAI, jsSecrets, "")
	fmt.Println()

	fuzzResults := runFuzzer(opts.TargetURL, cfg, cfg.Scan.Threads, jsPaths, opts.NoFuzz)

	exporter := output.NewExporter(opts.Output, opts.Format, opts.TargetURL)
	exporter.PrintSummary(opts.TargetURL, jsSecrets, jsPaths, fps, fuzzResults)

	exporter.Export(opts.TargetURL, jsSecrets, jsPaths, fps, fuzzResults)

	fmt.Println()
	utils.PrintInfo("扫描完成")
}
