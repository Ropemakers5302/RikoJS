package fuzzer

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rikojs/internal/config"
	"github.com/rikojs/pkg/utils"
)

type Result struct {
	URL        string
	StatusCode int
	ContentLen int64
	Title      string
	Redirect   string
}

type Fuzzer struct {
	cfg         *config.Config
	dictionary  []string
	results     []Result
	mu          sync.Mutex
	baseURL     string
	progress    int64
	total       int64
	found       int64
	maxRequests int
}

func NewFuzzer(cfg *config.Config) *Fuzzer {
	return &Fuzzer{
		cfg:         cfg,
		dictionary:  make([]string, 0),
		results:     make([]Result, 0),
		maxRequests: 5000,
	}
}

func (f *Fuzzer) LoadDictionary(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") && len(line) < 100 {
			f.dictionary = append(f.dictionary, line)
			count++
			if count >= f.maxRequests {
				break
			}
		}
	}

	return scanner.Err()
}

func (f *Fuzzer) Fuzz(targetURL string, discoveredPaths []string) ([]Result, error) {
	f.baseURL = strings.TrimSuffix(targetURL, "/")

	utils.PrintInfo("正在加载字典...")
	if err := f.LoadDictionary("dicc.txt"); err != nil {
		utils.PrintWarn(fmt.Sprintf("字典加载失败: %v", err))
	}

	paths := f.mergePaths(discoveredPaths)
	f.total = int64(len(paths))

	utils.PrintInfo(fmt.Sprintf("待扫描路径总数: %d (线程数: %d)", f.total, f.cfg.Scan.Threads))

	if len(paths) == 0 {
		return nil, nil
	}

	utils.PrintInfo("启动高并发模糊测试...")
	fmt.Println()

	go f.printProgress()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	f.fuzzPaths(ctx, paths)

	fmt.Println()
	f.printResults()

	return f.results, nil
}

func (f *Fuzzer) mergePaths(discoveredPaths []string) []string {
	seen := make(map[string]bool)
	paths := make([]string, 0)

	for _, p := range discoveredPaths {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	for _, dictPath := range f.dictionary {
		if !seen[dictPath] {
			seen[dictPath] = true
			paths = append(paths, dictPath)
		}
	}

	return paths
}

func (f *Fuzzer) fuzzPaths(ctx context.Context, paths []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, f.cfg.Scan.Threads)
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     10 * time.Second,
		},
	}

	for _, path := range paths {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			atomic.AddInt64(&f.progress, 1)

			fullURL := f.buildURL(p)
			result := f.probeURL(ctx, client, fullURL)
			if result != nil && result.StatusCode == 200 {
				f.mu.Lock()
				f.results = append(f.results, *result)
				f.mu.Unlock()
				atomic.AddInt64(&f.found, 1)
			}
		}(path)
	}
	wg.Wait()
}

func (f *Fuzzer) buildURL(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return f.baseURL + path
}

func (f *Fuzzer) probeURL(ctx context.Context, client *http.Client, urlStr string) *Result {
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode
	contentLen := resp.ContentLength
	redirect := ""
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		redirect = resp.Header.Get("Location")
	}

	return &Result{
		URL:        urlStr,
		StatusCode: statusCode,
		ContentLen: contentLen,
		Redirect:   redirect,
	}
}

func (f *Fuzzer) printProgress() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			progress := atomic.LoadInt64(&f.progress)
			found := atomic.LoadInt64(&f.found)
			percent := float64(progress) / float64(f.total) * 100
			fmt.Printf("\r%s[进度]%s %d/%d (%.1f%%) | 发现: %d    ",
				utils.ColorCyan, utils.ColorReset, progress, f.total, percent, found)
		}
	}
}

func (f *Fuzzer) printResults() {
	if len(f.results) == 0 {
		utils.PrintInfo("未发现有效路径")
		return
	}

	utils.PrintInfo(fmt.Sprintf("发现 %d 个有效端点 (状态码200)", len(f.results)))
	fmt.Println()

	for _, r := range f.results {
		fmt.Printf("%s[200]%s %s", utils.ColorGreen, utils.ColorReset, r.URL)
		if r.ContentLen > 0 {
			fmt.Printf(" [%d 字节]", r.ContentLen)
		}
		fmt.Println()
	}
}

func (f *Fuzzer) GetResults() []Result {
	return f.results
}

func sanitizeFilename(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return strings.ReplaceAll(u, "://", "_")
	}
	return parsed.Host
}
