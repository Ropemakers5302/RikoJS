package jsanalyser

import (
	"regexp"
	"strings"
)

type Extractor struct {
	pathPatterns []*regexp.Regexp
	urlPatterns  []*regexp.Regexp
}

func NewExtractor() *Extractor {
	return &Extractor{
		pathPatterns: initPathPatterns(),
		urlPatterns:  initURLPatterns(),
	}
}

func initPathPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`["'](/api/[^"']+)["']`),
		regexp.MustCompile(`["'](/v[0-9]+/[^"']+)["']`),
		regexp.MustCompile(`["'](/[a-zA-Z][a-zA-Z0-9_\-/]+)["']`),
		regexp.MustCompile(`["']\s*([a-zA-Z][a-zA-Z0-9_\-/]*/[a-zA-Z][a-zA-Z0-9_\-/]*)\s*["']`),
		regexp.MustCompile(`(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`\.ajax\s*\(\s*\{[^}]*url\s*:\s*["']([^"']+)["']`),
		regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`axios\.(?:get|post|put|delete)\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`baseUrl\s*[=:]\s*["']([^"']+)["']`),
		regexp.MustCompile(`apiUrl\s*[=:]\s*["']([^"']+)["']`),
		regexp.MustCompile(`endpoint\s*[=:]\s*["']([^"']+)["']`),
	}
}

func initURLPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`https?://[^\s'"<>]+\.[a-zA-Z]{2,}`),
		regexp.MustCompile(`["'](https?://[^"']+)["']`),
	}
}

func (e *Extractor) ExtractPaths(content string) []string {
	paths := make([]string, 0)
	seen := make(map[string]bool)

	for _, pattern := range e.pathPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				path := cleanPath(match[1])
				if isValidPath(path) && !seen[path] {
					seen[path] = true
					paths = append(paths, path)
				}
			}
		}
	}

	return paths
}

func (e *Extractor) ExtractURLs(content string) []string {
	urls := make([]string, 0)
	seen := make(map[string]bool)

	for _, pattern := range e.urlPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				url := match[1]
				if !seen[url] {
					seen[url] = true
					urls = append(urls, url)
				}
			}
		}
	}

	return urls
}

func cleanPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.TrimSuffix(path, ";")
	path = strings.TrimSuffix(path, ",")
	path = strings.Trim(path, "\"'")

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return path
}

func isValidPath(path string) bool {
	if len(path) < 4 {
		return false
	}

	invalidPatterns := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".webm",
	}

	for _, ext := range invalidPatterns {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			return false
		}
	}

	if strings.Contains(path, "function(") ||
		strings.Contains(path, "()") ||
		strings.Contains(path, "=>") {
		return false
	}

	return true
}
